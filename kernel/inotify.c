#include <stdlib.h>
#include <string.h>
#include "kernel/calls.h"
#include "kernel/fs.h"
#include "kernel/inotify.h"
#include "fs/path.h"
#include "fs/poll.h"

// inotify: file change notification.
//
// Linux attaches watches to inodes. The filesystems here have no inode
// objects that outlive an open file, so a watch is attached to the normalized
// path of the file instead, and follows the file when it is renamed. Events
// come from the generic filesystem layer and from reads and writes made
// through this kernel. Two things follow from that:
//  - a change made through another hard link of a watched file is not seen;
//  - changes that bypass the kernel are not seen: writes through a shared
//    memory mapping, and anything the host does to the files directly.

struct inotify_watch {
    struct list links;
    int_t wd;
    uint32_t mask; // events wanted, plus IN_ONESHOT_
    char *path; // absolute, no trailing slash, "/" for the root
    size_t path_len;
};

struct inotify_queued {
    struct list links;
    int_t wd;
    uint32_t mask;
    uint32_t cookie;
    uint32_t len; // size of name with its padding, 0 if there is no name
    char name[];
};

struct inotify {
    struct list instances;
    struct fd *fd;
    struct list watches;
    struct list events;
    unsigned queued;
    bool overflowed; // an IN_Q_OVERFLOW event is in the queue
    int_t next_wd;
    // Mirrors queued, so poll can look without taking inotify_lock. Events
    // wake pollers while holding that lock, and poll calls back into here
    // holding its own, so taking it in poll would deadlock.
    _Atomic unsigned readable;
};

// what Linux allows by default (fs.inotify.max_queued_events)
#define INOTIFY_MAX_QUEUED 16384

// the on-the-wire event header, followed by len bytes of name
struct inotify_event_ {
    int_t wd;
    uint32_t mask;
    uint32_t cookie;
    uint32_t len;
};

// events that can happen to a watched file itself
#define SELF_EVENTS (IN_ACCESS_ | IN_MODIFY_ | IN_ATTRIB_ | IN_CLOSE_WRITE_ | IN_CLOSE_NOWRITE_ | IN_OPEN_)
// events reported, with a name, to the watch on a file's directory
#define CHILD_EVENTS (SELF_EVENTS | IN_MOVED_FROM_ | IN_MOVED_TO_ | IN_CREATE_ | IN_DELETE_)

// protects every instance, its watches and its queue
static lock_t inotify_lock = LOCK_INITIALIZER;
static struct list inotify_instances = LIST_INITIALIZER(inotify_instances);
_Atomic uint32_t inotify_interest;
static uint32_t next_cookie;

static struct fd_ops inotify_ops;

#define IN_CLOEXEC_ O_CLOEXEC_
#define IN_NONBLOCK_ O_NONBLOCK_

// Recomputes inotify_interest after watches were added, changed or removed.
// IN_IGNORED_ is always set while any watch exists, so that the result is
// nonzero even for a watch that asked for nothing the hooks produce.
static void update_interest(void) {
    uint32_t interest = 0;
    struct inotify *in;
    list_for_each_entry(&inotify_instances, in, instances) {
        struct inotify_watch *watch;
        list_for_each_entry(&in->watches, watch, links)
            interest |= (watch->mask & IN_ALL_EVENTS_) | IN_IGNORED_;
    }
    atomic_store(&inotify_interest, interest);
}

static void queue_event(struct inotify *in, int_t wd, uint32_t mask, uint32_t cookie, const char *name) {
    size_t name_len = name != NULL ? strlen(name) : 0;

    // an event identical to the newest one in the queue adds nothing
    if (!list_empty(&in->events)) {
        struct inotify_queued *last = list_entry(in->events.prev, struct inotify_queued, links);
        if (last->wd == wd && last->mask == mask && last->cookie == cookie &&
                (last->len != 0) == (name_len != 0) &&
                (name_len == 0 || strcmp(last->name, name) == 0))
            return;
    }

    // a full queue gets one overflow marker and then drops events
    if (in->queued >= INOTIFY_MAX_QUEUED) {
        if (in->overflowed)
            return;
        in->overflowed = true;
        wd = -1;
        mask = IN_Q_OVERFLOW_;
        cookie = 0;
        name_len = 0;
    }

    // the name is nul terminated and padded to a multiple of the header size
    uint32_t len = 0;
    if (name_len != 0)
        len = (name_len + 1 + sizeof(struct inotify_event_) - 1) & ~(sizeof(struct inotify_event_) - 1);
    struct inotify_queued *event = calloc(1, sizeof(*event) + len);
    if (event == NULL)
        return;
    event->wd = wd;
    event->mask = mask;
    event->cookie = cookie;
    event->len = len;
    if (name_len != 0)
        memcpy(event->name, name, name_len);
    list_add_tail(&in->events, &event->links);
    in->queued++;
    atomic_store(&in->readable, in->queued);

    notify(&in->fd->cond);
    poll_wakeup(in->fd, POLL_READ);
}

// Removes a watch, telling its owner with IN_IGNORED.
static void remove_watch(struct inotify *in, struct inotify_watch *watch) {
    queue_event(in, watch->wd, IN_IGNORED_, 0, NULL);
    list_remove(&watch->links);
    free(watch->path);
    free(watch);
}

// Queues mask on a watch if the watch asked for any of it. Returns true if
// that removed the watch (it was a oneshot).
static bool deliver(struct inotify *in, struct inotify_watch *watch, uint32_t mask, uint32_t cookie, const char *name) {
    uint32_t events = mask & watch->mask & IN_ALL_EVENTS_;
    if (events == 0)
        return false;
    queue_event(in, watch->wd, events | (mask & IN_ISDIR_), cookie, name);
    if (watch->mask & IN_ONESHOT_) {
        remove_watch(in, watch);
        return true;
    }
    return false;
}

// Splits a normalized path into the length of its directory part and its
// last component. The directory of "/a" is the root, which is length 0 here.
static const char *path_split(const char *path, size_t *dir_len) {
    const char *slash = strrchr(path, '/');
    if (slash == NULL) {
        *dir_len = 0;
        return path;
    }
    *dir_len = slash - path;
    return slash + 1;
}

static bool watch_is_path(struct inotify_watch *watch, const char *path, size_t path_len) {
    if (path_len == 0) // the root, given as ""
        return watch->path_len == 1;
    return watch->path_len == path_len && memcmp(watch->path, path, path_len) == 0;
}

// Sends self_mask to watches on path and child_mask, with the last component
// of path as the name, to watches on its directory. inotify_lock must be held.
static void dispatch(const char *path, uint32_t self_mask, uint32_t child_mask, uint32_t cookie) {
    if (strcmp(path, "/") == 0)
        path = "";
    size_t path_len = strlen(path);
    size_t dir_len;
    const char *name = path_split(path, &dir_len);
    bool removed = false;

    struct inotify *in;
    list_for_each_entry(&inotify_instances, in, instances) {
        struct inotify_watch *watch, *tmp;
        list_for_each_entry_safe(&in->watches, watch, tmp, links) {
            if (watch_is_path(watch, path, path_len)) {
                if (self_mask != 0)
                    removed |= deliver(in, watch, self_mask, 0, NULL);
            } else if (path_len != 0 && watch_is_path(watch, path, dir_len)) {
                if (child_mask != 0)
                    removed |= deliver(in, watch, child_mask, cookie, name);
            }
        }
    }
    if (removed)
        update_interest();
}

void inotify_path_event(const char *path, uint32_t mask) {
    if (!inotify_wants(mask))
        return;
    lock(&inotify_lock);
    uint32_t flags = mask & IN_ISDIR_;
    dispatch(path, (mask & SELF_EVENTS) | flags, (mask & CHILD_EVENTS) | flags, 0);
    unlock(&inotify_lock);
}

void inotify_fd_event(struct fd *fd, uint32_t mask) {
    if (!inotify_wants(mask))
        return;
    // only files and directories opened from a filesystem have a path to match
    if (fd->mount == NULL || fd->mount->fs->getpath == NULL)
        return;
    if (!S_ISREG(fd->type) && !S_ISDIR(fd->type))
        return;
    char path[MAX_PATH + 1];
    if (generic_getpath(fd, path) < 0)
        return;
    inotify_path_event(path, mask | (S_ISDIR(fd->type) ? IN_ISDIR_ : 0));
}

// Ends every watch on exactly this path: the file is gone.
static void drop_watches_on(const char *path) {
    size_t path_len = strlen(path);
    struct inotify *in;
    list_for_each_entry(&inotify_instances, in, instances) {
        struct inotify_watch *watch, *tmp;
        list_for_each_entry_safe(&in->watches, watch, tmp, links) {
            if (!watch_is_path(watch, path, path_len))
                continue;
            // a oneshot watch is removed by the delivery itself
            if (!deliver(in, watch, IN_DELETE_SELF_, 0, NULL))
                remove_watch(in, watch);
        }
    }
    update_interest();
}

void inotify_path_removed(const char *path, bool is_dir) {
    if (!inotify_watching())
        return;
    if (strcmp(path, "/") == 0)
        path = "";
    lock(&inotify_lock);
    dispatch(path, 0, IN_DELETE_ | (is_dir ? IN_ISDIR_ : 0), 0);
    drop_watches_on(path);
    unlock(&inotify_lock);
}

void inotify_path_moved(const char *from, const char *to, bool is_dir) {
    if (!inotify_watching())
        return;
    if (strcmp(from, "/") == 0 || strcmp(to, "/") == 0 || from[0] == '\0' || to[0] == '\0')
        return; // the root cannot be renamed
    if (strcmp(from, to) == 0)
        return; // renaming a file to itself does nothing
    lock(&inotify_lock);
    uint32_t flags = is_dir ? IN_ISDIR_ : 0;
    // the two halves of a rename are tied together by a shared cookie
    uint32_t cookie = ++next_cookie;
    if (cookie == 0)
        cookie = ++next_cookie;
    dispatch(from, 0, IN_MOVED_FROM_ | flags, cookie);
    dispatch(to, 0, IN_MOVED_TO_ | flags, cookie);
    // whatever was at the destination has been replaced
    drop_watches_on(to);

    // Watches on the renamed file, and on anything below it if it is a
    // directory, stay with their files under the new name.
    size_t from_len = strlen(from);
    size_t to_len = strlen(to);
    struct inotify *in;
    list_for_each_entry(&inotify_instances, in, instances) {
        struct inotify_watch *watch, *tmp;
        list_for_each_entry_safe(&in->watches, watch, tmp, links) {
            if (watch->path_len < from_len || memcmp(watch->path, from, from_len) != 0)
                continue;
            if (watch->path[from_len] != '\0' && watch->path[from_len] != '/')
                continue;
            bool is_self = watch->path[from_len] == '\0';

            size_t new_len = to_len + (watch->path_len - from_len);
            char *new_path = malloc(new_len + 1);
            if (new_path == NULL)
                continue;
            memcpy(new_path, to, to_len);
            strcpy(new_path + to_len, watch->path + from_len);
            free(watch->path);
            watch->path = new_path;
            watch->path_len = new_len;

            if (is_self)
                deliver(in, watch, IN_MOVE_SELF_ | flags, 0, NULL);
        }
    }
    update_interest();
    unlock(&inotify_lock);
}

fd_t sys_inotify_init1(int_t flags) {
    STRACE("inotify_init1(%#x)", flags);
    if (flags & ~(IN_CLOEXEC_|IN_NONBLOCK_))
        return _EINVAL;

    struct inotify *in = calloc(1, sizeof(*in));
    if (in == NULL)
        return _ENOMEM;
    struct fd *fd = adhoc_fd_create(&inotify_ops);
    if (fd == NULL) {
        free(in);
        return _ENOMEM;
    }
    in->fd = fd;
    in->next_wd = 1;
    list_init(&in->watches);
    list_init(&in->events);
    fd->data = in;

    lock(&inotify_lock);
    list_add(&inotify_instances, &in->instances);
    unlock(&inotify_lock);
    return f_install(fd, flags);
}

int_t sys_inotify_add_watch(fd_t inotify_f, addr_t path_addr, uint_t mask) {
    char path_raw[MAX_PATH];
    if (user_read_string(path_addr, path_raw, sizeof(path_raw)))
        return _EFAULT;
    STRACE("inotify_add_watch(%d, \"%s\", %#x)", inotify_f, path_raw, mask);
    struct fd *fd = f_get(inotify_f);
    if (fd == NULL)
        return _EBADF;
    if (fd->ops != &inotify_ops)
        return _EINVAL;
    if ((mask & IN_ALL_EVENTS_) == 0)
        return _EINVAL;
    if ((mask & IN_MASK_ADD_) && (mask & IN_MASK_CREATE_))
        return _EINVAL;

    // the file has to exist and be readable by the caller
    bool follow = !(mask & IN_DONT_FOLLOW_);
    struct statbuf stat;
    int err = generic_statat(AT_PWD, path_raw, &stat, follow);
    if (err < 0)
        return err;
    if ((mask & IN_ONLYDIR_) && !S_ISDIR(stat.mode))
        return _ENOTDIR;
    err = access_check(&stat, AC_R);
    if (err < 0)
        return err;

    char path[MAX_PATH];
    err = path_normalize(AT_PWD, path_raw, path, follow ? N_SYMLINK_FOLLOW : N_SYMLINK_NOFOLLOW);
    if (err < 0)
        return err;
    if (path[0] == '\0')
        strcpy(path, "/");
    size_t path_len = strlen(path);

    struct inotify *in = fd->data;
    uint32_t wanted = mask & (IN_ALL_EVENTS_ | IN_ONESHOT_);
    lock(&inotify_lock);
    // watching a file again changes the existing watch instead of adding one
    struct inotify_watch *watch;
    list_for_each_entry(&in->watches, watch, links) {
        if (watch->path_len != path_len || memcmp(watch->path, path, path_len) != 0)
            continue;
        int_t wd = _EEXIST;
        if (!(mask & IN_MASK_CREATE_)) {
            if (mask & IN_MASK_ADD_)
                watch->mask |= wanted;
            else
                watch->mask = wanted;
            wd = watch->wd;
            update_interest();
        }
        unlock(&inotify_lock);
        return wd;
    }

    watch = malloc(sizeof(*watch));
    char *path_copy = strdup(path);
    if (watch == NULL || path_copy == NULL) {
        free(watch);
        free(path_copy);
        unlock(&inotify_lock);
        return _ENOMEM;
    }
    watch->wd = in->next_wd++;
    watch->mask = wanted;
    watch->path = path_copy;
    watch->path_len = path_len;
    list_add_tail(&in->watches, &watch->links);
    update_interest();
    int_t wd = watch->wd;
    unlock(&inotify_lock);
    return wd;
}

int_t sys_inotify_rm_watch(fd_t inotify_f, int_t wd) {
    STRACE("inotify_rm_watch(%d, %d)", inotify_f, wd);
    struct fd *fd = f_get(inotify_f);
    if (fd == NULL)
        return _EBADF;
    if (fd->ops != &inotify_ops)
        return _EINVAL;

    struct inotify *in = fd->data;
    int_t err = _EINVAL;
    lock(&inotify_lock);
    struct inotify_watch *watch, *tmp;
    list_for_each_entry_safe(&in->watches, watch, tmp, links) {
        if (watch->wd == wd) {
            remove_watch(in, watch);
            update_interest();
            err = 0;
            break;
        }
    }
    unlock(&inotify_lock);
    return err;
}

static ssize_t inotify_read(struct fd *fd, void *buf, size_t bufsize) {
    struct inotify *in = fd->data;
    lock(&inotify_lock);
    while (list_empty(&in->events)) {
        if (fd->flags & O_NONBLOCK_) {
            unlock(&inotify_lock);
            return _EAGAIN;
        }
        int err = wait_for(&fd->cond, &inotify_lock, NULL);
        if (err < 0) {
            unlock(&inotify_lock);
            return err;
        }
    }

    // hand over as many whole events as fit
    size_t copied = 0;
    while (!list_empty(&in->events)) {
        struct inotify_queued *event = list_first_entry(&in->events, struct inotify_queued, links);
        size_t size = sizeof(struct inotify_event_) + event->len;
        if (size > bufsize - copied)
            break;
        struct inotify_event_ header = {
            .wd = event->wd,
            .mask = event->mask,
            .cookie = event->cookie,
            .len = event->len,
        };
        memcpy((char *) buf + copied, &header, sizeof(header));
        memcpy((char *) buf + copied + sizeof(header), event->name, event->len);
        copied += size;

        if (event->mask & IN_Q_OVERFLOW_)
            in->overflowed = false;
        list_remove(&event->links);
        free(event);
        in->queued--;
    }
    atomic_store(&in->readable, in->queued);
    unlock(&inotify_lock);

    // the buffer was too small for even the first event
    if (copied == 0)
        return _EINVAL;
    return copied;
}

static int inotify_poll(struct fd *fd) {
    struct inotify *in = fd->data;
    return atomic_load(&in->readable) != 0 ? POLL_READ : 0;
}

static ssize_t inotify_ioctl_size(int cmd) {
    if (cmd == FIONREAD_)
        return sizeof(dword_t);
    return -1;
}

// FIONREAD: how many bytes a read would return if the buffer were big enough
static int inotify_ioctl(struct fd *fd, int cmd, void *arg) {
    if (cmd != FIONREAD_)
        return _ENOTTY;
    struct inotify *in = fd->data;
    dword_t size = 0;
    lock(&inotify_lock);
    struct inotify_queued *event;
    list_for_each_entry(&in->events, event, links)
        size += sizeof(struct inotify_event_) + event->len;
    unlock(&inotify_lock);
    *(dword_t *) arg = size;
    return 0;
}

static int inotify_close(struct fd *fd) {
    struct inotify *in = fd->data;
    lock(&inotify_lock);
    list_remove(&in->instances);
    struct inotify_watch *watch, *watch_tmp;
    list_for_each_entry_safe(&in->watches, watch, watch_tmp, links) {
        list_remove(&watch->links);
        free(watch->path);
        free(watch);
    }
    struct inotify_queued *event, *event_tmp;
    list_for_each_entry_safe(&in->events, event, event_tmp, links) {
        list_remove(&event->links);
        free(event);
    }
    update_interest();
    unlock(&inotify_lock);
    free(in);
    return 0;
}

static struct fd_ops inotify_ops = {
    .read = inotify_read,
    .poll = inotify_poll,
    .ioctl_size = inotify_ioctl_size,
    .ioctl = inotify_ioctl,
    .close = inotify_close,
};
