#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "kernel/fs.h"
#include "fs/fd.h"
#include "fs/inode.h"
#include "fs/path.h"
#include "fs/dev.h"
#include "kernel/task.h"
#include "kernel/errno.h"
#include "kernel/inotify.h"

// inotify hooks. In all of them path is relative to its mount, which is how
// find_mount_and_trim_path leaves it; the mount point is put back on to get
// the absolute path that watches are matched against.

static void mount_full_path(struct mount *mount, const char *path, char *full, size_t size) {
    snprintf(full, size, "%s%s", mount->point, path);
}

static bool mount_path_is_dir(struct mount *mount, const char *path) {
    struct statbuf stat = {};
    return mount->fs->stat(mount, path, &stat) == 0 && S_ISDIR(stat.mode);
}

static void notify_path(struct mount *mount, const char *path, uint32_t mask) {
    if (!inotify_wants(mask))
        return;
    char full[MAX_PATH * 2];
    mount_full_path(mount, path, full, sizeof(full));
    inotify_path_event(full, mask);
}

// For events where the caller does not already know whether the file is a
// directory.
static void notify_path_any(struct mount *mount, const char *path, uint32_t mask) {
    if (!inotify_wants(mask))
        return;
    notify_path(mount, path, mask | (mount_path_is_dir(mount, path) ? IN_ISDIR_ : 0));
}

static void notify_removed(struct mount *mount, const char *path, bool is_dir) {
    if (!inotify_watching())
        return;
    char full[MAX_PATH * 2];
    mount_full_path(mount, path, full, sizeof(full));
    inotify_path_removed(full, is_dir);
}

struct mount *find_mount_and_trim_path(char *path) {
    struct mount *mount = mount_find(path);
    char *dst = path;
    const char *src = path + strlen(mount->point);
    while (*src != '\0')
        *dst++ = *src++;
    *dst = '\0';
    return mount;
}

bool contains_mount_point(const char *path) {
    struct mount *mount;
    list_for_each_entry(&mounts, mount, mounts) {
        int n = strlen(path);
        if (strncmp(path, mount->point, n) == 0 &&
                (mount->point[n] == '\0' || mount->point[n] == '/'))
            return true;
    }
    return false;
}

static struct fd *generic_openat_impl(struct fs_info *fs, struct fd *at,
        const char *path_raw, int flags, int mode) {
    if (flags & O_RDWR_ && flags & O_WRONLY_)
        return ERR_PTR(_EINVAL);

    // TODO really, really, seriously reconsider what I'm doing with the strings
    char path[MAX_PATH];
    // O_NOFOLLOW has to be honored here rather than by handing the flag to the
    // host open(): path_normalize resolves the final component itself, so by
    // the time the fs open() runs the symlink is already gone. Leaving it
    // unresolved makes the S_ISLNK check below return ELOOP, as Linux does.
    int normalize_flags = (flags & O_NOFOLLOW_ ? N_SYMLINK_NOFOLLOW : N_SYMLINK_FOLLOW) |
        (flags & O_CREAT_ ? N_PARENT_DIR_WRITE : 0);
    int err = fs ? path_normalize_in_fs(fs, at, path_raw, path, normalize_flags) :
        path_normalize(at, path_raw, path, normalize_flags);
    if (err < 0)
        return ERR_PTR(err);
    struct mount *mount = find_mount_and_trim_path(path);
    // for inotify: will O_CREAT make a new file, or open one that exists?
    bool creating = false;
    if ((flags & O_CREAT_) && inotify_wants(IN_CREATE_)) {
        struct statbuf existing = {};
        creating = mount->fs->stat(mount, path, &existing) < 0;
    }
    struct fd *fd = mount->fs->open(mount, path, flags, mode);
    if (IS_ERR(fd)) {
        // if an error happens after this point, fd_close will release the
        // mount, but right now we need to do it manually
        mount_release(mount);
        return fd;
    }
    fd->mount = mount;

    struct statbuf stat;
    // Filesystem callbacks must not run under the global inode lock. Procfs
    // fstat takes pids_lock; a proc reader can hold that while waiting on mm,
    // whose unmap path holds mm while calling inode_release: a lock cycle.
    // Fakefs already pins its inode during open, before metadata can vanish.
    // Other filesystems retain their opened object through fd itself.
    err = fd->mount->fs->fstat(fd, &stat);
    if (err < 0)
        goto error;
    if (fd->inode == NULL) {
        fd->inode = inode_get(mount, stat.inode);
        if (fd->inode == NULL) {
            err = _ENOMEM;
            goto error;
        }
    }
    fd->type = stat.mode & S_IFMT;
    fd->flags = flags;

    int accmode;
    if (flags & O_RDWR_) accmode = AC_R | AC_W;
    else if (flags & O_WRONLY_) accmode = AC_W;
    else accmode = AC_R;
    err = access_check(&stat, accmode);
    if (err < 0)
        goto error;

    if (S_ISLNK(fd->type)) {
        // path_normalize should have resolved symlinks, but if it didn't,
        // return an error instead of crashing the whole app.
        err = _ELOOP;
        goto error;
    }
    if (S_ISBLK(fd->type) || S_ISCHR(fd->type)) {
        int type;
        if (S_ISBLK(fd->type))
            type = DEV_BLOCK;
        else
            type = DEV_CHAR;
        err = dev_open(dev_major(stat.rdev), dev_minor(stat.rdev), type, fd);
        if (err < 0)
            goto error;
    }
    err = _ENXIO;
    if (S_ISSOCK(fd->type))
        goto error;
    err = _EISDIR;
    if (S_ISDIR(fd->type) && flags & (O_RDWR_ | O_WRONLY_))
        goto error;
    err = _ENOTDIR;
    if (!S_ISDIR(fd->type) && flags & O_DIRECTORY_)
        goto error;

    if (inotify_wants(IN_CREATE_ | IN_MODIFY_ | IN_OPEN_)) {
        uint32_t dir = S_ISDIR(fd->type) ? IN_ISDIR_ : 0;
        if (creating)
            notify_path(mount, path, IN_CREATE_ | dir);
        else if ((flags & O_TRUNC_) && S_ISREG(fd->type))
            notify_path(mount, path, IN_MODIFY_);
        notify_path(mount, path, IN_OPEN_ | dir);
    }
    return fd;

error:
    fd_close(fd);
    return ERR_PTR(err);
}

struct fd *generic_openat(struct fd *at, const char *path, int flags, int mode) {
    return generic_openat_impl(NULL, at, path, flags, mode);
}

struct fd *generic_open_in_fs(struct fs_info *fs, const char *path, int flags, int mode) {
    return generic_openat_impl(fs, AT_PWD, path, flags, mode);
}

struct fd *generic_open(const char *path, int flags, int mode) {
    return generic_openat(AT_PWD, path, flags, mode);
}

int generic_getpath(struct fd *fd, char *buf) {
    int err = fd->mount->fs->getpath(fd, buf);
    if (err < 0)
        return err;
    if (strlen(buf) + strlen(fd->mount->point) >= MAX_PATH)
        return _ENAMETOOLONG;
    memmove(buf + strlen(fd->mount->point), buf, strlen(buf) + 1);
    memcpy(buf, fd->mount->point, strlen(fd->mount->point));
    if (buf[0] == '\0')
        strcpy(buf, "/");
    return 0;
}

int generic_accessat(struct fd *dirfd, const char *path_raw, int mode) {
    char path[MAX_PATH];
    int err = path_normalize(dirfd, path_raw, path, N_SYMLINK_FOLLOW);
    if (err < 0)
        return err;

    struct mount *mount = find_mount_and_trim_path(path);
    struct statbuf stat = {};
    err = mount->fs->stat(mount, path, &stat);
    mount_release(mount);
    if (err < 0)
        return err;
    return access_check(&stat, mode);
}

int generic_linkat(struct fd *src_at, const char *src_raw, struct fd *dst_at, const char *dst_raw) {
    char src[MAX_PATH];
    int err = path_normalize(src_at, src_raw, src, N_SYMLINK_NOFOLLOW);
    if (err < 0)
        return err;
    char dst[MAX_PATH];
    err = path_normalize(dst_at, dst_raw, dst, N_SYMLINK_NOFOLLOW | N_PARENT_DIR_WRITE);
    if (err < 0)
        return err;
    struct mount *mount = find_mount_and_trim_path(src);
    struct mount *dst_mount = find_mount_and_trim_path(dst);
    if (mount != dst_mount)
        err = _EXDEV;
    else if (mount->fs->link == NULL)
        err = _EPERM;
    else
        err = mount->fs->link(mount, src, dst);
    if (err >= 0) {
        notify_path(mount, src, IN_ATTRIB_); // its link count changed
        notify_path(dst_mount, dst, IN_CREATE_);
    }
    mount_release(mount);
    mount_release(dst_mount);
    return err;
}

int generic_unlinkat(struct fd *at, const char *path_raw) {
    char path[MAX_PATH];
    /* Include N_PARENT_DIR_WRITE so path_normalize checks write permission
     * on the parent directory. This makes read-only bind mounts (whose
     * top-level directory is mode 0555 in meta.db) reject `rm` with EACCES
     * without needing any special case in fakefs. */
    int err = path_normalize(at, path_raw, path, N_SYMLINK_NOFOLLOW | N_PARENT_DIR_WRITE);
    if (err < 0)
        return err;
    struct mount *mount = find_mount_and_trim_path(path);
    err = _EPERM;
    if (mount->fs->unlink)
        err = mount->fs->unlink(mount, path);
    if (err >= 0)
        notify_removed(mount, path, false);
    mount_release(mount);
    return err;
}

int generic_renameat(struct fd *src_at, const char *src_raw, struct fd *dst_at, const char *dst_raw) {
    char src[MAX_PATH];
    /* Rename removes the src from its parent directory, so we also need
     * write permission on src's parent — not just dst's. */
    int err = path_normalize(src_at, src_raw, src, N_SYMLINK_NOFOLLOW | N_PARENT_DIR_WRITE);
    if (err < 0)
        return err;
    char dst[MAX_PATH];
    err = path_normalize(dst_at, dst_raw, dst, N_SYMLINK_NOFOLLOW | N_PARENT_DIR_WRITE);
    if (err < 0)
        return err;
    if (contains_mount_point(src))
        return _EBUSY;
    struct mount *mount = find_mount_and_trim_path(src);
    struct mount *dst_mount = find_mount_and_trim_path(dst);
    // has to be asked before the rename, while the old name still exists
    bool watching = inotify_watching();
    bool is_dir = watching && mount_path_is_dir(mount, src);
    if (mount != dst_mount)
        err = _EXDEV;
    else if (mount->fs->rename == NULL)
        err = _EPERM;
    else
        err = mount->fs->rename(mount, src, dst);
    if (err >= 0 && watching) {
        char from[MAX_PATH * 2], to[MAX_PATH * 2];
        mount_full_path(mount, src, from, sizeof(from));
        mount_full_path(dst_mount, dst, to, sizeof(to));
        inotify_path_moved(from, to, is_dir);
    }
    mount_release(mount);
    mount_release(dst_mount);
    return err;
}

int generic_symlinkat(const char *target, struct fd *at, const char *link_raw) {
    char link[MAX_PATH];
    int err = path_normalize(at, link_raw, link, N_SYMLINK_NOFOLLOW | N_PARENT_DIR_WRITE);
    if (err < 0)
        return err;
    struct mount *mount = find_mount_and_trim_path(link);
    err = _EPERM;
    if (mount->fs->symlink)
        err = mount->fs->symlink(mount, target, link);
    if (err >= 0)
        notify_path(mount, link, IN_CREATE_);
    mount_release(mount);
    return err;
}

int generic_mknodat(struct fd *at, const char *path_raw, mode_t_ mode, dev_t_ dev) {
    if (S_ISDIR(mode) || S_ISLNK(mode))
        return _EINVAL;
    if (!superuser() && (S_ISBLK(mode) || S_ISCHR(mode)))
        return _EPERM;

    char path[MAX_PATH];
    int err = path_normalize(at, path_raw, path, N_SYMLINK_NOFOLLOW | N_PARENT_DIR_WRITE);
    if (err < 0)
        return err;
    struct mount *mount = find_mount_and_trim_path(path);
    err = _EPERM;
    if (mount->fs->mknod)
        err = mount->fs->mknod(mount, path, mode, dev);
    if (err >= 0)
        notify_path(mount, path, IN_CREATE_);
    mount_release(mount);
    return err;
}

int generic_setattrat(struct fd *at, const char *path_raw, struct attr attr, bool follow_links) {
    char path[MAX_PATH];
    int err = path_normalize(at, path_raw, path, follow_links ? N_SYMLINK_FOLLOW : N_SYMLINK_NOFOLLOW);
    if (err < 0)
        return err;
    struct mount *mount = find_mount_and_trim_path(path);
    err = _EPERM;
    if (mount->fs->setattr)
        err = mount->fs->setattr(mount, path, attr);
    if (err >= 0) // changing the size is a change to the contents
        notify_path_any(mount, path, attr.type == attr_size ? IN_MODIFY_ : IN_ATTRIB_);
    mount_release(mount);
    return err;
}

int generic_utime(struct fd *at, const char *path_raw, struct timespec atime, struct timespec mtime, bool follow_links) {
    char path[MAX_PATH];
    int err = path_normalize(at, path_raw, path, follow_links ? N_SYMLINK_FOLLOW : N_SYMLINK_NOFOLLOW);
    if (err < 0)
        return err;
    struct mount *mount = find_mount_and_trim_path(path);
    err = _EPERM;
    if (mount->fs->utime)
        err = mount->fs->utime(mount, path, atime, mtime);
    if (err >= 0)
        notify_path_any(mount, path, IN_ATTRIB_);
    mount_release(mount);
    return err;
}

ssize_t generic_readlinkat(struct fd *at, const char *path_raw, char *buf, size_t bufsize) {
    char path[MAX_PATH];
    int err = path_normalize(at, path_raw, path, N_SYMLINK_NOFOLLOW);
    if (err < 0)
        return err;
    struct mount *mount = find_mount_and_trim_path(path);
    err = _EINVAL;
    if (mount->fs->readlink)
        err = mount->fs->readlink(mount, path, buf, bufsize);
    mount_release(mount);
    return err;
}

int generic_mkdirat(struct fd *at, const char *path_raw, mode_t_ mode) {
    char path[MAX_PATH];
    int err = path_normalize(at, path_raw, path, N_SYMLINK_FOLLOW | N_PARENT_DIR_WRITE);
    if (err < 0)
        return err;
    struct mount *mount = find_mount_and_trim_path(path);
    err = _EPERM;
    if (mount->fs->mkdir)
        err = mount->fs->mkdir(mount, path, mode);
    if (err >= 0)
        notify_path(mount, path, IN_CREATE_ | IN_ISDIR_);
    mount_release(mount);
    return err;
}

int generic_rmdirat(struct fd *at, const char *path_raw) {
    char path[MAX_PATH];
    int err = path_normalize(at, path_raw, path, N_SYMLINK_FOLLOW | N_PARENT_DIR_WRITE);
    if (err < 0)
        return err;
    if (contains_mount_point(path))
        return _EBUSY;
    struct mount *mount = find_mount_and_trim_path(path);
    err = _EPERM;
    if (mount->fs->rmdir)
        err = mount->fs->rmdir(mount, path);
    if (err >= 0)
        notify_removed(mount, path, true);
    mount_release(mount);
    return err;
}

int generic_seek(struct fd *fd, off_t_ off, int whence, size_t size) {
    off_t_ new_off = fd->offset;
    if (whence == LSEEK_SET) {
        fd->offset = off;
    } else if (whence == LSEEK_CUR) {
        if (__builtin_add_overflow(new_off, off, &new_off) || new_off < 0)
            return _EINVAL;
        fd->offset = new_off;
    } else if (whence == LSEEK_END) {
        new_off = size + off;
        if (new_off < 0)
            return _EINVAL;
        fd->offset = new_off;
    } else {
        return _EINVAL;
    }
    return 0;
}
