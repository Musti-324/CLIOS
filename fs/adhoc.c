#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "debug.h"
#include "kernel/fs.h"
#include "fs/fd.h"
#include "fs/real.h"
#include "kernel/errno.h"

static struct mount adhoc_mount;

struct fd *adhoc_fd_create(const struct fd_ops *ops) {
    struct fd *fd = fd_create(ops);
    if (fd == NULL)
        return NULL;
    mount_retain(&adhoc_mount);
    fd->mount = &adhoc_mount;
    fd->stat = (struct statbuf) {};
    return fd;
}

// Most adhoc fds are pure kernel objects, but one made by memfd_create is
// backed by a host file, and that file is what holds its contents and size.
static bool adhoc_has_host_file(struct fd *fd) {
    return fd->ops == &realfs_fdops;
}

static int adhoc_fstat(struct fd *fd, struct statbuf *stat) {
    *stat = fd->stat;
    if (adhoc_has_host_file(fd)) {
        struct stat real_stat;
        if (fstat(fd->real_fd, &real_stat) == 0) {
            stat->size = real_stat.st_size;
            stat->blocks = real_stat.st_blocks;
        }
    }
    return 0;
}

static int adhoc_fsetattr(struct fd *fd, struct attr attr) {
    switch (attr.type) {
        case attr_uid:
            fd->stat.uid = attr.uid;
            break;
        case attr_gid:
            fd->stat.gid = attr.gid;
            break;
        case attr_mode:
            fd->stat.mode = (fd->stat.mode & S_IFMT) | (attr.mode & ~S_IFMT);
            break;
        case attr_size:
            if (!adhoc_has_host_file(fd))
                return _EINVAL;
            if (ftruncate(fd->real_fd, attr.size) < 0)
                return errno_map();
            break;
    }
    return 0;
}

static int adhoc_getpath(struct fd *fd, char *buf) {
    const char *type = "unknown"; // TODO allow this to be customized
    if (fd->stat.inode == 0)
        sprintf(buf, "anon_inode:[%s]", type);
    else
        sprintf(buf, "%s:[%lu]", type, (unsigned long) fd->stat.inode);
    return 0;
}

bool is_adhoc_fd(struct fd *fd) {
    return fd->mount == &adhoc_mount;
}

static const struct fs_ops adhoc_fs = {
    .magic = 0x09041934, // FIXME wrong for pipes and sockets
    .fstat = adhoc_fstat,
    .fsetattr = adhoc_fsetattr,
    .getpath = adhoc_getpath,
};

static struct mount adhoc_mount = {
    .fs = &adhoc_fs,
    .point = "",
};
