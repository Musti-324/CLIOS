#ifndef KERNEL_INOTIFY_H
#define KERNEL_INOTIFY_H

#include <stdatomic.h>
#include <stdbool.h>
#include "misc.h"

struct fd;

// events
#define IN_ACCESS_ 0x00000001
#define IN_MODIFY_ 0x00000002
#define IN_ATTRIB_ 0x00000004
#define IN_CLOSE_WRITE_ 0x00000008
#define IN_CLOSE_NOWRITE_ 0x00000010
#define IN_OPEN_ 0x00000020
#define IN_MOVED_FROM_ 0x00000040
#define IN_MOVED_TO_ 0x00000080
#define IN_CREATE_ 0x00000100
#define IN_DELETE_ 0x00000200
#define IN_DELETE_SELF_ 0x00000400
#define IN_MOVE_SELF_ 0x00000800
#define IN_ALL_EVENTS_ 0x00000fff
// sent by the kernel whether asked for or not
#define IN_UNMOUNT_ 0x00002000
#define IN_Q_OVERFLOW_ 0x00004000
#define IN_IGNORED_ 0x00008000
// flags for inotify_add_watch
#define IN_ONLYDIR_ 0x01000000
#define IN_DONT_FOLLOW_ 0x02000000
#define IN_EXCL_UNLINK_ 0x04000000
#define IN_MASK_CREATE_ 0x10000000
#define IN_MASK_ADD_ 0x20000000
// flag in a returned event
#define IN_ISDIR_ 0x40000000
#define IN_ONESHOT_ 0x80000000

// The events asked for by all watches put together, zero when nothing is
// being watched. The filesystem code checks this before doing any work for a
// notification, so it costs one load when nobody is watching.
extern _Atomic uint32_t inotify_interest;
static inline bool inotify_wants(uint32_t mask) {
    return (atomic_load_explicit(&inotify_interest, memory_order_relaxed) & mask) != 0;
}
// True if there is any watch at all. Removing or renaming a watched file has
// to be tracked whatever events its watches asked for.
static inline bool inotify_watching(void) {
    return atomic_load_explicit(&inotify_interest, memory_order_relaxed) != 0;
}

// Paths are absolute normalized paths, as produced by path_normalize (the
// root may be given as either "" or "/").

// Something happened to the file at path. mask is one event, with IN_ISDIR_
// added if the file is a directory. It is reported to watches on the file
// itself and, with the file's name, to watches on its directory.
void inotify_path_event(const char *path, uint32_t mask);
// Same, for an open file.
void inotify_fd_event(struct fd *fd, uint32_t mask);
// The name at path was removed.
void inotify_path_removed(const char *path, bool is_dir);
// The file at from was renamed to to, replacing whatever was there.
void inotify_path_moved(const char *from, const char *to, bool is_dir);

#endif
