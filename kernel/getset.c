#include "kernel/calls.h"
#include "kernel/task.h"
#include "kernel/personality.h"

pid_t_ sys_getpid() {
    STRACE("getpid()");
    return current->tgid;
}
pid_t_ sys_gettid() {
    STRACE("gettid()");
    return current->pid;
}
pid_t_ sys_getppid() {
    STRACE("getppid()");
    pid_t_ ppid;
    lock(&pids_lock);
    if (current->parent != NULL)
        ppid = current->parent->pid;
    else
        ppid = 0;
    unlock(&pids_lock);
    return ppid;
}

// Capabilities. Privilege checks in this kernel are uid based (superuser()),
// so the sets are bookkeeping: they make capget/capset behave as programs
// expect (root starts with everything, the sets can only shrink, and they
// follow the uids the way Linux does), but dropping a capability does not by
// itself take a privilege away.
#define CAP_VERSION_1_ 0x19980330
#define CAP_VERSION_2_ 0x20071026
#define CAP_VERSION_3_ 0x20080522
#define CAP_SETPCAP_ 8
#define CAP_LAST_CAP_ 40
#define CAP_FULL_SET_ ((UINT64_C(1) << (CAP_LAST_CAP_ + 1)) - 1)

struct cap_header_ {
    dword_t version;
    pid_t_ pid;
};
struct cap_data_ {
    dword_t effective;
    dword_t permitted;
    dword_t inheritable;
};
struct cap_sets {
    uint64_t effective, permitted, inheritable;
};

static struct cap_sets task_caps(struct task *task) {
    if (task->caps_valid) {
        return (struct cap_sets) {
            .effective = task->cap_effective,
            .permitted = task->cap_permitted,
            .inheritable = task->cap_inheritable,
        };
    }
    // What a process has after exec with no file capabilities: everything
    // permitted if any uid is root, and effective too if the euid is root.
    struct cap_sets caps = {};
    if (task->uid == 0 || task->euid == 0 || task->suid == 0)
        caps.permitted = CAP_FULL_SET_;
    if (task->euid == 0)
        caps.effective = caps.permitted;
    return caps;
}

static void task_set_caps(struct task *task, struct cap_sets caps) {
    task->cap_effective = caps.effective;
    task->cap_permitted = caps.permitted;
    task->cap_inheritable = caps.inheritable;
    task->caps_valid = true;
}

struct old_uids {
    uid_t_ uid, euid, suid;
    struct cap_sets caps;
};
static struct old_uids uids_save(void) {
    return (struct old_uids) {current->uid, current->euid, current->suid, task_caps(current)};
}
// Called after any change to the uids. Mirrors Linux's cap_emulate_setxuid,
// and resets the filesystem uid, which always follows a new euid.
static void uids_changed(struct old_uids old) {
    current->fsuid_set = false;
    struct cap_sets caps = old.caps;
    bool had_root = old.uid == 0 || old.euid == 0 || old.suid == 0;
    bool has_root = current->uid == 0 || current->euid == 0 || current->suid == 0;
    if (had_root && !has_root)
        caps.permitted = caps.effective = 0;
    if (old.euid == 0 && current->euid != 0)
        caps.effective = 0;
    if (old.euid != 0 && current->euid == 0)
        caps.effective = caps.permitted;
    task_set_caps(current, caps);
}

dword_t sys_getuid32() {
    STRACE("getuid32()");
    return current->uid;
}

dword_t sys_geteuid32() {
    STRACE("geteuid32()");
    return current->euid;
}

int_t sys_setuid(uid_t_ uid) {
    STRACE("setuid(%d)", uid);
    struct old_uids old = uids_save();
    if (superuser()) {
        current->uid = current->suid = uid;
    } else {
        if (uid != current->uid && uid != current->suid)
            return _EPERM;
    }
    current->euid = uid;
    uids_changed(old);
    return 0;
}

dword_t sys_setresuid(uid_t_ ruid, uid_t_ euid, uid_t_ suid) {
    STRACE("setresuid(%d, %d, %d)", ruid, euid, suid);
    if (!superuser()) {
        if (ruid != (uid_t) -1 && ruid != current->uid && ruid != current->euid && ruid != current->suid)
            return _EPERM;
        if (euid != (uid_t) -1 && euid != current->uid && euid != current->euid && euid != current->suid)
            return _EPERM;
        if (suid != (uid_t) -1 && suid != current->uid && suid != current->euid && suid != current->suid)
            return _EPERM;
    }

    struct old_uids old = uids_save();
    if (ruid != (uid_t) -1)
        current->uid = ruid;
    if (euid != (uid_t) -1)
        current->euid = euid;
    if (suid != (uid_t) -1)
        current->suid = suid;
    uids_changed(old);
    return 0;
}

int_t sys_getresuid(addr_t ruid_addr, addr_t euid_addr, addr_t suid_addr) {
    STRACE("getresuid(%#x, %#x, %#x)", ruid_addr, euid_addr, suid_addr);
    if (user_put(ruid_addr, current->uid))
        return _EFAULT;
    if (user_put(euid_addr, current->euid))
        return _EFAULT;
    if (user_put(suid_addr, current->suid))
        return _EFAULT;
    return 0;
}

int_t sys_setreuid(uid_t_ ruid, uid_t_ euid) {
    return sys_setresuid(ruid, euid, -1);
}

dword_t sys_getgid32() {
    STRACE("getgid32()");
    return current->gid;
}

dword_t sys_getegid32() {
    STRACE("getegid32()");
    return current->egid;
}

int_t sys_setgid(uid_t_ gid) {
    STRACE("setgid(%d)", gid);
    if (superuser()) {
        current->gid = current->sgid = gid;
    } else {
        if (gid != current->gid && gid != current->sgid)
            return _EPERM;
    }
    current->egid = gid;
    current->fsgid_set = false;
    return 0;
}

dword_t sys_setresgid(uid_t_ rgid, uid_t_ egid, uid_t_ sgid) {
    STRACE("setresgid(%d, %d, %d)", rgid, egid, sgid);
    if (!superuser()) {
        if (rgid != (uid_t) -1 && rgid != current->gid && rgid != current->egid && rgid != current->sgid)
            return _EPERM;
        if (egid != (uid_t) -1 && egid != current->gid && egid != current->egid && egid != current->sgid)
            return _EPERM;
        if (sgid != (uid_t) -1 && sgid != current->gid && sgid != current->egid && sgid != current->sgid)
            return _EPERM;
    }

    if (rgid != (uid_t) -1)
        current->gid = rgid;
    if (egid != (uid_t) -1)
        current->egid = egid;
    if (sgid != (uid_t) -1)
        current->sgid = sgid;
    current->fsgid_set = false;
    return 0;
}

int_t sys_getresgid(addr_t rgid_addr, addr_t egid_addr, addr_t sgid_addr) {
    STRACE("getresgid(%#x, %#x, %#x)", rgid_addr, egid_addr, sgid_addr);
    if (user_put(rgid_addr, current->gid))
        return _EFAULT;
    if (user_put(egid_addr, current->egid))
        return _EFAULT;
    if (user_put(sgid_addr, current->sgid))
        return _EFAULT;
    return 0;
}

int_t sys_setregid(uid_t_ rgid, uid_t_ egid) {
    return sys_setresgid(rgid, egid, -1);
}

int_t sys_getgroups(dword_t size, addr_t list) {
    STRACE("getgroups(%d, %#x)", size, list);
    if (size == 0)
        return current->ngroups;
    if (size < current->ngroups)
        return _EINVAL;
    for (unsigned i = 0; i < current->ngroups; i++)
        STRACE(" %d", current->groups[i]);
    if (user_write(list, current->groups, current->ngroups * sizeof(uid_t_)))
        return _EFAULT;
    return current->ngroups;
}

int_t sys_setgroups(dword_t size, addr_t list) {
    STRACE("setgroups(%d, %#x)", size, list);
    if (size > MAX_GROUPS)
        return _EINVAL;
    if (user_read(list, current->groups, size * sizeof(uid_t_)))
        return _EFAULT;
    for (unsigned i = 0; i < size; i++)
        STRACE(" %d", current->groups[i]);
    current->ngroups = size;
    return 0;
}

// setfsuid and setfsgid cannot report errors: they always return the previous
// value, and the caller finds out whether the change happened by calling
// again. An id is accepted if it matches one of the caller's own ids.
int_t sys_setfsuid(uid_t_ uid) {
    STRACE("setfsuid(%d)", uid);
    uid_t_ old = task_fsuid(current);
    if (superuser() || uid == current->uid || uid == current->euid ||
            uid == current->suid || uid == old) {
        if (uid != (uid_t_) -1) {
            current->fsuid = uid;
            current->fsuid_set = uid != current->euid;
        }
    }
    return old;
}

int_t sys_setfsgid(uid_t_ gid) {
    STRACE("setfsgid(%d)", gid);
    uid_t_ old = task_fsgid(current);
    if (superuser() || gid == current->gid || gid == current->egid ||
            gid == current->sgid || gid == old) {
        if (gid != (uid_t_) -1) {
            current->fsgid = gid;
            current->fsgid_set = gid != current->egid;
        }
    }
    return old;
}

// Reads and checks a capability header. Returns the number of 32-bit data
// structs the version uses. For an unknown version the preferred one is
// written back and EINVAL returned, which is how libcap probes for it.
static int cap_read_header(addr_t header_addr, struct cap_header_ *header) {
    if (user_get(header_addr, *header))
        return _EFAULT;
    switch (header->version) {
        case CAP_VERSION_1_:
            return 1;
        case CAP_VERSION_2_:
        case CAP_VERSION_3_:
            return 2;
    }
    dword_t version = CAP_VERSION_3_;
    if (user_put(header_addr, version))
        return _EFAULT;
    return _EINVAL;
}

int_t sys_capget(addr_t header_addr, addr_t data_addr) {
    STRACE("capget(%#x, %#x)", header_addr, data_addr);
    struct cap_header_ header;
    int count = cap_read_header(header_addr, &header);
    if (count == _EINVAL && data_addr == 0)
        return 0; // version probe
    if (count < 0)
        return count;
    if (header.pid < 0)
        return _EINVAL;

    struct cap_sets caps;
    if (header.pid == 0 || header.pid == current->pid) {
        caps = task_caps(current);
    } else {
        lock(&pids_lock);
        struct task *task = pid_get_task(header.pid);
        if (task == NULL) {
            unlock(&pids_lock);
            return _ESRCH;
        }
        caps = task_caps(task);
        unlock(&pids_lock);
    }

    struct cap_data_ data[2] = {
        {(dword_t) caps.effective, (dword_t) caps.permitted, (dword_t) caps.inheritable},
        {caps.effective >> 32, caps.permitted >> 32, caps.inheritable >> 32},
    };
    if (user_write(data_addr, data, count * sizeof(data[0])))
        return _EFAULT;
    return 0;
}

int_t sys_capset(addr_t header_addr, addr_t data_addr) {
    STRACE("capset(%#x, %#x)", header_addr, data_addr);
    struct cap_header_ header;
    int count = cap_read_header(header_addr, &header);
    if (count < 0)
        return count;
    // a process may only change its own capabilities
    if (header.pid != 0 && header.pid != current->pid)
        return _EPERM;

    struct cap_data_ data[2] = {};
    if (user_read(data_addr, data, count * sizeof(data[0])))
        return _EFAULT;
    struct cap_sets new = {
        .effective = data[0].effective | (uint64_t) data[1].effective << 32,
        .permitted = data[0].permitted | (uint64_t) data[1].permitted << 32,
        .inheritable = data[0].inheritable | (uint64_t) data[1].inheritable << 32,
    };

    struct cap_sets old = task_caps(current);
    // Capabilities can be dropped but not gained: the permitted set may only
    // shrink, the effective set must stay inside it, and the inheritable set
    // may only grow from the permitted set unless CAP_SETPCAP is effective.
    if (new.permitted & ~old.permitted)
        return _EPERM;
    if (new.effective & ~new.permitted)
        return _EPERM;
    if (!(old.effective & (UINT64_C(1) << CAP_SETPCAP_)) &&
            (new.inheritable & ~(old.inheritable | old.permitted)))
        return _EPERM;
    task_set_caps(current, new);
    return 0;
}

// The execution domain is recorded but has no effect: there is only one ABI
// and guest addresses are never randomized.
int_t sys_personality(dword_t persona) {
    STRACE("personality(%#x)", persona);
    lock(&current->group->lock);
    dword_t old = current->group->personality;
    if (persona != 0xffffffff)
        current->group->personality = persona;
    unlock(&current->group->lock);
    return old;
}
