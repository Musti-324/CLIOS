#include "ptrace.h"
#include "kernel/calls.h"
#include "kernel/errno.h"
#include "kernel/signal.h"
#include "task.h"
#include <string.h>

// Returns stopped child with the given pid, locked with the ptrace lock
static struct task *find_child(pid_t_ pid) {
    struct task *child = NULL;
    list_for_each_entry(&current->children, child, siblings) {
        if (child->pid == pid) {
            lock(&child->ptrace.lock);
            if (child->ptrace.stopped) {
                goto found;
            }

            unlock(&child->ptrace.lock);
        }
    }
    child = NULL;
found:
    return child;
}

// Register sets. The tracee is parked in signal_delivery_stop on its own
// thread while these run, so its cpu state is stable and can be read and
// written directly.

// the largest register set, with the alignment the vector registers need
union regset_buf {
    struct user_pt_regs_ regs;
    struct user_fpsimd_state_ fpsimd;
    uint64_t tls;
    int_t syscall;
};

// Returns the size of a register set, or 0 if there is no such set.
static size_t regset_size(addr_t type) {
    switch (type) {
        case NT_PRSTATUS_: return sizeof(struct user_pt_regs_);
        case NT_PRFPREG_: return sizeof(struct user_fpsimd_state_);
        case NT_ARM_TLS_: return sizeof(uint64_t);
        case NT_ARM_SYSTEM_CALL_: return sizeof(int_t);
    }
    return 0;
}

static void regset_get(struct cpu_state *cpu, addr_t type, union regset_buf *buf) {
    switch (type) {
        case NT_PRSTATUS_:
            memcpy(buf->regs.regs, cpu->regs, sizeof(buf->regs.regs));
            buf->regs.sp = cpu->sp;
            buf->regs.pc = cpu->pc;
            // user mode (EL0t) with the current condition flags
            buf->regs.pstate = arm64_get_nzcv(cpu) & 0xf0000000;
            break;
        case NT_PRFPREG_:
            memcpy(buf->fpsimd.vregs, cpu->fp, sizeof(buf->fpsimd.vregs));
            buf->fpsimd.fpsr = cpu->fpsr;
            buf->fpsimd.fpcr = cpu->fpcr;
            buf->fpsimd.reserved[0] = buf->fpsimd.reserved[1] = 0;
            break;
        case NT_ARM_TLS_:
            buf->tls = cpu->tls_ptr;
            break;
        case NT_ARM_SYSTEM_CALL_:
            // the syscall number travels in x8
            buf->syscall = (int_t) cpu->regs[8];
            break;
    }
}

static void regset_set(struct cpu_state *cpu, addr_t type, const union regset_buf *buf) {
    switch (type) {
        case NT_PRSTATUS_:
            memcpy(cpu->regs, buf->regs.regs, sizeof(buf->regs.regs));
            cpu->sp = buf->regs.sp;
            cpu->pc = buf->regs.pc;
            // only the condition flags of pstate belong to the tracee
            arm64_set_nzcv(cpu, (uint32_t) buf->regs.pstate & 0xf0000000);
            break;
        case NT_PRFPREG_:
            memcpy(cpu->fp, buf->fpsimd.vregs, sizeof(buf->fpsimd.vregs));
            cpu->fpsr = buf->fpsimd.fpsr;
            cpu->fpcr = buf->fpsimd.fpcr;
            break;
        case NT_ARM_TLS_:
            cpu->tls_ptr = buf->tls;
            break;
        case NT_ARM_SYSTEM_CALL_:
            cpu->regs[8] = (uint64_t) (int64_t) buf->syscall;
            break;
    }
}

// PTRACE_GETREGSET and PTRACE_SETREGSET: addr is the note type and data
// points to an iovec describing the tracer's buffer. At most the size of the
// set is transferred, and the iovec length is updated to what was.
static int ptrace_regset(struct task *child, bool set, addr_t type, addr_t iov_addr) {
    size_t size = regset_size(type);
    if (size == 0)
        return _EINVAL;
    struct iovec64_ iov;
    if (user_get(iov_addr, iov))
        return _EFAULT;
    if (iov.len < size)
        size = iov.len;

    union regset_buf buf;
    // start from the current values so a short write leaves the rest alone
    regset_get(&child->cpu, type, &buf);
    if (set) {
        if (user_read(iov.base, &buf, size))
            return _EFAULT;
        regset_set(&child->cpu, type, &buf);
    } else {
        if (user_write(iov.base, &buf, size))
            return _EFAULT;
    }

    iov.len = size;
    if (user_put(iov_addr, iov))
        return _EFAULT;
    return 0;
}

dword_t sys_ptrace(dword_t request, dword_t pid, addr_t addr, addr_t data) {
    switch (request) {
        case PTRACE_TRACEME_:
            STRACE("ptrace(PTRACE_TRACEME, %d, %#x, %#x)", pid, addr, data);
            current->ptrace.traced = true;
            return 0;

        case PTRACE_PEEKTEXT_:
        case PTRACE_PEEKDATA_: {
            STRACE("ptrace(PTRACE_PEEKDATA, %d, %#x, %#x)", pid, addr, data);
            struct task *child = find_child(pid);
            if (!child) return _EPERM;

            // One 64-bit word, stored where data points. (The C library
            // wrapper is what turns this into a return value.)
            uint64_t peek;
            int err = 0;
            if (user_get_task(child, addr, peek) || user_put(data, peek))
                err = _EFAULT;
            unlock(&child->ptrace.lock);
            return err;
        }

        case PTRACE_POKETEXT_:
        case PTRACE_POKEDATA_: {
            STRACE("ptrace(PTRACE_POKEDATA, %d, %#x, %#x)", pid, addr, data);
            struct task *child = find_child(pid);
            if (!child) return _EPERM;

            uint64_t poke = data;
            int err = 0;
            if (user_write_task_ptrace(child, addr, &poke, sizeof(poke)))
                err = _EFAULT;
            unlock(&child->ptrace.lock);
            return err;
        }

        case PTRACE_GETREGSET_:
        case PTRACE_SETREGSET_: {
            STRACE("ptrace(PTRACE_%sREGSET, %d, %#x, %#x)",
                    request == PTRACE_SETREGSET_ ? "SET" : "GET", pid, addr, data);
            struct task *child = find_child(pid);
            if (!child) return _EPERM;

            int err = ptrace_regset(child, request == PTRACE_SETREGSET_, addr, data);
            unlock(&child->ptrace.lock);
            return err;
        }

        // AArch64 has no USER area and no GETREGS-style requests; Linux
        // answers them with EIO and debuggers use the register sets instead.
        case PTRACE_PEEKUSER_:
        case PTRACE_POKEUSER_:
        case PTRACE_GETREGS_:
        case PTRACE_SETREGS_:
        case PTRACE_GETFPREGS_:
        case PTRACE_SETFPREGS_:
            STRACE("ptrace(%d, %d, %#x, %#x)", request, pid, addr, data);
            return _EIO;

        case PTRACE_CONT_: {
            STRACE("ptrace(PTRACE_CONT, %d, %#x, %#x)", pid, addr, data);
            struct task *child = find_child(pid);
            if (!child) return _EPERM;

            child->ptrace.stopped = false;
            notify(&child->ptrace.cond);
            unlock(&child->ptrace.lock);

            return 0;
        }

        case PTRACE_KILL_: {
            STRACE("ptrace(PTRACE_KILL, %d, %#x, %#x)", pid, addr, data);
            struct task *child = find_child(pid);
            if (!child) return _EPERM;

            child->ptrace.stopped = false;
            send_signal(child, SIGKILL_, SIGINFO_NIL);
            unlock(&child->ptrace.lock);

            return 0;
        }

        case PTRACE_SINGLESTEP_: {
            STRACE("ptrace(PTRACE_SINGLESTEP, %d, %#x, %#x)", pid, addr, data);
            struct task *child = find_child(pid);
            if (!child) return _EPERM;

            child->ptrace.stopped = false;
            notify(&child->ptrace.cond);
            unlock(&child->ptrace.lock);

            return 0;
        }

        case PTRACE_SETOPTIONS_:
            STRACE("ptrace(PTRACE_SETOPTIONS, %d, %#x, %#x)", pid, addr, data);
            return _EINVAL;

        case PTRACE_GETSIGINFO_: {
            STRACE("ptrace(PTRACE_GETSIGINFO, %d, %#x, %#x)", pid, addr, data);
            struct task *child = find_child(pid);
            if (!child) return _EPERM;

            int err = 0;
            if (data && user_put(data, child->ptrace.info))
                err = _EFAULT;
            unlock(&child->ptrace.lock);
            return err;
        }

        default:
            STRACE("ptrace(%d, %d, %#x, %#x)", request, pid, addr, data);
            return _EPERM;
    }
}
