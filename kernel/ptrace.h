#ifndef KERNEL_PTRACE_H
#define KERNEL_PTRACE_H

#include "misc.h"
#include "emu/cpu.h"

#define PTRACE_TRACEME_ 0
#define PTRACE_PEEKTEXT_ 1
#define PTRACE_PEEKDATA_ 2
#define PTRACE_PEEKUSER_ 3
#define PTRACE_POKETEXT_ 4
#define PTRACE_POKEDATA_ 5
#define PTRACE_POKEUSER_ 6
#define PTRACE_CONT_ 7
#define PTRACE_KILL_ 8
#define PTRACE_SINGLESTEP_ 9
#define PTRACE_GETREGS_ 12
#define PTRACE_SETREGS_ 13
#define PTRACE_GETFPREGS_ 14
#define PTRACE_SETFPREGS_ 15
#define PTRACE_SETOPTIONS_ 0x4200
#define PTRACE_GETSIGINFO_ 0x4202
#define PTRACE_GETREGSET_ 0x4204
#define PTRACE_SETREGSET_ 0x4205

#define PTRACE_EVENT_FORK_ 1

// Register sets for PTRACE_GETREGSET/SETREGSET, named by ELF note type. This
// is the only way to read registers on AArch64, which has no GETREGS.
#define NT_PRSTATUS_ 1
#define NT_PRFPREG_ 2
#define NT_ARM_TLS_ 0x401
#define NT_ARM_SYSTEM_CALL_ 0x404

// NT_PRSTATUS: struct user_pt_regs
struct user_pt_regs_ {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

// NT_PRFPREG: struct user_fpsimd_state
struct user_fpsimd_state_ {
    union arm64_vreg vregs[32];
    uint32_t fpsr;
    uint32_t fpcr;
    uint32_t reserved[2];
};
static_assert(sizeof(struct user_pt_regs_) == 272, "user_pt_regs size");
static_assert(sizeof(struct user_fpsimd_state_) == 528, "user_fpsimd_state size");

dword_t sys_ptrace(dword_t request, dword_t pid, addr_t addr, addr_t data);

#endif /* KERNEL_PTRACE_H */
