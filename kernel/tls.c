#include "kernel/calls.h"

struct user_desc {
    dword_t entry_number;
    dword_t base_addr;
    dword_t limit;
    unsigned int seg_32bit:1;
    unsigned int contents:2;
    unsigned int read_exec_only:1;
    unsigned int limit_in_pages:1;
    unsigned int seg_not_present:1;
    unsigned int useable:1;
};


int sys_set_tid_address(addr_t tid) {
    current->clear_tid = tid;
    return sys_getpid();
}
