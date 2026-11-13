#include <stddef.h>
#include <stdbool.h>
#include "fs/proc.h"

// /proc/net/dev - network device statistics
// Format: Interface|Receive|Transmit
static int proc_show_net_dev(struct proc_entry *UNUSED(entry), struct proc_data *buf) {
    // Header
    proc_printf(buf, "Inter-|   Receive                                                |  Transmit\n");
    proc_printf(buf, " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n");

    // For iSH emulator, we report minimal network stats
    // lo (loopback) interface
    proc_printf(buf, "    lo:       0       0    0    0    0     0          0         0");
    proc_printf(buf, "        0       0    0    0    0     0       0          0\n");

    // eth0 (dummy ethernet) - some programs expect this
    proc_printf(buf, "  eth0:       0       0    0    0    0     0          0         0");
    proc_printf(buf, "        0       0    0    0    0     0       0          0\n");

    return 0;
}

// Exported /proc/net directory entry
struct proc_children proc_net_children = PROC_CHILDREN({
    {"dev", .show = proc_show_net_dev},
});
