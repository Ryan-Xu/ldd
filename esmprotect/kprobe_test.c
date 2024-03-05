#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>

static struct kprobe kp;

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    // 获取进程 ID 和信号
    struct task_struct *task = (struct task_struct *)regs->di;
    int pid = task->pid;
    int sig = regs->dx;

    printk(KERN_INFO "[+] security_task_kill called with pid: %d, signal: %d, comm: %s\n", pid, sig, task->comm);
    if (strcmp(task->comm, "killme") == 0) {
        printk(KERN_INFO "[+] prohibit kill pid: %d, signal: %d, comm: %s\n", pid, sig, task->comm);
        return -1;
    } else {
        printk(KERN_INFO "[+] allow kill pid: %d, signal: %d, comm: %s\n", pid, sig, task->comm);
    }

    return 0;
}

static void handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags) {
    // 获取进程 ID 和信号
    struct task_struct *task = (struct task_struct *)regs->di;
    int pid = task->pid;
    int sig = regs->dx;

    // Do something after the sys_kill call
    printk(KERN_INFO "[+] post sys_kill -- %s pid %d sig %d\n", current->comm, pid, sig);
}

static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr) {
    printk(KERN_ERR "[+] Fault handler: probe failed, returned %d\n", trapnr);
    return 0;
}

static int __init kprobe_init(void) {
    kp.symbol_name = "security_task_kill";
    kp.pre_handler = handler_pre;
    kp.post_handler = handler_post;
    kp.fault_handler = handler_fault;

    if (register_kprobe(&kp) < 0) {
        printk(KERN_ERR "Failed to register kprobe\n");
        return -1;
    }

    printk(KERN_INFO "Kprobe registered for function %s\n", kp.symbol_name);
    return 0;
}

static void __exit kprobe_exit(void) {
    unregister_kprobe(&kp);
    printk(KERN_INFO "Kprobe unregistered for function %s\n", kp.symbol_name);
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");
