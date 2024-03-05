/*
 * a simple char device driver: globalmem without mutex
 * Copyright (C) 2024 xu.ruican (xu.ruican@asiainfo-sec.com)
 *
 * Licensed under GPLv2 or later.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <linux/init_task.h>
#include <linux/delay.h>    // loops_per_jiffy
#include <linux/syscalls.h>
#include <linux/kallsyms.h>

#define GLOBALMEM_SIZE  0x1000
#define MEM_CLEAR 0x1
#define GLOBALMEM_MAJOR 230
#define DEVICE_NUM 1

/***************************************************/
#define CR0_WP 0x00010000   // Write Protect Bit (CR0:16)

void **syscall_table;
unsigned long **find_sys_call_table(void);

long (*orig_sys_kill)(int pid, int sig);

unsigned long **find_sys_call_table() 
{    
	unsigned long ptr;
	unsigned long *p;

    printk(KERN_INFO "finding syscall table from: %p\n", (void *)ksys_close);

	for (ptr = (unsigned long)ksys_close; ptr < (unsigned long)&loops_per_jiffy; ptr += sizeof(void *)) 
	{             
		p = (unsigned long *)ptr;

		if (p[__NR_close] == (unsigned long)ksys_close) 
		{
			printk(KERN_INFO "Found the sys_call_table!!!\n");
			return (unsigned long **)p;
		}
	}

	return NULL;
}

char* getNameByPid( pid_t pid ) 
{ 
    struct task_struct * task = NULL, * p = NULL; 
    struct list_head * pos = NULL; 
    char *callProcess;
    task = & init_task;   

    list_for_each( pos, &task->tasks ) 
    { 
        p = list_entry( pos, struct task_struct, tasks ) ;  
        printk( KERN_INFO "%d/t%s/n" , p->pid, p->comm ) ; 
        if (p->pid == pid)
        {
             callProcess = p->comm;
        }
    }  
    
    return callProcess;
}  

long my_sys_kill(int pid, int sig) 
{
	long ret; 
	char *callProcess;
	char *destinationProcess;

    printk(KERN_INFO "sys_kill -- %s pid %d sig %d\n", current->comm, pid, sig);

	//获取系统调用发起者的进程名
	callProcess = current->comm;

	//获取kill指令的目标进程名
	destinationProcess = getNameByPid(pid);

	//禁止"受保护进程"被KILL 
	if ( (strcmp(destinationProcess, "killme") == 0) )
	{
		//相同，禁止执行，返回值：-1 
		ret = -1;         
	}
	else
	{
		//不相同，放行继续执行
		ret = orig_sys_kill(pid, sig); 
	} 

	return ret;
}

/***************************************************/

static int globalmem_major = GLOBALMEM_MAJOR;
module_param(globalmem_major, int, S_IRUGO);


struct globalmem_dev {
    struct cdev cdev;
    unsigned char mem[GLOBALMEM_SIZE];
};

struct globalmem_dev *globalmem_devp;


static int globalmem_open(struct inode *inode, struct file *filp)
{
    struct globalmem_dev *dev = container_of(inode->i_cdev,
            struct globalmem_dev, cdev);
    filp->private_data = dev;
    return 0;
}

static int globalmem_release(struct inode *inode, struct file *filp)
{
    return 0;
}

static long globalmem_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct globalmem_dev *dev = filp->private_data;

    switch (cmd) {
        case MEM_CLEAR:
            memset(dev->mem, 0, GLOBALMEM_SIZE);
            printk(KERN_INFO "globalmem is set to zero\n");
            break;
        default:
            return -EINVAL;
    }

    return 0;
}

static ssize_t globalmem_read(struct file *filp, char __user *buf, size_t size,
        loff_t *ppos)
{
    unsigned long p = *ppos;
    unsigned int count = size;
    int ret = 0;
    struct globalmem_dev *dev = filp->private_data;

    if (p >= GLOBALMEM_SIZE)
        return 0;
    if (count > GLOBALMEM_SIZE - p)
        count = GLOBALMEM_SIZE - p;

    if (copy_to_user(buf, dev->mem + p, count)) {
        ret = -EFAULT;
    } else {
        *ppos += count;
        ret = count;

        printk(KERN_INFO "read %u bytes(s) from %lu\n", count, p);
    }

    return ret;
}

static ssize_t globalmem_write(struct file *filp, const char __user *buf,
        size_t size, loff_t *ppos)
{
    unsigned long p = *ppos;
    unsigned int count = size;
    int ret = 0;
    struct globalmem_dev *dev = filp->private_data;

    if (p >= GLOBALMEM_SIZE)
        return 0;
    if (count > GLOBALMEM_SIZE - p)
        count = GLOBALMEM_SIZE - p;

    if (copy_from_user(dev->mem + p, buf, count)) {
        ret = -EFAULT;
    } else {
        *ppos += count;
        ret = count;

        printk(KERN_INFO "written %u bytes(s) from %lu\n", count, p);
    }

    return ret;
}

static loff_t globalmem_llseek(struct file *filp, loff_t offset, int orig)
{
    loff_t ret = 0;
    switch (orig) {
        case 0:
            if (offset < 0) {
                ret = -EINVAL;
                break;
            }
            if ((unsigned int)offset > GLOBALMEM_SIZE) {
                ret = -EINVAL;
                break;
            }
            filp->f_pos = (unsigned int)offset;
            ret = filp->f_pos;
            break;
        case 1:
            if ((filp->f_pos + offset) > GLOBALMEM_SIZE) {
                ret = -EINVAL;
                break;
            }
            if ((filp->f_pos + offset) < 0) {
                ret = -EINVAL;
                break;
            }
            filp->f_pos += offset;
            ret = filp->f_pos;
            break;
        default:
            ret = -EINVAL;
            break;
    }

    return ret;
}

static const struct file_operations globalmem_fops = {
    .owner = THIS_MODULE,
    .llseek = globalmem_llseek,
    .read = globalmem_read,
    .write = globalmem_write,
    .unlocked_ioctl = globalmem_ioctl,
    .open = globalmem_open,
    .release = globalmem_release,
};


static void globalmem_setup_cdev(struct globalmem_dev *dev, int index)
{
    int err, devno = MKDEV(globalmem_major, index);

    cdev_init(&dev->cdev, &globalmem_fops);
    dev->cdev.owner = THIS_MODULE;
    err = cdev_add(&dev->cdev, devno, 1);
    if (err)
        printk(KERN_NOTICE "Error %d adding globalmem %d", err, index);
}

static int __init globalmem_init(void)
{
    int ret, i;
	unsigned long cr0;

    dev_t devno = MKDEV(globalmem_major, 0);

    if (globalmem_major)
        ret = register_chrdev_region(devno, DEVICE_NUM, "globalmem");
    else {
        ret = alloc_chrdev_region(&devno, 0, DEVICE_NUM, "globalmem");
        globalmem_major = MAJOR(devno);
    }

    if (ret < 0)
        return ret;

    globalmem_devp = kzalloc(sizeof(struct globalmem_dev) * DEVICE_NUM, GFP_KERNEL);
    if (!globalmem_devp) {
        ret = -ENOMEM;
        goto fail_malloc;
    }

    for (i = 0; i < DEVICE_NUM; i++)
        globalmem_setup_cdev(globalmem_devp + i, i);


	/***************************************************/
	//syscall_table = (void **)find_sys_call_table();
	syscall_table = (void *)kallsyms_lookup_name("sys_call_table");
	if (!syscall_table) 
	{
		printk(KERN_DEBUG "Cannot find the system call address\n"); 
		return -1;
	}
    else 
		printk(KERN_DEBUG "find the system call address: %p\n", syscall_table); 

	cr0 = read_cr0();
	write_cr0(cr0 & ~CR0_WP);

	orig_sys_kill = syscall_table[__NR_kill];
	syscall_table[__NR_kill] = my_sys_kill;

	write_cr0(cr0);
	/***************************************************/

    return 0;

fail_malloc:
    unregister_chrdev_region(devno, DEVICE_NUM);
    return ret;
}

module_init(globalmem_init);

static void __exit globalmem_exit(void)
{
	int i;

	/***************************************************/
	unsigned long cr0;
	cr0 = read_cr0();
	write_cr0(cr0 & ~CR0_WP); 

	syscall_table[__NR_kill] = orig_sys_kill;

	write_cr0(cr0);
	/***************************************************/

    for (i = 0; i < DEVICE_NUM; i++)
        cdev_del(&(globalmem_devp + i)->cdev);
    kfree(globalmem_devp);
    unregister_chrdev_region(MKDEV(globalmem_major, 0), DEVICE_NUM);
}

module_exit(globalmem_exit);

MODULE_AUTHOR("xu.ruican <xu.ruican@asiainfo-sec.com>");
MODULE_LICENSE("GPL v2");
