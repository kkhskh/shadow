#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rtnetlink.h>
#include "../recovery_evaluator/recovery_evaluator.h"

/* Shadow driver states */
enum shadow_state {
    SHADOW_PASSIVE,    /* Monitoring original driver */
    SHADOW_ACTIVE,     /* Taking over during recovery */
    SHADOW_RECOVERING  /* Restoring driver state */
};

/* Structure to store network device state */
struct net_device_state {
    char name[IFNAMSIZ];
    unsigned char mac_addr[ETH_ALEN];
    unsigned int mtu;
    unsigned int flags;
    struct net_device_stats stats;
    bool is_up;
    u32 features;
    unsigned int tx_queue_len;
};

/* Shadow driver structure */
struct network_shadow {
    enum shadow_state state;
    struct net_device *dev;         /* Original network device */
    struct net_device_state saved_state;
    struct notifier_block netdev_notifier;
    bool recovery_in_progress;
    char device_name[IFNAMSIZ];
};

static struct network_shadow *shadow_driver;

/* Function to save device state */
static void save_device_state(struct net_device *dev)
{
    struct network_shadow *shadow = shadow_driver;
    unsigned char *dst, *src;
    
    if (!dev || !shadow)
        return;
        
    strncpy(shadow->saved_state.name, dev->name, IFNAMSIZ);
    
    /* Careful handling of MAC address copy to avoid const issues */
    if (dev->dev_addr) {
        dst = shadow->saved_state.mac_addr;
        src = dev->dev_addr;
        memcpy(dst, src, ETH_ALEN);
    }
    
    shadow->saved_state.mtu = dev->mtu;
    shadow->saved_state.flags = dev->flags;
    shadow->saved_state.is_up = netif_running(dev);
    shadow->saved_state.features = dev->features;
    shadow->saved_state.tx_queue_len = dev->tx_queue_len;
    
    add_event(NULL, PHASE_NONE, "Saved state for device %s", dev->name);
}

/* Function to restore device state */
static int restore_device_state(struct net_device *dev)
{
    struct network_shadow *shadow = shadow_driver;
    unsigned char *dst, *src;
    int ret = 0;
    
    if (!dev || !shadow)
        return -EINVAL;
    
    if (!rtnl_is_locked())
        rtnl_lock();
    
    /* Restore basic device attributes */
    dev->mtu = shadow->saved_state.mtu;
    
    /* Safe copy of MAC address */
    if (dev->dev_addr) {
        dst = dev->dev_addr;
        src = shadow->saved_state.mac_addr;
        memcpy(dst, src, ETH_ALEN);
    }
    
    dev->flags = shadow->saved_state.flags;
    dev->tx_queue_len = shadow->saved_state.tx_queue_len;
    
    /* Restore device state */
    if (shadow->saved_state.is_up && !netif_running(dev)) {
        if (dev->netdev_ops && dev->netdev_ops->ndo_open)
            ret = dev->netdev_ops->ndo_open(dev);
        if (ret)
            add_event(NULL, PHASE_RECOVERY_FAILED, 
                     "Failed to restore device %s state", dev->name);
    } else if (!shadow->saved_state.is_up && netif_running(dev)) {
        if (dev->netdev_ops && dev->netdev_ops->ndo_stop)
            dev->netdev_ops->ndo_stop(dev);
    }
    
    if (rtnl_is_locked())
        rtnl_unlock();
    
    add_event(NULL, PHASE_RECOVERY_COMPLETE, 
             "Restored state for device %s", dev->name);
    
    return ret;
}

/* Network device notifier callback */
static int netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
    struct net_device *dev = (struct net_device *)ptr;  /* Direct cast for older kernels */
    struct network_shadow *shadow = shadow_driver;
    
    if (!shadow || !dev)
        return NOTIFY_DONE;
    
    switch (event) {
    case NETDEV_REGISTER:
        if (!shadow->dev && strcmp(dev->name, shadow->device_name) == 0) {
            shadow->dev = dev;
            shadow->state = SHADOW_PASSIVE;
            start_test("network_shadow", dev->name);
            add_event(NULL, PHASE_NONE, 
                     "Started monitoring device %s", dev->name);
            save_device_state(dev);
        }
        break;
        
    case NETDEV_UNREGISTER:
        if (dev == shadow->dev) {
            if (!shadow->recovery_in_progress) {
                shadow->state = SHADOW_ACTIVE;
                shadow->recovery_in_progress = true;
                add_event(NULL, PHASE_FAILURE_DETECTED, 
                         "Device %s unregistered unexpectedly", dev->name);
                
                /* We'd normally start a timer here for recovery */
                printk(KERN_INFO "Shadow driver active: device %s failed\n", dev->name);
                add_event(NULL, PHASE_DRIVER_STOPPED, "Recovery would be started here");
            }
            shadow->dev = NULL;
        }
        break;
        
    case NETDEV_UP:
        if (dev == shadow->dev) {
            save_device_state(dev);
        }
        break;
        
    case NETDEV_DOWN:
        if (dev == shadow->dev && !shadow->recovery_in_progress) {
            save_device_state(dev);
        }
        break;
    }
    
    return NOTIFY_DONE;
}

/* Proc file operations */
static int shadow_proc_show(struct seq_file *m, void *v)
{
    struct network_shadow *shadow = shadow_driver;
    
    if (!shadow)
        return -EINVAL;
    
    seq_printf(m, "Network Shadow Driver Status:\n");
    seq_printf(m, "Monitored device: %s\n", 
               shadow->device_name);
    seq_printf(m, "State: %d\n", shadow->state);
    seq_printf(m, "Recovery in progress: %s\n",
               shadow->recovery_in_progress ? "yes" : "no");
    
    return 0;
}

static int shadow_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, shadow_proc_show, NULL);
}

static const struct file_operations shadow_proc_fops = {
    .owner = THIS_MODULE,
    .open = shadow_proc_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

/* Module parameters */
static char device_name[IFNAMSIZ] = "eth0";
module_param_string(device, device_name, IFNAMSIZ, 0644);
MODULE_PARM_DESC(device, "Network device to monitor (default: eth0)");

/* Module initialization */
static int __init network_shadow_init(void)
{
    struct network_shadow *shadow;
    struct proc_dir_entry *proc_entry;
    
    /* Allocate shadow driver structure */
    shadow = kzalloc(sizeof(*shadow), GFP_KERNEL);
    if (!shadow)
        return -ENOMEM;
    
    /* Initialize shadow driver */
    shadow->state = SHADOW_PASSIVE;
    shadow->dev = NULL;
    shadow->recovery_in_progress = false;
    strncpy(shadow->device_name, device_name, IFNAMSIZ - 1);
    
    /* Register network device notifier */
    shadow->netdev_notifier.notifier_call = netdev_event;
    register_netdevice_notifier(&shadow->netdev_notifier);
    
    /* Create proc entry */
    proc_entry = proc_create("network_shadow", 0644, NULL, &shadow_proc_fops);
    if (!proc_entry) {
        unregister_netdevice_notifier(&shadow->netdev_notifier);
        kfree(shadow);
        return -ENOMEM;
    }
    
    shadow_driver = shadow;
    
    printk(KERN_INFO "Network Shadow Driver loaded\n");
    printk(KERN_INFO "Monitoring device: %s\n", shadow->device_name);
    return 0;
}

static void __exit network_shadow_exit(void)
{
    if (shadow_driver) {
        unregister_netdevice_notifier(&shadow_driver->netdev_notifier);
        remove_proc_entry("network_shadow", NULL);
        kfree(shadow_driver);
    }
    
    printk(KERN_INFO "Network Shadow Driver unloaded\n");
}

module_init(network_shadow_init);
module_exit(network_shadow_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shadow Driver Implementation");
MODULE_DESCRIPTION("Network Shadow Driver Implementation");