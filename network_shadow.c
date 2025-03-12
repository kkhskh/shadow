#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rtnetlink.h>
#include <linux/kmod.h>
#include <linux/version.h>
#include "../recovery_evaluator/recovery_evaluator.h"

/* Forward compatibility for older kernels */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static inline struct net_device *netdev_notifier_info_to_dev(void *ptr)
{
    return (struct net_device *)ptr;
}
#endif

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
    char driver_name[64];     /* The actual driver module name */
};

/* Shadow driver structure */
struct network_shadow {
    enum shadow_state state;
    struct net_device *dev;         /* Original network device */
    struct net_device_state saved_state;
    struct notifier_block netdev_notifier;
    bool recovery_in_progress;
    char device_name[IFNAMSIZ];     /* Device name to monitor (e.g., eth0) */
    struct timer_list recovery_timer;
    unsigned long recovery_start_time;
    int recovery_attempts;
};

static struct network_shadow *shadow_driver;
static int recovery_timeout = 10;  /* Timeout in seconds */
module_param(recovery_timeout, int, 0644);
MODULE_PARM_DESC(recovery_timeout, "Timeout in seconds for driver recovery");

/* Function to save device state */
static void save_device_state(struct net_device *dev)
{
    struct network_shadow *shadow = shadow_driver;
    
    if (!dev || !shadow)
        return;
        
    strncpy(shadow->saved_state.name, dev->name, IFNAMSIZ);
    if (dev->dev_addr)
        memcpy(shadow->saved_state.mac_addr, dev->dev_addr, ETH_ALEN);
    shadow->saved_state.mtu = dev->mtu;
    shadow->saved_state.flags = dev->flags;
    shadow->saved_state.is_up = netif_running(dev);
    shadow->saved_state.features = dev->features;
    shadow->saved_state.tx_queue_len = dev->tx_queue_len;
    
    if (dev->netdev_ops && dev->netdev_ops->ndo_get_stats) {
        struct net_device_stats *stats = dev->netdev_ops->ndo_get_stats(dev);
        if (stats)
            memcpy(&shadow->saved_state.stats, stats, sizeof(struct net_device_stats));
    }
    
    /* Save the driver name if we can find it */
    if (dev->dev.driver && dev->dev.driver->name)
        strncpy(shadow->saved_state.driver_name, dev->dev.driver->name, 
                sizeof(shadow->saved_state.driver_name) - 1);
    
    add_event(NULL, PHASE_NONE, "Saved state for device %s (driver: %s)", 
             dev->name, shadow->saved_state.driver_name);
}

/* Function to restore device state */
static int restore_device_state(struct net_device *dev)
{
    struct network_shadow *shadow = shadow_driver;
    int ret = 0;
    
    if (!dev || !shadow)
        return -EINVAL;
    
    if (!rtnl_is_locked())
        rtnl_lock();
    
    /* Restore basic device attributes */
    dev->mtu = shadow->saved_state.mtu;
    if (dev->dev_addr && shadow->saved_state.mac_addr[0] != 0)
        memcpy(dev->dev_addr, shadow->saved_state.mac_addr, ETH_ALEN);
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

/* Function to reload a driver module */
static int reload_driver(const char *driver_name)
{
    char *rmmod_argv[] = { "/sbin/rmmod", (char *)driver_name, NULL };
    char *modprobe_argv[] = { "/sbin/modprobe", (char *)driver_name, NULL };
    int ret;
    
    if (!driver_name || driver_name[0] == '\0')
        return -EINVAL;
    
    printk(KERN_INFO "Shadow driver: Reloading driver %s\n", driver_name);
    add_event(NULL, PHASE_DRIVER_RESTARTING, "Reloading driver %s", driver_name);
    
    /* Unload the driver */
    ret = call_usermodehelper(rmmod_argv[0], rmmod_argv, NULL, UMH_WAIT_PROC);
    if (ret != 0) {
        printk(KERN_ERR "Failed to unload driver %s: %d\n", driver_name, ret);
        
        /* Try with modprobe -r instead */
        char *modprobe_r_argv[] = { "/sbin/modprobe", "-r", (char *)driver_name, NULL };
        ret = call_usermodehelper(modprobe_r_argv[0], modprobe_r_argv, NULL, UMH_WAIT_PROC);
        if (ret != 0) {
            printk(KERN_ERR "Failed to unload driver %s with modprobe -r: %d\n", driver_name, ret);
            return ret;
        }
    }
    
    /* Give the system time to settle */
    msleep(500);
    
    /* Reload the driver */
    ret = call_usermodehelper(modprobe_argv[0], modprobe_argv, NULL, UMH_WAIT_PROC);
    if (ret != 0) {
        printk(KERN_ERR "Failed to reload driver %s: %d\n", driver_name, ret);
        return ret;
    }
    
    return 0;
}

/* Function to start recovery process */
static void start_recovery(void)
{
    struct network_shadow *shadow = shadow_driver;
    
    if (!shadow || shadow->state != SHADOW_ACTIVE)
        return;
    
    printk(KERN_INFO "Shadow driver: Starting recovery for device %s\n", 
           shadow->device_name);
    
    shadow->state = SHADOW_RECOVERING;
    shadow->recovery_start_time = jiffies;
    shadow->recovery_attempts++;
    
    /* Record recovery start */
    add_event(NULL, PHASE_DRIVER_STOPPED, 
              "Starting recovery for device %s (attempt %d)", 
              shadow->device_name, shadow->recovery_attempts);
    
    /* Start a timer to check if recovery succeeds */
    mod_timer(&shadow->recovery_timer, 
              jiffies + msecs_to_jiffies(recovery_timeout * 1000));
    
    /* Reload the driver if we know its name */
    if (shadow->saved_state.driver_name[0] != '\0')
        reload_driver(shadow->saved_state.driver_name);
}

/* Recovery timer function */
static void recovery_timeout_fn(unsigned long data)
{
    struct network_shadow *shadow = (struct network_shadow *)data;
    
    if (!shadow)
        return;
    
    if (shadow->state == SHADOW_RECOVERING) {
        printk(KERN_ERR "Shadow driver: Recovery timeout for device %s\n", 
               shadow->device_name);
        
        /* Recovery failed, try again or give up */
        if (shadow->recovery_attempts < 3) {
            printk(KERN_INFO "Shadow driver: Retrying recovery for device %s\n", 
                   shadow->device_name);
            start_recovery();
        } else {
            printk(KERN_ERR "Shadow driver: Recovery failed after %d attempts\n", 
                   shadow->recovery_attempts);
            
            shadow->state = SHADOW_ACTIVE;  /* Stay active to handle requests */
            add_event(NULL, PHASE_RECOVERY_FAILED, 
                     "Recovery failed after %d attempts", shadow->recovery_attempts);
            end_test(false);
        }
    }
}

/* Network device notifier callback */
static int netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
    struct net_device *dev = netdev_notifier_info_to_dev(ptr);
    struct network_shadow *shadow = shadow_driver;
    
    if (!shadow || !dev)
        return NOTIFY_DONE;
    
    switch (event) {
    case NETDEV_REGISTER:
        /* If we're in recovery mode and our device shows up again, restore it */
        if ((shadow->state == SHADOW_ACTIVE || shadow->state == SHADOW_RECOVERING) && 
            strcmp(dev->name, shadow->device_name) == 0) {
            
            printk(KERN_INFO "Shadow driver: Device %s reappeared\n", dev->name);
            shadow->dev = dev;
            
            /* Cancel any pending recovery timer */
            del_timer(&shadow->recovery_timer);
            
            /* Restore device state */
            restore_device_state(dev);
            
            /* Go back to passive mode */
            shadow->state = SHADOW_PASSIVE;
            shadow->recovery_in_progress = false;
            
            add_event(NULL, PHASE_RECOVERY_COMPLETE, 
                     "Device %s successfully recovered", dev->name);
            end_test(true);
        }
        /* If we're in passive mode and our device registers, start monitoring it */
        else if (shadow->state == SHADOW_PASSIVE && shadow->dev == NULL && 
                 strcmp(dev->name, shadow->device_name) == 0) {
            
            shadow->dev = dev;
            start_test("network_shadow", dev->name);
            add_event(NULL, PHASE_NONE, 
                     "Started monitoring device %s", dev->name);
            
            /* Save initial state */
            save_device_state(dev);
        }
        break;
        
    case NETDEV_UNREGISTER:
        if (dev == shadow->dev) {
            shadow->dev = NULL;
            
            if (!shadow->recovery_in_progress) {
                printk(KERN_INFO "Shadow driver: Device %s unregistered, starting recovery\n", 
                       dev->name);
                
                shadow->state = SHADOW_ACTIVE;
                shadow->recovery_in_progress = true;
                add_event(NULL, PHASE_FAILURE_DETECTED, 
                         "Device %s unregistered unexpectedly", dev->name);
                
                /* Start recovery process */
                start_recovery();
            }
        }
        break;
        
    case NETDEV_UP:
        if (dev == shadow->dev) {
            save_device_state(dev);
        }
        break;
        
    case NETDEV_CHANGE:
        if (dev == shadow->dev) {
            /* Update our saved state with any changes */
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
    seq_printf(m, "Monitored device: %s\n", shadow->device_name);
    seq_printf(m, "Current state: %s\n", 
               shadow->state == SHADOW_PASSIVE ? "passive" :
               shadow->state == SHADOW_ACTIVE ? "active" : "recovering");
    seq_printf(m, "Device present: %s\n", 
               shadow->dev ? "yes" : "no");
    
    if (shadow->dev) {
        seq_printf(m, "Device info:\n");
        seq_printf(m, "  Name: %s\n", shadow->dev->name);
        seq_printf(m, "  MTU: %d\n", shadow->dev->mtu);
        seq_printf(m, "  State: %s\n", 
                  netif_running(shadow->dev) ? "up" : "down");
    }
    
    seq_printf(m, "Recovery info:\n");
    seq_printf(m, "  Recovery in progress: %s\n",
               shadow->recovery_in_progress ? "yes" : "no");
    seq_printf(m, "  Recovery attempts: %d\n", shadow->recovery_attempts);
    
    if (shadow->recovery_in_progress) {
        unsigned long elapsed = (jiffies - shadow->recovery_start_time) / HZ;
        seq_printf(m, "  Time in recovery: %lu seconds\n", elapsed);
    }
    
    return 0;
}

static int shadow_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, shadow_proc_show, NULL);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
static const struct file_operations shadow_proc_fops = {
    .owner = THIS_MODULE,
    .open = shadow_proc_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
#else
static const struct proc_ops shadow_proc_fops = {
    .proc_open = shadow_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};
#endif

/* Module parameters */
static char *device = "eth0";
module_param(device, charp, 0644);
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
    shadow->recovery_attempts = 0;
    strncpy(shadow->device_name, device, IFNAMSIZ - 1);
    
    /* Initialize the recovery timer */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
    setup_timer(&shadow->recovery_timer, recovery_timeout_fn, (unsigned long)shadow);
#else
    timer_setup(&shadow->recovery_timer, recovery_timeout_fn, 0);
#endif
    
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
        /* Clean up the timer */
        del_timer_sync(&shadow_driver->recovery_timer);
        
        /* Unregister our notifier */
        unregister_netdevice_notifier(&shadow_driver->netdev_notifier);
        
        /* Remove proc entry */
        remove_proc_entry("network_shadow", NULL);
        
        /* Free memory */
        kfree(shadow_driver);
        shadow_driver = NULL;
    }
    
    printk(KERN_INFO "Network Shadow Driver unloaded\n");
}

module_init(network_shadow_init);
module_exit(network_shadow_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shadow Driver Implementation");
MODULE_DESCRIPTION("Network Shadow Driver Implementation");