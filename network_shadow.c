#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rtnetlink.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>  /* Add this new include */
#include "../recovery_evaluator/recovery_evaluator.h"
#include <linux/ethtool.h>

/* Add the kprobe-based kallsyms_lookup_name solution here */
static unsigned long lookup_name(const char *name)
{
    struct kprobe kp = {
        .symbol_name = name
    };
    unsigned long addr;
    
    if (register_kprobe(&kp) < 0)
        return 0;
        
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    
    return addr;
}

static unsigned long (*kallsyms_lookup_name_func)(const char *name);

static int init_kallsyms_lookup(void)
{
    /* First check if kallsyms_lookup_name is still directly available */
    kallsyms_lookup_name_func = (void*)lookup_name("kallsyms_lookup_name");
    if (!kallsyms_lookup_name_func) {
        printk(KERN_ERR "Shadow driver: Could not find kallsyms_lookup_name\n");
        return -EINVAL;
    }
    
    return 0;
}

/* Function Tapping Infrastructure */
struct function_tap {
    char *name;
    void *original;
    void *replacement;
    bool is_active;
};

/* Array to store all taps for network driver functions */
#define MAX_TAPS 32
static struct function_tap function_taps[MAX_TAPS];
static int num_taps = 0;

/* Function to register a tap */
static int register_tap(const char *func_name, void *replacement) {
    unsigned long addr;
    
    if (num_taps >= MAX_TAPS)
        return -ENOSPC;
    
    addr = kallsyms_lookup_name_func(func_name);
    if (!addr) {
        printk(KERN_WARNING "Shadow driver: Could not find symbol %s\n", func_name);
        return -EINVAL;
    }
    
    function_taps[num_taps].name = kstrdup(func_name, GFP_KERNEL);
    function_taps[num_taps].original = (void *)addr;
    function_taps[num_taps].replacement = replacement;
    function_taps[num_taps].is_active = false;
    
    num_taps++;
    return 0;
}
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
    /* Enhanced state tracking */
    struct ethtool_cmd ecmd;     /* Ethtool settings */
    u32 msg_enable;              /* Debug message level */
    u8 perm_addr[ETH_ALEN];      /* Permanent MAC address */
    bool multicast_list_saved;   /* Did we save multicast list? */
    struct dev_mc_list *mc_list; /* Multicast address list */
    int mc_count;                /* Number of multicast addresses */
    
    /* Connection tracking */
    struct {
        bool in_use;
        int protocol;
        struct sockaddr local_addr;
        struct sockaddr remote_addr;
        int state;
    } connections[16];  /* Track up to 16 connections */
    int num_connections;
};

/* Shadow driver structure */
struct network_shadow {
    enum shadow_state state;
    struct net_device *dev;         /* Original network device */
    struct net_device_state saved_state;
    struct notifier_block netdev_notifier;
    bool recovery_in_progress;
    char device_name[IFNAMSIZ];
    struct work_struct recovery_work;  /* Work for recovery process */

};

static struct network_shadow *shadow_driver;
static void recovery_work_fn(struct work_struct *work);
static int shadow_ndo_open(struct net_device *dev);
static int shadow_ndo_stop(struct net_device *dev);
static netdev_tx_t shadow_ndo_start_xmit(struct sk_buff *skb, struct net_device *dev);
static int shadow_ndo_set_mac_address(struct net_device *dev, void *addr);
static int shadow_ndo_change_mtu(struct net_device *dev, int new_mtu);


/* Function to save device state */
static void save_device_state(struct net_device *dev)
{
    struct network_shadow *shadow = shadow_driver;
    
    if (!dev || !shadow)
        return;
        
    strncpy(shadow->saved_state.name, dev->name, IFNAMSIZ);
    
    /* Careful handling of MAC address copy to avoid const issues */
    if (dev->dev_addr) {
        unsigned char *src = (unsigned char *)dev->dev_addr;
        memcpy(shadow->saved_state.mac_addr, src, ETH_ALEN);
    }
    
    shadow->saved_state.mtu = dev->mtu;
    shadow->saved_state.flags = dev->flags;
    shadow->saved_state.is_up = netif_running(dev);
    shadow->saved_state.features = dev->features;
    shadow->saved_state.tx_queue_len = dev->tx_queue_len;
    
    /* Save device statistics */
    if (dev->netdev_ops && dev->netdev_ops->ndo_get_stats) {
        struct net_device_stats *stats = dev->netdev_ops->ndo_get_stats(dev);
        if (stats)
            memcpy(&shadow->saved_state.stats, stats, sizeof(struct net_device_stats));
    }
    
    /* Save ethtool settings - skip for newer kernels that use different API */
    printk(KERN_INFO "Shadow driver: Ethtool settings save skipped - kernel API changed\n");
    
    /* Save debug message level - not directly accessible in newer kernels */
    shadow->saved_state.msg_enable = 0; /* Use a safe default */
    
    /* Save permanent MAC address if available */
    if (dev->perm_addr) {
        memcpy(shadow->saved_state.perm_addr, dev->perm_addr, ETH_ALEN);
    }
    
    /* Save multicast list (limited implementation) */
    shadow->saved_state.multicast_list_saved = false;
    shadow->saved_state.mc_count = 0;
    /* In a real implementation, you'd need to copy the multicast list here */
    
    /* For real connection tracking, you would use netfilter hooks
     * This is a placeholder to show the concept */
    shadow->saved_state.num_connections = 0;
    
    printk(KERN_INFO "Shadow driver: Saved enhanced state for device %s\n", dev->name);
    /* Comment out add_event until recovery_evaluator is implemented */
    // add_event(NULL, PHASE_NONE, "Saved enhanced state for device %s", dev->name);
}


/* Function to restore device state */
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
    
    /* Safe copy of MAC address */
    if (dev->dev_addr) {
        unsigned char *dst = (unsigned char *)dev->dev_addr;
        memcpy(dst, shadow->saved_state.mac_addr, ETH_ALEN);
    }
    
    dev->flags = shadow->saved_state.flags;
    dev->tx_queue_len = shadow->saved_state.tx_queue_len;
    
    /* Restore ethtool settings - skip for newer kernels */
    printk(KERN_INFO "Shadow driver: Ethtool settings restore skipped - kernel API changed\n");
    
    /* Debug message level restoration skipped - not directly accessible */
    
    /* Restore multicast list would go here */
    if (shadow->saved_state.multicast_list_saved) {
        /* In a real implementation, you'd restore the multicast list here */
        printk(KERN_INFO "Shadow driver: Would restore multicast list\n");
    }
    
    /* Restore device state */
    if (shadow->saved_state.is_up && !netif_running(dev)) {
        if (dev->netdev_ops && dev->netdev_ops->ndo_open)
            ret = dev->netdev_ops->ndo_open(dev);
        if (ret)
            printk(KERN_ERR "Shadow driver: Failed to restore device %s state\n", dev->name);
            // add_event(NULL, PHASE_RECOVERY_FAILED, "Failed to restore device %s state", dev->name);
    } else if (!shadow->saved_state.is_up && netif_running(dev)) {
        if (dev->netdev_ops && dev->netdev_ops->ndo_stop)
            dev->netdev_ops->ndo_stop(dev);
    }
    
    /* For a real implementation, restore connections using netfilter hooks
     * This is a placeholder to show the concept */
    if (shadow->saved_state.num_connections > 0) {
        printk(KERN_INFO "Shadow driver: Would restore %d connections\n", 
               shadow->saved_state.num_connections);
    }
    
    if (rtnl_is_locked())
        rtnl_unlock();
    
    printk(KERN_INFO "Shadow driver: Restored enhanced state for device %s\n", dev->name);
    // add_event(NULL, PHASE_RECOVERY_COMPLETE, "Restored state for device %s", dev->name);
    
    return ret;
}

/* Example replacement for transmit function */
static netdev_tx_t shadow_ndo_start_xmit(struct sk_buff *skb, struct net_device *dev) {
    int i;
    netdev_tx_t ret = NETDEV_TX_BUSY;
    struct function_tap *tap = NULL;
    
    /* Find the original function tap */
    for (i = 0; i < num_taps; i++) {
        if (strcmp(function_taps[i].name, "ndo_start_xmit") == 0) {
            tap = &function_taps[i];
            break;
        }
    }
    
    if (!tap)
        return NETDEV_TX_BUSY;
    
    /* If in passive mode, just call the original function */
    if (shadow_driver->state == SHADOW_PASSIVE) {
        if (tap->original) {
            netdev_tx_t (*orig_fn)(struct sk_buff *, struct net_device *) = tap->original;
            ret = orig_fn(skb, dev);
        }
    } else if (shadow_driver->state == SHADOW_ACTIVE) {
        /* In active mode, handle the request ourselves */
        // add_event(NULL, PHASE_NONE, "Shadow handling transmit request during recovery");
        dev_kfree_skb_any(skb); /* Just drop packets during recovery */
        ret = NETDEV_TX_OK;      /* Pretend it worked */
    }
    
    return ret;
}


/* Example replacement for open function */
static int shadow_ndo_open(struct net_device *dev) {
    int i;
    int ret = -EINVAL;
    struct function_tap *tap = NULL;
    
    /* Find the original function tap */
    for (i = 0; i < num_taps; i++) {
        if (strcmp(function_taps[i].name, "e1000_open") == 0) {
            tap = &function_taps[i];
            break;
        }
    }
    
    if (!tap)
        return -EINVAL;
    
    /* If in passive mode, just call the original function */
    if (shadow_driver->state == SHADOW_PASSIVE && tap->original) {
        int (*orig_fn)(struct net_device *) = tap->original;
        ret = orig_fn(dev);
    } else if (shadow_driver->state == SHADOW_ACTIVE) {
        /* Simulate successful open */
        netif_carrier_on(dev);
        netif_start_queue(dev);
        ret = 0;
    }
    
    return ret;
}

/* Example replacement for stop function */
static int shadow_ndo_stop(struct net_device *dev) {
    int i;
    int ret = -EINVAL;
    struct function_tap *tap = NULL;
    
    /* Find the original function tap */
    for (i = 0; i < num_taps; i++) {
        if (strcmp(function_taps[i].name, "e1000_stop") == 0) {
            tap = &function_taps[i];
            break;
        }
    }
    
    if (!tap)
        return -EINVAL;
    
    /* If in passive mode, just call the original function */
    if (shadow_driver->state == SHADOW_PASSIVE && tap->original) {
        int (*orig_fn)(struct net_device *) = tap->original;
        ret = orig_fn(dev);
    } else if (shadow_driver->state == SHADOW_ACTIVE) {
        /* Simulate successful stop */
        netif_stop_queue(dev);
        netif_carrier_off(dev);
        ret = 0;
    }
    
    return ret;
}

/* Example replacement for set MAC address function */
static int shadow_ndo_set_mac_address(struct net_device *dev, void *addr) {
    int i;
    int ret = -EINVAL;
    struct function_tap *tap = NULL;
    
    /* Find the original function tap */
    for (i = 0; i < num_taps; i++) {
        if (strcmp(function_taps[i].name, "e1000_set_mac") == 0) {
            tap = &function_taps[i];
            break;
        }
    }
    
    if (!tap)
        return -EINVAL;
    
    /* If in passive mode, just call the original function */
    if (shadow_driver->state == SHADOW_PASSIVE && tap->original) {
        int (*orig_fn)(struct net_device *, void *) = tap->original;
        ret = orig_fn(dev, addr);
    } else if (shadow_driver->state == SHADOW_ACTIVE) {
        /* Simulate successful MAC address change */
        if (netif_running(dev))
            return -EBUSY;
            
        if (dev->addr_assign_type & NET_ADDR_RANDOM)
            dev->addr_assign_type &= ~NET_ADDR_RANDOM;
            
        memcpy((void *)dev->dev_addr, addr, ETH_ALEN);
        ret = 0;
    }
    
    return ret;
}

/* Example replacement for change MTU function */
static int shadow_ndo_change_mtu(struct net_device *dev, int new_mtu) {
    int i;
    int ret = -EINVAL;
    struct function_tap *tap = NULL;
    
    /* Find the original function tap */
    for (i = 0; i < num_taps; i++) {
        if (strcmp(function_taps[i].name, "e1000_change_mtu") == 0) {
            tap = &function_taps[i];
            break;
        }
    }
    
    if (!tap)
        return -EINVAL;
    
    /* If in passive mode, just call the original function */
    if (shadow_driver->state == SHADOW_PASSIVE && tap->original) {
        int (*orig_fn)(struct net_device *, int) = tap->original;
        ret = orig_fn(dev, new_mtu);
    } else if (shadow_driver->state == SHADOW_ACTIVE) {
        /* Simulate successful MTU change */
        if (new_mtu < 68 || new_mtu > 9000)
            return -EINVAL;
            
        dev->mtu = new_mtu;
        ret = 0;
    }
    
    return ret;
}


/* Add recovery sequence */
static void start_recovery(struct network_shadow *shadow) {
    if (!shadow || shadow->recovery_in_progress)
        return;
    
    shadow->recovery_in_progress = true;
    shadow->state = SHADOW_ACTIVE;
    
    // add_event(NULL, PHASE_DRIVER_STOPPED, "Shadow driver activating for %s", shadow->device_name);
    
    /* Schedule work to perform recovery */
    schedule_work(&shadow->recovery_work);
}

/* Recovery work function */
static void recovery_work_fn(struct work_struct *work) {
    struct network_shadow *shadow = container_of(work, struct network_shadow, recovery_work);
    
    /* Step 1: Activate all taps to intercept calls */
    int i;
    for (i = 0; i < num_taps; i++) {
        function_taps[i].is_active = true;
    }
    
    // add_event(NULL, PHASE_DRIVER_RESTARTING, "Restarting driver for %s", shadow->device_name);
    
    /* Step 2: Request module reload */
    /* In a real implementation, you'd need to:
     * 1. Get module name from device
     * 2. Request kernel to unload module
     * 3. Request kernel to load module
     */
    
    /* For simulation purposes, we'll just wait a bit */
    msleep(1000);
    
    /* Step 3: Check if device reappeared */
    if (shadow->dev) {
        /* Success! Restore device state */
        restore_device_state(shadow->dev);
        shadow->recovery_in_progress = false;
        shadow->state = SHADOW_PASSIVE;
        // add_event(NULL, PHASE_RECOVERY_COMPLETE, "Recovery complete for %s", shadow->device_name);
    } else {
        /* Failed recovery */
        shadow->recovery_in_progress = false;
        // add_event(NULL, PHASE_RECOVERY_FAILED, "Recovery failed for %s", shadow->device_name);
    }
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
            printk(KERN_INFO "Shadow driver: Started monitoring device %s\n", dev->name);
            // start_test("network_shadow", dev->name);
            // add_event(NULL, PHASE_NONE, "Started monitoring device %s", dev->name);
            save_device_state(dev);
        }
        break;
        
    case NETDEV_UNREGISTER:
        if (dev == shadow->dev) {
            if (!shadow->recovery_in_progress) {
                shadow->state = SHADOW_ACTIVE;
                shadow->recovery_in_progress = true;
                printk(KERN_INFO "Shadow driver: Device %s unregistered unexpectedly\n", dev->name);
                // add_event(NULL, PHASE_FAILURE_DETECTED, "Device %s unregistered unexpectedly", dev->name);
                
                /* Start the recovery process */
                printk(KERN_INFO "Shadow driver active: device %s failed, starting recovery\n", dev->name);
                start_recovery(shadow);
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

/* Use proc_ops structure for newer kernels, file_operations for older kernels */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops shadow_proc_ops = {
    .proc_open = shadow_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations shadow_proc_fops = {
    .owner = THIS_MODULE,
    .open = shadow_proc_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
#endif

/* Module parameters */
static char device_name[IFNAMSIZ] = "eth0";
module_param_string(device, device_name, IFNAMSIZ, 0644);
MODULE_PARM_DESC(device, "Network device to monitor (default: eth0)");

/* Module initialization */
static int __init network_shadow_init(void)
{
    struct network_shadow *shadow;
    struct proc_dir_entry *proc_entry;
    int ret;
    
    /* Initialize the kallsyms lookup function */
    ret = init_kallsyms_lookup();
    if (ret < 0) {
        printk(KERN_ERR "Shadow driver: Failed to initialize kallsyms lookup\n");
        return ret;
    }
    
    /* Allocate shadow driver structure */
    shadow = kzalloc(sizeof(*shadow), GFP_KERNEL);
    if (!shadow)
        return -ENOMEM;
    
    /* Initialize shadow driver */
    shadow->state = SHADOW_PASSIVE;
    shadow->dev = NULL;
    shadow->recovery_in_progress = false;
    strncpy(shadow->device_name, device_name, IFNAMSIZ - 1);
    
    /* Initialize recovery work */
    INIT_WORK(&shadow->recovery_work, recovery_work_fn);
    
    /* Register function taps for common network functions */
    register_tap("e1000_open", shadow_ndo_open);
    register_tap("e1000_stop", shadow_ndo_stop);
    register_tap("e1000_start_xmit", shadow_ndo_start_xmit);
    register_tap("e1000_set_mac", shadow_ndo_set_mac_address);
    register_tap("e1000_change_mtu", shadow_ndo_change_mtu);
    
    /* Register network device notifier */
    shadow->netdev_notifier.notifier_call = netdev_event;
    register_netdevice_notifier(&shadow->netdev_notifier);
    
    /* Create proc entry using the appropriate structure type */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
    proc_entry = proc_create("network_shadow", 0644, NULL, &shadow_proc_ops);
#else
    proc_entry = proc_create("network_shadow", 0644, NULL, &shadow_proc_fops);
#endif
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
        shadow_driver = NULL;
    }
    
    printk(KERN_INFO "Network Shadow Driver unloaded\n");
}

module_init(network_shadow_init);
module_exit(network_shadow_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shadow Driver Implementation");
MODULE_DESCRIPTION("Network Shadow Driver Implementation");