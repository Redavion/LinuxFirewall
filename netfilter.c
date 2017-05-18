// Carver and Alison's Netfilter Kernel Module

#define MODULE
#define LINUX
#define __KERNEL__

#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/string.h>


/*
 * Whenever the user writes to the /proc file that you register, you'll get a callback
 * to the function that you registered as the ".read" member in your file_operations variable. you can then
 * do a simple parsing of their input to add the addresses that you need to filter whether they are
 * input or output
 */

// What the structure of a node is
struct list_of_IP{
    bool blocked;
    bool monitored; //if it is being monitored then it CANNOT BE BLOCKED
    char in_or_out; //0: neither in nor out (default value), 1: in, 2: out
    unsigned int numberOfPacketsReceived;
    unsigned int numberOfPacketsBlocked;
    //   unsigned int ip_address;
    char ip_address[32];
    struct list_head list;
};

// Initialize a list called mylist
static struct list_of_IP mylist;
int len, tmp;
static char *msg=0;
static ssize_t read_proc(struct file*filp, char __user * buf, size_t count, loff_t *offp) {
    printk (KERN_INFO "PROC READ\n");
    if (count > tmp){
        count = tmp;
    }
    tmp = tmp - count;
    copy_to_user (buf, msg, count);
    if (count==0)
    tmp = len;
    return count;
}


// Gobal booleans for all incoming/outgoing packets blocked
bool blockAllIn;
bool blockAllOut;

static ssize_t write_proc (struct file *filp, const char __user * buf, size_t count, loff_t * offp) {
    printk (KERN_INFO "PROC WRITE\n");
    if (msg == 0 || count > 100) {
        printk (KERN_INFO "Invalid entry: either msg is 0 or count >100\n");
        return -1;
    }

    // You have to move data from user space to kernel buffer
    copy_from_user (msg, buf, count);

    // Char array from message to be manipulated. Extra space to prevent overflow
    char a[strlen(msg)+10];

    // Copy the char *msg into the char[] a
    strncpy(a, msg, strlen(msg));

    // Set up char *tokens to point to use in parsing a
    char *tok;
    char *tok0;
    char *tok1;
    char *tok2;
    char *aptr = a;

    // Puts the first line of a into what tok points at
    tok = strsep(&aptr, "\n");
    //The following three strseps parses the three possible arguments from tok
    tok0 = strsep(&tok, " ");
    tok1 = strsep(&tok, " ");
    tok2 = strsep(&tok, " ");

    // Initialize the three char[] used to compare the arguments
    char command0[strlen(tok0)];
    char command1[32];
    char command2[8];

    //Copy strings into the three char[] if the pointer is not null
    //The first pointer will never be null
    strcpy(command0, tok0);
    if (!(tok1 == 0)){
        strcpy(command1, tok1);
    }
    if (!(tok2 == 0)){
        strcpy(command2, tok2);
    }
    // For testing
    //    printk(KERN_INFO "START:\n");
    //    printk(KERN_INFO "%s\n", command0);
    //    printk(KERN_INFO "%s\n", command1);
    //    printk(KERN_INFO "%s\n", command2);

    len = count;
    tmp = len;

    // Check the first argument to see if it is ALLI
    // Block or unblock according to second argument.
    // NOTE: all strcmp's return 0 if strings are equal
    if (!strcmp(command0, "ALLI")){
        if (!strcmp(command1,"b")){
            blockAllIn = true;
        }else if (!strcmp(command1, "u")){
            blockAllIn = false;
        } else {
            printk(KERN_INFO "Invalid argument\n");
            return -1;
        }
        // Check the first argument to see if it is ALLO
        // Block or unblock according to second argument.
    } else if (!strcmp(command0, "ALLO")){
        if (!strcmp(command1,"b")){
            blockAllOut = true;
        } else if (!strcmp(command1,"u")){
            blockAllOut = false;
        } else {
            printk(KERN_INFO "Invalid argument\n");
        return -1;
        }
    // Check the first argument to see if it is ALL0
    } else if (!strcmp(command0, "IP")) {
        // Check second argument to block
        if (!strcmp(command2, "b")) {
            struct list_head *iterator;
            struct list_of_IP *entry;
            bool isAlreadyThere = false;
            list_for_each(iterator, &mylist.list){
                entry = list_entry(iterator,
                struct list_of_IP, list);
                if (!strcmp(entry->ip_address, command1)){
                    // The IP address is already in the list
                    //set blocked equal to true
                    entry->blocked = true;
                    isAlreadyThere = true;
                    break;
                }
            }
            // If the IP is not in the list, add it
            if (!isAlreadyThere){
                struct list_of_IP* newEntry = kmalloc(sizeof(*newEntry), GFP_KERNEL);
                strcpy(newEntry->ip_address, command1);
                newEntry->blocked = true;
                // Set blocked equal to true
                newEntry->monitored=false;
                newEntry->in_or_out= 'n';
                newEntry->numberOfPacketsReceived = 0;
                newEntry->numberOfPacketsBlocked = 0;
                list_add_tail(&(newEntry->list), &(mylist.list));
                printk(KERN_INFO "successfully added the ip address to list\n");
            }
        // Check second argument to unblock the IP Address
        } else if (!strcmp(command2, "ub")){
            struct list_head *iterator, *iterator2;
            struct list_of_IP *entry;
            list_for_each_safe(iterator, iterator2, &mylist.list){
                entry = list_entry(iterator, struct list_of_IP, list);
                if (!strcmp(entry->ip_address, command1)){
                    // The IP address is already in the list
                    //set blocked equal to false
                    entry->blocked = false;

                    if (entry->monitored == false){
                        printk(KERN_INFO "free node\n");
                        list_del(iterator);
                        //it is not being monitored or even blocked so remove from list
                        kfree(entry);
                    }
                }
            }
        // Check second argument to monitor the IP address
        } else if (!strcmp(command2, "m")) {
            struct list_head *iterator;
            struct list_of_IP *entry;
            bool isAlreadyThere = false;
            list_for_each(iterator, &mylist.list){
                entry = list_entry(iterator, struct list_of_IP, list);
                if (!strcmp(entry->ip_address, command1)){
                    // The IP address is already in the list
                    if (entry->monitored != true){
                        // If it's not being monitored
                        entry->monitored = true;
                        // Set monitor equal to true
                        entry->numberOfPacketsReceived= 0;
                        // Set the running packet count to 0
                    }
                    isAlreadyThere = true;
                    break;
                }
            }
            // If the IP is not in the list, add it
            if (!isAlreadyThere){
                struct list_of_IP* newEntry = kmalloc(sizeof(*newEntry), GFP_KERNEL);
                strcpy(newEntry->ip_address, command1);
                newEntry->monitored = true;
                // Set blocked equal to true
                newEntry->blocked = false;
                newEntry->in_or_out= 'n';
                newEntry->numberOfPacketsReceived = 0;
                newEntry->numberOfPacketsBlocked = 0;
                list_add_tail(&(newEntry->list), &(mylist.list));
                printk(KERN_INFO "successfully added the ip address to list\n");
            }
        // Check second argument to unmonitor the IP address
        } else if (!strcmp(command2, "um")) {
            // Initialize pointers and iterator to traverse list
            struct list_head *p, *q;
            struct list_of_IP *iterator;
            // Traverse list
            list_for_each_safe(p,q,&mylist.list){
                iterator = list_entry(p, struct list_of_IP, list);
                if (!strcmp(iterator->ip_address, command1)){
                    iterator->monitored = false;
                    if (iterator->blocked == false) {
                        printk(KERN_INFO "free node\n");
                        list_del(p);
                        // Delete node if not blocked and no longer being monitored
                        kfree(iterator);
                        break;
                    }
                }
            }
        } else {
            printk(KERN_INFO "Invalid argument\n");
            return -1;
        }
    } else if (!strcmp(command0, "STATS")){
        if (!strcmp(command1, "ALL")){ //if you want to print out every monitored IP address
            struct list_head *iterator;
            struct list_of_IP *entry;
            bool isAlreadyThere = false;
            printk(KERN_INFO
            "STATS:\n");
            list_for_each(iterator, &mylist.list){
                entry = list_entry(iterator,
                struct list_of_IP, list);
                if (entry->monitored){  //is it being monitored
                    printk(KERN_INFO
                    "Packet info::: ip address: %s, in or out: %c, Packets Recieved(Accepted): %u, Packets Blocked: %u\n", entry->ip_address, entry->in_or_out, entry->numberOfPacketsReceived, entry->numberOfPacketsBlocked);
                }
            }
        } else { //if you only want to print out a specific IP address's info
            struct list_head *iterator;
            struct list_of_IP *entry;
            bool isAlreadyThere = false;
            printk(KERN_INFO"STATS:\n");
            list_for_each(iterator, &mylist.list){
                entry = list_entry(iterator,
                struct list_of_IP, list);
                if (entry->monitored && (!strcmp(entry->ip_address,command1))){  //is it being monitored and is it the right ip address
                    isAlreadyThere = true;
                    printk(KERN_INFO
                    "Packet info::: ip address: %s, in or out: %c, Packets Recieved(Accepted): %u, Packets Blocked: %u\n", entry->ip_address, entry->in_or_out, entry->numberOfPacketsReceived, entry->numberOfPacketsBlocked);
                }
            }
            if (!isAlreadyThere){
                printk(KERN_INFO "This IP address is not being monitored by you.\n");
            }
        }

    } else {
        printk(KERN_INFO "Invalid argument\n");
        return -1;
    }
    // Returns count if successful
    return count;
}

// File operations able to be done on the proc file system
static const struct file_operations proc_fops = {
        .owner = THIS_MODULE,
        .read = read_proc,
        .write = write_proc,
};

void
create_new_proc_entry (void)
{
    // Creates a new proc file called filter
    proc_create ("filter", 0666, NULL, &proc_fops);
    msg = kmalloc (100 * sizeof (char), GFP_KERNEL);
    if (msg == 0)
    {
        printk (KERN_INFO "msg should not be 0\n");
    }
}

// Initialize the hooks so that packets will be caught
static struct nf_hook_ops nfho;
static struct nf_hook_ops nfho_out;
struct sk_buff *sock_buff;
struct iphdr *ip_header;
void ip_hl_to_str(unsigned int ip, char *ip_str) {
    /*convert hl to byte array first*/
    unsigned char ip_array[4];
    memset(ip_array, 0, 4);
    ip_array[0] = (ip_array[0] | (ip >> 24));
    ip_array[1] = (ip_array[1] | (ip >> 16));
    ip_array[2] = (ip_array[2] | (ip >> 8));
    ip_array[3] = (ip_array[3] | ip);
    sprintf(ip_str, "%u.%u.%u.%u", ip_array[0], ip_array[1], ip_array[2], ip_array[3]);
}

unsigned int ip_str_to_hl(char *ip_str) {
    /*convert the string to byte array first, e.g.: from "131.132.162.25" to [131][132][162][25]*/
    unsigned char ip_array[4];
    int i = 0;
    unsigned int ip = 0;
    if (ip_str==NULL) {
        return 0;
    }
    memset(ip_array, 0, 4);
    while (ip_str[i]!='.') {
        ip_array[0] = ip_array[0]*10 + (ip_str[i++]-'0');
    }
    ++i;
    while (ip_str[i]!='.') {
        ip_array[1] = ip_array[1]*10 + (ip_str[i++]-'0');
    }
    ++i;
    while (ip_str[i]!='.') {
        ip_array[2] = ip_array[2]*10 + (ip_str[i++]-'0');
    }
    ++i;
    while (ip_str[i]!=' ') {
        ip_array[3] = ip_array[3]*10 + (ip_str[i++]-'0');
    }
    /*convert from byte array to host long integer format*/
    ip = (ip_array[0] << 24);
    ip = (ip | (ip_array[1] << 16));
    ip = (ip | (ip_array[2] << 8));
    ip = (ip | ip_array[3]);
    //printk(KERN_INFO "ip_str_to_hl convert %s to %un", ip_str, ip);
    return ip;
}

// This hook func is for packets that our INCOMING
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    // IF ALLI b was executed, no incoming packet should make it through.
    if (blockAllIn==true){
        printk(KERN_INFO "DROPPED INCOMING PACKET DUE TO BLOCK ALL IN\n");
        // DROP PACKET
        return NF_DROP;

    }
    sock_buff=skb;
    ip_header = (struct iphdr *)skb_network_header(skb);
    if (!sock_buff){return NF_ACCEPT;}
    // Get source and destination IP addresses from header
    unsigned int src_ip = (unsigned int) ip_header->saddr;
    unsigned int dest_ip = (unsigned int) ip_header->daddr;

    char src_ip_str[16];
    char dest_ip_str[16];
    ip_hl_to_str(src_ip, src_ip_str);
    ip_hl_to_str(dest_ip, dest_ip_str);
    printk(KERN_INFO "Incoming packet: src %s, dest %s\n", src_ip_str, dest_ip_str);

    // Initialize pointers and iterator to tranverse list
    struct list_head *iterator;
    struct list_of_IP *entry;
    bool isAlreadyThere = false;
    int i = 0;
    // Traverse the list
    list_for_each(iterator, &mylist.list){
        i++;
        entry = list_entry(iterator, struct list_of_IP, list);
        //Compare if the entry's IP is the same as the packet's source
        if (!strcmp(entry->ip_address, src_ip_str)){
            // Mark that the packet is incoming
            entry->in_or_out = 'i';
            // Check if monitored
            if (entry->monitored) {
                // If monitored, increase the respective packet count
                if (entry->blocked){
                    (entry->numberOfPacketsBlocked)++;
                } else {

                    (entry->numberOfPacketsReceived)++;
                }
            }
            if (entry->blocked){
                // If the entry->blocked is true, drop Packet
                printk(KERN_INFO "DROPPED INCOMING PACKET %s\n", src_ip_str);
                return NF_DROP;
            } else {
                // Otherwise accept
                printk(KERN_INFO "ACCEPT INCOMING PACKET %s\n", src_ip_str);
                return NF_ACCEPT;
            }
        }
    }

    printk(KERN_INFO "ACCEPT INCOMING PACKET %s\n", src_ip_str);
    return NF_ACCEPT;
}


// This hook func is for packets that our OUTGOING
unsigned int hook_func_outgoing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    // IF ALLO b was executed, no incoming packet should make it through.
    if (blockAllOut==true){
        // DROP PACKET
        printk(KERN_INFO "DROP OUTGOING PACKET DUE TO BLOCK ALL OUT\n");
        return NF_DROP;

    }
    sock_buff=skb;
    ip_header = (struct iphdr *)skb_network_header(skb);
    if (!sock_buff){return NF_ACCEPT;}
    // Get source and destination IP addresses from header
    unsigned int src_ip = (unsigned int) ip_header->saddr;
    unsigned int dest_ip = (unsigned int) ip_header->daddr;

    char src_ip_str[16];
    char dest_ip_str[16];
    ip_hl_to_str(src_ip, src_ip_str);
    ip_hl_to_str(dest_ip, dest_ip_str);

    printk(KERN_INFO "Outgoing packet: src %s, dest %s\n", src_ip_str, dest_ip_str);


    // Initialize pointers and iterator to tranverse list
    struct list_head *iterator;
    struct list_of_IP *entry;
    bool isAlreadyThere = false;
    int i = 0;
    // Traverse the list
    list_for_each(iterator, &mylist.list)
    {
        i++;
        entry = list_entry(iterator,struct list_of_IP, list);
        // Compare if the entry's IP is the same as the packet's destination
        if (!strcmp(entry->ip_address, dest_ip_str)) {
            // Mark that the packet is outgoing
            entry->in_or_out = 'o';
            // Check if monitored
            if (entry->monitored) {
                // If monitored, increase the respective packet count
                if (entry->blocked) {
                    (entry->numberOfPacketsBlocked)++;
                } else {
                    (entry->numberOfPacketsReceived)++;

                }
            }
            if (entry->blocked) {
                // If the entry is blocked, drop packet
                printk(KERN_INFO "DROP OUTGOING PACKET %s\n", dest_ip_str);
                return NF_DROP;
            } else {
                // Otherwise accept
                printk(KERN_INFO "ACCEPT OUTGOING PACKET %s\n", dest_ip_str);
                return NF_ACCEPT;
            }

        }
    }
    printk(KERN_INFO "ACCEPT OUTGOING PACKET %s\n", dest_ip_str);
    return NF_ACCEPT;
}




int
init_module(void)
{
    printk (KERN_INFO "Initialize module\n");

    // Initialize the list
    INIT_LIST_HEAD(&(mylist.list));

    // Create the proc file
    create_new_proc_entry ();

    // Register both of the hooks
    // Register for incoming
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = PF_INET;
    nf_register_hook(&nfho);

    //Register for outgoing
    nfho_out.hook=hook_func_outgoing;
    nfho_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_out.pf = PF_INET;
    nf_register_hook(&nfho_out);

    /*
     * A non 0 return means init_module failed; module can't be loaded.
     */
    return 0;
}

// Module cleanup
void
cleanup_module(void)
{
    // Pointers and iterator to tranverse list
    struct list_head *p, *q;
    struct list_of_IP *iterator;

    // Unregister hooks
    nf_unregister_hook(&nfho);
    nf_unregister_hook(&nfho_out);
    // Traverse list
    list_for_each_safe(p,q,&mylist.list){
        // Delete nodes
        printk(KERN_INFO "free node\n");
        iterator = list_entry(p, struct list_of_IP, list);
        list_del(p);
        kfree(iterator);
    }
    remove_proc_entry("filter", NULL);
    printk (KERN_INFO "Module Cleaned Up\n");
}
MODULE_LICENSE ("GPL");
