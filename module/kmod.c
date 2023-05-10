#include <linux/module.h> /* Needed by all modules */ 
#include<linux/kernel.h>
#include<linux/cred.h>

static int __init hello_2_init(void) 
{ 
    prepare_kernel_cred(0);
    return 0; 
} 
 
static void __exit hello_2_exit(void) 
{ 
    pr_info("Goodbye, world 2\n"); 
} 
 
module_init(hello_2_init); 
module_exit(hello_2_exit); 
 
MODULE_LICENSE("GPL");