#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "vm.h"
#include "memstat.h"

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  kexit(n);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return kfork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return kwait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int t;
  int n;

  argint(0, &n);
  argint(1, &t);
  addr = myproc()->sz;

  if(t == SBRK_EAGER || n < 0) {
    if(growproc(n) < 0) {
      return -1;
    }
  } else {
    // Lazily allocate memory for this process: increase its memory
    // size but don't allocate memory. If the processes uses the
    // memory, vmfault() will allocate it.
    if(addr + n < addr)
      return -1;
    myproc()->sz += n;
  }
  return addr;
}

uint64
sys_pause(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  if(n < 0)
    n = 0;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(killed(myproc())){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kkill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

uint64
sys_memstat(void)
{
  uint64 addr;
  struct proc *p = myproc();
  
  argaddr(0, &addr);
  
  // Temporary struct to build the response
  struct proc_mem_stat stat;
  stat.pid = p->pid;
  stat.next_fifo_seq = p->next_fifo_seq;
  stat.num_pages_total = 0;
  stat.num_resident_pages = 0;
  stat.num_swapped_pages = 0;
  
  // Count and copy page info
  int pages_reported = 0;
  for (int i = 0; i < p->num_pages && pages_reported < MAX_PAGES_INFO; i++) {
    stat.pages[pages_reported].va = (uint)p->pages[i].va;
    stat.pages[pages_reported].state = p->pages[i].state;
    stat.pages[pages_reported].is_dirty = p->pages[i].is_dirty;
    stat.pages[pages_reported].seq = p->pages[i].seq;
    stat.pages[pages_reported].swap_slot = p->pages[i].swap_slot;
    
    stat.num_pages_total++;
    if (p->pages[i].state == RESIDENT) {
      stat.num_resident_pages++;
    } else if (p->pages[i].state == SWAPPED) {
      stat.num_swapped_pages++;
    }
    
    pages_reported++;
  }
  
  // Copy to user space
  if (copyout(p->pagetable, addr, (char *)&stat, sizeof(stat)) < 0) {
    return -1;
  }
  
  return 0;
}
