#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "memstat.h"
#include "sleeplock.h"
#include "fs.h"
#include "stat.h"
#include "fcntl.h"
#include "file.h"

struct cpu cpus[NCPU];

struct proc proc[NPROC];

struct proc *initproc;

int nextpid = 1;
struct spinlock pid_lock;

extern void forkret(void);
static void freeproc(struct proc *p);

extern char trampoline[]; // trampoline.S

// helps ensure that wakeups of wait()ing
// parents are not lost. helps obey the
// memory model when using p->parent.
// must be acquired before any p->lock.
struct spinlock wait_lock;

// Allocate a page for each process's kernel stack.
// Map it high in memory, followed by an invalid
// guard page.
void
proc_mapstacks(pagetable_t kpgtbl)
{
  struct proc *p;
  
  for(p = proc; p < &proc[NPROC]; p++) {
    char *pa = kalloc();
    if(pa == 0)
      panic("kalloc");
    uint64 va = KSTACK((int) (p - proc));
    kvmmap(kpgtbl, va, (uint64)pa, PGSIZE, PTE_R | PTE_W);
  }
}

// initialize the proc table.
void
procinit(void)
{
  struct proc *p;
  
  initlock(&pid_lock, "nextpid");
  initlock(&wait_lock, "wait_lock");
  for(p = proc; p < &proc[NPROC]; p++) {
      initlock(&p->lock, "proc");
      p->state = UNUSED;
      p->kstack = KSTACK((int) (p - proc));
  }
}

// Must be called with interrupts disabled,
// to prevent race with process being moved
// to a different CPU.
int
cpuid()
{
  int id = r_tp();
  return id;
}

// Return this CPU's cpu struct.
// Interrupts must be disabled.
struct cpu*
mycpu(void)
{
  int id = cpuid();
  struct cpu *c = &cpus[id];
  return c;
}

// Return the current struct proc *, or zero if none.
struct proc*
myproc(void)
{
  push_off();
  struct cpu *c = mycpu();
  struct proc *p = c->proc;
  pop_off();
  return p;
}

int
allocpid()
{
  int pid;
  
  acquire(&pid_lock);
  pid = nextpid;
  nextpid = nextpid + 1;
  release(&pid_lock);

  return pid;
}

// Look in the process table for an UNUSED proc.
// If found, initialize state required to run in the kernel,
// and return with p->lock held.
// If there are no free procs, or a memory allocation fails, return 0.
static struct proc*
allocproc(void)
{
  struct proc *p;

  for(p = proc; p < &proc[NPROC]; p++) {
    acquire(&p->lock);
    if(p->state == UNUSED) {
      goto found;
    } else {
      release(&p->lock);
    }
  }
  return 0;

found:
  p->pid = allocpid();
  p->state = USED;

  // Allocate a trapframe page.
  if((p->trapframe = (struct trapframe *)kalloc()) == 0){
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  // An empty user page table.
  p->pagetable = proc_pagetable(p);
  if(p->pagetable == 0){
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  // Set up new context to start executing at forkret,
  // which returns to user space.
  memset(&p->context, 0, sizeof(p->context));
  p->context.ra = (uint64)forkret;
  p->context.sp = p->kstack + PGSIZE;

  // Initialize demand paging fields
  p->text_start = 0;
  p->text_end = 0;
  p->data_start = 0;
  p->data_end = 0;
  p->heap_start = 0;
  p->stack_top = 0;
  p->next_fifo_seq = 1;
  p->swap_file = 0;
  p->swap_slots_used = 0;
  p->num_pages = 0;
  p->exec_inode = 0;
  p->exec_offset = 0;
  p->num_segments = 0;
  memset(p->swap_bitmap, 0, sizeof(p->swap_bitmap));
  memset(p->pages, 0, sizeof(p->pages));
  memset(p->segments, 0, sizeof(p->segments));

  return p;
}

// free a proc structure and the data hanging from it,
// including user pages.
// p->lock must be held.
static void
freeproc(struct proc *p)
{
  if(p->trapframe)
    kfree((void*)p->trapframe);
  p->trapframe = 0;
  if(p->pagetable)
    proc_freepagetable(p->pagetable, p->sz);
  p->pagetable = 0;
  
  // Note: swap file cleanup moved to kexit() before freeproc is called
  // to avoid doing filesystem operations while holding p->lock
  
  p->sz = 0;
  p->pid = 0;
  p->parent = 0;
  p->name[0] = 0;
  p->chan = 0;
  p->killed = 0;
  p->xstate = 0;
  p->state = UNUSED;
  p->num_pages = 0;
  p->swap_slots_used = 0;
}

// Create a user page table for a given process, with no user memory,
// but with trampoline and trapframe pages.
pagetable_t
proc_pagetable(struct proc *p)
{
  pagetable_t pagetable;

  // An empty page table.
  pagetable = uvmcreate();
  if(pagetable == 0)
    return 0;

  // map the trampoline code (for system call return)
  // at the highest user virtual address.
  // only the supervisor uses it, on the way
  // to/from user space, so not PTE_U.
  if(mappages(pagetable, TRAMPOLINE, PGSIZE,
              (uint64)trampoline, PTE_R | PTE_X) < 0){
    uvmfree(pagetable, 0);
    return 0;
  }

  // map the trapframe page just below the trampoline page, for
  // trampoline.S.
  if(mappages(pagetable, TRAPFRAME, PGSIZE,
              (uint64)(p->trapframe), PTE_R | PTE_W) < 0){
    uvmunmap(pagetable, TRAMPOLINE, 1, 0);
    uvmfree(pagetable, 0);
    return 0;
  }

  return pagetable;
}

// Free a process's page table, and free the
// physical memory it refers to.
void
proc_freepagetable(pagetable_t pagetable, uint64 sz)
{
  uvmunmap(pagetable, TRAMPOLINE, 1, 0);
  uvmunmap(pagetable, TRAPFRAME, 1, 0);
  
  // Before calling uvmfree, explicitly unmap all user pages including stack
  // This ensures guard page and stack pages get freed properly
  struct proc *p = myproc();
  if(p && p->stack_top > 0) {
    uint64 stack_base = p->stack_top - USERSTACK * PGSIZE;
    uint64 guard_page = stack_base - PGSIZE;
    // Unmap guard and stack pages explicitly
    for(uint64 va = guard_page; va < p->stack_top; va += PGSIZE) {
      pte_t *pte = walk(pagetable, va, 0);
      if(pte && (*pte & PTE_V)) {
        uvmunmap(pagetable, va, 1, 1);
      }
    }
  }
  
  uvmfree(pagetable, sz);
}

// Set up first user process.
void
userinit(void)
{
  struct proc *p;

  p = allocproc();
  initproc = p;
  
  p->cwd = namei("/");

  p->state = RUNNABLE;

  release(&p->lock);
}

// Shrink user memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint64 sz;
  struct proc *p = myproc();

  sz = p->sz;
  if(n > 0){
    if((sz = uvmalloc(p->pagetable, sz, sz + n, PTE_W)) == 0) {
      return -1;
    }
  } else if(n < 0){
    sz = uvmdealloc(p->pagetable, sz, sz + n);
  }
  p->sz = sz;
  return 0;
}

// Create a new process, copying the parent.
// Sets up child kernel stack to return as if from fork() system call.
int
kfork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *p = myproc();

  // Allocate process.
  if((np = allocproc()) == 0){
    return -1;
  }

  // Copy user memory from parent to child.
  if(uvmcopy(p->pagetable, np->pagetable, p->sz) < 0){
    freeproc(np);
    release(&np->lock);
    return -1;
  }
  np->sz = p->sz;
  
  // Copy segment information
  np->text_start = p->text_start;
  np->text_end = p->text_end;
  np->data_start = p->data_start;
  np->data_end = p->data_end;
  np->heap_start = p->heap_start;
  np->stack_top = p->stack_top;
  
  // Copy segment info for lazy loading
  np->num_segments = p->num_segments;
  for(i = 0; i < p->num_segments; i++) {
    np->segments[i] = p->segments[i];
  }
  
  // Copy exec inode reference if exists
  if(p->exec_inode) {
    np->exec_inode = idup(p->exec_inode);
  }
  
  // Copy page tracking info
  np->num_pages = p->num_pages;
  np->next_fifo_seq = p->next_fifo_seq;
  for(i = 0; i < p->num_pages; i++) {
    np->pages[i].va = p->pages[i].va;
    np->pages[i].state = p->pages[i].state;
    np->pages[i].is_dirty = p->pages[i].is_dirty;
    np->pages[i].seq = p->pages[i].seq;
    np->pages[i].swap_slot = -1;  // Child gets no swap initially
    
    // If parent page is swapped, child will fault and reload from executable or allocate new
    if(p->pages[i].state == SWAPPED) {
      np->pages[i].state = UNMAPPED;  // Child must reload
    }
  }
  
  // Child gets its own swap file if it needs to swap
  // Don't copy parent's swap file

  // copy saved user registers.
  *(np->trapframe) = *(p->trapframe);

  // Cause fork to return 0 in the child.
  np->trapframe->a0 = 0;

  // increment reference counts on open file descriptors.
  for(i = 0; i < NOFILE; i++)
    if(p->ofile[i])
      np->ofile[i] = filedup(p->ofile[i]);
  np->cwd = idup(p->cwd);

  safestrcpy(np->name, p->name, sizeof(p->name));

  pid = np->pid;

  release(&np->lock);

  acquire(&wait_lock);
  np->parent = p;
  release(&wait_lock);

  acquire(&np->lock);
  np->state = RUNNABLE;
  release(&np->lock);

  return pid;
}

// Pass p's abandoned children to init.
// Caller must hold wait_lock.
void
reparent(struct proc *p)
{
  struct proc *pp;

  for(pp = proc; pp < &proc[NPROC]; pp++){
    if(pp->parent == p){
      pp->parent = initproc;
      wakeup(initproc);
    }
  }
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait().
void
kexit(int status)
{
  struct proc *p = myproc();

  if(p == initproc)
    panic("init exiting");

  // Close all open files.
  for(int fd = 0; fd < NOFILE; fd++){
    if(p->ofile[fd]){
      struct file *f = p->ofile[fd];
      fileclose(f);
      p->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(p->cwd);
  end_op();
  p->cwd = 0;
  
  // Clean up swap file before acquiring locks
  if(p->swap_file) {
    int freed_slots = p->swap_slots_used;
    printf("[pid %d] SWAPCLEANUP freed_slots=%d\n", p->pid, freed_slots);
    
    // Close swap file
    fileclose(p->swap_file);
    p->swap_file = 0;
    
    // Delete the swap file from filesystem
    char swapname[16];
    char name[DIRSIZ];
    swapname[0] = '/';
    swapname[1] = 'p';
    swapname[2] = 'g';
    swapname[3] = 's';
    swapname[4] = 'w';
    swapname[5] = 'p';
    int pid = p->pid;
    for(int i = 10; i >= 6; i--) {
      swapname[i] = '0' + (pid % 10);
      pid /= 10;
    }
    swapname[11] = 0;
    
    begin_op();
    struct inode *dp = nameiparent(swapname, name);
    if(dp != 0) {
      ilock(dp);
      struct inode *ip = dirlookup(dp, name, 0);
      if(ip != 0) {
        ilock(ip);
        ip->nlink--;
        iupdate(ip);
        iunlockput(ip);
      }
      iunlockput(dp);
    }
    end_op();
  }
  
  // Release exec inode if held
  if(p->exec_inode) {
    begin_op();
    iput(p->exec_inode);
    end_op();
    p->exec_inode = 0;
  }

  acquire(&wait_lock);

  // Give any children to init.
  reparent(p);

  // Parent might be sleeping in wait().
  wakeup(p->parent);
  
  acquire(&p->lock);

  p->xstate = status;
  p->state = ZOMBIE;

  release(&wait_lock);

  // Jump into the scheduler, never to return.
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
kwait(uint64 addr)
{
  struct proc *pp;
  int havekids, pid;
  struct proc *p = myproc();

  acquire(&wait_lock);

  for(;;){
    // Scan through table looking for exited children.
    havekids = 0;
    for(pp = proc; pp < &proc[NPROC]; pp++){
      if(pp->parent == p){
        // make sure the child isn't still in exit() or swtch().
        acquire(&pp->lock);

        havekids = 1;
        if(pp->state == ZOMBIE){
          // Found one.
          pid = pp->pid;
          if(addr != 0 && copyout(p->pagetable, addr, (char *)&pp->xstate,
                                  sizeof(pp->xstate)) < 0) {
            release(&pp->lock);
            release(&wait_lock);
            return -1;
          }
          freeproc(pp);
          release(&pp->lock);
          release(&wait_lock);
          return pid;
        }
        release(&pp->lock);
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || killed(p)){
      release(&wait_lock);
      return -1;
    }
    
    // Wait for a child to exit.
    sleep(p, &wait_lock);  //DOC: wait-sleep
  }
}

// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run.
//  - swtch to start running that process.
//  - eventually that process transfers control
//    via swtch back to the scheduler.
void
scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();

  c->proc = 0;
  for(;;){
    // The most recent process to run may have had interrupts
    // turned off; enable them to avoid a deadlock if all
    // processes are waiting. Then turn them back off
    // to avoid a possible race between an interrupt
    // and wfi.
    intr_on();
    intr_off();

    int found = 0;
    for(p = proc; p < &proc[NPROC]; p++) {
      acquire(&p->lock);
      if(p->state == RUNNABLE) {
        // Switch to chosen process.  It is the process's job
        // to release its lock and then reacquire it
        // before jumping back to us.
        p->state = RUNNING;
        c->proc = p;
        swtch(&c->context, &p->context);

        // Process is done running for now.
        // It should have changed its p->state before coming back.
        c->proc = 0;
        found = 1;
      }
      release(&p->lock);
    }
    if(found == 0) {
      // nothing to run; stop running on this core until an interrupt.
      asm volatile("wfi");
    }
  }
}

// Switch to scheduler.  Must hold only p->lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->noff, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void)
{
  int intena;
  struct proc *p = myproc();

  if(!holding(&p->lock))
    panic("sched p->lock");
  if(mycpu()->noff != 1)
    panic("sched locks");
  if(p->state == RUNNING)
    panic("sched RUNNING");
  if(intr_get())
    panic("sched interruptible");

  intena = mycpu()->intena;
  swtch(&p->context, &mycpu()->context);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void
yield(void)
{
  struct proc *p = myproc();
  acquire(&p->lock);
  p->state = RUNNABLE;
  sched();
  release(&p->lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch to forkret.
void
forkret(void)
{
  extern char userret[];
  static int first = 1;
  struct proc *p = myproc();

  // Still holding p->lock from scheduler.
  release(&p->lock);

  if (first) {
    // File system initialization must be run in the context of a
    // regular process (e.g., because it calls sleep), and thus cannot
    // be run from main().
    fsinit(ROOTDEV);

    first = 0;
    // ensure other cores see first=0.
    __sync_synchronize();

    // We can invoke kexec() now that file system is initialized.
    // Put the return value (argc) of kexec into a0.
    p->trapframe->a0 = kexec("/init", (char *[]){ "/init", 0 });
    if (p->trapframe->a0 == -1) {
      panic("exec");
    }
  }

  // return to user space, mimicing usertrap()'s return.
  prepare_return();
  uint64 satp = MAKE_SATP(p->pagetable);
  uint64 trampoline_userret = TRAMPOLINE + (userret - trampoline);
  ((void (*)(uint64))trampoline_userret)(satp);
}

// Sleep on channel chan, releasing condition lock lk.
// Re-acquires lk when awakened.
void
sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();
  
  // Must acquire p->lock in order to
  // change p->state and then call sched.
  // Once we hold p->lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup locks p->lock),
  // so it's okay to release lk.

  acquire(&p->lock);  //DOC: sleeplock1
  release(lk);

  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  release(&p->lock);
  acquire(lk);
}

// Wake up all processes sleeping on channel chan.
// Caller should hold the condition lock.
void
wakeup(void *chan)
{
  struct proc *p;

  for(p = proc; p < &proc[NPROC]; p++) {
    if(p != myproc()){
      acquire(&p->lock);
      if(p->state == SLEEPING && p->chan == chan) {
        p->state = RUNNABLE;
      }
      release(&p->lock);
    }
  }
}

// Kill the process with the given pid.
// The victim won't exit until it tries to return
// to user space (see usertrap() in trap.c).
int
kkill(int pid)
{
  struct proc *p;

  for(p = proc; p < &proc[NPROC]; p++){
    acquire(&p->lock);
    if(p->pid == pid){
      p->killed = 1;
      if(p->state == SLEEPING){
        // Wake process from sleep().
        p->state = RUNNABLE;
      }
      release(&p->lock);
      return 0;
    }
    release(&p->lock);
  }
  return -1;
}

void
setkilled(struct proc *p)
{
  acquire(&p->lock);
  p->killed = 1;
  release(&p->lock);
}

int
killed(struct proc *p)
{
  int k;
  
  acquire(&p->lock);
  k = p->killed;
  release(&p->lock);
  return k;
}

// Copy to either a user address, or kernel address,
// depending on usr_dst.
// Returns 0 on success, -1 on error.
int
either_copyout(int user_dst, uint64 dst, void *src, uint64 len)
{
  struct proc *p = myproc();
  if(user_dst){
    return copyout(p->pagetable, dst, src, len);
  } else {
    memmove((char *)dst, src, len);
    return 0;
  }
}

// Copy from either a user address, or kernel address,
// depending on usr_src.
// Returns 0 on success, -1 on error.
int
either_copyin(void *dst, int user_src, uint64 src, uint64 len)
{
  struct proc *p = myproc();
  if(user_src){
    return copyin(p->pagetable, dst, src, len);
  } else {
    memmove(dst, (char*)src, len);
    return 0;
  }
}

// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [USED]      "used",
  [SLEEPING]  "sleep ",
  [RUNNABLE]  "runble",
  [RUNNING]   "run   ",
  [ZOMBIE]    "zombie"
  };
  struct proc *p;
  char *state;

  printf("\n");
  for(p = proc; p < &proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    printf("%d %s %s", p->pid, state, p->name);
    printf("\n");
  }
}

// Find page info for a given virtual address
struct page_info*
find_page_info(struct proc *p, uint64 va)
{
  va = PGROUNDDOWN(va);
  for(int i = 0; i < p->num_pages; i++) {
    if(p->pages[i].va == va) {
      return &p->pages[i];
    }
  }
  return 0;
}

// Add a new page info entry
struct page_info*
add_page_info(struct proc *p, uint64 va)
{
  if(p->num_pages >= MAX_PAGES) {
    return 0;
  }
  va = PGROUNDDOWN(va);
  
  // Check if already exists
  struct page_info *pi = find_page_info(p, va);
  if(pi) {
    return pi;
  }
  
  // Add new entry
  p->pages[p->num_pages].va = va;
  p->pages[p->num_pages].state = UNMAPPED;
  p->pages[p->num_pages].is_dirty = 0;
  p->pages[p->num_pages].seq = 0;
  p->pages[p->num_pages].swap_slot = -1;
  return &p->pages[p->num_pages++];
}

// Allocate a swap slot
int
alloc_swap_slot(struct proc *p)
{
  for(int i = 0; i < MAX_SWAP_SLOTS; i++) {
    int word = i / 64;
    int bit = i % 64;
    if((p->swap_bitmap[word] & (1UL << bit)) == 0) {
      p->swap_bitmap[word] |= (1UL << bit);
      p->swap_slots_used++;
      return i;
    }
  }
  return -1;
}

// Free a swap slot
void
free_swap_slot(struct proc *p, int slot)
{
  if(slot < 0 || slot >= MAX_SWAP_SLOTS) {
    return;
  }
  int word = slot / 64;
  int bit = slot % 64;
  if(p->swap_bitmap[word] & (1UL << bit)) {
    p->swap_bitmap[word] &= ~(1UL << bit);
    p->swap_slots_used--;
  }
}

// Create swap file for process
int
create_swap_file(struct proc *p)
{
  if(p->swap_file) {
    return 0; // Already created
  }
  
  char swapname[16];
  swapname[0] = '/';
  swapname[1] = 'p';
  swapname[2] = 'g';
  swapname[3] = 's';
  swapname[4] = 'w';
  swapname[5] = 'p';
  int pid = p->pid;
  for(int i = 10; i >= 6; i--) {
    swapname[i] = '0' + (pid % 10);
    pid /= 10;
  }
  swapname[11] = 0;
  
  begin_op();
  struct inode *ip = create(swapname, T_FILE, 0, 0);
  if(ip == 0) {
    end_op();
    return -1;
  }
  
  p->swap_file = filealloc();
  if(p->swap_file == 0) {
    iunlockput(ip);
    end_op();
    return -1;
  }
  
  p->swap_file->type = FD_INODE;
  p->swap_file->off = 0;
  p->swap_file->ip = ip;
  p->swap_file->readable = 1;
  p->swap_file->writable = 1;
  iunlock(ip);
  end_op();
  
  return 0;
}

// Swap out a page to disk
int
swap_out_page(struct proc *p, uint64 va, int slot)
{
  if(!p->swap_file) {
    if(create_swap_file(p) < 0) {
      return -1;
    }
  }
  
  // Get physical address
  pte_t *pte = walk(p->pagetable, va, 0);
  if(pte == 0 || (*pte & PTE_V) == 0) {
    return -1;
  }
  
  uint64 pa = PTE2PA(*pte);
  
  // Write page to swap file
  begin_op();
  ilock(p->swap_file->ip);
  if(writei(p->swap_file->ip, 0, pa, slot * PGSIZE, PGSIZE) != PGSIZE) {
    iunlock(p->swap_file->ip);
    end_op();
    return -1;
  }
  iunlock(p->swap_file->ip);
  end_op();
  
  return 0;
}

// Swap in a page from disk
int
swap_in_page(struct proc *p, uint64 va, int slot)
{
  if(!p->swap_file) {
    return -1;
  }
  
  // Allocate physical page
  char *mem = kalloc();
  if(mem == 0) {
    return -1;
  }
  
  // Read page from swap file
  begin_op();
  ilock(p->swap_file->ip);
  if(readi(p->swap_file->ip, 0, (uint64)mem, slot * PGSIZE, PGSIZE) != PGSIZE) {
    iunlock(p->swap_file->ip);
    end_op();
    kfree(mem);
    return -1;
  }
  iunlock(p->swap_file->ip);
  end_op();
  
  // Map the page
  if(mappages(p->pagetable, va, PGSIZE, (uint64)mem, PTE_U | PTE_R | PTE_W) < 0) {
    kfree(mem);
    return -1;
  }
  
  return 0;
}

// Handle page fault - main entry point
// Parameters:
//   va: virtual address that caused the fault
//   access_type: 0=read, 1=write, 2=exec
//   from_user: 1 if from user trap, 0 if from copyin/copyout
int
handle_page_fault(uint64 va, int access_type, int from_user)
{
  struct proc *p = myproc();
  va = PGROUNDDOWN(va);
  
  // Determine access type string
  char *access_str = "read";
  if(access_type == 1) access_str = "write";
  else if(access_type == 2) access_str = "exec";
  
  // Quick validation first - reject addresses beyond MAXVA immediately
  // This prevents walk() from being called on invalid high addresses
  if(va >= MAXVA) {
    if(from_user) {
      printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=invalid\n", p->pid, va, access_str);
      printf("[pid %d] KILL invalid-access va=0x%lx access=%s\n", p->pid, va, access_str);
      setkilled(p);
    }
    return -1;
  }
  
  // First check if page is already mapped (for dirty bit tracking)
  pte_t *pte = walk(p->pagetable, va, 0);
  if(pte && (*pte & PTE_V)) {
    // Page exists but not user-accessible (e.g., guard page, kernel page)
    if((*pte & PTE_U) == 0) {
      if(from_user) {
        printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=invalid\n", p->pid, va, access_str);
        printf("[pid %d] KILL invalid-access va=0x%lx access=%s\n", p->pid, va, access_str);
        setkilled(p);
      }
      return -1;
    }
    
    // Page is already mapped - this might be a write to a read-only page for dirty tracking
    if(access_type == 1) { // write access
      // Check if this is a write to text segment - NOT ALLOWED
      if(va >= p->text_start && va < p->text_end) {
        // Write to text segment - kill process
        if(from_user) {
          printf("[pid %d] PAGEFAULT va=0x%lx access=write cause=exec\n", p->pid, va);
          printf("[pid %d] KILL invalid-access va=0x%lx access=write\n", p->pid, va);
          setkilled(p);
        }
        return -1;
      }
      
      struct page_info *pi = find_page_info(p, va);
      if(pi && pi->state == RESIDENT && !pi->is_dirty) {
        // First write to this page - mark it dirty
        *pte |= PTE_W;  // Add write permission
        pi->is_dirty = 1;
        return 0;
      }
    }
  }
  
  // Check if address is valid
  int valid = 0;
  char *cause = "invalid";
  int is_text = 0;  // Track if this is text segment for write protection
  
  // Calculate guard page boundaries
  uint64 stack_base = p->stack_top - USERSTACK * PGSIZE;
  uint64 guard_base = stack_base - PGSIZE;
  
  // Reject access to guard page explicitly
  if(va >= guard_base && va < stack_base) {
    // This is the guard page - always invalid
    valid = 0;
    cause = "invalid";
  }
  // Check text segment
  else if(va >= p->text_start && va < p->text_end) {
    valid = 1;
    cause = "exec";
    is_text = 1;
  }
  // Check data segment
  else if(va >= p->data_start && va < p->data_end) {
    valid = 1;
    cause = "exec";
  }
  // Check heap
  else if(va >= p->heap_start && va < p->sz) {
    valid = 1;
    cause = "heap";
  }
  // Check stack (within one page below current stack pointer, but not guard page)
  // Stack grows downward, so valid range is [sp - PGSIZE, stack_top)
  else if(va >= p->trapframe->sp - PGSIZE && va < p->stack_top) {
    valid = 1;
    cause = "stack";
  }
  
  // Check if page was swapped
  struct page_info *pi = find_page_info(p, va);
  if(pi && pi->state == SWAPPED) {
    valid = 1;
    cause = "swap";
  }
  
  // Only log and kill if from user trap, not from copyin/copyout
  if(from_user) {
    // Log page fault
    printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=%s\n", p->pid, va, access_str, cause);
    
    if(!valid) {
      // Invalid access - kill process
      printf("[pid %d] KILL invalid-access va=0x%lx access=%s\n", p->pid, va, access_str);
      setkilled(p);
      return -1;
    }
    
    // Check for write to text segment - NOT ALLOWED
    if(is_text && access_type == 1) {
      printf("[pid %d] KILL invalid-access va=0x%lx access=write\n", p->pid, va);
      setkilled(p);
      return -1;
    }
  } else {
    // From copyin/copyout - just fail silently for invalid addresses
    if(!valid) {
      return -1;
    }
    // Also fail for writes to text segment
    if(is_text && access_type == 1) {
      return -1;
    }
  }
  
  // Add page info if not exists
  if(!pi) {
    pi = add_page_info(p, va);
    if(!pi) {
      printf("[pid %d] KILL out-of-memory\n", p->pid);
      setkilled(p);
      return -1;
    }
  }
  
  // Handle swapped page
  if(pi->state == SWAPPED) {
    // Try to allocate memory
    char *mem = kalloc();
    if(mem == 0) {
      // Need to evict a page
      if(evict_page_fifo(p) < 0) {
        printf("[pid %d] KILL swap-exhausted\n", p->pid);
        setkilled(p);
        return -1;
      }
      mem = kalloc();
      if(mem == 0) {
        printf("[pid %d] KILL out-of-memory\n", p->pid);
        setkilled(p);
        return -1;
      }
    }
    
    // Read from swap
    begin_op();
    ilock(p->swap_file->ip);
    if(readi(p->swap_file->ip, 0, (uint64)mem, pi->swap_slot * PGSIZE, PGSIZE) != PGSIZE) {
      iunlock(p->swap_file->ip);
      end_op();
      kfree(mem);
      printf("[pid %d] KILL swap-read-error\n", p->pid);
      setkilled(p);
      return -1;
    }
    iunlock(p->swap_file->ip);
    end_op();
    
    printf("[pid %d] SWAPIN va=0x%lx slot=%d\n", p->pid, va, pi->swap_slot);
    
    // Free swap slot
    free_swap_slot(p, pi->swap_slot);
    pi->swap_slot = -1;
    
    // Map the page (without W to track first write)
    if(mappages(p->pagetable, va, PGSIZE, (uint64)mem, PTE_U | PTE_R) < 0) {
      kfree(mem);
      printf("[pid %d] KILL mapping-error\n", p->pid);
      setkilled(p);
      return -1;
    }
    
    pi->state = RESIDENT;
    pi->seq = p->next_fifo_seq++;
    pi->is_dirty = 0;
    printf("[pid %d] RESIDENT va=0x%lx seq=%d\n", p->pid, va, pi->seq);
    
    return 0;
  }
  
  // Handle text/data from executable
  if(va >= p->text_start && va < p->data_end) {
    // Try to allocate memory
    char *mem = kalloc();
    if(mem == 0) {
      // Need to evict a page
      if(evict_page_fifo(p) < 0) {
        printf("[pid %d] KILL swap-exhausted\n", p->pid);
        setkilled(p);
        return -1;
      }
      mem = kalloc();
      if(mem == 0) {
        printf("[pid %d] KILL out-of-memory\n", p->pid);
        setkilled(p);
        return -1;
      }
    }
    
    // Load from executable using segment info
    memset(mem, 0, PGSIZE);
    if(p->exec_inode) {
      // Find which segment this VA belongs to
      for(int i = 0; i < p->num_segments; i++) {
        if(va >= p->segments[i].va_start && va < p->segments[i].va_end) {
          // Calculate offset in file for this page
          uint64 seg_offset = va - p->segments[i].va_start;
          uint64 file_offset = p->segments[i].file_off + seg_offset;
          
          // Calculate how much to read (don't read beyond filesz)
          uint64 read_size = PGSIZE;
          if(seg_offset >= p->segments[i].filesz) {
            // Beyond file data, just zero (BSS section)
            read_size = 0;
          } else if(seg_offset + PGSIZE > p->segments[i].filesz) {
            // Partial page
            read_size = p->segments[i].filesz - seg_offset;
          }
          
          if(read_size > 0) {
            begin_op();
            ilock(p->exec_inode);
            readi(p->exec_inode, 0, (uint64)mem, file_offset, read_size);
            iunlock(p->exec_inode);
            end_op();
          }
          break;
        }
      }
    }
    
    printf("[pid %d] LOADEXEC va=0x%lx\n", p->pid, va);
    
    // Determine permissions from segment flags
    int perm = PTE_U | PTE_R;
    for(int i = 0; i < p->num_segments; i++) {
      if(va >= p->segments[i].va_start && va < p->segments[i].va_end) {
        if(p->segments[i].flags & 0x1) perm |= PTE_X;  // Executable
        if(p->segments[i].flags & 0x2) perm |= PTE_W;  // Writable
        break;
      }
    }
    
    if(mappages(p->pagetable, va, PGSIZE, (uint64)mem, perm) < 0) {
      kfree(mem);
      printf("[pid %d] KILL mapping-error\n", p->pid);
      setkilled(p);
      return -1;
    }
    
    pi->state = RESIDENT;
    pi->seq = p->next_fifo_seq++;
    pi->is_dirty = 0;
    printf("[pid %d] RESIDENT va=0x%lx seq=%d\n", p->pid, va, pi->seq);
    
    return 0;
  }
  
  // Handle heap/stack - allocate zero-filled page
  char *mem = kalloc();
  if(mem == 0) {
    // Need to evict a page
    if(evict_page_fifo(p) < 0) {
      printf("[pid %d] KILL swap-exhausted\n", p->pid);
      setkilled(p);
      return -1;
    }
    mem = kalloc();
    if(mem == 0) {
      printf("[pid %d] KILL out-of-memory\n", p->pid);
      setkilled(p);
      return -1;
    }
  }
  
  memset(mem, 0, PGSIZE);
  printf("[pid %d] ALLOC va=0x%lx\n", p->pid, va);
  
  // Map the page (without W to track first write)
  if(mappages(p->pagetable, va, PGSIZE, (uint64)mem, PTE_U | PTE_R) < 0) {
    kfree(mem);
    printf("[pid %d] KILL mapping-error\n", p->pid);
    setkilled(p);
    return -1;
  }
  
  pi->state = RESIDENT;
  pi->seq = p->next_fifo_seq++;
  pi->is_dirty = 0;
  printf("[pid %d] RESIDENT va=0x%lx seq=%d\n", p->pid, va, pi->seq);
  
  return 0;
}

// Evict a page using FIFO
int
evict_page_fifo(struct proc *p)
{
  printf("[pid %d] MEMFULL\n", p->pid);
  
  // Find oldest resident page (lowest seq number)
  int victim_idx = -1;
  int min_seq = __INT_MAX__;
  
  for(int i = 0; i < p->num_pages; i++) {
    if(p->pages[i].state == RESIDENT && p->pages[i].seq < min_seq) {
      min_seq = p->pages[i].seq;
      victim_idx = i;
    }
  }
  
  if(victim_idx < 0) {
    // No resident pages to evict
    return -1;
  }
  
  struct page_info *victim = &p->pages[victim_idx];
  uint64 va = victim->va;
  
  printf("[pid %d] VICTIM va=0x%lx seq=%d algo=FIFO\n", p->pid, va, victim->seq);
  
  // Get the PTE
  pte_t *pte = walk(p->pagetable, va, 0);
  if(pte == 0 || (*pte & PTE_V) == 0) {
    return -1;
  }
  
  // Check if dirty
  int is_dirty = victim->is_dirty;
  
  if(is_dirty) {
    printf("[pid %d] EVICT va=0x%lx state=dirty\n", p->pid, va);
    
    // Need to swap out
    int slot = alloc_swap_slot(p);
    if(slot < 0) {
      printf("[pid %d] SWAPFULL\n", p->pid);
      return -1;
    }
    
    // Create swap file if needed
    if(!p->swap_file) {
      if(create_swap_file(p) < 0) {
        free_swap_slot(p, slot);
        return -1;
      }
    }
    
    // Write to swap
    if(swap_out_page(p, va, slot) < 0) {
      free_swap_slot(p, slot);
      return -1;
    }
    
    printf("[pid %d] SWAPOUT va=0x%lx slot=%d\n", p->pid, va, slot);
    
    victim->state = SWAPPED;
    victim->swap_slot = slot;
  } else {
    printf("[pid %d] EVICT va=0x%lx state=clean\n", p->pid, va);
    printf("[pid %d] DISCARD va=0x%lx\n", p->pid, va);
    
    victim->state = UNMAPPED;
  }
  
  // Unmap and free the physical page
  uvmunmap(p->pagetable, va, 1, 1);
  
  return 0;
}
