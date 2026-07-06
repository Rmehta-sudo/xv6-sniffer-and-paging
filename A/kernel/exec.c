#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "elf.h"
#include "fcntl.h"
#include "memstat.h"

// map ELF permissions to PTE permission bits.
int flags2perm(int flags)
{
    int perm = 0;
    if(flags & 0x1)
      perm = PTE_X;
    if(flags & 0x2)
      perm |= PTE_W;
    return perm;
}

//
// the implementation of the exec() system call
//
int
kexec(char *path, char **argv)
{
  char *s, *last;
  int i, off;
  uint64 argc, sz = 0, sp, ustack[MAXARG], stackbase;
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  pagetable_t pagetable = 0, oldpagetable;
  struct proc *p = myproc();

  begin_op();

  // Open the executable file.
  if((ip = namei(path)) == 0){
    end_op();
    return -1;
  }
  ilock(ip);

  // Read the ELF header.
  if(readi(ip, 0, (uint64)&elf, 0, sizeof(elf)) != sizeof(elf))
    goto bad;

  // Is this really an ELF file?
  if(elf.magic != ELF_MAGIC)
    goto bad;

  if((pagetable = proc_pagetable(p)) == 0)
    goto bad;

  // Load program segments into memory
  uint64 text_start = 0, text_end = 0, data_start = 0, data_end = 0;
  int found_text = 0, found_data = 0;
  p->num_segments = 0;
  
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, 0, (uint64)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz)
      goto bad;
    if(ph.vaddr + ph.memsz < ph.vaddr)
      goto bad;
    if(ph.vaddr % PGSIZE != 0)
      goto bad;
    
    // Track text and data regions
    if((ph.flags & 0x1) && !(ph.flags & 0x2)) {
      // Executable, not writable = text
      if(!found_text) {
        text_start = ph.vaddr;
        found_text = 1;
      }
      text_end = ph.vaddr + ph.memsz;
    } else {
      // Writable or non-executable = data
      if(!found_data) {
        data_start = ph.vaddr;
        found_data = 1;
      }
      data_end = ph.vaddr + ph.memsz;
    }
    
    // LAZY LOADING: Don't allocate or load pages, just track segment info
    // Save segment information for on-demand loading
    if(p->num_segments < MAX_SEGMENTS) {
      p->segments[p->num_segments].va_start = ph.vaddr;
      p->segments[p->num_segments].va_end = ph.vaddr + ph.memsz;
      p->segments[p->num_segments].file_off = ph.off;
      p->segments[p->num_segments].filesz = ph.filesz;
      p->segments[p->num_segments].flags = ph.flags;
      p->num_segments++;
    }
    
    // Update size to include this segment
    if(ph.vaddr + ph.memsz > sz)
      sz = ph.vaddr + ph.memsz;
  }
  
  // Keep the inode reference for demand paging
  p->exec_inode = idup(ip);
  p->exec_offset = 0;
  
  iunlockput(ip);
  end_op();
  ip = 0;

  p = myproc();
  uint64 oldsz = p->sz;

  // Set up stack region (lazy allocation)
  sz = PGROUNDUP(sz);
  uint64 heap_start = sz;
  
  // Reserve space for stack but don't allocate
  sz = sz + (USERSTACK+1)*PGSIZE;
  sp = sz;
  stackbase = sp - USERSTACK*PGSIZE;
  
  // Allocate guard page (below the stack) to catch stack overflow
  char *guard_mem = kalloc();
  if(guard_mem == 0)
    goto bad;
  memset(guard_mem, 0, PGSIZE);
  
  uint64 guard_page = stackbase - PGSIZE;
  if(mappages(pagetable, guard_page, PGSIZE, (uint64)guard_mem, PTE_R | PTE_W) < 0) {
    kfree(guard_mem);
    goto bad;
  }
  // Clear PTE_U to make guard page inaccessible to user code
  uvmclear(pagetable, guard_page);
  
  // Allocate only the first stack page that we'll use immediately
  char *stack_mem = kalloc();
  if(stack_mem == 0)
    goto bad;
  memset(stack_mem, 0, PGSIZE);
  
  // Map the initial stack page
  uint64 initial_stack_page = PGROUNDDOWN(sp - PGSIZE);
  if(mappages(pagetable, initial_stack_page, PGSIZE, (uint64)stack_mem, PTE_U | PTE_R | PTE_W) < 0) {
    kfree(stack_mem);
    goto bad;
  }

  // Copy argument strings into new stack, remember their
  // addresses in ustack[].
  for(argc = 0; argv[argc]; argc++) {
    if(argc >= MAXARG)
      goto bad;
    sp -= strlen(argv[argc]) + 1;
    sp -= sp % 16; // riscv sp must be 16-byte aligned
    if(sp < stackbase)
      goto bad;
    if(copyout(pagetable, sp, argv[argc], strlen(argv[argc]) + 1) < 0)
      goto bad;
    ustack[argc] = sp;
  }
  ustack[argc] = 0;

  // push a copy of ustack[], the array of argv[] pointers.
  sp -= (argc+1) * sizeof(uint64);
  sp -= sp % 16;
  if(sp < stackbase)
    goto bad;
  if(copyout(pagetable, sp, (char *)ustack, (argc+1)*sizeof(uint64)) < 0)
    goto bad;

  // a0 and a1 contain arguments to user main(argc, argv)
  // argc is returned via the system call return
  // value, which goes in a0.
  p->trapframe->a1 = sp;

  // Save program name for debugging.
  for(last=s=path; *s; s++)
    if(*s == '/')
      last = s+1;
  safestrcpy(p->name, last, sizeof(p->name));
    
  // Commit to the user image.
  oldpagetable = p->pagetable;
  p->pagetable = pagetable;
  p->sz = sz;
  p->trapframe->epc = elf.entry;  // initial program counter = main
  p->trapframe->sp = sp; // initial stack pointer
  
  // Save memory layout for demand paging
  p->text_start = text_start;
  p->text_end = text_end;
  p->data_start = data_start;
  p->data_end = data_end;
  p->heap_start = heap_start;
  p->stack_top = sz;
  
  // Initialize page tracking
  p->num_pages = 0;
  p->next_fifo_seq = 1;
  
  // Don't create swap file yet - will be created on first swap-out
  // This avoids creating empty files that need cleanup
  
  // Log initialization
  printf("[pid %d] INIT-LAZYMAP text=[0x%lx,0x%lx) data=[0x%lx,0x%lx) heap_start=0x%lx stack_top=0x%lx\n",
         p->pid, text_start, text_end, data_start, data_end, heap_start, sz);
  
  // Add the initial stack page to tracking
  struct page_info *pi = add_page_info(p, initial_stack_page);
  if(pi) {
    pi->state = RESIDENT;
    pi->seq = p->next_fifo_seq++;
    pi->is_dirty = 0;
  }
  
  proc_freepagetable(oldpagetable, oldsz);

  return argc; // this ends up in a0, the first argument to main(argc, argv)

 bad:
  if(pagetable)
    proc_freepagetable(pagetable, sz);
  if(ip){
    iunlockput(ip);
    end_op();
  }
  return -1;
}

// loadseg function removed - using lazy loading instead
