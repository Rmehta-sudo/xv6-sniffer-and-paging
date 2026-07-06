// Memory statistics structures for memstat() syscall

#ifndef _MEMSTAT_H_
#define _MEMSTAT_H_

#define MAX_PAGES_INFO 128 // Max pages to report per syscall

// Page states
#define UNMAPPED 0 
#define RESIDENT 1 
#define SWAPPED  2

struct page_stat {
  unsigned int va;          // Virtual address (page-aligned)
  int state;        // UNMAPPED, RESIDENT, or SWAPPED
  int is_dirty;     // 1 if page has been written to
  int seq;          // FIFO sequence number (if resident)
  int swap_slot;    // Swap slot number (if swapped)
};

struct proc_mem_stat {
  int pid;
  int num_pages_total;      // Total virtual pages
  int num_resident_pages;   // Pages currently in memory
  int num_swapped_pages;    // Pages currently swapped out
  int next_fifo_seq;        // Next sequence number to assign
  struct page_stat pages[MAX_PAGES_INFO];
};

#endif // _MEMSTAT_H_
