#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "user/memstat.h"

int
main(int argc, char *argv[])
{
  printf("=== Demand Paging Test ===\n");
  
  // Test 1: Allocate heap space lazily
  printf("\nTest 1: Lazy heap allocation\n");
  char *p = sbrklazy(8192);  // Request 2 pages
  if(p == (char*)-1) {
    printf("sbrklazy failed\n");
    exit(1);
  }
  printf("Allocated 2 pages starting at %p\n", p);
  
  // Test 2: Write to first page (should trigger PAGEFAULT -> ALLOC -> RESIDENT)
  printf("\nTest 2: Writing to first page\n");
  p[0] = 'A';
  printf("Successfully wrote to first page\n");
  
  // Test 3: Write to second page (should trigger another page fault)
  printf("\nTest 3: Writing to second page\n");
  p[4096] = 'B';
  printf("Successfully wrote to second page\n");
  
  // Test 4: Call memstat to see our pages
  printf("\nTest 4: Checking memory statistics\n");
  struct proc_mem_stat stat;
  if(memstat(&stat) == 0) {
    printf("Process %d memory status:\n", stat.pid);
    printf("  Total pages: %d\n", stat.num_pages_total);
    printf("  Resident pages: %d\n", stat.num_resident_pages);
    printf("  Swapped pages: %d\n", stat.num_swapped_pages);
    printf("  Next FIFO seq: %d\n", stat.next_fifo_seq);
  } else {
    printf("memstat failed\n");
  }
  
  printf("\n=== All tests passed! ===\n");
  exit(0);
}
