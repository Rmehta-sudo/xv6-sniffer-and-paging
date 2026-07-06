#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/memstat.h"

void
print_memstat(const char *label)
{
  struct proc_mem_stat stat;
  if(memstat(&stat) < 0){
    printf("memstat failed\n");
    return;
  }
  
  printf("%s: pid=%d pages=%d resident=%d swapped=%d\n",
         label, stat.pid, stat.num_pages_total, 
         stat.num_resident_pages, stat.num_swapped_pages);
}

int
main(int argc, char *argv[])
{
  printf("Fork test with demand paging\n");
  
  // Allocate some memory
  char *p = sbrklazy(8192);
  if(p == (char*)-1){
    printf("sbrk failed\n");
    exit(1);
  }
  
  printf("Parent allocated 2 pages\n");
  
  // Write to first page
  p[0] = 'P';
  p[100] = 'A';
  printf("Parent wrote to first page\n");
  
  print_memstat("Parent before fork");
  
  int pid = fork();
  
  if(pid < 0){
    printf("fork failed\n");
    exit(1);
  }
  
  if(pid == 0){
    // Child
    printf("\nChild process started\n");
    print_memstat("Child after fork");
    
    // Read parent's data
    printf("Child reading parent's data: %c %c\n", p[0], p[100]);
    
    // Write to second page (should fault and allocate)
    p[4096] = 'C';
    printf("Child wrote to second page\n");
    
    print_memstat("Child after write");
    
    printf("Child exiting\n");
    exit(0);
  } else {
    // Parent
    printf("\nParent waiting for child\n");
    wait(0);
    
    print_memstat("Parent after child exit");
    
    // Verify parent's data unchanged
    printf("Parent's data: %c %c\n", p[0], p[100]);
    
    printf("Fork test completed\n");
    exit(0);
  }
}
