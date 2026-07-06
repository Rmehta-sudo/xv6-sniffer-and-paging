#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/memstat.h"

int
main(int argc, char *argv[])
{
  printf("Fork with page tracking test\n");
  
  // Allocate some memory
  char *p = sbrklazy(8192);
  if(p == (char*)-1){
    printf("sbrk failed\n");
    exit(1);
  }
  
  // Write to first page
  p[0] = 'A';
  p[100] = 'B';
  
  // Don't write to second page (keep it clean)
  
  printf("Parent allocated and wrote to first page\n");
  
  // Get parent memory stats
  struct proc_mem_stat stat;
  if(memstat(&stat) < 0){
    printf("memstat failed\n");
    exit(1);
  }
  
  printf("Parent - pages: %d, resident: %d\n", 
         stat.num_pages_total, stat.num_resident_pages);
  
  int pid = fork();
  if(pid < 0){
    printf("fork failed\n");
    exit(1);
  }
  
  if(pid == 0){
    // Child
    printf("Child started\n");
    
    // Verify we can read parent's data
    if(p[0] == 'A' && p[100] == 'B'){
      printf("Child verified parent data: %c %c\n", p[0], p[100]);
    } else {
      printf("Child data mismatch!\n");
    }
    
    // Write to child's page
    p[200] = 'C';
    
    // Get child memory stats
    if(memstat(&stat) < 0){
      printf("memstat failed\n");
      exit(1);
    }
    
    printf("Child - pages: %d, resident: %d\n", 
           stat.num_pages_total, stat.num_resident_pages);
    
    exit(0);
  } else {
    // Parent
    wait(0);
    printf("Parent: child completed\n");
    
    // Verify parent's data is unchanged
    if(p[0] == 'A' && p[100] == 'B'){
      printf("Parent data still valid: %c %c\n", p[0], p[100]);
    } else {
      printf("Parent data corrupted!\n");
    }
  }
  
  printf("Fork test completed\n");
  exit(0);
}
