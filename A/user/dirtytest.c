#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/memstat.h"

int
main(int argc, char *argv[])
{
  printf("Dirty bit tracking test\n");
  
  // Allocate memory lazily
  char *p = sbrklazy(4096);
  if(p == (char*)-1){
    printf("sbrk failed\n");
    exit(1);
  }
  
  printf("Allocated page at %p\n", p);
  
  // Read from page (should allocate it but not mark dirty)
  char c = p[0];
  printf("Read value: %d\n", c);
  
  // Get memory stats
  struct proc_mem_stat stat;
  if(memstat(&stat) < 0){
    printf("memstat failed\n");
    exit(1);
  }
  
  printf("After read - pages: %d, resident: %d, dirty pages: ", 
         stat.num_pages_total, stat.num_resident_pages);
  int dirty_count = 0;
  for(int i = 0; i < stat.num_pages_total; i++){
    if(stat.pages[i].is_dirty) dirty_count++;
  }
  printf("%d\n", dirty_count);
  
  // Write to page (should mark dirty)
  p[100] = 42;
  printf("Wrote value 42\n");
  
  // Get memory stats again
  if(memstat(&stat) < 0){
    printf("memstat failed\n");
    exit(1);
  }
  
  printf("After write - pages: %d, resident: %d, dirty pages: ", 
         stat.num_pages_total, stat.num_resident_pages);
  dirty_count = 0;
  for(int i = 0; i < stat.num_pages_total; i++){
    if(stat.pages[i].is_dirty) dirty_count++;
  }
  printf("%d\n", dirty_count);
  
  printf("Dirty bit test completed\n");
  exit(0);
}
