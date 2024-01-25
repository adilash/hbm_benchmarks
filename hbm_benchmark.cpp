#include <numa.h>
#include <numaif.h>
#include <sys/mman.h>
#include <utmpx.h>

#include <chrono>
#include <unistd.h>
#include <iostream>
#include "linux/mman.h"
#include <mutex>
#include <vector>
#include <thread>
#include <future>

#define SLAB_SZ_2MB (1024 * 2 * 1024)
#define SLAB_SZ_1GB (1024 * 1024 * 1024)

int k = 0;
uint64_t c;

class Logger {
  std::mutex mut;

public:
  template <typename... Args>
  void log(const std::string &format, Args... args) {
// #ifdef DEBUG
    std::lock_guard<std::mutex> lk(mut);
    std::printf(format.c_str(), args...);
    std::cout << std::endl;
// #endif
  }
};


Logger logger;

void accessSequentiall(char *ptr, uint64_t len) {
  //std::cout<<len/8<<std::endl;
  uint64_t p;
  for (uint64_t i = 0; i < len/8; i++)
  {
    p += (((uint64_t *)ptr)[i] == 4829423918012392647llu)?1:0;
  }

  c = p;
  
}

void task(int core, void *ptr, uint64_t len) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  pthread_t pthread = pthread_self();
  CPU_SET(core, &cpuset);  
  // if(0 == pthread_setaffinity_np(pthread, sizeof(cpu_set_t), &cpuset))
  // std::cout<<"pinned to" << core<<std::endl;
  auto start = std::chrono::high_resolution_clock::now();
  accessSequentiall((char *)ptr, len);
  return;
}

int main(int argc, char **argv) {
  srand(time(NULL));
  std::cout<<std::fixed;
  numa_set_bind_policy(1);
  double result=0;
  for (size_t k = 0; k < 5; k++) {
  
  void *ptr =
      mmap(nullptr, SLAB_SZ_1GB *6llu, PROT_WRITE | PROT_READ | PROT_EXEC,
           MAP_ANONYMOUS | MAP_PRIVATE |MAP_HUGETLB | MAP_HUGE_2MB,  -1, 0);
  if(ptr==MAP_FAILED)
  {
    std::cout<<"map failed";
    return -1;
  }
    // auto map_time_end = std::chrono::high_resolution_clock::now();
  
  numa_tonode_memory(ptr, SLAB_SZ_1GB*6llu, atoi(argv[1]));

  // std::cout<<ptr<<" "<<(char *)ptr + (SLAB_SZ_1GB *6llu);
  int nm;
  

  // *((char *)ptr)='a';
  // auto access_time = std::chrono::high_resolution_clock::now();
  // memset(ptr, 'a', SLAB_SZ_1GB * 6llu);
  for (uint64_t i = 0; i < (SLAB_SZ_1GB*6llu)/8; i++)
  {
    ((uint64_t *)ptr)[i]=rand();
  }
  // auto access_time_end = std::chrono::high_resolution_clock::now();

  // std::cout<<" first access time:"<<
  //   std::chrono::duration_cast<std::chrono::microseconds>(access_time_end-access_time).count()<<"\n";

  // std::cout<<" maptime:"<<
    // std::chrono::duration_cast<std::chrono::microseconds>(map_time_end-map_time).count()<<"\n";

  get_mempolicy(&nm, NULL, 0, (void *)ptr, MPOL_F_NODE | MPOL_F_ADDR);
  std::cout <<"pid: "<<getpid()<< " memory moved to:" << nm << std::endl;

  // std::vector<std::thread> threads;
  std::vector<std::thread> threads;
  // std::vector<std::future<double>> futures;
  Logger logger;
  int numa_node = atoi(argv[2]);
   auto start = std::chrono::high_resolution_clock::now();
   uint64_t no_of_cores = atoi(argv[3]);
   uint64_t per_core_size = (SLAB_SZ_1GB*6llu)/no_of_cores;
   for (int i = 0; i < no_of_cores; i++) {
    threads.emplace_back(task,(numa_node*8)+i, ((char *)ptr)+(per_core_size*i), per_core_size);
    }

    for (size_t i = 0; i < no_of_cores; i++)
    {
      threads[i].join();
    }
    auto end = std::chrono::high_resolution_clock::now();
    long double bandwidth=(long double) 64;
    bandwidth *= (6llu*SLAB_SZ_1GB/8);
    bandwidth *= 1000000;
    bandwidth /= 1048576;
    bandwidth /= (long double)  std::chrono::duration_cast<std::chrono::microseconds>(
        end - start).count(); 
    result += bandwidth;
    std::cout<<"fork join GBps: "<<bandwidth/1024<<std::endl;
    munmap(ptr, SLAB_SZ_1GB*6llu);
    }
    std::cout<<"\nAverage bandwidth across 5 runs GBps: "<<result/(5*1024)<<std::endl;
}
