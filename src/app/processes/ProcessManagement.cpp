#include "ProcessManagement.hpp"
#include "../encryptDecrypt/Cryption.hpp"
#include <atomic>
#include <cstring>
#include <semaphore.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <thread>

ProcessManagement::ProcessManagement() {

  itemsSemaphore = sem_open("/items_semaphore", O_CREAT, 0666, 0);

  if (itemsSemaphore == SEM_FAILED) {
    perror("sem_open itemsSemaphore");
    exit(EXIT_FAILURE);
  }

  emptySlotsSemaphore = sem_open("/empty_slots_semaphore", O_CREAT, 0666, 1000);

  if (emptySlotsSemaphore == SEM_FAILED) {
    perror("sem_open emptySlotsSemaphore");
    exit(EXIT_FAILURE);
  }

  shmFd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);

  if (shmFd < 0) {
    perror("shm_open");
    exit(EXIT_FAILURE);
  }

  if (ftruncate(shmFd, sizeof(SharedMemory)) == -1) {
    perror("ftruncate");
    exit(EXIT_FAILURE);
  }

  // mmap is used to map the shared memory object into the calling process's
  sharedMem = static_cast<SharedMemory *>(mmap(nullptr, sizeof(SharedMemory),
                                               PROT_READ | PROT_WRITE,
                                               MAP_SHARED, shmFd, 0));

  if (sharedMem == MAP_FAILED) {
    perror("mmap");
    exit(EXIT_FAILURE);
  }

  // Initialize shared memory

  sharedMem->front.store(0);
  sharedMem->rear.store(0);
  sharedMem->size.store(0);
}

ProcessManagement::~ProcessManagement() {
  munmap(sharedMem, sizeof(SharedMemory));
  shm_unlink(SHM_NAME);
  sem_close(itemsSemaphore);
  sem_close(emptySlotsSemaphore);
  sem_unlink("/items_semaphore");
  sem_unlink("/empty_slots_semaphore");
}

bool ProcessManagement::submitToQueue(std::unique_ptr<Task> task) {
  sem_wait(emptySlotsSemaphore);
  std::unique_lock<std::mutex> lock(queueLock);

  if (sharedMem->size.load() >= 1000) {
    return false;
  }

  strcpy(sharedMem->tasks[sharedMem->rear], task->toString().c_str());
  sharedMem->rear.store((sharedMem->rear + 1) % 1000);
  sharedMem->size.fetch_add(1);

  lock.unlock();
  sem_post(itemsSemaphore);

  std::thread thread_1(&ProcessManagement::executeTask, this);
  thread_1.detach();

  return true;
}

void ProcessManagement::executeTask() {
  sem_wait(itemsSemaphore);
  std::unique_lock<std::mutex> lock(queueLock);
  char taskStr[256];

  if (sharedMem->size.load() == 0) {
    lock.unlock();
    sem_post(emptySlotsSemaphore);
    return; // No tasks to execute
  }

  strcpy(taskStr, sharedMem->tasks[sharedMem->front]);
  sharedMem->front.store((sharedMem->front + 1) % 1000);
  sharedMem->size.fetch_sub(1);

  lock.unlock();
  sem_post(emptySlotsSemaphore);

  executeCryption(taskStr);
}
