#ifndef __CONFIG_H
#define __CONFIG_H

#include <stdbool.h>

#define LOG_FILE_MAX 1000000 // Max lines in logfile
#define LOG_FILE "logfile.log" // Logfile
#define LOG_VERBOSE false // Verbose mode for logging
#define SHM_FILE "shmOSS.shm" // File to use for shared memory tokens
#define MAX_PROCESSES 18 // Max child processes to run concurrently regardless of user input
#define MSG_BUFFER_LEN 2048 // Max buffer size for message queues
#define MAX_ERR_BUFF 1024 // Max buffer length for error messages
#define MAX_RUNTIME 300 // 5m
#define MAX_RUN_PROCS 40 // Max num of processes to run ever
#define MAX_PROC_MEM 32 // Any process will only use 32KB of memory
#define MAX_MAIN_MEM 256 // Max system memory is 256KB
#define MIN_TIME_LAUNCH 1000000 // Minium time between child spawn in nanoseconds (1 ms)
#define MAX_TIME_LAUNCH 500000000 // Maximum time between child spawn in nanoseconds ( 500ms )
#define PERCENT_WRITES 30 // 30% writes 70% reads
#define PERCENT_SEGFAULT 5 // 5% segfault chance

#endif
