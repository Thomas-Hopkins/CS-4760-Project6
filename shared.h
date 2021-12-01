#ifndef __SHARED_H
#define __SHARED_H

#include <stdbool.h>
#include "config.h"

enum Shared_Mem_Tokens {OSS_SHM, OSS_MSG, PROC_MSG};

struct time_clock {
    unsigned long nanoseconds;
    unsigned long seconds;
};

struct message {
    long int msg_type;
    char msg_text[MSG_BUFFER_LEN];
};

struct mem_frame {
    unsigned int ref_bit: 8; // 8 reference bits for replacement algo
    unsigned int dirty_bit: 1; // bit marking dirty or not
    int owner_pid; // Owner simulated pid
};

struct process_ctrl_block {
    unsigned int sim_pid;
    pid_t actual_pid;
    int page_table[MAX_PROC_MEM]; // Array of indexes pointing to frames in main memory allocated to this process
};

struct oss_shm {
    struct time_clock sys_clock;
    struct process_ctrl_block process_table[MAX_PROCESSES];
    struct mem_frame main_memory[MAX_MAIN_MEM];
    bool allocated_frames[MAX_MAIN_MEM]; // 256 bit vector each bit representing a main memory frame if taken or not
};

void dest_oss();
void init_oss(bool create);
void add_time(struct time_clock* Time, unsigned long seconds, unsigned long nanoseconds);
void sub_time(struct time_clock* Time, unsigned long seconds, unsigned long nanoseconds);
void recieve_msg(struct message* msg, int msg_queue, bool wait);
void send_msg(struct message* msg, int msg_queue, bool wait);


#endif
