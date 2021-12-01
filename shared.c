#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <unistd.h>

#include "shared.h"

struct oss_shm* shared_mem = NULL;
static int oss_msg_queue;
static int proc_msg_queue;

// Private function to get shared memory key
int get_shm(int token) {
	key_t key;

	// Get numeric key of shared memory file
	key = ftok(SHM_FILE, token);
	if (key == -1) return -1;

	// Get shared memory id from the key
	return shmget(key, sizeof(struct oss_shm), 0644 | IPC_CREAT);
}

// Public function to initalize the oss shared resources
// Pass create = true for intializalizing values
void init_oss(bool create) {
	// Get shared memory
    int mem_id = get_shm(OSS_SHM);
    if (mem_id < 0) {
        printf("Could not get shared memory file.");
    }
	shared_mem = shmat(mem_id, NULL, 0);
    if (shared_mem < 0) {
        printf("Could not attach to shared memory.");
    }

	// Get message queue
	key_t oss_msg_key = ftok(SHM_FILE, OSS_MSG);
	key_t proc_msg_key = ftok(SHM_FILE, PROC_MSG);

	if (oss_msg_key < 0 || proc_msg_key < 0) {
        perror("Could not get message queue(s) file");
	}

	if (create) {
		oss_msg_queue = msgget(oss_msg_key, 0644 | IPC_CREAT);
		proc_msg_queue = msgget(proc_msg_key, 0644 | IPC_CREAT);
	}
	else {
		oss_msg_queue = msgget(oss_msg_key, 0644 | IPC_EXCL);
		proc_msg_queue = msgget(proc_msg_key, 0644 | IPC_EXCL);
	}

	if (oss_msg_queue < 0 || proc_msg_queue < 0) {
        printf("Could not attach to message queue(s).");
	}

	// If not creating, return out
	if (!create) return;

	for (int i = 0; i < MAX_MAIN_MEM; i++) {
		shared_mem->main_memory[i].dirty_bit = false;
		shared_mem->main_memory[i].owner_pid = -1;
		shared_mem->main_memory[i].ref_bit = 0;
	}

	// Setup system clock
	shared_mem->sys_clock.seconds = 0;
	shared_mem->sys_clock.nanoseconds = 0;
}

// Public function to destruct oss shared resources
void dest_oss() {
	// Remove shared memory
	int mem_id = get_shm(OSS_SHM);
	if (mem_id < 0) {
        perror("Could not get shared memory file");
    }
	if (shmctl(mem_id, IPC_RMID, NULL) < 0) {
        perror("Could not remove shared memory");
	}

	shared_mem = NULL;

	// remove message queues
	if (msgctl(oss_msg_queue, IPC_RMID, NULL) < 0) {
		perror("Could not detach message queue");
	}
	if (msgctl(proc_msg_queue, IPC_RMID, NULL) < 0) {
		perror("Could not detach message queue");
	}
}

// Public function to add time to clock
void add_time(struct time_clock* Time, unsigned long seconds, unsigned long nanoseconds) {
	Time->seconds += seconds;
	Time->nanoseconds += nanoseconds;
	if (Time->nanoseconds > 1000000000)
	{
		Time->seconds += 1;
		Time->nanoseconds -= 1000000000;
	}
}

// Private function to subtract time from clock
bool __sub_time(struct time_clock* Time, unsigned long seconds, unsigned long nanoseconds) {
	// If subtracting more nanoseconds then is on the clock
	if (nanoseconds > Time->nanoseconds) {
		// See if we can borrow a second
		if (Time->seconds < 1) return false;
		// Borrow a second
		Time->nanoseconds += 1000000000;
		Time->seconds -= 1;
	}
	// Subtract the nanoseconds
	Time->nanoseconds -= nanoseconds;

	// If subtracting more seconds than we have on clock
	if (seconds > Time->seconds) {
		// Add back the nanoseconds we took
		add_time(Time, 0, nanoseconds);
		return false;
	}
	// Subtract the seconds
	Time->seconds -= seconds;
	return true;
}

// public interface function to subtract time from clock
void sub_time(struct time_clock* Time, unsigned long seconds, unsigned long nanoseconds) {
	if (!__sub_time(Time, seconds, nanoseconds)) {
		perror("Could not subtract time.");
	}
}

void recieve_msg(struct message* msg, int msg_queue, bool wait) {
	int msg_queue_id;
	if (msg_queue == OSS_MSG) {
		msg_queue_id = oss_msg_queue;
	}
	else if (msg_queue == PROC_MSG) {
		msg_queue_id = proc_msg_queue;
	}
	else {
		printf("Got unexpected message queue ID of %d\n", msg_queue);
	}
	if (msgrcv(msg_queue_id, msg, sizeof(struct message), msg->msg_type, wait ? 0 : IPC_NOWAIT) < 0) {
		perror("Could not recieve message");
		fprintf(stderr, "msg: %s type: %ld queue: %d wait?: %d\n", msg->msg_text, msg->msg_type, msg_queue_id, wait);
	}
}

void send_msg(struct message* msg, int msg_queue, bool wait) {
	int msg_queue_id;
	if (msg_queue == OSS_MSG) {
		msg_queue_id = oss_msg_queue;
	}
	else if (msg_queue == PROC_MSG) {
		msg_queue_id = proc_msg_queue;
	}
	else {
		printf("Got unexpected message queue ID of %d\n", msg_queue);
	}
	if (msgsnd(msg_queue_id, msg, sizeof(struct message), wait ? 0 : IPC_NOWAIT) < 0) {
		perror("Could not send message");
		fprintf(stderr, "msg: %s type: %ld queue: %d wait?: %d\n", msg->msg_text, msg->msg_type, msg_queue_id, wait);
	}
}