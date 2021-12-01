#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <wait.h>
#include <string.h>

#include "shared.h"
#include "config.h"
#include "queue.h"

static pid_t children[MAX_PROCESSES];
static size_t num_children = 0;
extern struct oss_shm* shared_mem;
static struct Queue proc_queue;
static struct message msg;
static char* exe_name;
static int log_line = 0;
static int total_procs = 0;
static struct time_clock next_spawn; // Next time to try to spawn a child process

struct statistics {
    unsigned int reads;
    unsigned int writes;
    unsigned int seg_faults;
    unsigned int hits;
    unsigned int page_faults;
};

static struct statistics stats;

void help();
void signal_handler(int signum);
void initialize();
int launch_child(char* command);
void try_spawn_child();
void handle_processes();
void remove_child(pid_t pid);
void output_stats();
void save_to_log(char* text);

int main(int argc, char** argv) {
    int option;
    int num_proc;
    char error_buf[MAX_ERR_BUFF];
    exe_name = argv[0];

    // Process arguments
    while ((option = getopt(argc, argv, "hp:")) != -1) {
        switch (option) {
            case 'h':
                help();
                exit(EXIT_SUCCESS);
            case 'p':
                num_proc = atoi(optarg);
				// Assume invalid input if 0
				if (num_proc == 0) {
					errno = EINVAL;
					snprintf(error_buf, MAX_ERR_BUFF, "%s: Passed invalid integer for num of processes to run", exe_name);
					perror(error_buf);
					return EXIT_FAILURE;
				}
                else if (num_proc > MAX_PROCESSES) {
                    errno = EINVAL;
					snprintf(error_buf, MAX_ERR_BUFF, "%s: Max number of processes is %d Defaulting to %d", exe_name, MAX_PROCESSES, MAX_PROCESSES);
					perror(error_buf);
					return EXIT_FAILURE;
                }
				break;
            case '?':
                // Getopt handles error messages
                exit(EXIT_FAILURE);
        }
    }

    // Clear logfile
    FILE* file_ptr = fopen(LOG_FILE, "w");
    fclose(file_ptr);


    // Initialize
    initialize();

    // Main OSS loop. We handle scheduling processes here.
    while (true) {
        // Simulate some passed time for this loop (1 second and [0, 1000] nanoseconds)
        add_time(&(shared_mem->sys_clock), 1, rand() % 1000);
        // try to spawn a new child if enough time has passed
        try_spawn_child();

        // Handle process requests 
        handle_processes();

        // TODO: Every ___ references shift ref_bit 

        // See if any child processes have terminated
        pid_t pid = waitpid(-1, NULL, WNOHANG);
		if (pid > 0) {
            // Clear up this process for future use
            remove_child(pid);
		}

        // If we've run all the processes we need and have no more children we can exit
        if (total_procs > MAX_RUN_PROCS && queue_is_empty(&proc_queue)) {
            break;
        } 
    }
    output_stats();
    dest_oss();
    exit(EXIT_SUCCESS);
}

void help() {
    printf("Operating System Simulator usage\n");
	printf("\n");
	printf("[-h]\tShow this help dialogue.\n");
	printf("\n");
}

void signal_handler(int signum) {
    // Issue messages
	if (signum == SIGINT) {
		fprintf(stderr, "\nRecieved SIGINT signal interrupt, terminating children.\n");
	}
	else if (signum == SIGALRM) {
		fprintf(stderr, "\nProcess execution timeout. Failed to finish in %d seconds.\n", MAX_RUNTIME);
	}

    // Kill active children
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (children[i] > 0) {
            kill(children[i], SIGKILL);
            children[i] = 0;
            num_children--;
        }
    }

    output_stats();

    // Cleanup oss shared memory
    dest_oss();

    if (signum == SIGINT) exit(EXIT_SUCCESS);
	if (signum == SIGALRM) exit(EXIT_SUCCESS);
}

void initialize() {
    // Initialize random number gen
    srand((int)time(NULL) + getpid());

    // Attach to and initialize shared memory.
    init_oss(true);

    // initialize process queue
    queue_init(&proc_queue);

    // Initialize children array
    for (int i = 0; i < MAX_PROCESSES; i++) {
        children[i] = 0;
    }

    // init stats
    stats.writes = 0;
    stats.reads = 0;
    stats.page_faults = 0;
    stats.seg_faults = 0;
    stats.hits = 0;

    // init child spawn clock
    next_spawn.nanoseconds = 0;
    next_spawn.seconds = 0;

    // Setup signal handlers
	signal(SIGINT, signal_handler);
	signal(SIGALRM, signal_handler);

	// Terminate in MAX_RUNTIME	
	alarm(MAX_RUNTIME);
}

int launch_child(char* command) {
    char* cmd1 = strtok(command, " ");
    char* cmd2 = strtok(NULL, " ");
    char* cmd3 = strtok(NULL, " \n");
    return execl(cmd1, cmd1, cmd2, cmd3, NULL);
}

void remove_child(pid_t pid) {
	// Remove pid from children list (slow linear search - but small list so inconsequential)
    for (int i = 0; i < num_children; i++) {
		if (children[i] == pid) {
			// If match, set pid to 0
			children[i] = 0;
            num_children--;
            break;
		}
	}
}

void try_spawn_child() {
    // If we have spawned the maxiumum number of processes ever do not try
    if (total_procs >= MAX_RUN_PROCS) return;

    // Check if enough time has passed on simulated sys clock to spawn new child
    if ((shared_mem->sys_clock.seconds >= next_spawn.seconds) && (shared_mem->sys_clock.nanoseconds - next_spawn.nanoseconds)) {
        // Update next spawn time
        add_time(&next_spawn, 0, (rand() % MAX_TIME_LAUNCH) + MIN_TIME_LAUNCH);

        // Check process control block availablity
        if (num_children < MAX_PROCESSES) {
            // Find open slot to put pid
            int sim_pid;
            for (sim_pid = 0; sim_pid < MAX_PROCESSES; sim_pid++) {
                if (children[sim_pid] == 0) break;
            }

            // Add to process table
            shared_mem->process_table[sim_pid].sim_pid = sim_pid;
            
            // TODO: Allocate 32KB memory to this process

            // Fork and launch child process
            pid_t pid = fork();
            if (pid == 0) {
                char command[100];
                snprintf(command, 100, "./user_proc -p %d", sim_pid);
                if (launch_child(command) < 0) {
                    printf("Failed to launch process.\n");
                    exit(EXIT_FAILURE);
                }
            } 
            else {
                // keep track of child's real pid
                children[sim_pid] = pid;
                num_children++;
                // add to queue
                queue_insert(&proc_queue, sim_pid);
                shared_mem->process_table[sim_pid].actual_pid = pid;
                total_procs++;
            }
            // Add some time for generating a process (0.1ms)
            add_time(&shared_mem->sys_clock, 0, rand() % 100000);
        }
    }
}

// Handle children processes requests over message queues
void handle_processes() {
    char log_buf[100];
    // Return if no process in queue
    int sim_pid = queue_pop(&proc_queue);
    if (sim_pid < 0) return;


    // Tell queued process to run
    strncpy(msg.msg_text, "run", MSG_BUFFER_LEN);
    msg.msg_type = shared_mem->process_table[sim_pid].actual_pid;
    send_msg(&msg, PROC_MSG, false);

    snprintf(log_buf, 100, "OSS sent run message to P%d at %ld:%ld", sim_pid, shared_mem->sys_clock.seconds, shared_mem->sys_clock.nanoseconds);
    save_to_log(log_buf);
    add_time(&shared_mem->sys_clock, 0, rand() % 10000);

    // Wait for process to respond back 
    strncpy(msg.msg_text, "", MSG_BUFFER_LEN);
    msg.msg_type = shared_mem->process_table[sim_pid].actual_pid;
    recieve_msg(&msg, OSS_MSG, true);

    add_time(&shared_mem->sys_clock, 0, rand() % 10000);
    char* cmd = strtok(msg.msg_text, " ");

    // If read memory command
    if (strncmp(cmd, "read", MSG_BUFFER_LEN) == 0) {
        char* cmd2 = strtok(NULL, " ");
        snprintf(log_buf, 100, "OSS recieved request from P%d to read memory %s at %ld:%ld", sim_pid, cmd2, shared_mem->sys_clock.seconds, shared_mem->sys_clock.nanoseconds);
        save_to_log(log_buf);

        // Determine if memory is already in main memory
        // if yes, hit
        // If not, page fault (more time)
            
            // If memory is full replace LRU (smallest ref_bit) with process request
                // If dirty bit set on replaced this takes more time to simulate disk usage
            // If memory not full fill first open (determined from allocated_frames) with process request

        // referenced, so set most significant ref_bit to 1

        strncpy(msg.msg_text, "success", MSG_BUFFER_LEN);
        msg.msg_type = shared_mem->process_table[sim_pid].actual_pid;
        send_msg(&msg, PROC_MSG, false);

        stats.reads++;
    }
    else if (strncmp(cmd, "write", MSG_BUFFER_LEN) == 0) {
        char* cmd2 = strtok(NULL, " ");
        snprintf(log_buf, 100, "OSS recieved request from P%d to write memory %s at %ld:%ld", sim_pid, cmd2, shared_mem->sys_clock.seconds, shared_mem->sys_clock.nanoseconds);
        save_to_log(log_buf);

        // Determine if memory is already in main memory
        // if yes, hit
        // If not, page fault (more time)
            
            // If memory is full replace LRU (smallest ref_bit) with process request
                // If dirty bit set on replaced this takes more time to simulate disk usage
            // If memory not full fill first open (determined from allocated_frames) with process request

        // referenced, so set most significant ref_bit to 1
        // write so set dirty bit

        strncpy(msg.msg_text, "success", MSG_BUFFER_LEN);
        msg.msg_type = shared_mem->process_table[sim_pid].actual_pid;
        send_msg(&msg, PROC_MSG, false);

        stats.writes++;
    }
    else if (strncmp(cmd, "terminate", MSG_BUFFER_LEN) == 0) {
        snprintf(log_buf, 100, "OSS handling termination of P%d at %ld:%ld", sim_pid, shared_mem->sys_clock.seconds, shared_mem->sys_clock.nanoseconds);
        save_to_log(log_buf);

        // Free any memory used by this process that is in main memory

        // Do not requeue this process.
        remove_child(shared_mem->process_table[sim_pid].actual_pid);
        return;
    }

    // Re-queue this process
    queue_insert(&proc_queue, sim_pid);

    // Add some time for handling a process (0.1ms)
    add_time(&shared_mem->sys_clock, 0, rand() % 100000);
}

void output_stats() {
    printf("\n");
    printf("| STATISTICS |\n");
    printf("--MEMORY READ/WRITE\n");
    printf("\t%-12s %d\n", "READS:", stats.reads);
    printf("\t%-12s %d\n", "WRITES:", stats.writes);

    unsigned int total_accesses = stats.reads + stats.writes;
    printf("\t%-12s %d\n", "TOTAL:", total_accesses);

    printf("--MEMORY HITS/FAULTS\n");
    printf("\t%-12s %d\n", "HITS:", stats.hits);
    printf("\t%-12s %d\n", "PAGE FAULTS:", stats.page_faults);
    printf("\t%-12s %d\n", "SEG FAULTS:", stats.seg_faults);

    printf("--MEMORY GENERAL\n");
    float total_sec = shared_mem->sys_clock.seconds + (shared_mem->sys_clock.nanoseconds * 0.000000001);
    float access_per_sec = total_accesses / total_sec;
    printf("\t%-18s %.3f\n", "ACESSESS/S:", access_per_sec);
    float pagefaults_per_access = stats.page_faults / total_accesses;
    printf("\t%-18s %.3f\n", "PAGEFAULTS/ACCESS:", pagefaults_per_access);
    float segfaults_per_access = stats.seg_faults / total_accesses;
    printf("\t%-18s %.3f\n", "SEGFAULTS/ACCESS:", segfaults_per_access);

    printf("--SIMULATED TIME\n");
    printf("\t%-12s %ld\n", "SECONDS:", shared_mem->sys_clock.seconds);
    printf("\t%-12s %ld\n", "NANOSECONDS:", shared_mem->sys_clock.nanoseconds);
    printf("\n");
}

void save_to_log(char* text) {
	FILE* file_log = fopen(LOG_FILE, "a+");
    log_line++;
    if (log_line > LOG_FILE_MAX) {
        errno = EINVAL;
        perror("Log file has exceeded max length.");
    }

    // Make sure file is opened
	if (file_log == NULL) {
		perror("Could not open logfile");
        return;
	}

    fprintf(file_log, "%s\n", text);

    fclose(file_log);
}