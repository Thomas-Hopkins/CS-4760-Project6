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
static int num_proc = MAX_PROCESSES;
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
void get_page();
void replace_memory(int main_mem_ind, int sim_pid, int page_ind);
void get_memory(int sim_pid, int page_ind, bool write);
void remove_child(pid_t pid);
void output_memory();
void output_stats();
void save_to_log(char* text);

int main(int argc, char** argv) {
    int option;
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
					num_proc = MAX_PROCESSES;
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
        // Simulate some passed time for this loop (1 second and [1000000, 10000000] nanoseconds)
        add_time(&(shared_mem->sys_clock), 0, (rand() % 9000001) + 100000000);
        // try to spawn a new child if enough time has passed
        try_spawn_child();

        // Handle process requests 
        handle_processes();

        // Every 100 references shift ref_bit
        if (stats.writes + stats.reads > 100){
            for (int i = 0; i < MAX_MAIN_MEM; i++) {
                shared_mem->main_memory[i].ref_bit = shared_mem->main_memory[i].ref_bit >> 1;
            }
        }

        // See if any child processes have terminated
        pid_t pid = waitpid(-1, NULL, WNOHANG);
		if (pid > 0) {
            // Clear up this process for future use
            remove_child(pid);
		}

        // If we've run all the processes we need and have no more children we can exit
        if (total_procs >= MAX_RUN_PROCS && queue_is_empty(&proc_queue) && num_children <= 0) {
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
    for (int i = 0; i < num_proc; i++) {
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
    for (int i = 0; i < num_proc; i++) {
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
    if ((shared_mem->sys_clock.seconds > next_spawn.seconds) ||
    ((shared_mem->sys_clock.seconds == next_spawn.seconds) && (shared_mem->sys_clock.nanoseconds >= next_spawn.nanoseconds))) {
        // Update next spawn time
        add_time(&next_spawn, 0, (rand() % MAX_TIME_LAUNCH) + MIN_TIME_LAUNCH);

        // Check process control block availablity
        if (num_children < num_proc) {
            // Find open slot to put pid
            int sim_pid;
            for (sim_pid = 0; sim_pid < num_proc; sim_pid++) {
                if (children[sim_pid] == 0) break;
            }

            // Add to process table
            shared_mem->process_table[sim_pid].sim_pid = sim_pid;
            
            // Allocate 32KB memory to this process
            for (int i = 0; i < MAX_PROC_MEM; i++) {
                int main_mem_addr = 0;
                // find open memory frame
                main_mem_addr = -1;
                for (int i = 0; i < MAX_MAIN_MEM; i++) {
                    if (!shared_mem->allocated_frames[i]) {
                        main_mem_addr = i;
                        break;
                    }
                }
                if (main_mem_addr < 0) {
                    // no open frame found -> run LRU replacement algo
                    replace_memory(main_mem_addr, sim_pid, i);
                } 
                shared_mem->process_table[sim_pid].page_table[i] = main_mem_addr;
                shared_mem->allocated_frames[main_mem_addr] = true;
                shared_mem->main_memory[main_mem_addr].owner_pid = sim_pid;
            }

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

        // Try to get the memory frame that this process is pointing to
        int page_ind = atoi(cmd2);
        snprintf(log_buf, 100, "OSS recieved request from P%d to read memory %d at %ld:%ld", sim_pid, shared_mem->process_table[sim_pid].page_table[page_ind], shared_mem->sys_clock.seconds, shared_mem->sys_clock.nanoseconds);
        save_to_log(log_buf);
        get_memory(sim_pid, page_ind, false);

        strncpy(msg.msg_text, "success", MSG_BUFFER_LEN);
        msg.msg_type = shared_mem->process_table[sim_pid].actual_pid;
        send_msg(&msg, PROC_MSG, false);

        stats.reads++;
    }
    else if (strncmp(cmd, "write", MSG_BUFFER_LEN) == 0) {
        char* cmd2 = strtok(NULL, " ");
        
        // Try to get the memory frame that this process is pointing to
        int page_ind = atoi(cmd2);
        snprintf(log_buf, 100, "OSS recieved request from P%d to write memory %d at %ld:%ld", sim_pid, shared_mem->process_table[sim_pid].page_table[page_ind], shared_mem->sys_clock.seconds, shared_mem->sys_clock.nanoseconds);
        save_to_log(log_buf);
        get_memory(sim_pid, page_ind, true);

        strncpy(msg.msg_text, "success", MSG_BUFFER_LEN);
        msg.msg_type = shared_mem->process_table[sim_pid].actual_pid;
        send_msg(&msg, PROC_MSG, false);

        stats.writes++;
    }
    else if (strncmp(cmd, "terminate", MSG_BUFFER_LEN) == 0) {
        snprintf(log_buf, 100, "OSS handling termination of P%d at %ld:%ld", sim_pid, shared_mem->sys_clock.seconds, shared_mem->sys_clock.nanoseconds);
        save_to_log(log_buf);

        // Free any memory used by this process that is in main memory
        for (int i = 0; i < MAX_PROC_MEM; i++) {
            int main_mem_ind = shared_mem->process_table->page_table[i];
            if (shared_mem->main_memory[main_mem_ind].owner_pid == sim_pid) {
                shared_mem->main_memory[main_mem_ind].owner_pid = -1;
                shared_mem->main_memory[main_mem_ind].ref_bit = 0;
                shared_mem->main_memory[main_mem_ind].dirty_bit = 0;
                shared_mem->allocated_frames[main_mem_ind] = false;
            }
        }

        output_memory();

        // Do not requeue this process.
        remove_child(shared_mem->process_table[sim_pid].actual_pid);
        return;
    }

    // Re-queue this process
    queue_insert(&proc_queue, sim_pid);

    // Add some time for handling a process (0.1ms)
    add_time(&shared_mem->sys_clock, 0, rand() % 100000);
}

void replace_memory(int main_mem_ind, int sim_pid, int page_ind) {
    char log_buf[100];
    int least_mem = shared_mem->main_memory[0].ref_bit;
    int least_mem_ind;
    for (least_mem_ind = 1; least_mem_ind < MAX_MAIN_MEM; least_mem_ind++) {
        if (shared_mem->main_memory[least_mem_ind].ref_bit < least_mem) least_mem = shared_mem->main_memory[least_mem_ind].ref_bit;
        // Simulate time for finding LRU (around 10ns per iteration)
        add_time(&shared_mem->sys_clock, 0, 10);
    }
    if (LOG_VERBOSE) {
        snprintf(log_buf, 100, "Replacing frame %d of used by P%d with P%d.", main_mem_ind, shared_mem->main_memory[least_mem_ind].owner_pid, sim_pid);
        save_to_log(log_buf);
    }

    // Simulate more time for dirty bit (because of disk usage), 1000ns +/- 500ns
    if (shared_mem->main_memory->dirty_bit > 0) {
        if (LOG_VERBOSE) {
            snprintf(log_buf, 100, "Dirty bit of frame P%d-%d is set, simulating more time.", sim_pid, main_mem_ind);
            save_to_log(log_buf);
        }
        add_time(&shared_mem->sys_clock, 0, (rand() % 1001) + 500);
    }
    
    // Update process's reference to this memory address
    shared_mem->process_table[sim_pid].page_table[page_ind] = least_mem_ind;
    // Replace main memory frame
    shared_mem->main_memory[least_mem_ind].owner_pid = sim_pid;
    shared_mem->main_memory[least_mem_ind].dirty_bit = 0;

    // Update allocated
    shared_mem->allocated_frames[main_mem_ind] = true;
}

void get_memory(int sim_pid, int page_ind, bool write) {
    char log_buf[100];
    // Catch segfaults
    if (page_ind > MAX_PROC_MEM) {
        snprintf(log_buf, 100, "Address P%d-%d outside of memory bounds, segfault.", sim_pid, page_ind);
        save_to_log(log_buf);
        stats.seg_faults++;
        add_time(&shared_mem->sys_clock, 0, 5);
        return;
    }

    int main_mem_ind = shared_mem->process_table[sim_pid].page_table[page_ind];
    // If the owner of this frame is not this process it must have been swapped, thus page fault
    if (shared_mem->main_memory[main_mem_ind].owner_pid != sim_pid) {
        stats.page_faults++;
        if (LOG_VERBOSE) {
            snprintf(log_buf, 100, "Address P%d-%d not in frame, pagefault.", sim_pid, main_mem_ind);
            save_to_log(log_buf);
        }
        // find open memory frame
        main_mem_ind = -1;
        for (int i = 0; i < MAX_MAIN_MEM; i++) {
            if (!shared_mem->allocated_frames[i]) {
                main_mem_ind = i;
                break;
            }
        }
        if (main_mem_ind < 0) {
            // no open frame found -> run LRU replacement algo
            replace_memory(main_mem_ind, sim_pid, page_ind);
        }
        // Open frame found, insert into this
        else {
            if (LOG_VERBOSE) {
                snprintf(log_buf, 100, "Inserting into empty frame P%d-%d.", sim_pid, main_mem_ind);
                save_to_log(log_buf);
            }
            // Update process's reference to this memory address
            shared_mem->process_table[sim_pid].page_table[page_ind] = main_mem_ind;
            // Replace main memory frame
            shared_mem->main_memory[main_mem_ind].owner_pid = sim_pid;
            shared_mem->main_memory[main_mem_ind].dirty_bit = 0;

            // Update allocated
            shared_mem->allocated_frames[main_mem_ind] = true;
        }
    }
    else {
        // hit
        if (LOG_VERBOSE) {
            snprintf(log_buf, 100, "Address P%d-%d in frame, hit.", sim_pid, main_mem_ind);
            save_to_log(log_buf);
        }
        stats.hits++;
        // Simulate time (10ns)
        add_time(&shared_mem->sys_clock, 0, 10);
    }
    // Set most sig bit to 1 since we referenced this
    shared_mem->main_memory[main_mem_ind].ref_bit |= 128;

    // Set dirty bit if this is a write operation
    if (write) shared_mem->main_memory[main_mem_ind].dirty_bit = 1;

    // Write out memory every 100 refs
    if (((stats.writes + stats.reads) % 100) == 0) output_memory(); 
}

void output_memory() {
    char log_buf[100];
    snprintf(log_buf, 100, "Current memory layout at time %ld:%ld is:", shared_mem->sys_clock.seconds, shared_mem->sys_clock.nanoseconds);
    save_to_log(log_buf);

    snprintf(log_buf, 100, "%19s%10s%10s", "Occupied", "RefByte", "DirtyBit");
    save_to_log(log_buf);

    for (int i = 0; i < MAX_MAIN_MEM; i++) {
        bool occupied = shared_mem->allocated_frames[i];
        snprintf(log_buf, 100, "%s %3d%s%6s%11d%9d", "Frame", i, ":", occupied ? "Yes" : "No", shared_mem->main_memory[i].ref_bit, shared_mem->main_memory[i].dirty_bit);
        save_to_log(log_buf);
    }
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
    float pagefaults_per_access = stats.page_faults / (float)total_accesses;
    printf("\t%-18s %.3f\n", "PAGEFAULTS/ACCESS:", pagefaults_per_access);
    float segfaults_per_access = stats.seg_faults / (float)total_accesses;
    printf("\t%-18s %.3f\n", "SEGFAULTS/ACCESS:", segfaults_per_access);

    printf("--SIMULATED TIME\n");
    printf("\t%-12s %ld\n", "SECONDS:", shared_mem->sys_clock.seconds);
    printf("\t%-12s %ld\n", "NANOSECONDS:", shared_mem->sys_clock.nanoseconds);

    printf("--GENERAL & CONFIG\n");
    printf("\t%-18s %d\n", "TOTAL PROCESSES:", total_procs);
    printf("\t%-18s %d\n", "TOTAL LOGLINES:", log_line);
    printf("\t%-18s %s\n", "VERBOSE MODE:", LOG_VERBOSE ? "true" : "false");
    printf("\t%-18s %s\n", "LOGFILE:", LOG_FILE);
    printf("\t%-18s %d%%\n", "CHANCE WRITES:", PERCENT_WRITES);
    printf("\t%-18s %d%%\n", "CHANCE SEGFAULT:", PERCENT_SEGFAULT);

    
    printf("\n");
}

void save_to_log(char* text) {
    if (log_line > LOG_FILE_MAX) return;
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