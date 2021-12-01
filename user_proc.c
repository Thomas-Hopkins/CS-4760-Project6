#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "shared.h"
#include "config.h"

extern struct oss_shm* shared_mem;
static struct message msg;
static char* exe_name;
static int sim_pid;

void help() {
    printf("Operating System Simulator Child usage\n");
    printf("Runs as a child of the OSS. Not to be run alone.\n");
}

void init_child() {
    // Init rand gen, shared mem, and msg queues
    srand((int)time(NULL) + getpid());
    init_oss(false);
}

int main(int argc, char** argv) {
    int option;
    exe_name = argv[0];

    while ((option = getopt(argc, argv, "hp:")) != -1) {
        switch (option)
        {
        case 'h':
            help();
            exit(EXIT_SUCCESS);
        case 'p':
            sim_pid = atoi(optarg);
            break;
        case '?':
            // Getopt handles error messages
            exit(EXIT_FAILURE);
        }
    }
    init_child();

    unsigned int num_references = 0;
    while (true) {
        // Wait for message from OSS telling me to run
        strncpy(msg.msg_text, "", MSG_BUFFER_LEN);
        msg.msg_type = getpid();
        recieve_msg(&msg, PROC_MSG, true);

        // terminate this process after 900-1100 memory references (1000 +/- 100)
        if (num_references > ((rand() % 200) + 900)) {
            // Send termination message to OSS and exit
            strncpy(msg.msg_text, "terminate", MSG_BUFFER_LEN);
            msg.msg_type = getpid();
            send_msg(&msg, OSS_MSG, false);
            exit(sim_pid);
        }
        // Request to read/write some memory for this process
        else {
            // Get a random page of this process's memory frame
            unsigned int page = rand() % MAX_PROC_MEM;

            // Generate a read/write message to this page
            if (rand() % 101 <= PERCENT_WRITES) {
                snprintf(msg.msg_text, MSG_BUFFER_LEN, "write %d", page);
            }
            else {
                snprintf(msg.msg_text, MSG_BUFFER_LEN, "read %d", page);
            }
            msg.msg_type = getpid();
            send_msg(&msg, OSS_MSG, false);

            // Wait for response back 
            recieve_msg(&msg, PROC_MSG, true);
            // TODO: Do something with the response?

            num_references++;
        }
    }

    exit(EXIT_SUCCESS);
}