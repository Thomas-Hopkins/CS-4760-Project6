#ifndef __QUEUE_H
#define __QUEUE_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#define MAX_ELEMENTS 100

struct Queue {
    int front_ind;
    int rear_ind;
    int elements[MAX_ELEMENTS];
    size_t size;
};

void queue_init(struct Queue* queue);
int queue_pop(struct Queue* queue);
int queue_peek(struct Queue* queue);
void queue_insert(struct Queue* queue, int element);
bool queue_is_full(struct Queue* queue);
bool queue_is_empty(struct Queue* queue);
void queue_print(struct Queue* queue);

#endif
