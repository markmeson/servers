#ifndef QUEUE_H
#define QUEUE_H

#include "vecpclient.h"

typedef struct node {
	client *pclient;
	struct node *next;
} node, node_t;

typedef struct {
	node *head;
	node *tail;
} queue;

void init_queue(queue *q);
void enqueue(queue *q, client *p_client);
client *dequeue(queue *q);

#endif
