#include <stdlib.h>
#include "queue.h"

void init_queue(queue *q) {
	q->head = NULL;
	q->tail = NULL;
}

void enqueue(queue *q, client *p_client) {
	node *newnode = (node *)malloc(sizeof(node_t));
	newnode->pclient = p_client;
	newnode->next = NULL;

	if(q->tail == NULL)
		q->head = newnode;
	else
		q->tail->next = newnode;
	q->tail = newnode;
}

client *dequeue(queue *q) {
	if(!q->head)
		return NULL;

	client *result = q->head->pclient;
	node_t *tmp = q->head;
	q->head = q->head->next;

	if(!q->head) q->tail = NULL;

	free(tmp);
	
	return result;
}
