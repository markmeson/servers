/* A queue for char pointers */

#include <stdlib.h>
#include "chatqueue.h"

void pcq_init_queue(pcq *q) {
	q->head = NULL;
	q->tail = NULL;
}

void pcq_enqueue(pcq *q, char *msg) {
	pcqnode *newnode = (pcqnode *)malloc(sizeof(pcqnode_t));
	newnode->msg = msg;
	newnode->next = NULL;

	if(q->tail == NULL)
		q->head = newnode;
	else
		q->tail->next = newnode;

	q->tail = newnode;
}

char *pcq_dequeue(pcq *q) {
	if(!q->head)
		return NULL;

	char *result = q->head->msg;
	pcqnode_t *tmp = q->head;
	q->head = q->head->next;

	if(!q->head) q->tail = NULL;

	free(tmp);
	
	return result;
}
