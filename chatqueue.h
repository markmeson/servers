#ifndef CHATQUEUE_H
#define CHATQUEUE_H

typedef struct pcqnode {
	char *msg;
	struct pcqnode *next;
} pcqnode, pcqnode_t;

typedef struct {
	pcqnode *head;
	pcqnode *tail;
} pcq;

void pcq_init_queue(pcq *q);
void pcq_enqueue(pcq *q, char *msg);
char *pcq_dequeue(pcq *q);

#endif
