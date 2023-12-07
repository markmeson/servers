#include "vecpclient.h"
#include <stdlib.h>
#include <stdio.h>

void vecpclient_init(vecpclient *v, int capacity) {
	v->size = 0;
	v->capacity = capacity;
	v->clients = (client **)malloc(sizeof(client *) * capacity);
}

void vecpclient_resize(vecpclient *v, int capacity) {
	if(capacity <= v->capacity) return;
	v->clients = (client **)realloc(v->clients, sizeof(client *) * capacity);
	v->capacity = capacity;
}

void vecpclient_push_back(vecpclient *v, client *c) {
	if(v->size == v->capacity)
		vecpclient_resize(v, v->size * 2);
	v->clients[v->size] = c;
	v->size++;
}

void vecpclient_insert_before(vecpclient *v, int index, client *c) {
	if(v->size == v->capacity)
		vecpclient_resize(v, v->size * 2);
	for(int i = v->size - 1; i > index - 2; i--)
		v->clients[i+1] = v->clients[i];
	v->clients[index-1] = c;
	v->size++;
}

void vecpclient_insert_after(vecpclient *v, int index, client *c) {
	if(v->size == v->capacity)
		vecpclient_resize(v, v->size * 2);
	for(int i = v->size - 1; i > index; i--)
		v->clients[i+1] = v->clients[i];
	v->clients[index+1] = c;
	v->size++;
}

client *vecpclient_at(vecpclient *v, int index) {
	if(index < 0 || index > v->size)
		return NULL;
	return v->clients[index];
}

client *vecpclient_pop_back(vecpclient *v) {
	if(v->size < 1) return NULL;
	v->size--;
	return v->clients[v->size];
}

void vecpclient_erase(vecpclient *v, int index) {
	if(index < 0 || index > v->size)
		return;
	for(int i=index; i < v->size-1; i++)
		v->clients[i] = v->clients[i+1];
	v->size--;
}

void vecpclient_clear(vecpclient *v) {
	v->size = 0;
}

void vecpclient_print(vecpclient *v) {
	printf("Vec size=%d, capacity=%d\n", v->size, v->capacity);
	for(int i=0; i < v->size; i++)
		printf("[%d]=0x%.16lX\n", i, (unsigned long)v->clients[i]);
	printf("\n");
}
