#include "vecpthread.h"
#include <stdlib.h>
#include <stdio.h>

void vecpthread_init(vecpthread *vec, int capacity) {
	vec->size = 0;
	vec->capacity = capacity;
	vec->data = (threadmap *)malloc(sizeof(threadmap) * capacity);
}

void vecpthread_resize(vecpthread *vec, int capacity) {
	if(capacity <= vec->capacity) return;
	vec->data = (threadmap *)realloc(vec->data, sizeof(threadmap) * capacity);
	vec->capacity = capacity;
}

void vecpthread_push_back(vecpthread *vec, threadmap *tm) {
	if(vec->size == vec->capacity)
		vecpthread_resize(vec, vec->size * 2);
	vec->data[vec->size] = *tm;
	vec->size++;
}

void vecpthread_insert_before(vecpthread *vec, int index, threadmap *tm) {
	if(vec->size == vec->capacity)
		vecpthread_resize(vec, vec->size * 2);
	for(int i = vec->size - 1; i > index - 2; i--)
		vec->data[i+1] = vec->data[i];
	vec->data[index-1] = *tm;
	vec->size++;
}

void vecpthread_insert_after(vecpthread *vec, int index, threadmap *tm) {
	if(vec->size == vec->capacity)
		vecpthread_resize(vec, vec->size * 2);
	for(int i = vec->size - 1; i > index; i--)
		vec->data[i+1] = vec->data[i];
	vec->data[index+1] = *tm;
	vec->size++;
}

threadmap *vecpthread_at(vecpthread *vec, int index) {
	if(index < 0 || index > vec->size)
		return NULL;
	return &vec->data[index];
}

threadmap *vecpthread_pop_back(vecpthread *vec) {
	if(vec->size < 1) return NULL;
	vec->size--;
	return &vec->data[vec->size];
}

void vecpthread_erase(vecpthread *vec, int index) {
	if(index < 0 || index > vec->size)
		return;
	for(int i=index; i < vec->size-1; i++)
		vec->data[i] = vec->data[i+1];
	vec->size--;
}

void vecpthread_clear(vecpthread *vec) {
	vec->size = 0;
}

void vecpthread_print(vecpthread *vec) {
	printf("Vec size=%d, capacity=%d\n", vec->size, vec->capacity);
	for(int i=0; i < vec->size; i++)
		printf("[%d]=0x%.16lX\n", i, (unsigned long)vec->data[i]);
	printf("\n");
}
