#include <pthread.h>

typedef struct threadmap {
	pthread_t thread;
	umap_uip map;
} threadmap;

typedef struct vecpthread {
	int size;
	int capacity;
	threadmap *data;
} vecpthread;

void vecpthread_init(vecpthread *v, int capacity);
void vecpthread_resize(vecpthread *v, int capacity);
void vecpthread_push_back(vecpthread *vec, threadmap *p);
void vecpthread_insert_before(vecpthread *vec, int index, threadmap *p);
void vecpthread_insert_after(vecpthread *vec, int index, threadmap *p);
threadmap *vecpthread_at(vecpthread *vec, int index);
threadmap *vecpthread_pop_back(vecpthread *vec);
void vecpthread_erase(vecpthread *vec, int index);
void vecpthread_clear(vecpthread *vec);
void vecpthread_print(vecpthread *vec);
