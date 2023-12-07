#ifndef DYNAMICSERVER_H
#define DYNAMICSERVER_H

#include <stdbool.h>
#include "vecpclient.h"
#include "../ll/llv.h"

#define FREE_FD -1
#define SOCKETERROR -1
#define STREAMSOCK_SHUTDOWN 0
#define INFINITE -1

#define THREAD_INDEX 0
#define DEFAULT_SERVERPORT 8989
#define BACKLOG 20
#define BUFSIZE 4096
#define ACCEPT_POOL_SIZE 2
#define MIN_POLL_THREADS 5
#define MAX_THREAD_CLIENTS 3

struct thread_info {
	int id;
	client *first_client;
	int socket;
};

int check(int value, const char *msg);
void *handle_connection(client *p_client);
void *accept_thread_function(void *arg);
void *poll_thread_function(void *p_ti);
int start_server(unsigned short port, void (*handler)());

#endif
