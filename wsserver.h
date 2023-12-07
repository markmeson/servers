#ifndef WSSERVER_H
#define WSSERVER_H

#include <stdbool.h>
#include "vecpclient.h"
#include "../hashtables/umapuip.h"

#define WS_NOOP			0x3
#define WS_MAGIC_STRING "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_STATE_BEGIN		0x01
#define WS_STATE_HEADER		0x02
#define WS_STATE_FIN			0x04
#define WS_STATE_MASK_KEY	0x08
#define WS_STATE_SIZE16		0x10
#define WS_STATE_PAYLOAD	0x40
#define WS_STATE_DISCONNECT 0x80

#define WS_PING_STRING			"hello?"
#define WS_PING_STRING_LEN 	6

#define STREAMSOCK_SHUTDOWN 0
#define FREE_FD -1
#define SOCKETERROR -1
#define INFINITE -1

#define THREAD_INDEX 0
#define SERVERPORT 9289
#define BACKLOG 20
#define ACCEPT_POOL_SIZE 2
#define MIN_POLL_THREADS 5
#define MAX_THREAD_CLIENTS 3
#define MAX_CHAT_SIZE 500
#define MAX_PAYLOAD_LEN 4050

typedef struct thread_info {
	int id;
	int socket;
	client *first_client;
	umap_uip *climap;
	char *read_buffer;
	char *write_buffer;
} thread_info;

void show_binary(uint8_t *d, int len);

int check(int value, const char *msg);
void *handle_connection(client *p_client);
void *accept_thread_function(void *arg);
void *poll_thread_function(void *p_ti);
bool disconnect_client(client *c, int *hitfd, struct thread_info *ti, bool close_sock);
int check_ip(char *ip);

void current_time(char *sz_time);
bool http_init_response(char *http_response, int type);
unsigned char *ws_key_validate(char *key);

extern pthread_mutex_t client_mutex;
extern vecpclient pclients;

#endif
