#ifndef VECPCLIENT_H
#define VECPCLIENT_H

#include <arpa/inet.h>
#include <openssl/ssl.h>

#define MAX_NAME 23
#define BUFSIZE 4096
#define HDRSIZE 10

struct ws_header {
	uint16_t opcode	: 4;
	uint16_t rsv3		: 1;
	uint16_t rsv2		: 1;
	uint16_t rsv1		: 1;
	uint16_t fin		: 1;
	uint16_t len7		: 7;
	uint16_t ismask	: 1;
	union {
		uint16_t len16;
		uint64_t len64;
	};
	int size;
	int payload_len;
};

typedef struct client {
	int socket;
	in_addr_t addr;
	char ip[INET_ADDRSTRLEN];
	SSL *ssl;
	unsigned short uid;
	unsigned int index;
	char nick[MAX_NAME];
	int lastnickchg;

	//ws
	struct ws_header header;
	uint8_t		state;
	uint8_t		mask_key[4];
	uint8_t		lastop;
	uint16_t	remain;
	uint8_t		hdr_read;
	uint16_t	payload_len;
	uint16_t	payload_read;	
	uint16_t	payload_saved;
	char 			payload[BUFSIZE];
} client;

typedef struct vecpclient {
	int size;
	int capacity;
	client **clients;
} vecpclient;

void vecpclient_init(vecpclient *v, int capacity);
void vecpclient_resize(vecpclient *v, int capacity);
void vecpclient_push_back(vecpclient *v, client *c);
void vecpclient_insert_before(vecpclient *v, int index, client *c);
void vecpclient_insert_after(vecpclient *v, int index, client *c);
client *vecpclient_pop_back(vecpclient *v);
void vecpclient_erase(vecpclient *v, int index);
void vecpclient_clear(vecpclient *v);
void vecpclient_print(vecpclient *v);

#endif
