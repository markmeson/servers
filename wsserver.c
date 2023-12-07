#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include "../base64/base64.h"
#include "../hashtables/umapuiui.h"
#include "../ll/ll.h"
#include "../split/split.h"
#include "../vector/vecui.h"
#include "queue.h"
#include "vecpclient.h"
#include "wscomm.h"
#include "wsserver.h"

int server_sock;

pthread_t accept_pool[ACCEPT_POOL_SIZE];
pthread_mutex_t accept_mutex = PTHREAD_MUTEX_INITIALIZER; //for connection queue
pthread_cond_t accept_condition = PTHREAD_COND_INITIALIZER;
queue conn_q;

vecpclient pclients;
umap_uiui ipmap;
pthread_mutex_t ip_mutex = PTHREAD_MUTEX_INITIALIZER; //for ip limiting
vecui thread_cc;
static int uid = 100;
pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER; //for poll threads

void handle_signal(int sig) {
	signal(sig, SIG_IGN);
	printf(" -- Caught Ctrl+C!\n");
	pthread_mutex_lock(&client_mutex);
	//TODO: tell all threads to close socket and shut down
	pthread_mutex_unlock(&client_mutex);
	check(close(server_sock), "Failed to close server socket");
	exit(1);
}

int main(int argc, char *argv[]) {
	//Close gracefully if Ctrl+C is used
	signal(SIGINT, handle_signal);

	//intialize connection queue
	init_queue(&conn_q);

	//initialize accept threads
	for(int i = 0; i < ACCEPT_POOL_SIZE; i++)
		pthread_create(&accept_pool[i], NULL, accept_thread_function, NULL);
	
	//initialize clients vector
	vecpclient_init(&pclients, 32);

	//initialize ip umap
	umap_uiui_init(&ipmap, 32);

	//initialize vector for tracking number of clients in each thread
	vecui_init(&thread_cc, 5);

	//initialize SSL context and load SSL certificate/key
	SSL_CTX *sslx = SSL_CTX_new(TLS_server_method());
	if (!sslx) {
		printf("Error created SSL context\n");
		return -1;
	}
	// NOTE: Certificate must be loaded BEFORE creating SSL object!
	if (SSL_CTX_use_certificate_file(sslx, "fullchain.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		printf("Error loading certificate pem\n");
		return -1;
	}
	if (SSL_CTX_use_PrivateKey_file(sslx, "privkey.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		printf("Error loading private key pem\n");
		return -1;
	}
	if (!SSL_CTX_check_private_key(sslx)) {
		ERR_print_errors_fp(stderr);
		printf("Private key does not match certificate!\n");
		return -1;
	}

	//set up server and client sockets and sockaddr's
	int client_sock, optval, optlen, client_addr_size;
	struct sockaddr_in server_addr, client_addr;
	client_addr_size = sizeof(client_addr);
	server_sock = socket(AF_INET, SOCK_STREAM, 0);
	check(server_sock, "Failed to create server socket");
	printf("Server socket created\n");

	optval = 1;
	optlen = 4;
	setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, optlen);

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(SERVERPORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	
	//Bind server address to socket
	check(bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)), "Failed to bind server socket");
	printf("Successfully bound server socket\n");

	//Listen on server socket
	listen(server_sock, BACKLOG);
	printf("Listening on server socket\n");

	//Accept client connections
	printf("Waiting for incoming connections...\n");
	while(1) {
		client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_addr_size);
		if(client_sock == SOCKETERROR) {
			perror("Client socket error");
			continue;
		}

		client *pclient = malloc(sizeof(client));
		pclient->addr = client_addr.sin_addr.s_addr;
		pthread_mutex_lock(&ip_mutex);
		if (umap_uiui_at(&ipmap, pclient->addr) > 2) {
			pthread_mutex_unlock(&ip_mutex);
			close(client_sock);
			free(pclient);
			continue;
		} else {
			if (!umap_uiui_inc(&ipmap, pclient->addr, 1))
				umap_uiui_insert(&ipmap, pclient->addr, 1);
			pthread_mutex_unlock(&ip_mutex);
		}

		inet_ntop(AF_INET, (void *)&client_addr.sin_addr, pclient->ip, INET_ADDRSTRLEN); 
		printf("New client (sock=%d ip=%s)\n", client_sock, pclient->ip);

		pclient->ssl = SSL_new(sslx);
		if (!pclient->ssl) {
			ERR_print_errors_fp(stderr);
			printf("Failed creating SSL object for client (%s)\n", pclient->ip);
			close(client_sock);
			free(pclient);
			continue;
		}
		if (!SSL_set_fd(pclient->ssl, client_sock)) {
			printf("Failed to associate client SSL object with socket (%s)\n", pclient->ip);
			SSL_free(pclient->ssl);
			close(client_sock);
			free(pclient);
			continue;
		}
		if (SSL_accept(pclient->ssl) == SOCKETERROR) {
			ERR_print_errors_fp(stderr);
			printf("Failed TLS handshake with client (%s)\n", pclient->ip);
			SSL_free(pclient->ssl);
			close(client_sock);
			free(pclient);
			continue;
		}
		printf("TLS handshake successful\n");

		pclient->socket = client_sock;

		pthread_mutex_lock(&accept_mutex);
		enqueue(&conn_q, pclient);
		pthread_cond_signal(&accept_condition);
		pthread_mutex_unlock(&accept_mutex);
	}

	//cleanup...

	return 0;
}

void *accept_thread_function(void *arg) {
	while(1) {
		pthread_mutex_lock(&accept_mutex);
		client *pclient = dequeue(&conn_q);
		if(!pclient)
			pthread_cond_wait(&accept_condition, &accept_mutex);
		pthread_mutex_unlock(&accept_mutex);
		if(pclient)
			handle_connection(pclient);
	}
}

void *poll_thread_function(void *p_ti) {
	struct thread_info ti = *(struct thread_info *)p_ti;
	free(p_ti);
	client *c = ti.first_client;

	//printf("Starting thread %d\n\n", ti.id);

	int bytes_read;
	char read_buffer[BUFSIZE];
	char write_buffer[BUFSIZE];
	ti.read_buffer = read_buffer;
	ti.write_buffer = write_buffer;

	//create thread-local map for socket->client
	umap_uip client_map;
	umap_uip_init(&client_map, 32);
	umap_uip_insert(&client_map, (unsigned int)c->socket, (void *)c);
	ti.climap = &client_map;

	struct pollfd fds[MAX_THREAD_CLIENTS + 1];
	fds[THREAD_INDEX].fd = ti.socket;
	fds[THREAD_INDEX].events = POLLIN;
	fds[1].fd = c->socket;
	fds[1].events = POLLIN | POLLHUP | POLLRDHUP | POLLNVAL;
	for(int i=2; i < MAX_THREAD_CLIENTS + 1; i++)
		fds[i].fd = FREE_FD;

	// service first thread client before beginning to poll
	sprintf(c->nick, "restorer%hu", c->uid);
	ws_ssend_newuser_all(c, &ti);
	ws_ssend_cli_list(c, &ti);

	while(1) {
		check(poll((struct pollfd *)fds, MAX_THREAD_CLIENTS+1, INFINITE), "Poll error");
		
		for(int i=0; i < MAX_THREAD_CLIENTS + 1; i++) {
			short res = fds[i].revents;
			if(!res) continue;
			if(i == THREAD_INDEX) {
				//unix socket was triggered -> update fds with new client
				read(ti.socket, &c, 8);
				for(int j=1; j < MAX_THREAD_CLIENTS + 1; j++) {
					if(fds[j].fd == FREE_FD) {
						umap_uip_insert(&client_map, (unsigned int)c->socket, (void *)c);
						fds[j].fd = c->socket;
						fds[j].events = POLLIN | POLLRDHUP | POLLHUP | POLLNVAL;
						//printf("Thread %d: New Client (%d)\n", ti.id, c->uid);
						sprintf(c->nick, "restorer%hu", c->uid);
						ws_ssend_newuser_all(c, &ti);
						ws_ssend_cli_list(c, &ti);
						break;
					}
					assert(j < MAX_THREAD_CLIENTS);
				}
				break;
			}

			int *hitfd = &fds[i].fd;
			c = (client *)umap_uip_at(&client_map, *hitfd);

			if(res & POLLIN) {
				while (c->state & WS_STATE_HEADER) {
					check((bytes_read = SSL_read(c->ssl, (void *)&c->header + c->hdr_read, c->remain)), "Client read error");
					if (bytes_read == STREAMSOCK_SHUTDOWN) {
						printf("Client %d closing TCP connection\n", c->uid);
						if (!disconnect_client(c, hitfd, &ti, true))
							return NULL;
						break;
					}
					c->remain -= bytes_read;
					c->hdr_read += bytes_read;
					if (c->remain)
						break;
					c->hdr_read = 0;

					if (c->state & WS_STATE_BEGIN) {
						c->state &= ~WS_STATE_BEGIN;
						c->lastop = c->header.opcode == WS_OP_CONTINUE ? c->lastop : c->header.opcode;
						if (c->lastop == WS_OP_CLOSE) {
							//printf("Client %d sent disconnect opcode!\n", c->uid);
							if (!disconnect_client(c, hitfd, &ti, true))
								return NULL;
							break;
						}
						//printf("Client %d opcode: %d\n", c->uid, c->lastop);
						if (c->header.fin)
							c->state |= WS_STATE_FIN;
						else
							c->state &= ~WS_STATE_FIN;
						if (!(c->header.ismask)) {
							if(!disconnect_client(c, hitfd, &ti, true))
								return NULL;
							break;
						}
						c->payload_len = c->header.len7;
						if (c->payload_len == 126) {
							c->state |= WS_STATE_SIZE16;
							c->remain = 2;
							continue;
						} else if (c->payload_len == 127) {
							if (!disconnect_client(c, hitfd, &ti, true))
								return NULL;
							break;
						}
					} else if (c->state & WS_STATE_SIZE16)
						c->payload_len = c->header.len16;

					if (c->payload_len + c->payload_saved > MAX_PAYLOAD_LEN) {
						if (!disconnect_client(c, hitfd, &ti, true))
							return NULL;
						break;
					}
					c->remain = sizeof(c->mask_key) + c->payload_len;
					c->state &= ~WS_STATE_HEADER;
					c->state |= WS_STATE_PAYLOAD;
					break;
				}

				if (c == NULL)
					break;

				if (c->state & WS_STATE_PAYLOAD) {
					check((bytes_read = SSL_read(c->ssl, c->payload + c->payload_saved + c->payload_read, c->remain)), "Client read error");
					c->remain -= bytes_read;
					c->payload_read += bytes_read;
					if (c->remain)
						continue;

					c->payload_read = 0;
					c->remain = 2;
					c->header.len64 = 0;
					c->state &= ~WS_STATE_PAYLOAD;
					c->state |= WS_STATE_HEADER | WS_STATE_BEGIN;

					memcpy(c->mask_key, c->payload + c->payload_saved, 4);
					for (int z=0; z < c->payload_len; z++)
						c->payload[c->payload_saved+z] = c->payload[c->payload_saved+z+4] ^ c->mask_key[z % 4];
					c->payload_saved += c->payload_len;
					c->payload[c->payload_saved] = 0;
					if (c->state & WS_STATE_FIN) {
						switch (c->lastop) {
							case WS_OP_TEXT:
								break;
							case WS_OP_BINARY:
								//printf("Client %d sent %d bytes of binary data\n", c->uid, c->payload_saved);
								ws_handle_payload(c, &ti);
								break;
							case WS_OP_PING:
								printf("Client %d sent a ping. Sending pong...\n", c->uid);
								ws_pong(c);
								break;
							case WS_OP_PONG:
								printf("Client %d sent a pong, verified\n", c->uid);
								break;
							default:
								printf("Client %d sent unknown opcode (%d)! Disconnecting...\n", c->uid, c->lastop);
								disconnect_client(c, hitfd, &ti, true);
						}
						c->payload_saved = 0;
					} else break; //wait for msg with FIN
				}
			} else if (res & (POLLHUP | POLLRDHUP | POLLNVAL))
				if(!disconnect_client(c, hitfd, &ti, !(res & POLLNVAL)))
					return NULL;
			else
				printf("Unhandled poll event: %hX\n", res);
		}
	}
}

bool disconnect_client(client *c, int *hitfd, thread_info *ti, bool close_sock) {
	if (close_sock) {
		if (!SSL_shutdown(c->ssl))
			SSL_shutdown(c->ssl);
		check(close(c->socket), "Close client socket error");
	}
	*hitfd = FREE_FD;

	spck_user_quit *s = (spck_user_quit *)ti->write_buffer;
	s->type = SCMD_USER_QUIT;
	s->uid = c->uid;

	pthread_mutex_lock(&ip_mutex);
	umap_uiui_dec(&ipmap, c->addr, 1);
	pthread_mutex_unlock(&ip_mutex);

	pthread_mutex_lock(&client_mutex);
	vecpclient_erase(&pclients, c->index);
	thread_cc.data[ti->id]--;
	umap_uip_erase(ti->climap, c->socket);
	//printf("Thread %d: Client %d (sock %d) disconnect\n", ti->id, c->uid, c->socket);
	printf("%s disconnected\n", c->nick);
	SSL_free(c->ssl);
	free(c);
	c = NULL;
	if (ti->climap->size == 0) {
		check(close(ti->socket), "Close thread socket error");
		pthread_mutex_unlock(&client_mutex);
		ws_ssend_all(ti, sizeof(spck_user_quit));
		return false;
	}
	pthread_mutex_unlock(&client_mutex);
	ws_ssend_all(ti, sizeof(spck_user_quit));
	//umap_uip_print(ti->climap);
	return true;
}

int check(int ret, const char *msg) {
	if(ret == SOCKETERROR) {
		perror(msg);
		exit(1);
	}
	return ret;
}

void *handle_connection(client *p_client) {
	int bytes_read = 0;
	char read_buffer[1024];
	char response_buffer[1024];
	unsigned char *b64_key;

	//handle websockets handshake request
	check(bytes_read = SSL_read(p_client->ssl, read_buffer, 1024), "Read new client socket failed");
	read_buffer[bytes_read] = 0;

	//manage headers 
	ll headers, main_header;
	ll_init_list(&headers);
	ll_init_list(&main_header);
	split(&headers, read_buffer, "\r\n");
	split(&main_header, headers.head->data, " ");
	//ll_print_list(&headers);

	//enforce GET
	if(strcmp(main_header.head->data, "GET")) {
		printf("Client at socket %d not using GET, closing connection\n", p_client->socket);
		goto __DENY;
	}

	//enforce HTTP version >= 1.1
	char *http_version = main_header.tail->data + 5;
	if(strcmp(http_version, "1.1") &&
		strcmp(http_version, "2.0") &&
		strcmp(http_version, "3.0")) {
		printf("Client at socket %d bad HTTP version\n", p_client->socket);
		goto __DENY;
	}

	//printf("New client at socket %d using GET with HTTP version %s\n", p_client->socket, http_version);

	//obtain client ws key
	ll_node *ws_header = ll_search_to(&headers, "Sec-WebSocket-Key", 17);
	if(!ws_header) {
		printf("WS Key Header not found\n");
		goto __DENY;
	}
	char *ws_key = strchr(ws_header->data, ' ') + 1;
	//printf("Key: %s\n", ws_key);

	//validate the key with the magic WS string and notify client
	b64_key = ws_key_validate(ws_key);
	//printf("Validated key: %s -> %s\n", ws_key, b64_key);
	if(http_init_response(response_buffer, 101)) {
		strcat(response_buffer, b64_key);
		strcat(response_buffer, "\r\n\r\n");
		SSL_write(p_client->ssl, response_buffer, strlen(response_buffer));
	} else
		goto __DENY;

	p_client->lastop = WS_NOOP;
	p_client->remain = 2;
	p_client->state = WS_STATE_HEADER | WS_STATE_BEGIN;
	p_client->hdr_read = 0;
	p_client->payload_read = 0;
	p_client->payload_saved = 0;

	int to_thread_id = -1; //corresponds to index in thread_cc vector
	int min_clients = MAX_THREAD_CLIENTS;

	//add client to vector, create new thread if needed, and update thread client count
	pthread_mutex_lock(&client_mutex);

	p_client->uid = uid++;
	p_client->index = pclients.size;
	vecpclient_push_back(&pclients, p_client);

	for(int i=0; i < thread_cc.size; i++) {
		if(thread_cc.data[i] < min_clients) {
			min_clients = thread_cc.data[i];
			to_thread_id = i;
		}
	}

	/* when all threads are full, if min_clients is already 0,
	 	 it means an old terminated thread will be restarted
	 	 and to_thread_id will keep its id from the above for loop,
	 	 otherwise a new thread will be appended to the vector */

	if(min_clients == 0 || min_clients == MAX_THREAD_CLIENTS) {
		//Create a new thread OR restart a defunct one
		if(min_clients == MAX_THREAD_CLIENTS) {
			to_thread_id = thread_cc.size; //entirely new threads are appended to vector
			vecui_push_back(&thread_cc, 1);
		}
		thread_cc.data[to_thread_id] = 1; //in case of a terminated thread being restarted
		struct thread_info *ti = (struct thread_info *)malloc(sizeof(struct thread_info));
		ti->id = to_thread_id;
		ti->first_client = p_client;
		ti->socket = socket(AF_UNIX, SOCK_DGRAM, 0);
		check(ti->socket, "Thread socket error");
		struct sockaddr_un thread_addr = {AF_UNIX};
		sprintf(thread_addr.sun_path+1, "pollthread%d", ti->id);
		thread_addr.sun_path[0] = '\0'; //abstract socket
		check(bind(ti->socket, (struct sockaddr *)&thread_addr, sizeof(thread_addr)), "Thread bind error");
		pthread_t new_thread;
		pthread_create(&new_thread, NULL, poll_thread_function, ti);
	} else {
		//Add the client to an already existing thread
		thread_cc.data[to_thread_id]++;
		struct sockaddr_un to_thread_addr = {AF_UNIX};
		sprintf(to_thread_addr.sun_path+1, "pollthread%d", to_thread_id);
		to_thread_addr.sun_path[0] = '\0';
		int local_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
		check(local_sock, "Create unix socket error");
		check(connect(local_sock, (struct sockaddr *)&to_thread_addr, sizeof(to_thread_addr)), "Connect error");
		check(send(local_sock, &p_client, 8, 0), "Send error"); //send 64-bit client pointer
		check(close(local_sock), "Close unix socket error");
	}
	
	pthread_mutex_unlock(&client_mutex);

	//cleanup
	if (b64_key)
		free(b64_key);
	ll_clear_list(&main_header);
	ll_clear_list(&headers);
	return NULL;

	__DENY:
		if (http_init_response(response_buffer, 400))
			SSL_write(p_client->ssl, response_buffer, strlen(response_buffer));
		if (!SSL_shutdown(p_client->ssl))
			SSL_shutdown(p_client->ssl);
		SSL_free(p_client->ssl);
		close(p_client->socket);
		free(p_client);

		if (b64_key)
			free(b64_key);
		ll_clear_list(&main_header);
		ll_clear_list(&headers);
		return NULL;
}

bool http_init_response(char *http_response, int type) {
	switch(type) {
		case 101:
		{
			sprintf(http_response, "HTTP/1.1 101 Switching Protocols\r\n");
			strcat(http_response, "Upgrade: websocket\r\n");
			strcat(http_response, "Connection: Upgrade\r\n");
			strcat(http_response, "Sec-WebSocket-Accept: ");
			break;
		}
		case 400:
		{
			char sz_time[50];
			current_time(sz_time);
			sprintf(http_response, "HTTP/1.1 400 Bad Request\r\nDate: %s\r\n", sz_time);
			strcat(http_response, "Server: Frib's websocket server\r\n\r\n");
			break;
		}
		default:
			return false;
	}
	return true;
}

void current_time(char *sz_time) {
	time_t rawtime;
	struct tm *timestamp;
	time(&rawtime);
	timestamp = localtime(&rawtime);
	sprintf(sz_time, "%s", asctime(timestamp));
}

/* Caller must free returned pointer */
unsigned char *ws_key_validate(char *key) {
	char keybuf[28+36+1];
	sprintf(keybuf, "%s%s", key, WS_MAGIC_STRING);
	size_t len = strlen(keybuf);
	unsigned char hash[SHA_DIGEST_LENGTH];
	memset(hash, 0, SHA_DIGEST_LENGTH);
	SHA1(keybuf, len, hash);
	size_t outlen;
	return base64_encode(hash, 20, &outlen);
}

void show_binary(uint8_t *d, int len)  {
	for(int i=0; i < len; i++) {
		for(int j=0; j < 8; j++)
			printf("%d ", (d[i] >> j) & 1);
		printf(" ");
	}
	printf("\n");
}

