#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "/home/mark/projects/c/hashtables/umapuip.h"
#include "/home/mark/projects/c/vector/vecui.h"
#include "queue.h"
#include "vecpclient.h"
#include "dynamicserver.h"

int server_sock;

pthread_t accept_pool[ACCEPT_POOL_SIZE];
pthread_mutex_t accept_mutex = PTHREAD_MUTEX_INITIALIZER; //for connection queue
pthread_cond_t accept_condition = PTHREAD_COND_INITIALIZER;
queue conn_q;

vecpclient pclients;
vecui thread_cc;
int uid = 100;
pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER; //for poll threads

void (*data_handler)(char *, int, int);

//Close gracefully if Ctrl+C is used ??
void handle_signal(int sig) {
	signal(sig, SIG_IGN);
	check(close(server_sock), "Failed to close server socket");
	exit(1);
}

/* port - 0 to use default port */
int start_server(unsigned short port, void (*handler)(char *, int, int)) {
  data_handler = handler;
	signal(SIGINT, handle_signal);

	//intialize connection queue
	init_queue(&conn_q);

	//initialize accept threads
	for(int i = 0; i < ACCEPT_POOL_SIZE; i++)
		pthread_create(&accept_pool[i], NULL, accept_thread_function, NULL);
	
	//initialize clients vector
	vecpclient_init(&pclients, 32);

	//initialize vector for tracking number of clients in each thread
	vecui_init(&thread_cc, 5);

	//Set up server and client sockets and sockaddr's
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
	server_addr.sin_port = htons(port ? port : DEFAULT_SERVERPORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	
	//Bind server address to socket
	check(bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)), "Failed to bind server socket");
	printf("Successfully bound server socket\n");

	//Listen on server socket
	listen(server_sock, BACKLOG);
	printf("Listening on server socket\n");

	//Accept client connections
	printf("Waiting for incoming connections...\n");
	char cli_ip[INET_ADDRSTRLEN];
	while(1) {
		client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_addr_size);
		if(client_sock == SOCKETERROR) {
			printf("Client socket error\n");
			continue;
		} else
			printf("Client socket %d\n", client_sock);

		inet_ntop(AF_INET, (void *)&client_addr.sin_addr, cli_ip, INET_ADDRSTRLEN); 
		printf("New client (socket=%d ip=%s)\n", client_sock, cli_ip);

		client *pclient = malloc(sizeof(client));
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
	struct thread_info *ti = (struct thread_info *)p_ti;
	int tid = ti->id;
	int thread_sock = ti->socket;
	client *c = ti->first_client;
	free(ti);

	printf("Starting thread %d\n\n", tid);

	int bytes_read;
	char read_buffer[BUFSIZE];

	//create thread-local map for socket->client
	umap_uip client_map;
	umap_uip_init(&client_map, 32);
	umap_uip_insert(&client_map, (unsigned int)c->socket, (void *)c);

	struct pollfd fds[MAX_THREAD_CLIENTS + 1];
	fds[THREAD_INDEX].fd = thread_sock;
	fds[THREAD_INDEX].events = POLLIN;
	fds[1].fd = c->socket;
	fds[1].events = POLLIN | POLLHUP | POLLRDHUP | POLLNVAL;
	for(int i=2; i < MAX_THREAD_CLIENTS + 1; i++)
		fds[i].fd = FREE_FD;

	while(1) {
		check(poll((struct pollfd *)fds, MAX_THREAD_CLIENTS+1, INFINITE), "Poll error");
		
		for(int i=0; i < MAX_THREAD_CLIENTS + 1; i++) {
			short res = fds[i].revents;
			if(!res) continue;
			if(i == THREAD_INDEX) {
				//unix socket was triggered -> update fds with new client
				read(thread_sock, &c, 8);
				for(int j=1; j < MAX_THREAD_CLIENTS + 1; j++) {
					if(fds[j].fd == FREE_FD) {
						umap_uip_insert(&client_map, (unsigned int)c->socket, (void *)c);
						fds[j].fd = c->socket;
						fds[j].events = POLLIN | POLLRDHUP | POLLHUP | POLLNVAL;
						printf("Thread %d: New Client (%d)\n", tid, c->uid);
						break;
					}
					assert(j < MAX_THREAD_CLIENTS);
				}
				break;
			}
			int *hitfd = &fds[i].fd;
			c = (client *)umap_uip_at(&client_map, *hitfd);
			if(res & POLLIN) {
				bytes_read = recv(*hitfd, read_buffer, BUFSIZE, 0);
				if(bytes_read != STREAMSOCK_SHUTDOWN) {
          read_buffer[bytes_read] = 0;
          if (data_handler)
            data_handler(read_buffer, bytes_read, *hitfd);
          else
            printf("Message (%d bytes) from client %d (socket %d): %s\n", bytes_read, c->uid, *hitfd, read_buffer);
					continue;
				}
			}
			if(bytes_read == STREAMSOCK_SHUTDOWN || res & (POLLHUP | POLLRDHUP | POLLNVAL)) {
				//client disconnected
				*hitfd = FREE_FD;
				if(!(res & POLLNVAL))
					check(close(c->socket), "Close client socket error");
				pthread_mutex_lock(&client_mutex);
				vecpclient_erase(&pclients, c->index);
				thread_cc.data[tid]--;
				umap_uip_erase(&client_map, c->socket);
				printf("Thread %d: Client %d (sock %d) disconnect\n", tid, c->uid, c->socket);
				free(c);
				if(client_map.size == 0) {
					printf("Terminating thread %d\n", tid);
					check(close(thread_sock), "Close thread socket error");
					pthread_mutex_unlock(&client_mutex);
					return NULL;
				}
				pthread_mutex_unlock(&client_mutex);
				umap_uip_print(&client_map);
			} else
				printf("Unhandled poll event: %hX\n", res);
		}
	}
}

int check(int ret, const char *msg) {
	if(ret == SOCKETERROR) {
		perror(msg);
		exit(1);
	}
	return ret;
}

void *handle_connection(client *p_client) {
	int to_thread_id; //corresponds to index in thread_cc vector
	int min_clients = MAX_THREAD_CLIENTS;

	//add client to vector, create new thread if needed, and update thread client count
	pthread_mutex_lock(&client_mutex);

	p_client->uid = uid++;
	p_client->index = pclients.size;
	vecpclient_push_back(&pclients, p_client);

	//do not start (or restart) a new thread unless all other threads are full
	bool all_threads_full = true;
	for (int i = 0; i < thread_cc.size; ++i) {
		if (thread_cc.data[i] > 0 && thread_cc.data[i] < MAX_THREAD_CLIENTS) {
			all_threads_full = false;
			break;
		}
	}

	//Only use a min_clients of 0 when all threads are full
	for (int i=0; i < thread_cc.size; i++) {
		if(thread_cc.data[i] < min_clients && !(thread_cc.data[i] == 0 && !all_threads_full)) {
			min_clients = thread_cc.data[i];
			to_thread_id = i;
		}
	}

	/* when all threads are full, if min_clients is already 0,
	 	 it means an old terminated thread will be restarted
	 	 and to_thread_id will keep its id from the above for loop,
	 	 otherwise a new thread will be appended to the vector */

	if(min_clients == 0 || min_clients == MAX_THREAD_CLIENTS) {
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
	return NULL;

	__DENY:
		close(p_client->socket);
		free(p_client);
		return NULL;
}

