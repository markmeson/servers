#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include "nonthreaded-server.h"

#define BACKLOG 20
#define MAX_CLIENTS 3

int server_sock, client_sock[MAX_CLIENTS], conn_count;

//close gracefully if Ctrl+C is used
void handle_signal(int sig) {
	signal(sig, SIG_IGN);
	if(conn_count)
		close(client_sock[conn_count-1]);
	close(server_sock);
	exit(1);
}

int main(int argc, char *argv[]) {
	signal(SIGINT, handle_signal);

	//set up server and client sockets and sockaddr's
	int optval, optlen;
	struct sockaddr_in server_addr, client_addr, client_addr_size;

	conn_count = 0;

	server_sock = socket(AF_INET, SOCK_STREAM, 0);
	optval = 1;
	optlen = 4;
	setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, optlen);

	check(server_sock, "Failed to create server socket");
	printf("Server socket created\n");

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(8989);
	server_addr.sin_addr.s_addr = INADDR_ANY;

	//Bind server address to socket
	check(bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)), "Failed to bind server socket");
	printf("Successfully bound server socket\n");

	//Listen on server socket
	listen(server_sock, BACKLOG);
	printf("Listening on server socket\n");

	//Accept client connections
	while(1) {
		printf("Waiting for incoming connections...\n");
		client_sock[conn_count] = accept(server_sock, (struct sockaddr *)&client_addr, (socklen_t *)&client_addr_size);
		check(client_sock[conn_count], "Accept failed");

		conn_count++;
		printf("New connection accepted! (Total = %d)\n", conn_count);
		
		if(conn_count >= MAX_CLIENTS)
			break;
	}

	if(conn_count)
		for(int i = 0; i < conn_count; i++)
			check(close(client_sock[i]), "Failed to close a client socket");
	check(close(server_sock), "Failed to close server socket");

	return 0;
}

int check(int ret, const char *msg) {
	if(ret == SOCKETERROR) {
		perror(msg);
		exit(1);
	}
	return ret;
}

