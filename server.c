#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include "server.h"

int server_sock;

//Close gracefully if Ctrl+C is used
void handle_signal(int sig) {
	signal(sig, SIG_IGN);
	close(server_sock);
	exit(1);
}

int main(int argc, char *argv[]) {

	//Set up server and client sockets and sockaddr's
	int client_sock;
	struct sockaddr_in server_addr, client_addr;
	socklen_t client_addr_size;

	server_sock = socket(AF_INET, SOCK_STREAM, 0);

	check(server_sock, "Failed to create server socket");
	printf("Server socket created\n");

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(8989);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	client_addr_size = sizeof(client_addr);
	
	//Bind server address to socket
	check(bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)), "Failed to bind server socket");
	printf("Successfully bound server socket\n");

	//Listen on server socket
	listen(server_sock, 10);
	printf("Listening on server socket\n");

	//Accept client connection
	printf("Waiting for incoming connections...\n");
	client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_addr_size);
	check(client_sock, "Accept failed");
	printf("New connection accepted!\n");

	check(close(client_sock), "Failed to close client socket");
	printf("Closed client socket\n");
	check(close(server_sock), "Failed to close server socket");
	printf("Closed server socket\n");

	return 0;
}

int check(int ret, const char *msg) {
	if(ret == SOCKETERROR) {
		perror(msg);
		exit(1);
	}
	return ret;
}

