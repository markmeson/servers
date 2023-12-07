#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFSIZE 4096
#define SOCKETERROR -1
#define LOCAL_IP "192.168.1.246"

char buffer[BUFSIZE];

int check(int ret, const char *msg) {
	if(ret == SOCKETERROR) {
		perror(msg);
		exit(1);
	}
	return ret;
}

int main(int argc, char *argv[]) {
	int socket_desc, bytes_read;

	//Set up client socket and server socket addr
	socket_desc = socket(AF_INET, SOCK_STREAM, 0);
	check((socket_desc), "Failed creating client socket");
	
	printf("Created client socket\n");

	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(8989);
	server_addr.sin_addr.s_addr = inet_addr(LOCAL_IP);

	//Connect to server
	check(connect(socket_desc, (struct sockaddr *)&server_addr, sizeof(server_addr)), "Failed connecting to server");
	printf("Successfully connected to server!\n");

	fgets(buffer, BUFSIZE, stdin);

	close(socket_desc);
	return 0;
}
