#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUFSIZE 4096
#define SOCKETERROR -1

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
	if(socket_desc < 0) {
		perror("Failed creating client socket");
		return 1;
	}
	printf("Created client socket\n");

	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(8989);
	server_addr.sin_addr.s_addr = inet_addr("192.168.1.19");

	//Connect to server
	if(connect(socket_desc, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("Connect failed");
		return 1;
	}
	
	printf("Successfully connected to server!\n");

	sprintf(buffer, "GET / HTTP/1.1\r\nHost: 192.168.1.19:8989\r\n"
"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:81.0) Gecko/20100101 Firefox/81.0\r\n"
"Accept: */*\r\n"
"Accept-Language: en-US,en;q=0.5\r\n"
"Accept-Encoding: gzip, deflate\r\n"
"Sec-WebSocket-Version: 13\r\n"
"Origin: http://192.168.1.19\r\n"
"Sec-WebSocket-Extensions: permessage-deflate\r\n"
"Sec-WebSocket-Key: rSlgwWVIIlGvrCettIa54A==\r\n"
"Connection: keep-alive, Upgrade\r\n"
"Pragma: no-cache\r\n"
"Cache-Control: no-cache\r\n"
"Upgrade: websocket\r\n\r\n");
	check(send(socket_desc, buffer, strlen(buffer), 0), "Send failed");
	printf("Message sent\n");
	check((bytes_read = recv(socket_desc, buffer, BUFSIZE, 0)), "Recv failed");
	
	buffer[bytes_read] = 0;
	printf("Response:\n%s\n", buffer);

	fgets(buffer, BUFSIZE, stdin);

	return 0;
}
