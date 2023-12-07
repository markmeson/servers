#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <unistd.h>

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

	//Set up server socket and server socket addr
	socket_desc = socket(AF_INET, SOCK_STREAM, 0);
	check((socket_desc), "Failed creating server socket");
	printf("Created server socket\n");

	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(9289);
	//server_addr.sin_addr.s_addr = inet_addr("104.248.192.203");
	server_addr.sin_addr.s_addr = inet_addr("192.168.1.19");

	//Connect to server
	check(connect(socket_desc, (struct sockaddr *)&server_addr, sizeof(server_addr)), "Failed connecting to server");
	printf("Successfully connected to server\n");

	//Create SSL context and SSL object
	SSL_CTX *sctx = SSL_CTX_new(TLS_client_method());
	if (!sctx) {
		printf("Failed creating SSL context\n");
		return -1;
	}
	SSL *cssl = SSL_new(sctx);
	if (!cssl) {
		printf("Failed creating SSL object\n");
		return -1;
	}
	if( SSL_set_fd(cssl, socket_desc) == 0) {
		printf("Failed creating SSL object\n");
		return -1;
	}

	//Perform TLS handshake
	int ret;
	if ((ret = SSL_connect(cssl)) != 1) {
		ERR_print_errors_fp(stderr);
		ret = SSL_get_error(cssl, ret);
		printf("Failed TLS handshake with server (%d)\n", ret);
		SSL_free(cssl);
		close(socket_desc);
		SSL_CTX_free(sctx);
		return -1;
	}
	printf("Successfully performed TLS handshake\n");

	fgets(buffer, BUFSIZE, stdin);

	SSL_free(cssl);
	close(socket_desc);
	SSL_CTX_free(sctx);
	return 0;
}
