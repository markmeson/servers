#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
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

	//Set up SSL context, SSL object, SSL certificate
	
	SSL_CTX *sctx = SSL_CTX_new(TLS_server_method());
	if (!sctx) {
		printf("Failed creating SSL context\n");
		return -1;
	}

	// NOTE: Certificate must be loaded BEFORE creating SSL object!
	if (SSL_CTX_use_certificate_file(sctx, "mycert.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		printf("Error loading certificate pem\n");
		return -1;
	}
	
	if (SSL_CTX_use_PrivateKey_file(sctx, "mycert.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		printf("Error loading private key pem\n");
		return -1;
	}

	if (!SSL_CTX_check_private_key(sctx)) {
		ERR_print_errors_fp(stderr);
		printf("Private key does not match certificate!\n");
		return -1;
	}

	SSL *sconn = SSL_new(sctx);
	if (!sconn) {
		printf("Failed creating SSL object\n");
		return -1;
	}
	
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(SERVERPORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	
	//Bind server address to socket
	check(bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)), "Failed to bind server socket");
	printf("Successfully bound server socket\n");

	//Listen on server socket
	listen(server_sock, 10);
	printf("Listening on server socket\n");

	//Accept client connection
	printf("Waiting for incoming connections...\n");
	client_addr_size = sizeof(client_addr);
	client_sock = accept(server_sock, (struct sockaddr *)&client_addr, (socklen_t *)&client_addr_size);
	check(client_sock, "Accept failed");

	printf("New connection accepted!\n");

	//Associate client socket with SSL object
	if (!SSL_set_fd(sconn, client_sock)) {
		perror("Failed to associate SSL with server socket");
		return -1;
	}

	printf("Performing TLS handshake...\n");
	int ret;
	if ((ret = SSL_accept(sconn)) == -1) {
		ERR_print_errors_fp(stderr);
		ret = SSL_get_error(sconn, ret);
		printf("Failed TLS handhsake with client (%d)\n", ret);
		return -1;
	}
	printf("Successfully performed TLS handhsake\n");

	SSL_free(sconn);
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

