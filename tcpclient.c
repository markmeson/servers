/* tcpclient.c */

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <cstdio>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#define IRR_ADMIN_PORT 30401

int main(int argc, char **argv)
{
	if(argc != 2) {
		printf("Please include the server IP as an argument!\n");
		return 1;
	}

	int sock, bytes_recieved;  
	char send_data[1024],recv_data[1024];
	struct hostent *host;
	struct sockaddr_in server_addr;  

	host = gethostbyname(argv[1]);

	if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("Socket");
		exit(1);
	}

	server_addr.sin_family = AF_INET;     
	server_addr.sin_port = htons(IRR_ADMIN_PORT);   
	server_addr.sin_addr = *((struct in_addr *)host->h_addr);
	bzero(&(server_addr.sin_zero),8); 

	printf("Connecting to \"%s\" on port %d\n", argv[1], IRR_ADMIN_PORT);
	if (connect(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
		perror("Connect");
		exit(1);
	}

	printf("Connection successful\n");
	printf("Sending a hello message...\n");
	sprintf(send_data, "Hello");
	send(sock, send_data, strlen(send_data), 0);
	while(1) {
		printf("Waiting for data...\n");
		bytes_recieved=recv(sock,recv_data,1024,0);
		recv_data[bytes_recieved] = '\0';

		if(!strcmp(recv_data, "q") || !strcmp(recv_data, "Q"))
		{
		 close(sock);
		 break;
		} else
			printf("\nRecieved data = %s " , recv_data);
		 
		printf("\nSEND (q or Q to quit) : ");
		fgets(send_data, 1024, stdin);
		 
		if(!strcmp(send_data , "q\n") || !strcmp(send_data, "Q\n")) {
		 send(sock, send_data, strlen(send_data), 0);   
		 close(sock);
		 break;
		} else
		 send(sock, send_data, strlen(send_data), 0); 
	}   

	return 0;
}
