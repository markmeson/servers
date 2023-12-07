#ifndef WSCOMM_H
#define WSCOMM_H

#define UID_SERVER			1

#define WS_OP_CONTINUE	0x0
#define WS_OP_TEXT			0x1
#define WS_OP_BINARY		0x2
#define WS_OP_CLOSE			0x8
#define WS_OP_PING			0x9
#define WS_OP_PONG			0xA

//Client/Server Commands
#define CCMD_CHAT					0x01
#define SCMD_CHAT					0x01
#define CCMD_SET_NICK			0x02
#define SCMD_SET_NICK			0x02
#define CCMD_NOTICE				0x03
#define SCMD_NOTICE				0x03
#define SCMD_CLI_LIST			0x04
#define SCMD_NEW_USER			0x05
#define SCMD_USER_QUIT		0x06

#include "wsserver.h"

#pragma pack(push, 1)

typedef struct cpck_chat {
	char type;
	char msg[0];
} cpck_chat;

typedef struct spck_chat {
	char type;
	unsigned short uid;
	char msg[0];
} spck_chat;

typedef struct cpck_set_nick {
	char type;
	char newnick[0];
} cpck_set_nick;

#define SSET_NICK_SUCCESS		0
#define SSET_NICK_BAD_LEN		1
#define SSET_NICK_TAKEN			2
#define SSET_NICK_WAIT			3
typedef struct spck_set_nick {
	char type;
	char result;
	unsigned short uid;
	char newnick[0];
} spck_set_nick;

typedef struct spck_notice {
	char type;
	unsigned short uid;
	char msg[0];
} spck_notice;

typedef struct s_cli_info {
	unsigned short uid;
	char nicklen;
	char nick[0];
} s_cli_info;

typedef struct spck_cli_list {
	char type;
	int  len;
	s_cli_info cli_list[0];
} spck_cli_list;

typedef struct spck_new_user {
	char type;
	unsigned short uid;
	char nick[0];
} spck_new_user;

typedef struct spck_user_quit {
	char type;
	unsigned short uid;
} spck_user_quit;

#pragma pack(pop)

void ws_get_header(struct ws_header *h, int len, int op);
void ws_handle_payload(client *c, thread_info *ti);
void ws_ping(client *c);
void ws_pong(client *c);
void ws_reply(client *c);
void ws_ssend(client *c, thread_info *ti, int len); // Send a packet to a single client
void ws_ssend_all(thread_info *ti, int len); //Send a packet to all clients
void ws_ssend_all_msg(char *msg, unsigned short uid_from, thread_info *ti); //Send a chat packet to all clients
void ws_ssend_except(client **c, int n, thread_info *ti, int len); //Send a packet to all clients except those in array c
void ws_ssend_n(client **c, int n, thread_info *ti, int len); //Send a packet only to those clients in array c
void ws_ssend_cli_list(client *c, thread_info *ti); //Send user list to a client
void ws_ssend_newuser_all(client *c, thread_info *ti); //Notify all clients of a new user
void ws_cnick_request(client *c, thread_info *ti); //Handle client nick change request
void ws_write(client *c, struct ws_header *h, void *payload); //Write data to client c

#endif
