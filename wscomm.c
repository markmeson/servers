#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "vecpclient.h"
#include "wscomm.h"

const char *ping_response = "hello back!";

void ws_get_header(struct ws_header *h, int len, int op) {
	h->size = 2;
	h->fin = 1;
	h->rsv1 = 0;
	h->rsv2 = 0;
	h->rsv3 = 0;
	h->opcode = op;
	h->ismask = 0;
	if (len < 126)
		h->len7 = len;
	else if (len <= 0xFFFF) {
		h->len7 = 126;
		h->len16 = len;
		h->size = 4;
	} else {
		h->len7 = 127;
		h->len64 = len;
		h->size = 10;
	}
	h->payload_len = len;
}

void ws_handle_payload(client *c, thread_info *ti) {
	switch (c->payload[0]) {
		case CCMD_SET_NICK:
		{
			ws_cnick_request(c, ti);
			break;
		}
		case CCMD_CHAT:
		{
			printf("%s: %s\n", c->nick, c->payload+1);
			char *msg = ((cpck_chat *)c->payload)->msg;
			msg[MAX_CHAT_SIZE] = 0;
			ws_ssend_all_msg(msg, c->uid, ti);
			break;
		}
		default:
		{
			printf("%s (%hu) sent an unknown command\n", c->nick, c->uid);
			break;
		}
	}
}

void ws_ping(client *c) {
	struct ws_header h;
	ws_get_header(&h, 12, WS_OP_TEXT);
	ws_write(c, &h, (void *)ping_response);
}

void ws_pong(client *c) {
	struct ws_header h;
	ws_get_header(&h, c->payload_saved, WS_OP_PONG);
	ws_write(c, &h, (void *)c->payload);
}

void ws_reply(client *c) {
	struct ws_header h;
	ws_get_header(&h, c->payload_saved + 1, WS_OP_TEXT);
	ws_write(c, &h, (void *)c->payload);
}
			
void ws_ssend(client *c, thread_info *ti, int len) {
	struct ws_header h;
	ws_get_header(&h, len, WS_OP_BINARY);
	ws_write(c, &h, ti->write_buffer);
}

void ws_ssend_msg(client *c, char *msg, unsigned short uid_from, thread_info *ti) {
	spck_chat *s = (spck_chat *)ti->write_buffer;
	s->type = SCMD_CHAT;
	s->uid = uid_from;
	strcpy(s->msg, msg);
	ws_ssend(c, ti, sizeof(spck_chat) + strlen(msg) + 1);
}

void ws_ssend_all(thread_info *ti, int len) {
	struct ws_header h;
	ws_get_header(&h, len, WS_OP_BINARY);
	pthread_mutex_lock(&client_mutex);
	for (int i=0; i < pclients.size; i++)
		ws_write(pclients.clients[i], &h, ti->write_buffer);
	pthread_mutex_unlock(&client_mutex);
}

void ws_ssend_all_msg(char *msg, unsigned short uid_from, thread_info *ti) {
	spck_chat *s = (spck_chat *)ti->write_buffer;
	s->type = SCMD_CHAT;
	s->uid = uid_from;
	strcpy(s->msg, msg);
	ws_ssend_all(ti, sizeof(spck_chat) + strlen(msg) + 1);
}

void ws_ssend_except(client **c, int n, thread_info *ti, int len) {
	struct ws_header h;
	ws_get_header(&h, len, WS_OP_BINARY);
	pthread_mutex_lock(&client_mutex);
	for (int i=0; i < pclients.size; i++)
		for (int j=0; j < n; j++)
			if (pclients.clients[i] != c[j])
				ws_write(pclients.clients[i], &h, ti->write_buffer);
	pthread_mutex_unlock(&client_mutex);
}

void ws_ssend_n(client **c, int n, thread_info *ti, int len) {
	struct ws_header h;
	ws_get_header(&h, len, WS_OP_BINARY);
	pthread_mutex_lock(&client_mutex);
	for (int i=0; i < pclients.size; i++)
		for (int j=0; j < n; j++)
			if (pclients.clients[i] == c[j])
				ws_write(pclients.clients[i], &h, ti->write_buffer);
	pthread_mutex_unlock(&client_mutex);
}

void ws_cnick_request(client *c, thread_info *ti) {
	char *newnick = ((cpck_set_nick *)c->payload)->newnick;
	spck_set_nick *s = (spck_set_nick *)ti->write_buffer;
	s->type = SCMD_SET_NICK;
	int len = strlen(newnick);
	if (len > MAX_NAME || len < 3) {
		s->result = SSET_NICK_BAD_LEN;
		s->uid = c->uid;
		ws_ssend(c, ti, sizeof(spck_set_nick));
		return;
	}
	pthread_mutex_lock(&client_mutex);
	if (!strcmp(newnick, "Server")) {
		pthread_mutex_unlock(&client_mutex);
		s->result = SSET_NICK_TAKEN;
		ws_ssend(c, ti, sizeof(spck_set_nick));
		return;
	}
	for (int i = 0; i < pclients.size; i++) {
		if (!strcmp(pclients.clients[i]->nick, newnick)) {
			pthread_mutex_unlock(&client_mutex);
			s->result = SSET_NICK_TAKEN;
			ws_ssend(c, ti, sizeof(spck_set_nick));
			return;
		}
	}
	pthread_mutex_unlock(&client_mutex);
	s->result = SSET_NICK_SUCCESS;
	s->uid = c->uid;
	strcpy(c->nick, newnick);
	memcpy(s->newnick, newnick, len);
	ws_ssend_all(ti, sizeof(spck_set_nick) + strlen(newnick));
}

void ws_ssend_newuser_all(client *c, thread_info *ti) {
	spck_new_user *s = (spck_new_user *)ti->write_buffer;
	s->type = SCMD_NEW_USER;
	s->uid = c->uid;
	strcpy(s->nick, c->nick);
	ws_ssend_all(ti, sizeof(spck_new_user) + strlen(c->nick) + 1);
}

void ws_ssend_cli_list(client *c, thread_info *ti) {
	spck_cli_list *l = (spck_cli_list *)ti->write_buffer;
	s_cli_info *s = l->cli_list;
	l->type = SCMD_CLI_LIST;
	l->len = 0;
	int list_size = sizeof(spck_cli_list);
	client *n;
	pthread_mutex_lock(&client_mutex);
	for (int i = 0; i < pclients.size; i++) {
		if ((n = pclients.clients[i]) != c) {
			s->uid = n->uid;
			s->nicklen = strlen(n->nick);
			memcpy(s->nick, n->nick, s->nicklen); 
			l->len++;
			list_size += sizeof(s_cli_info) + s->nicklen;
			s = (s_cli_info *)((char *)s->nick + s->nicklen);
		}
	}
	ws_ssend(c, ti, list_size);
	pthread_mutex_unlock(&client_mutex);
}

void ws_write(client *c, struct ws_header *h, void *payload) {
	SSL_write(c->ssl, h, h->size);
	SSL_write(c->ssl, payload, h->payload_len);
} 

