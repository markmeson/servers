all:
	gcc -o server server.c
	gcc -o sslserver sslserver.c -lssl -lcrypto
	gcc -o client client.c
	gcc -o sslclient sslclient.c -lssl -lcrypto
	gcc -o nonthreaded-server nonthreaded-server.c
	gcc -o dynserver dynamic_main.c dynamicserver.c vecpclient.c ../hashtables/umapuip.c ../hashtables/hashes.c queue.c ../vector/vecui.c -lpthread -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast
	gcc -g -o wsserver wsserver.c wscomm.c vecpclient.c ../hashtables/umapuip.c ../hashtables/umapuiui.c ../hashtables/hashes.c ../base64/base64.c queue.c ../split/split.c ../vector/vecui.c ../ll/ll.c -lpthread -lssl -lcrypto -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast

client: client.c
	gcc -o client client.c

dynamic: dynamicserver.c
	gcc -o dynserver dynamicserver.c vecpclient.c ../hashtables/umapuip.c queue.c ../vector/vecui.c -lpthread -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast

nonthreaded-server: nonthreaded-server.c
	gcc -o nonthreaded-server nonthreaded-server.c

server: server.c
	gcc -o server server.c

sslclient: sslclient.c
	gcc -o sslclient sslclient.c -lssl -lcrypto

sslserver: sslserver.c
	gcc -o sslserver sslserver.c -lssl -lcrypto

wsserver: wsserver.c
	gcc -o wsserver wsserver.c wscomm.c vecpclient.c ../hashtables/umapuiui.c ../hashtables/hashes.c ../hashtables/umapuip.c ../base64/base64.c queue.c ../split/split.c ../vector/vecui.c ../ll/ll.c -lpthread -lssl -lcrypto -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast
