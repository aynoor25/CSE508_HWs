all : pbproxy

pbproxy.o: pbproxy.c
	gcc -c pbproxy.c -o pbproxy.o -lcrypto

pbproxy: pbproxy.o
	gcc pbproxy.c -lcrypto -o pbproxy

clean:
	-rm -f pbproxy.o
	-rm -f pbproxy
