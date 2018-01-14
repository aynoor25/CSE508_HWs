all: mydump

mydump.o: mydump.c
	gcc -c -w mydump.c -o mydump.o

mydump: mydump.o
	gcc mydump.o -lpcap -o mydump

clean:
	-rm -f mydump.o
	-rm -f mydump


