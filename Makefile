all: mylib.so server

mylib.o: mylib.c
	gcc -std=gnu99 -Wall -fPIC -DPIC -I../include -c mylib.c

mylib.so: mylib.o
	ld -shared -L../lib/libdirtree.so -o mylib.so mylib.o -ldl

server: server.c
	gcc -std=gnu99 -Wall -fPIC -DPIC -o server server.c -I../include -L../lib -ldirtree

clean:
	rm -f *.o *.so server
