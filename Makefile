all: conetester

conetester: conetester.c
	gcc -pthread -lrt -g -o conetester conetester.c

clean:
	rm -f conetester

