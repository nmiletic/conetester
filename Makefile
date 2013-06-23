all: conetester

conetester:
	gcc -pthread -lrt -g -o conetester conetester.c

clean:
	rm -f conetester

