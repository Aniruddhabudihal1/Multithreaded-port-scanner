CC = gcc
CFLAGS = -Wall -Wextra -pthread
LDFLAGS = -pthread

all: port-scanner

port-scanner: main.o scanner.o input_parser.o
	$(CC) $(LDFLAGS) $^ -o $@

main.o: main.c head.h
	$(CC) $(CFLAGS) -c $< -o $@

scanner.o: scanner.c head.h
	$(CC) $(CFLAGS) -c $< -o $@

input_parser.o: input_parser.c head.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o port-scanner
