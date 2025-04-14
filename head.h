#ifndef _HEAD_H
#define _HEAD_H

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define WEB_ADDRESS 256
#define MAX_THREADS 100
#define MAX_PORTS 65535
#define DEFAULT_THREADS 20
#define DEFAULT_TIMEOUT_SEC 1
#define DEFAULT_TIMEOUT_USEC 0

// Structure to pass arguments to threads
typedef struct {
  char address[WEB_ADDRESS];
  int start_port;
  int end_port;
  int thread_id;
} ThreadArgs;

#endif /* _HEAD_H */
