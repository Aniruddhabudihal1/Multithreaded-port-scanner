#include "head.h"
#include <arpa/inet.h>

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

int main(int argc, char *argv[]) {
  int no_of_ports;
  char address[WEB_ADDRESS];

  printf("Enter the name of the website for which you would like to scan the "
         "ports : \n");
  scanf("%s", address);

  printf("Enter the number of ports for which you would like to scan : \n");
  scanf("%d", &no_of_ports);

  int port_value[no_of_ports];

  for (int i = 0; i < no_of_ports; i++) {
    printf("Enter the port number : \n");
    scanf("%d", &port_value[i]);
  }

  struct addrinfo
      input_hint; // this is basically the input you give in order to get some
                  // result and the following struct is the result
  struct addrinfo *resultant;

  memset(
      &input_hint, 0,
      sizeof(
          input_hint)); // This function sets the memory of input_hint with 0's

  input_hint.ai_family = AF_INET;  // For IPv4
  input_hint.ai_family = AF_INET6; // For IPv6

  printf("Address passed to getaddrinfo: %s\n", address);

  int status = getaddrinfo(address, NULL, &input_hint, &resultant);
  // This function returns the data related to the host name in the form of a
  // struct with all ai_flags, ai_family and all
  // This returns the resultant in the form of a linked list of information
  // where the resultant is the head of the linked list

  if (status != 0) {
    printf("Something went wrong with the getaddrinfo !! \n");
    exit(1);
  }

  struct addrinfo *temp = resultant;
  while (temp != NULL) {

    char address_string[INET6_ADDRSTRLEN];
    void *addr;

    if (temp->ai_family == AF_INET) {
      addr = &((struct sockaddr_in *)temp->ai_addr)->sin_addr;
    } else {
      addr = &((struct sockaddr_in6 *)temp->ai_addr)->sin6_addr;
    }

    inet_ntop(temp->ai_family, addr, address_string, sizeof(address_string));

    printf("Entry : \n");
    printf("\tAddress: %s\n", address_string);
    printf("\tType : %i\n", temp->ai_socktype);
    printf("\tFamily:%i\n", temp->ai_family);
    temp = temp->ai_next; // This is basically traverssing the linked list
  }

  freeaddrinfo(resultant); // This frees up the whole linked list
}
