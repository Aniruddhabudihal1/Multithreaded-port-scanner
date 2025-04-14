#include "head.h"

void domain_parser() {
  char address[WEB_ADDRESS];
  printf("Enter the name of the website for which you would like to scan the "
         "ports : \n");
  scanf("%s", address);

  struct addrinfo
      input_hint; // this is basically the input you give in order to get some
                  // result and the following struct is the result
  struct addrinfo *resultant;

  memset(
      &input_hint, 0,
      sizeof(
          input_hint)); // This function sets the memory of input_hint with 0's

  input_hint.ai_family = AF_UNSPEC; // For IPv6 or IPv4

  printf("\nAddress passed to getaddrinfo: %s\n", address);

  int status = getaddrinfo(address, NULL, &input_hint, &resultant);
  // This function returns the data related to the host name in the form of a
  // struct with all ai_flags, ai_family and all
  // This returns the resultant in the form of a linked list of information
  // where the resultant is the head of the linked list

  if (status != 0) {
    printf("Something went wrong with the getaddrinfo !! \n");
    exit(1);
  }
  int count = 1;
  struct addrinfo *temp = resultant;
  while (temp != NULL) {

    char address_string[INET6_ADDRSTRLEN];
    void *addr;
    void *port1;

    if (temp->ai_family == AF_INET) {
      addr = &((struct sockaddr_in *)temp->ai_addr)->sin_addr;

    } else {
      addr = &((struct sockaddr_in6 *)temp->ai_addr)->sin6_addr;
    }

    char x1[11];
    if (temp->ai_socktype == 1) {
      strcpy(x1, "TCP");
    } else if (temp->ai_socktype == 2) {
      strcpy(x1, "UDP");
    } else {
      strcpy(x1, "Raw socket");
    }

    inet_ntop(temp->ai_family, addr, address_string, sizeof(address_string));

    printf("Entry %d: \n", count);
    printf("\tAddress: %s\n", address_string);
    printf("\tType of connection : %s\n", x1);
    temp = temp->ai_next; // This is basically traverssing the linked list
    count++;
  }
  freeaddrinfo(resultant); // This frees up the whole linked list
}
