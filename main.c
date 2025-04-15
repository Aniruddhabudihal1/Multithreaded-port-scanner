#include "head.h"
#include <stdio.h>

void scan_specific_ports(const char *address, int *ports, int num_ports,
                         int num_threads);

int main() {
  int choice;
  printf("Choose an option:\n");
  printf("1. Domain Port Scan\n");
  printf("2. default Local Subnet Scan if you are lazy \n");
  printf("Enter your choice: ");
  scanf("%d", &choice);

  if (choice == 1) {
    domain_parser();
    int no_of_ports;
    int no_of_threads;

    printf("Enter the value of the IP address you would like to scan the port "
           "for:\n");
    char address[WEB_ADDRESS];
    scanf("%s", address);

    printf("Enter the number of ports you would like to scan:\n");
    scanf("%d", &no_of_ports);

    if (no_of_ports <= 0 || no_of_ports > MAX_PORTS) {
      printf("Invalid number of ports. Using a default of 10 common ports.\n");
      int default_ports[] = {21, 22, 23, 25, 80, 443, 3306, 8080, 8443, 9000};
      no_of_ports = 10;

      printf("Enter the number of threads you would like to use (1-100):\n");
      scanf("%d", &no_of_threads);

      if (no_of_threads <= 0 || no_of_threads > MAX_THREADS) {
        no_of_threads = DEFAULT_THREADS;
        printf("As the appropriate number has not been provided a default "
               "value of %d threads is being used\n",
               DEFAULT_THREADS);
      }

      scan_specific_ports(address, default_ports, no_of_ports, no_of_threads);
    } else {
      int port_values[no_of_ports];
      for (int i = 0; i < no_of_ports; i++) {
        printf("Enter the port value number %d to scan: ", i + 1);
        scanf("%d", &port_values[i]);

        if (port_values[i] <= 0 || port_values[i] > 65535) {
          printf("Invalid port number. Using port 80 instead.\n");
          port_values[i] = 80;
        }
      }

      printf("Enter the number of threads you would like to use (1-100):\n");
      scanf("%d", &no_of_threads);

      if (no_of_threads <= 0 || no_of_threads > MAX_THREADS) {
        no_of_threads = DEFAULT_THREADS;
        printf("Using default of %d threads.\n", DEFAULT_THREADS);
      }

      // Use the improved port scanning function
      scan_specific_ports(address, port_values, no_of_ports, no_of_threads);
    }

  } else if (choice == 2) {
    defaultScan();
  } else {
    printf("Select a proper option !! \n");
  }
  return 0;
}
