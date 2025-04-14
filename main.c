#include "head.h"

int main() {
    int choice;
    printf("Choose an option:\n");
    printf("1. Domain Port Scan\n");
    printf("2. Default Local Subnet Scan\n");
    printf("3. Custom Port Scan\n");
    printf("Enter your choice: ");
    scanf("%d", &choice);
    
    if (choice == 1) {
        domain_parser();
        
        // After parsing domain, get IP to scan
        char address[WEB_ADDRESS];
        printf("\nEnter the IP address from above to scan: ");
        scanf("%s", address);
        
        int start_port = 1;
        int end_port = 1024; // Default: scan well-known ports
        int num_threads = DEFAULT_THREADS;
        
        printf("Enter start port (1-65535): ");
        scanf("%d", &start_port);
        
        printf("Enter end port (1-65535): ");
        scanf("%d", &end_port);
        
        printf("Enter number of threads (1-100): ");
        scanf("%d", &num_threads);
        
        if (start_port < 1) start_port = 1;
        if (end_port > MAX_PORTS) end_port = MAX_PORTS;
        if (num_threads < 1) num_threads = 1;
        if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
        
        scan_target(address, start_port, end_port, num_threads);
    } 
    else if (choice == 2) {
        defaultScan();
    }
    else if (choice == 3) {
        char address[WEB_ADDRESS];
        int start_port, end_port, num_threads;
        
        printf("Enter target IP address: ");
        scanf("%s", address);
        
        printf("Enter start port (1-65535): ");
        scanf("%d", &start_port);
        
        printf("Enter end port (1-65535): ");
        scanf("%d", &end_port);
        
        printf("Enter number of threads (1-100): ");
        scanf("%d", &num_threads);
        
        if (start_port < 1) start_port = 1;
        if (end_port > MAX_PORTS) end_port = MAX_PORTS;
        if (num_threads < 1) num_threads = 1;
        if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
        
        scan_target(address, start_port, end_port, num_threads);
    }
    else {
        printf("Invalid option selected.\n");
    }
    
    return 0;
}
