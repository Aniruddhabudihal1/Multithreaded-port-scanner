#include "head.h"

int main() {
    int choice;
    printf("Choose an option:\n");
    printf("1. Domain Port Scan\n");
    printf("2. Default Local Subnet Scan\n");
    printf("Enter your choice: ");
    scanf("%d", &choice);
    
    if (choice == 1) {
        domain_parser();
    } 
    else if (choice == 2) {
        defaultScan();
    }
    else {
        printf("Invalid option selected.\n");
    }
    
    return 0;
}