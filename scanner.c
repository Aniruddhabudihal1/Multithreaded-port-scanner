#include "head.h"

short socketCreate(void) {
    short hSocket;
    hSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (hSocket == -1) {
        printf("\nSocket creation failed\n");
        abort();
    }
    return hSocket;
}

int socketConnect(int hSocket, char* address, int serverPort) {
    int iRetval = -1;
    struct sockaddr_in remote = {0};
    remote.sin_addr.s_addr = inet_addr(address);
    remote.sin_family = AF_INET;
    remote.sin_port = htons(serverPort);
    
    iRetval = connect(hSocket, (struct sockaddr*)&remote, sizeof(struct sockaddr_in));
    return iRetval;
}

// Thread function to scan ports
void* port_scan_thread(void* args) {
    ThreadArgs* thread_args = (ThreadArgs*)args;
    char* address = thread_args->address;
    int start_port = thread_args->start_port;
    int end_port = thread_args->end_port;
    int thread_id = thread_args->thread_id;
    
    struct timeval timeout;
    timeout.tv_sec = DEFAULT_TIMEOUT_SEC;
    timeout.tv_usec = DEFAULT_TIMEOUT_USEC;
    
    printf("Thread %d scanning ports %d to %d on %s\n", 
           thread_id, start_port, end_port, address);
    
    for (int port = start_port; port <= end_port; port++) {
        int sock = socketCreate();
        
        // Set socket options for faster timeout
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        
        // Make socket non-blocking
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        
        if (socketConnect(sock, address, port) == 0 || errno == EINPROGRESS) {
            fd_set fdset;
            FD_ZERO(&fdset);
            FD_SET(sock, &fdset);
            
            // Check if connection was successful
            if (select(sock + 1, NULL, &fdset, NULL, &timeout) == 1) {
                int so_error;
                socklen_t len = sizeof(so_error);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
                
                if (so_error == 0) {
                    printf("Port %d is open\n", port);
                }
            }
        }
        
        close(sock);
    }
    
    printf("Thread %d completed scanning\n", thread_id);
    pthread_exit(NULL);
    return NULL;
}

// Function to scan a target with multithreading
void scan_target(const char* address, int start_port, int end_port, int num_threads) {
    pthread_t threads[MAX_THREADS];
    ThreadArgs thread_args[MAX_THREADS];
    
    if (num_threads > MAX_THREADS) {
        num_threads = MAX_THREADS;
        printf("Limiting to maximum of %d threads\n", MAX_THREADS);
    }
    
    int ports_per_thread = (end_port - start_port + 1) / num_threads;
    
    printf("Starting multithreaded port scan on %s (ports %d-%d) with %d threads\n", 
           address, start_port, end_port, num_threads);
    
    // Create and start threads
    for (int i = 0; i < num_threads; i++) {
        thread_args[i].start_port = start_port + (i * ports_per_thread);
        thread_args[i].end_port = (i == num_threads - 1) ? 
                                  end_port : 
                                  start_port + ((i + 1) * ports_per_thread - 1);
        thread_args[i].thread_id = i + 1;
        strncpy(thread_args[i].address, address, WEB_ADDRESS - 1);
        thread_args[i].address[WEB_ADDRESS - 1] = '\0';
        
        if (pthread_create(&threads[i], NULL, port_scan_thread, &thread_args[i]) != 0) {
            perror("Failed to create thread");
            exit(EXIT_FAILURE);
        }
    }
    
    // Wait for all threads to complete
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("Port scan completed on %s\n", address);
}

// Default scan for subnet
void defaultScan() {
    printf("Scanning the local subnet for devices...\n");
    printf("This will take some time\n");
    
    // Create vars for IP address generation
    int blockOne = 192;
    int blockTwo = 168;
    int blockThree = 1;
    int blockFour = 1;
    
    char address[16];
    int num_threads = 5; // Use fewer threads for subnet scanning
    
    // Get local subnet (optional enhancement)
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    struct hostent *h = gethostbyname(hostname);
    
    if (h != NULL && h->h_addr_list[0] != NULL) {
        struct in_addr addr;
        memcpy(&addr, h->h_addr_list[0], sizeof(struct in_addr));
        char* ip = inet_ntoa(addr);
        
        // Parse IP to get subnet
        sscanf(ip, "%d.%d.%d.%d", &blockOne, &blockTwo, &blockThree, &blockFour);
        blockFour = 1; // Start from 1
    }
    
    printf("Starting subnet scan from %d.%d.%d.%d\n", blockOne, blockTwo, blockThree, blockFour);
    
    pthread_t threads[255];
    ThreadArgs thread_args[255];
    int thread_count = 0;
    
    // Scan a fixed range (e.g., 192.168.1.1 to 192.168.1.254)
    for (int host = 1; host <= 254; host++) {
        sprintf(address, "%d.%d.%d.%d", blockOne, blockTwo, blockThree, host);
        
        // Set up arguments for this thread
        thread_args[thread_count].start_port = 80; // Just scan port 80 for hosts by default
        thread_args[thread_count].end_port = 80;
        thread_args[thread_count].thread_id = thread_count + 1;
        strncpy(thread_args[thread_count].address, address, WEB_ADDRESS - 1);
        thread_args[thread_count].address[WEB_ADDRESS - 1] = '\0';
        
        if (pthread_create(&threads[thread_count], NULL, port_scan_thread, &thread_args[thread_count]) != 0) {
            perror("Failed to create thread");
            exit(EXIT_FAILURE);
        }
        
        thread_count++;
        
        // Limit active threads
        if (thread_count % 20 == 0 || host == 254) {
            // Wait for current batch to complete
            for (int i = 0; i < thread_count; i++) {
                pthread_join(threads[i], NULL);
            }
            thread_count = 0;
        }
    }
    
    printf("Subnet scan completed\n");
}
