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
                    printf("Port %d is open on %s\n", port, address);
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
    if (ports_per_thread < 1) ports_per_thread = 1;
    
    printf("Starting multithreaded port scan on %s (ports %d-%d) with %d threads\n", 
           address, start_port, end_port, num_threads);
    
    // Create and start threads
    for (int i = 0; i < num_threads; i++) {
        thread_args[i].start_port = start_port + (i * ports_per_thread);
        
        // Make sure we don't exceed the end_port
        if (i == num_threads - 1) {
            thread_args[i].end_port = end_port;
        } else {
            thread_args[i].end_port = start_port + ((i + 1) * ports_per_thread - 1);
            if (thread_args[i].end_port > end_port) {
                thread_args[i].end_port = end_port;
            }
        }
        
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

// Function to check if a host is up by scanning it (used by defaultScan)
int host_is_up(const char* address, int quick_check) {
    struct timeval timeout;
    timeout.tv_sec = 0;  // Use very short timeout for quick check
    timeout.tv_usec = quick_check ? 100000 : 300000;  // 100ms or 300ms
    
    // Try common ports: 80 (HTTP), 443 (HTTPS), 22 (SSH), 21 (FTP)
    int common_ports[] = {80, 443, 22, 21};
    int num_ports = quick_check ? 1 : sizeof(common_ports) / sizeof(common_ports[0]);
    
    for (int i = 0; i < num_ports; i++) {
        int sock = socketCreate();
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        
        struct sockaddr_in remote = {0};
        remote.sin_addr.s_addr = inet_addr(address);
        remote.sin_family = AF_INET;
        remote.sin_port = htons(common_ports[i]);
        
        if (connect(sock, (struct sockaddr*)&remote, sizeof(struct sockaddr_in)) == 0 || 
            errno == EINPROGRESS) {
            
            fd_set fdset;
            FD_ZERO(&fdset);
            FD_SET(sock, &fdset);
            
            if (select(sock + 1, NULL, &fdset, NULL, &timeout) == 1) {
                int so_error;
                socklen_t len = sizeof(so_error);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
                
                if (so_error == 0) {
                    close(sock);
                    return 1;  // Host is up
                }
            }
        }
        close(sock);
    }
    return 0;  // Host is down
}

// Structure to pass data to sweep threads
typedef struct {
    int thread_id;
    int start_host;
    int end_host;
    int blockOne;
    int blockTwo;
    int blockThree;
    char (*active_hosts)[16];
    int *count;
    pthread_mutex_t *mutex;
} SweepThreadArgs;

// Thread function for ping sweep
void* ping_sweep_thread(void* arg) {
    SweepThreadArgs* data = (SweepThreadArgs*)arg;
    
    for (int host = data->start_host; host <= data->end_host; host++) {
        char ip[16];
        sprintf(ip, "%d.%d.%d.%d", data->blockOne, data->blockTwo, data->blockThree, host);
        
        if (host_is_up(ip, 1)) {  // Quick check
            pthread_mutex_lock(data->mutex);
            if (*(data->count) < 255) {
                strcpy(data->active_hosts[*(data->count)], ip);
                (*(data->count))++;
                printf("Host found: %s\n", ip);
            }
            pthread_mutex_unlock(data->mutex);
        }
    }
    return NULL;
}

// Default scan for subnet with common ports
void defaultScan() {
    printf("Scanning the local subnet for devices...\n");
    printf("This will take some time\n");
    
    // Create vars for IP address generation
    int blockOne = 192;
    int blockTwo = 168;
    int blockThree = 1;
    
    char address[16];
    int num_threads = 8;  // Number of threads for host discovery
    
    // Common ports to scan
    int common_ports[] = {21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080};
    int num_common_ports = sizeof(common_ports) / sizeof(common_ports[0]);
    
    // Get local subnet (optional enhancement)
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    struct hostent *h = gethostbyname(hostname);
    
    if (h != NULL && h->h_addr_list[0] != NULL) {
        struct in_addr addr;
        memcpy(&addr, h->h_addr_list[0], sizeof(struct in_addr));
        char* ip = inet_ntoa(addr);
        
        // Parse IP to get subnet
        sscanf(ip, "%d.%d.%d.%d", &blockOne, &blockTwo, &blockThree, &blockThree);
        // We reset blockThree later if needed
    }
    
    printf("Starting subnet scan from %d.%d.%d.1\n", blockOne, blockTwo, blockThree);
    
    // First, do a quick ping sweep to find active hosts
    printf("Performing quick ping sweep to find active hosts...\n");
    
    char active_hosts[255][16];  // Store active IP addresses
    int active_host_count = 0;
    
    // Ping sweep with multiple threads
    pthread_t sweep_threads[MAX_THREADS];
    SweepThreadArgs sweep_args[MAX_THREADS];
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    
    int hosts_per_thread = 254 / num_threads;
    if (hosts_per_thread < 1) hosts_per_thread = 1;
    
    // Create threads for ping sweep
    for (int i = 0; i < num_threads; i++) {
        sweep_args[i].thread_id = i;
        sweep_args[i].start_host = 1 + (i * hosts_per_thread);
        sweep_args[i].end_host = (i == num_threads - 1) ? 254 : 
                               sweep_args[i].start_host + hosts_per_thread - 1;
        sweep_args[i].blockOne = blockOne;
        sweep_args[i].blockTwo = blockTwo;
        sweep_args[i].blockThree = blockThree;
        sweep_args[i].active_hosts = active_hosts;
        sweep_args[i].count = &active_host_count;
        sweep_args[i].mutex = &mutex;
        
        if (pthread_create(&sweep_threads[i], NULL, ping_sweep_thread, &sweep_args[i]) != 0) {
            perror("Failed to create sweep thread");
            exit(EXIT_FAILURE);
        }
    }
    
    // Wait for all ping sweep threads to complete
    for (int i = 0; i < num_threads; i++) {
        pthread_join(sweep_threads[i], NULL);
    }
    
    printf("Found %d active hosts\n", active_host_count);
    
    // Now scan common ports on active hosts
    printf("Scanning common ports on active hosts...\n");
    
    for (int i = 0; i < active_host_count; i++) {
        printf("Scanning ports on %s\n", active_hosts[i]);
        
        // Create a single thread to scan all common ports
        for (int j = 0; j < num_common_ports; j++) {
            ThreadArgs port_args;
            port_args.start_port = common_ports[j];
            port_args.end_port = common_ports[j];
            port_args.thread_id = 1;
            strncpy(port_args.address, active_hosts[i], WEB_ADDRESS - 1);
            port_args.address[WEB_ADDRESS - 1] = '\0';
            
            port_scan_thread(&port_args);
        }
    }
    
    pthread_mutex_destroy(&mutex);
    printf("Subnet scan completed\n");
}