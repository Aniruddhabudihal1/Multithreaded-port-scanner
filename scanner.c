#include "head.h"

short socketCreate(void) {
  short hSocket;
  hSocket = socket(AF_INET, SOCK_STREAM, 0);
  return hSocket;
}

int socketConnect(int hSocket, char *address, int serverPort) {
  int iRetval = -1;
  struct sockaddr_in remote = {0};
  remote.sin_addr.s_addr = inet_addr(address);
  remote.sin_family = AF_INET;
  remote.sin_port = htons(serverPort);

  iRetval =
      connect(hSocket, (struct sockaddr *)&remote, sizeof(struct sockaddr_in));
  return iRetval;
}

// A functino to scan ports
void *port_scan_thread(void *args) {
  ThreadArgs *thread_args = (ThreadArgs *)args;
  char *address = thread_args->address;
  int start_port = thread_args->start_port;
  int end_port = thread_args->end_port;
  int thread_id = thread_args->thread_id;

  struct timeval timeout;
  timeout.tv_sec = DEFAULT_TIMEOUT_SEC;
  timeout.tv_usec = DEFAULT_TIMEOUT_USEC;

  printf("The thread %d  is scanning from port %d to %d on the address :  %s\n",
         thread_id, start_port, end_port, address);

  for (int port = start_port; port <= end_port; port++) {
    int sock = socketCreate();

    // here we are using the timeout function we had defined earlier to manually
    // set in a timeout for the socket
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // here we are enabling non blockign in order to not make the thread wait
    // for the completion of another thread
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int result = socketConnect(sock, address, port);
    if (result == 0) {
      fd_set fdset;
      FD_ZERO(&fdset); // This initalises all the bits in the file descriptor to
                       // have a value of 0 so that select can act on it
      FD_SET(sock, &fdset); // This sets all of them to 0

      // here the select function Checks if the connection was successful
      if (select(sock + 1, NULL, &fdset, NULL, &timeout) == 1) {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);

        if (so_error == 0) {
          printf("The port %d is OPEN on address: %s\n", port, address);
        }
      }
    }

    close(sock);
  }

  printf("Thread %d has completed scanning\n", thread_id);
  pthread_exit(NULL);
  return NULL;
}

// Improved function to scan a target with multithreading
void scan_target(const char *address, int *ports, int num_ports,
                 int num_threads) {
  pthread_t threads[MAX_THREADS];
  ThreadArgs thread_args[MAX_THREADS];

  if (num_threads > MAX_THREADS) {
    num_threads = MAX_THREADS;
    printf("Limiting to maximum of %d threads\n", MAX_THREADS);
  }

  // Adjust number of threads if there are fewer ports than threads
  if (num_ports < num_threads) {
    num_threads = num_ports;
    printf("Adjusting to %d threads since there are only %d ports\n",
           num_threads, num_ports);
  }

  printf("Starting multithreaded port scan on the address : %s with %d ports "
         "and with %d threads\n",
         address, num_ports, num_threads);

  // Create and start threads
  int ports_per_thread = num_ports / num_threads;
  int extra_ports = num_ports % num_threads;
  int port_index = 0;

  for (int i = 0; i < num_threads; i++) {
    // Calculate how many ports this thread will scan
    int this_thread_ports = ports_per_thread + (i < extra_ports ? 1 : 0);

    if (this_thread_ports == 0) {
      continue; // here we are skipping creating a thread as there are no more
                // ports left to scan
    }

    thread_args[i].thread_id = i + 1;
    strncpy(thread_args[i].address, address, WEB_ADDRESS - 1);
    thread_args[i].address[WEB_ADDRESS - 1] = '\0';

    // Set start and end port for batch scanning
    thread_args[i].start_port = ports[port_index];
    thread_args[i].end_port = ports[port_index];

    pthread_create(&threads[i], NULL, port_scan_thread, &thread_args[i]);
    port_index++;
  }

  // here we  Wait for all threads to complete to proceed further
  for (int i = 0; i < num_threads; i++) {
    if (i < num_ports) { // Only join threads that were created
      pthread_join(threads[i], NULL);
    }
  }

  printf("Port scan completed on %s\n", address);
}

// Simplified scan function for specific ports
void scan_specific_ports(const char *address, int *ports, int num_ports,
                         int num_threads) {
  if (num_threads > MAX_THREADS) {
    num_threads = MAX_THREADS;
  }

  if (num_threads <= 0) {
    num_threads = DEFAULT_THREADS;
  }

  if (num_threads > num_ports) {
    num_threads = num_ports;
  }

  pthread_t threads[MAX_THREADS];
  ThreadArgs thread_args[MAX_THREADS];

  // Determining how many ports each thread will handle
  int ports_per_thread = num_ports / num_threads;
  int remaining_ports = num_ports % num_threads;

  printf("Starting port scannign on the address %s with %d threads\n", address,
         num_threads);

  int port_index = 0;

  // creating threads
  for (int i = 0; i < num_threads; i++) {
    int start_index = port_index;
    int ports_for_this_thread =
        ports_per_thread + (i < remaining_ports ? 1 : 0);

    if (ports_for_this_thread == 0)
      continue;

    int end_index = start_index + ports_for_this_thread - 1;

    // Set up thread arguments
    thread_args[i].thread_id = i + 1;
    strncpy(thread_args[i].address, address, WEB_ADDRESS - 1);
    thread_args[i].address[WEB_ADDRESS - 1] = '\0';
    thread_args[i].start_port = ports[start_index];
    thread_args[i].end_port = ports[end_index];

    // Create thread
    if (pthread_create(&threads[i], NULL, port_scan_thread, &thread_args[i]) !=
        0) {
      perror("Failed to create thread");
      exit(EXIT_FAILURE);
    }
    port_index = end_index + 1;
  }

  // Wait for all threads to complete
  for (int i = 0; i < num_threads; i++) {
    if (i < num_ports) {
      pthread_join(threads[i], NULL);
    }
  }

  printf("Port scan completed on %s\n", address);
}

// Function to check if a host is up by scanning it which is being used by
// defaultScan
int host_is_up(char *address, int quick_check) {
  struct timeval timeout;
  timeout.tv_sec = quick_check ? 0 : 1;
  timeout.tv_usec = quick_check ? 500000 : 0;

  int common_ports[] = {80, 443, 22, 21, 3389, 8080};
  int num_ports =
      quick_check ? 2 : sizeof(common_ports) / sizeof(common_ports[0]);

  for (int i = 0; i < num_ports; i++) {
    int sock = socketCreate();
    if (sock < 0)
      continue;

    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // int flags = fcntl(sock, F_GETFL, 0);
    // fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in remote = {0};
    remote.sin_addr.s_addr = inet_addr(address);
    remote.sin_family = AF_INET;
    remote.sin_port = htons(common_ports[i]);

    if (connect(sock, (struct sockaddr *)&remote, sizeof(struct sockaddr_in)) ==
        0) {
      close(sock);
      return 1; // Host is up
    }
    close(sock);
  }

  if (!quick_check) {
    int sock = socketCreate();
    if (sock >= 0) {
      struct timeval long_timeout;
      long_timeout.tv_sec = 2;
      long_timeout.tv_usec = 0;

      setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &long_timeout,
                 sizeof(long_timeout));
      setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &long_timeout,
                 sizeof(long_timeout));

      struct sockaddr_in remote = {0};
      remote.sin_addr.s_addr = inet_addr(address);
      remote.sin_family = AF_INET;
      remote.sin_port = htons(7);

      int result =
          connect(sock, (struct sockaddr *)&remote, sizeof(struct sockaddr_in));
      close(sock);

      if (result == 0 ||
          (result == -1 && errno != EHOSTUNREACH && errno != ENETUNREACH)) {
        return 1; // host is up
      }
    }
  }

  return 0; // Host is down
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
void *ping_sweep_thread(void *arg) {
  SweepThreadArgs *data = (SweepThreadArgs *)arg;

  for (int host = data->start_host; host <= data->end_host; host++) {
    char ip[16];
    sprintf(ip, "%d.%d.%d.%d", data->blockOne, data->blockTwo, data->blockThree,
            host);

    if (host_is_up(ip, 1)) { // Quick check
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
// Default scan for subnet with common ports
void defaultScan() {
  printf("Scanning the local subnet for devices...\n");
  printf("This will take some time\n");

  // Updated values based on your actual network (172.20.10.x)
  int blockOne = 172;
  int blockTwo = 20;
  int blockThree = 10;

  // Your netmask is 255.255.255.240, which means you only have 16 possible IPs
  // from 172.20.10.0 to 172.20.10.15 (and .0 is network address, .15 is
  // broadcast)
  int start_host = 1;
  int end_host = 14; // Usable range is typically .1 to .14 in a /28 subnet

  int num_threads = 4; // Reduced thread count since we have fewer hosts to scan

  // Common ports to scan
  int common_ports[] = {21,  22,  23,  25,  53,  80,   110,  111,  135,  139,
                        143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080};
  int num_common_ports = sizeof(common_ports) / sizeof(common_ports[0]);

  printf("Starting subnet scan from %d.%d.%d.%d to %d.%d.%d.%d\n", blockOne,
         blockTwo, blockThree, start_host, blockOne, blockTwo, blockThree,
         end_host);

  // First, do a quick ping sweep to find active hosts
  printf("Performing quick ping sweep to find active hosts : \n");

  char active_hosts[16][16]; // Reduced size since we're scanning fewer hosts
  int active_host_count = 0;

  // Ping sweep with multiple threads
  pthread_t sweep_threads[MAX_THREADS];
  SweepThreadArgs sweep_args[MAX_THREADS];
  pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

  int hosts_per_thread = (end_host - start_host + 1) / num_threads;
  if (hosts_per_thread < 1)
    hosts_per_thread = 1;

  // Create threads for ping sweep
  for (int i = 0; i < num_threads; i++) {
    sweep_args[i].thread_id = i;
    sweep_args[i].start_host = start_host + (i * hosts_per_thread);
    sweep_args[i].end_host = (i == num_threads - 1) ? end_host
                                                    : sweep_args[i].start_host +
                                                          hosts_per_thread - 1;
    sweep_args[i].blockOne = blockOne;
    sweep_args[i].blockTwo = blockTwo;
    sweep_args[i].blockThree = blockThree;
    sweep_args[i].active_hosts = active_hosts;
    sweep_args[i].count = &active_host_count;
    sweep_args[i].mutex = &mutex;

    if (pthread_create(&sweep_threads[i], NULL, ping_sweep_thread,
                       &sweep_args[i]) != 0) {
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
    scan_specific_ports(active_hosts[i], common_ports, num_common_ports, 4);
  }

  pthread_mutex_destroy(&mutex);
  printf("Subnet scan completed\n");
}
