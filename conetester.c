#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <net/ethernet.h>
#include <string.h>
#include <sys/time.h>
#include <math.h>
#include <sched.h>
#include <sys/un.h>

#define NSEC_PER_SEC    1000000000


#define PKT_BUF_SIZE 1000
#define HDRS_SIZE 40
#define TCP_WIN_SIZE 30000
#define START_SEQ 1000


#define REQUEST  "GET / HTTP/1.1\r\nHost: www.test.com\r\n\r\n"
#define RESPONSE "HTTP/1.1 200 OK\r\n\r\nthis is a test\r\n"

char *start_src_ip;
int num_src_ip;
char *start_dst_ip;
int num_dst_ip;
uint16_t start_src_port;
int num_src_port;
uint16_t start_dst_port;
int num_dst_port;
uint16_t tcp_win_size;
uint32_t start_seq;
char *network;
char *netmask;
long ns_sleep;
long rate, inter_rate, time_to_sec;
long ramp_up_time;
int full_speed = 0;
int test_is_done = 0;
int dont_close = 0;

int syn_sent = 0;
int syn_received = 0;
int syn_ack_sent = 0;
int syn_ack_received = 0;
int ack_sent = 0;
int ack_received = 0;
int request_sent = 0;
int request_received = 0;
int response_sent = 0;
int response_received = 0;
int fin1_sent = 0;
int fin1_received = 0;
int fin2_sent = 0;
int fin2_received = 0;
int last_ack_sent = 0;
int last_ack_received = 0;

int client = 0;

void ctrlc(int sig) {

        if (client) {

        printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
        printf("Current rate: %d\n", inter_rate);
        printf("----------------------------------\n");
        printf("        CLIENT STATS             \n");
        printf("==================================\n");
        printf("SYN_SENT           %d\n", syn_sent);
        printf("----------------------------------\n");
        printf("SYN_ACK_RECEIVED   %d\n", syn_ack_received);
        printf("----------------------------------\n");
        printf("ACK_SENT           %d\n", ack_sent);
        printf("----------------------------------\n");
        printf("REQUEST_SENT       %d\n", request_sent);
        printf("----------------------------------\n");
        printf("RESPONSE_RECEIVED  %d\n", response_received);
        printf("----------------------------------\n");
        printf("FIN1_RECEIVED      %d\n", fin1_received);
        printf("----------------------------------\n");
        printf("FIN2_SENT          %d\n", fin2_sent);
        printf("----------------------------------\n");
        printf("LAST_ACK_RECEIVED  %d\n", last_ack_received);
        printf("----------------------------------\n");
        printf("\n\n");

        }
        else {

        printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
        printf("----------------------------------\n");
        printf("        SERVER STATS             \n");
        printf("==================================\n");
        printf("SYN_RECEIVED       %d\n", syn_received);
        printf("----------------------------------\n");
        printf("SYN_ACK_SENT       %d\n", syn_ack_sent);
        printf("----------------------------------\n");
        printf("ACK_RECEIVED       %d\n", ack_received);
        printf("----------------------------------\n");
        printf("REQUEST_RECEIVED   %d\n", request_received);
        printf("----------------------------------\n");
        printf("RESPONSE_SENT      %d\n", response_sent);
        printf("----------------------------------\n");
        printf("FIN1_SENT          %d\n", fin1_sent);
        printf("----------------------------------\n");
        printf("FIN2_RECEIVED      %d\n", fin2_received);
        printf("----------------------------------\n");
        printf("LAST_ACK_SENT      %d\n", last_ack_sent);
        printf("----------------------------------\n");
        printf("\n\n");

        }

    exit(0);
}

uint16_t tsc(uint16_t len_tcp, uint16_t *src_addr, uint16_t *dest_addr, uint16_t *buff);

uint8_t *build_tcp_syn(uint8_t *buffer, uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport);
uint8_t *build_tcp_syn_ack(uint8_t *buffer);
uint8_t *build_tcp_ack(uint8_t *buffer);
uint8_t *build_request(uint8_t *buffer);
uint8_t *build_response(uint8_t *buffer);
uint8_t *build_1fin(uint8_t *buffer);
uint8_t *build_2fin(uint8_t *buffer);
uint8_t *build_last_ack(uint8_t *buffer);

int create_raw_socket();
int create_pkt_socket();

void *send_syn(void *ptr);
void *responder(void *ptr);
void *print_stats(void *ptr); 

void usage(void);

// !!! This function has been taken from:
// http://rt.wiki.kernel.org/index.php/Squarewave-example
/* the struct timespec consists of nanoseconds
 *  * and seconds. if the nanoseconds are getting
 *   * bigger than 1000000000 (= 1 second) the
 *    * variable containing seconds has to be
 *     * incremented and the nanoseconds decremented
 *      * by 1000000000.
 *       */
static inline void tsnorm(struct timespec *ts)
{
   while (ts->tv_nsec >= NSEC_PER_SEC) {
      ts->tv_nsec -= NSEC_PER_SEC;
      ts->tv_sec++;
   }
}

//convert time in miliseconds to timeval struct
void ms_to_tv (struct timeval *result, long int *ms) {
    result->tv_sec = *ms / 1000;
    result->tv_usec = (*ms % 1000) * 1000;
}


int main(int argc, char* argv[]) {
    pthread_t send_syn_thread, responder_thread, print_stats_thread;
    int ch;
    
    (void) signal(SIGINT, ctrlc);

    start_src_ip = NULL;
    num_src_ip = 1;
    start_dst_ip = NULL;
    num_dst_ip = 1;
    start_src_port = 10000;
    num_src_port = 10;
    start_dst_port = 80;
    num_dst_port = 1;
    tcp_win_size = 30000;
    start_seq = 1000;
    network = NULL;
    netmask = NULL;
    ns_sleep = 1000000000;



    while ((ch = getopt(argc, argv,"CSJs:d:p:n:m:z:x:r:u:b:h")) != -1) {
        switch (ch) {
        case 'C':
            client = 1;
            break;
        case 'S':
            client = 0;
            break;
        case 's':
            start_src_ip = optarg;
            break;
        case 'd':
            start_dst_ip = optarg;
            break;
        case 'p':
            start_src_port = atoi(optarg);
            break;
        case 'n':
            num_src_port = atol(optarg);
            break;
        case 'm':
            num_src_ip = atol(optarg);
            break;
        case 'b':
            num_dst_ip = atol(optarg);
            break;
        case 'z':
            network = optarg;
            break;
        case 'x':
            netmask = optarg;
            break;
        case 'r':
            rate = atol(optarg);
            break;
        case 'u':
            ramp_up_time = atol(optarg);
            break;
        case 'J':
            dont_close = 1;
             break;
        case 'h':
          usage();
            break;
        default:
            usage();
            break;
        }
    }

    if (client == 1) {
        if (pthread_create(&send_syn_thread, NULL, send_syn, NULL) < 0) {
           printf("pthread_create() error");
           exit(-1);
        }
    }  

    if (pthread_create(&responder_thread, NULL, responder, NULL) < 0) {
       printf("pthread_create() error");
       exit(-1);
    }  

    if (pthread_create(&print_stats_thread, NULL, print_stats, NULL) < 0) {
        printf("pthread_create() error");
       exit(-1);
    }



    if (client == 1) {
        pthread_join(send_syn_thread, NULL);
    }

    pthread_join(responder_thread, NULL);

    pthread_join(print_stats_thread, NULL);


    return 0;

}


void *print_stats(void *params) {

    while (1) {

        if (client) {

            printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
            printf("Current rate: %d\n", inter_rate);
            printf("----------------------------------\n");
            printf("        CLIENT STATS             \n");
            printf("==================================\n");
            printf("SYN_SENT           %d\n", syn_sent);
            printf("----------------------------------\n");
            printf("SYN_ACK_RECEIVED   %d\n", syn_ack_received);
            printf("----------------------------------\n");
            printf("ACK_SENT           %d\n", ack_sent);
            printf("----------------------------------\n");
            printf("REQUEST_SENT       %d\n", request_sent);
            printf("----------------------------------\n");
            printf("RESPONSE_RECEIVED  %d\n", response_received);
            printf("----------------------------------\n");
            printf("FIN1_RECEIVED      %d\n", fin1_received);
            printf("----------------------------------\n");
            printf("FIN2_SENT          %d\n", fin2_sent);
            printf("----------------------------------\n");
            printf("LAST_ACK_RECEIVED  %d\n", last_ack_received);
            printf("----------------------------------\n");
            printf("\n\n");
            if (test_is_done) {
                printf("Test is done. Press CTRL+C to exit.\n");
            }

        }
        else {

            printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
            printf("----------------------------------\n");
            printf("        SERVER STATS             \n");
            printf("==================================\n");
            printf("SYN_RECEIVED       %d\n", syn_received);
            printf("----------------------------------\n");
            printf("SYN_ACK_SENT       %d\n", syn_ack_sent);
            printf("----------------------------------\n");
            printf("ACK_RECEIVED       %d\n", ack_received);
            printf("----------------------------------\n");
            printf("REQUEST_RECEIVED   %d\n", request_received);
            printf("----------------------------------\n");
            printf("RESPONSE_SENT      %d\n", response_sent);
            printf("----------------------------------\n");
            printf("FIN1_SENT          %d\n", fin1_sent);
            printf("----------------------------------\n");
            printf("FIN2_RECEIVED      %d\n", fin2_received);
            printf("----------------------------------\n");
            printf("LAST_ACK_SENT      %d\n", last_ack_sent);
            printf("----------------------------------\n");
            printf("\n\n");

        }


        sleep(1);
    }
}


void *responder(void *params) {
    int byte_count;
    socklen_t fromlen;
    struct sockaddr_in saddr, daddr;
    uint8_t *buffer;
    struct in_addr tmpaddr;
    struct iphdr *ipheader;
    struct tcphdr *tcpheader;
    int pkt_socket, raw_socket;

    //!!! taken from:
    //http://rt.wiki.kernel.org/index.php/Squarewave-example
    struct sched_param sch_param;

    //setting realtime priority
    //to this thread
    sch_param.sched_priority = 80;
    if(sched_setscheduler(0, SCHED_FIFO, &sch_param)==-1){
            perror("sched_setscheduler failed");
            pthread_exit(NULL);
    }
    //!!! end of citation



    pkt_socket = create_pkt_socket();
    raw_socket = create_raw_socket();
    
    fromlen = sizeof(saddr);

    buffer = (uint8_t *)malloc(PKT_BUF_SIZE);
    memset((void *)buffer, 0, PKT_BUF_SIZE);
 
 
    while(1) {

        byte_count = recvfrom(pkt_socket, (void *)buffer, PKT_BUF_SIZE, 0, (struct sockaddr *)&saddr, &fromlen);
        if (byte_count == -1) {
            perror("recvfrom() error");
        }

        ipheader = (struct iphdr *)buffer;
        tcpheader = (struct tcphdr *)(buffer + sizeof(struct iphdr));

        
        if (((uint32_t)ipheader->daddr & (uint32_t)inet_addr(netmask)) == (uint32_t)inet_addr(network)) {
            tmpaddr.s_addr = ipheader->saddr;
//            printf("from IP address %s\n", inet_ntoa(tmpaddr));

                if (ipheader->id == htons(1)) {
                    buffer = build_tcp_syn_ack(buffer);

                    daddr.sin_family = AF_INET;
                    daddr.sin_port = tcpheader->dest;
                    daddr.sin_addr.s_addr = ipheader->daddr;

                    syn_received++;

                    if (sendto(raw_socket, buffer, HDRS_SIZE, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr)) < 0) {
                        perror("sendto() error");
                    }
                        
                    syn_ack_sent++;

                }
                else if (ipheader->id == htons(2)) {
                    buffer = build_tcp_ack(buffer);

                    daddr.sin_family = AF_INET;
                    daddr.sin_port = tcpheader->dest;
                    daddr.sin_addr.s_addr = ipheader->daddr;

                    syn_ack_received++;

                    if (sendto(raw_socket, buffer, HDRS_SIZE, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr)) < 0) {
                        perror("sendto() error");
                    }

                    ack_sent++; 

                    buffer = build_request(buffer);

                    if (sendto(raw_socket, buffer, HDRS_SIZE + strlen(REQUEST), 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr)) < 0) {
                        perror("sendto() error");
                    }

                    request_sent++;

                }
                else if (ipheader->id == htons(3)) {
                    ack_received++;
                }
                else if (ipheader->id == htons(4)) {
                    buffer = build_response(buffer);

                    daddr.sin_family = AF_INET;
                    daddr.sin_port = tcpheader->dest;
                    daddr.sin_addr.s_addr = ipheader->daddr;

                    request_received++;

                    if (sendto(raw_socket, buffer, HDRS_SIZE + strlen(RESPONSE), 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr)) < 0) {
                        perror("sendto() error");
                    }

                    response_sent++;
                
                    if (!dont_close) {

                        buffer = build_1fin(buffer);

                        if (sendto(raw_socket, buffer, HDRS_SIZE, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr)) < 0) {
                            perror("sendto() error");
                        }

                        fin1_sent++;
                    }

                }
                else if (ipheader->id == htons(5)) {
                    response_received++;
                }
                else if (ipheader->id == htons(6)) {
                    buffer = build_2fin(buffer);

                    daddr.sin_family = AF_INET;
                    daddr.sin_port = tcpheader->dest;
                    daddr.sin_addr.s_addr = ipheader->daddr;

                    fin1_received++;

                    if (sendto(raw_socket, buffer, HDRS_SIZE, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr)) < 0) {
                        perror("sendto() error");
                    }

                    fin2_sent++;
                }
                else if(ipheader->id == htons(7)) {
                    buffer = build_last_ack(buffer);

                    daddr.sin_family = AF_INET;
                    daddr.sin_port = tcpheader->dest;
                    daddr.sin_addr.s_addr = ipheader->daddr;

                    fin2_received++;

                    if (sendto(raw_socket, buffer, HDRS_SIZE, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr)) < 0) {
                        perror("sendto() error");
                    }

                    last_ack_sent++;
                }
                else if(ipheader->id == htons(8)) {
                    last_ack_received++;
                }

        }
    }
    free(buffer);
    close(raw_socket);
    close(pkt_socket);
}


void *send_syn(void *params) {

    struct sockaddr_in daddr;
    uint8_t *buffer;
    int raw_socket;
    uint32_t saddr, destaddr, start_saddr, start_destaddr, bsaddr, bdestaddr;
    uint16_t sport, dport, start_sport, start_dport, bsport, bdport;
    int nsport, ndport, nsaddr, ndestaddr;
    struct timespec dtime;
    long increase;

    //!!! taken from:
    //http://rt.wiki.kernel.org/index.php/Squarewave-example
    struct sched_param sch_param;

    //setting realtime priority
    //to this thread
    sch_param.sched_priority = 80;
    if(sched_setscheduler(0, SCHED_FIFO, &sch_param)==-1){
            perror("sched_setscheduler failed");
            pthread_exit(NULL);
    }
    //!!! end of citation

    buffer = (uint8_t *)malloc(PKT_BUF_SIZE);
    memset((void *)buffer, 0, PKT_BUF_SIZE);

    raw_socket = create_raw_socket();

    nsaddr = num_src_ip;
    ndestaddr = num_dst_ip;
    nsport = num_src_port;
    ndport = num_dst_port;

    start_saddr = ntohl(inet_addr(start_src_ip));
    start_destaddr = ntohl(inet_addr(start_dst_ip));

    saddr = start_saddr;
    destaddr = start_destaddr;

    start_sport = start_src_port;
    start_dport = start_dst_port;

    sport = start_sport;
    dport = start_dport;

    clock_gettime(0,&dtime);
    /* start after one second */
    dtime.tv_sec++;


    inter_rate = rate / ramp_up_time; 
    increase = inter_rate;
    ns_sleep = 1000000000/inter_rate;
    time_to_sec = inter_rate;

    while(1) {

        bsaddr = htonl(saddr);
        bdestaddr = htonl(destaddr);
        bsport = htons(sport);
        bdport = htons(dport);

        buffer = build_tcp_syn(buffer, bsaddr, bdestaddr, bsport, bdport);
   
        daddr.sin_family = AF_INET;
        daddr.sin_port = bdport;
        daddr.sin_addr.s_addr = bdestaddr;

        clock_nanosleep(0, TIMER_ABSTIME, &dtime, NULL);

        if (sendto(raw_socket, buffer, HDRS_SIZE, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr)) < 0) {
            perror("sendto() error");
        }
        syn_sent++;

        if (!full_speed) {

            if (time_to_sec > 1) {
                time_to_sec--;
            }
            else {
                inter_rate = inter_rate + increase;
                time_to_sec = inter_rate;
                ns_sleep = 1000000000/inter_rate;
                ramp_up_time--;
                printf("ramp_up_time: %d", ramp_up_time);
                if (ramp_up_time == 1) {
                    inter_rate = rate;
                    full_speed = 1;
                }
            }
        }

        dtime.tv_nsec+=ns_sleep;
        tsnorm(&dtime);

        if (destaddr < start_destaddr + ndestaddr - 1) {
            destaddr++;
        }
        else if (saddr < start_saddr + nsaddr - 1 ) {
           saddr++;
           destaddr = start_destaddr;
        }
        else if (sport < start_sport + nsport -1 ) {
            saddr = start_saddr;
            destaddr = start_destaddr;
            sport++;
        } 
        else {
            test_is_done = 1;
            printf("Test is done. Press CTRL+C to exit.\n");
            break;
        }

    }
    free(buffer);
    close(raw_socket);
}

int create_pkt_socket() {
    
    int pkt_socket;

    pkt_socket = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (pkt_socket == -1) {
        perror("socket() error");
        exit(-1);
    }

    return pkt_socket;
}


int create_raw_socket() {
    
    int raw_socket;
    int optval;

    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket == -1) {
        perror("socket() error");
        exit(-1);    
    }

    optval = 1;
    if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("setsockopt() error");
    }

    return raw_socket;
}

uint8_t *build_tcp_syn(uint8_t *buffer, uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport) {

    struct iphdr *ipheader;
    struct tcphdr *tcpheader;

    ipheader = (struct iphdr *)buffer;
    tcpheader = (struct tcphdr *)(buffer + sizeof(struct iphdr));

    ipheader->ihl = 5;
    ipheader->version = 4;
    ipheader->tos = 15;
    ipheader->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ipheader->id = htons(1);
    ipheader->frag_off = 0;
    ipheader->ttl = 64;
    ipheader->protocol = IPPROTO_TCP;
    ipheader->check = 0;
    ipheader->saddr = saddr;
    ipheader->daddr = daddr;

    tcpheader->source = sport;
    tcpheader->dest = dport;
    tcpheader->seq = htonl(START_SEQ);
    tcpheader->ack_seq = 0;
    tcpheader->res1 = 0;
    tcpheader->doff = sizeof(struct tcphdr)/4;
    tcpheader->fin = 0;
    tcpheader->syn = 1;
    tcpheader->rst = 0;
    tcpheader->psh = 0;
    tcpheader->ack = 0;
    tcpheader->urg = 0;
    tcpheader->res2 = 0;
    tcpheader->window = htons(TCP_WIN_SIZE);
    tcpheader->check = 0;
    tcpheader->check = tsc(sizeof(struct tcphdr), (uint16_t *)&ipheader->saddr, (uint16_t *)&ipheader->daddr, (uint16_t *)(buffer+sizeof(struct iphdr)));
    tcpheader->urg_ptr = 0;

    return buffer;

}   

uint8_t *build_tcp_syn_ack(uint8_t *buffer) {

    uint32_t iptmp;
    uint16_t porttmp;
    struct iphdr *ipheader;
    struct tcphdr *tcpheader;

    ipheader = (struct iphdr *)buffer;
    tcpheader = (struct tcphdr *)(buffer + sizeof(struct iphdr));

    ipheader->id = htons(2);
        
    iptmp = ipheader->saddr;
    ipheader->saddr = ipheader->daddr;
    ipheader->daddr = iptmp;

    porttmp = tcpheader->source;
    tcpheader->source = tcpheader->dest;
    tcpheader->dest = porttmp;


    tcpheader->ack = 1;
    tcpheader->ack_seq = htonl(1001);
    tcpheader->check = 0;
    tcpheader->check = tsc(sizeof(struct tcphdr), (uint16_t *)&ipheader->saddr, (uint16_t *)&ipheader->daddr, (uint16_t *)(buffer+sizeof(struct iphdr)));

    return buffer;

}

uint8_t *build_tcp_ack(uint8_t *buffer) {

    uint32_t iptmp;
    uint16_t porttmp;
    struct iphdr *ipheader;
    struct tcphdr *tcpheader;

    ipheader = (struct iphdr *)buffer;
    tcpheader = (struct tcphdr *)(buffer + sizeof(struct iphdr));

    ipheader->id = htons(3);

    iptmp = ipheader->saddr;
    ipheader->saddr = ipheader->daddr;
    ipheader->daddr = iptmp;

    porttmp = tcpheader->source;
    tcpheader->source = tcpheader->dest;
    tcpheader->dest = porttmp;

    tcpheader->syn = 0;
    tcpheader->seq = htonl(1001);
    tcpheader->check = 0;
    tcpheader->check = tsc(sizeof(struct tcphdr), (uint16_t *)&ipheader->saddr, (uint16_t *)&ipheader->daddr, (uint16_t *)(buffer+sizeof(struct iphdr)));

    return buffer;

}

uint8_t *build_request(uint8_t *buffer) {

    struct iphdr *ipheader;
    struct tcphdr *tcpheader;
    char *tcpdata;

    ipheader = (struct iphdr *)buffer;
    tcpheader = (struct tcphdr *)(buffer + sizeof(struct iphdr));

    tcpdata = (char *)(buffer + sizeof(struct iphdr) + sizeof(struct tcphdr));

    ipheader->id = htons(4);

    strcpy(tcpdata, REQUEST);
    tcpheader->check = 0;
    tcpheader->check = tsc(sizeof(struct tcphdr) + strlen(REQUEST), (uint16_t *)&ipheader->saddr, (uint16_t *)&ipheader->daddr, (uint16_t *)(buffer+sizeof(struct iphdr)));

    return buffer;

}

uint8_t *build_response(uint8_t *buffer) {

    uint32_t iptmp;
    uint16_t porttmp;
    uint32_t seqtmp;

    struct iphdr *ipheader;
    struct tcphdr *tcpheader;
    char *tcpdata;

    ipheader = (struct iphdr *)buffer;
    tcpheader = (struct tcphdr *)(buffer + sizeof(struct iphdr));
    tcpdata = (char *)(buffer + sizeof(struct iphdr) + sizeof(struct tcphdr));

    ipheader->id = htons(5);

    iptmp = ipheader->saddr;
    ipheader->saddr = ipheader->daddr;
    ipheader->daddr = iptmp;

    porttmp = tcpheader->source;
    tcpheader->source = tcpheader->dest;
    tcpheader->dest = porttmp;

    seqtmp = tcpheader->seq;
    tcpheader->seq = tcpheader->ack_seq;
    tcpheader->ack_seq = htonl(ntohl(seqtmp) + strlen(REQUEST));


    strcpy(tcpdata, RESPONSE);
    tcpheader->check = 0;
    tcpheader->check = tsc(sizeof(struct tcphdr) + strlen(RESPONSE), (uint16_t *)&ipheader->saddr, (uint16_t *)&ipheader->daddr, (uint16_t *)(buffer+sizeof(struct iphdr)));

    return buffer;
}

uint8_t *build_1fin(uint8_t *buffer) {

    struct iphdr *ipheader;
    struct tcphdr *tcpheader;
    char *tcpdata;

    ipheader = (struct iphdr *)buffer;
    tcpheader = (struct tcphdr *)(buffer + sizeof(struct iphdr));

    ipheader->id = htons(6);

    tcpheader->fin = 1;
    tcpheader->seq = htonl(ntohl(tcpheader->seq) + strlen(RESPONSE));

    tcpheader->check = 0;
    tcpheader->check = tsc(sizeof(struct tcphdr), (uint16_t *)&ipheader->saddr, (uint16_t *)&ipheader->daddr, (uint16_t *)(buffer+sizeof(struct iphdr)));

    return buffer;
}

uint8_t *build_2fin(uint8_t *buffer) {

    uint32_t iptmp;
    uint16_t porttmp;
    uint32_t seqtmp;

    struct iphdr *ipheader;
    struct tcphdr *tcpheader;
    char *tcpdata;

    ipheader = (struct iphdr *)buffer;
    tcpheader = (struct tcphdr *)(buffer + sizeof(struct iphdr));
 
    ipheader->id = htons(7);

    iptmp = ipheader->saddr;
    ipheader->saddr = ipheader->daddr;
    ipheader->daddr = iptmp;

    porttmp = tcpheader->source;
    tcpheader->source = tcpheader->dest;
    tcpheader->dest = porttmp;

    seqtmp = tcpheader->seq;
    tcpheader->seq = tcpheader->ack_seq;
    tcpheader->ack_seq = htonl(ntohl(seqtmp) + 1);

    tcpheader->check = 0;
    tcpheader->check = tsc(sizeof(struct tcphdr), (uint16_t *)&ipheader->saddr, (uint16_t *)&ipheader->daddr, (uint16_t *)(buffer+sizeof(struct iphdr)));

    return buffer;
}

uint8_t *build_last_ack(uint8_t *buffer) {

    uint32_t iptmp;
    uint16_t porttmp;
    uint32_t seqtmp;

    struct iphdr *ipheader;
    struct tcphdr *tcpheader;
    char *tcpdata;

    ipheader = (struct iphdr *)buffer;
    tcpheader = (struct tcphdr *)(buffer + sizeof(struct iphdr));
 
    ipheader->id = htons(8);

    iptmp = ipheader->saddr;
    ipheader->saddr = ipheader->daddr;
    ipheader->daddr = iptmp;

    porttmp = tcpheader->source;
    tcpheader->source = tcpheader->dest;
    tcpheader->dest = porttmp;

    tcpheader->fin = 0;

    seqtmp = tcpheader->seq;
    tcpheader->seq = tcpheader->ack_seq;
    tcpheader->ack_seq = htonl(ntohl(seqtmp) + 1);

    tcpheader->check = 0;
    tcpheader->check = tsc(sizeof(struct tcphdr), (uint16_t *)&ipheader->saddr, (uint16_t *)&ipheader->daddr, (uint16_t *)(buffer+sizeof(struct iphdr)));

    return buffer;
}



// Thanks to http://www.bloof.de/tcp_checksumming
uint16_t tsc(uint16_t len_tcp, uint16_t *src_addr, uint16_t *dest_addr, uint16_t *buff)
{
      
    uint16_t prot_tcp = 6;
    long sum;
    int i;
    uint16_t nleft;
    uint16_t *w;

    sum = 0;
    nleft = len_tcp;
    w = buff;
    
    while(nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if(nleft > 0) {
        sum += *w&ntohs(0xFF00);
    }
   
    /* add the pseudo header */ 
    sum += src_addr[0];
    sum += src_addr[1];
    sum += dest_addr[0];
    sum += dest_addr[1];
    sum += htons(len_tcp); 
    sum += htons(prot_tcp); 
      
   
    // keep only the last 16 bits of the 32 bit calculated sum and add the carries
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += (sum >> 16);
    
    // Take the bitwise complement of sum
    sum = ~sum;

    return ((uint16_t)sum);
}


void usage (void) {
    fprintf(stderr,"Usage: tester OPTIONS\n"
        "-S : Server mode. This instance will not initiate connections.\n"
        "   -z server_network : Enter network address which includes all server IP addresses\n"
        "   -x server_netmask : Enter netmask for the above server network address\n"
        "   -J                : Don't close the connection. There will be no FINs sent. Good for filling up the sesssion table.\n\n\n"
        "-C : Client mode. This instance will initiate connections per specified rate.\n"
        "   -z client_network         : Enter network address which includes all client IP addresses\n"
        "   -x client_netmask         : Enter netmask for the above client network address\n"
        "Client mode only options:\n"
        "   -s start_client_address   : Enter the first client IP address\n"
        "   -m number_of_clients      : Enter number of clients. IP address of each next client will be increased by 1.\n"
        "   -d start_server_address   : Enter the first server IP address\n"
        "   -b number_of_servers      : Enter number of servers. IP address of each next server will be increased by 1.\n"
        "   -p start_client_port      : Enter the first client source TCP port.\n"
        "   -n number_of_client_ports : Enter the number of client ports.\n"
        "   -r connection_rate        : Enter maximum connection rate.\n"
        "   -u ramp_up_time           : Enter time in seconds until maximum connection rate is reached. Each second conn rate will linearly increase until maximum.\n\n"
        "-h help\n\n"
        "Example usage:\n"
        "<1.1.1.1-1.1.1.10>---<192.168.1.1>-<Firewall>-<10.193.16.1>----<2.2.2.1-2.2.2.5>\n"
        "    Clients             Trust                    Untrust           Servers      \n"
        "1. Add routes to firewall interfaces:\n"
        "    On servers linux: route add -net 1.1.1.0/24 gw 10.193.16.1\n"
        "    On clients linux: route add -net 2.2.2.0/24 gw 192.168.1.1\n"
        "\n"
        "2. Start the server on servers linux: \n"
        "    ./tester -S -z 2.2.2.0 -x 255.255.255.0 \n"
        "\n"
        "3. Start the client on clients linux. \n"
        "    ./tester -C -s 1.1.1.1 -m 10 -b 5 -d 2.2.2.1 -p 10000 -n 10 -z 1.1.1.0 -x 255.255.255.0 -r 100 -u 10\n");           
exit(1);
}

