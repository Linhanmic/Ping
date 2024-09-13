#include "Ping.h"

Ping* Ping::instance = nullptr;

Ping::Ping(const std::string& target) : target(target), rawsock(0), pid(0), alive(false), packet_send(0), packet_recv(0) {
    instance = this;
    pingPackets.resize(128);
    memset(&dest, 0, sizeof(dest));
}

Ping::~Ping() {
    close(rawsock);
}

void Ping::run() {
    struct hostent* host = nullptr;
    struct protoent* protocol = nullptr;
    char protoname[] = "icmp";
    unsigned long inaddr = 1;
    int size = 128 * 1024;

    protocol = getprotobyname(protoname);
    if (protocol == nullptr) {
        perror("getprotobyname()");
        return;
    }

    rawsock = socket(AF_INET, SOCK_RAW, protocol->p_proto);
    if (rawsock < 0) {
        perror("socket");
        return;
    }

    pid = getuid();
    setsockopt(rawsock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    dest.sin_family = AF_INET;

    inaddr = inet_addr(target.c_str());
    if (inaddr == INADDR_NONE) {
        host = gethostbyname(target.c_str());
        if (host == nullptr) {
            perror("gethostbyname");
            return;
        }
        memcpy((char*)&dest.sin_addr, host->h_addr, host->h_length);
    } else {
        memcpy((char*)&dest.sin_addr, &inaddr, sizeof(inaddr));
    }

    inaddr = dest.sin_addr.s_addr;
    printf("PING %s (%ld.%ld.%ld.%ld) 56(84) bytes of data.\n",
           target.c_str(),
           (inaddr & 0x000000FF) >> 0,
           (inaddr & 0x0000FF00) >> 8,
           (inaddr & 0x00FF0000) >> 16,
           (inaddr & 0xFF000000) >> 24);

    signal(SIGINT, sigintHandler);
    alive = true;

    int err = pthread_create(&send_id, nullptr, sendThread, nullptr);
    if (err < 0) {
        return;
    }
    err = pthread_create(&recv_id, nullptr, recvThread, nullptr);
    if (err < 0) {
        return;
    }

    pthread_join(send_id, nullptr);
    pthread_join(recv_id, nullptr);

    printStatistics();
}

void* Ping::sendThread(void* arg) {
    instance->tv_begin = {0};
    gettimeofday(&instance->tv_begin, nullptr);

    while (instance->alive) {
        int size = 0;
        struct timeval tv;
        gettimeofday(&tv, nullptr);

        PingPacket* packet = instance->findPacket(-1);
        if (packet) {
            packet->seq = instance->packet_send;
            packet->flag = 1;
            gettimeofday(&packet->tv_begin, nullptr);
        }

        instance->packIcmp((struct icmp*)instance->send_buff, instance->packet_send, &tv, 64);
        size = sendto(instance->rawsock, instance->send_buff, 64, 0, (struct sockaddr*)&instance->dest, sizeof(instance->dest));
        if (size < 0) {
            perror("sendto error");
            continue;
        }
        instance->packet_send++;
        sleep(1);
    }
    return nullptr;
}

void* Ping::recvThread(void* arg) {
    struct timeval tv;
    tv.tv_usec = 200;
    tv.tv_sec = 0;
    fd_set readfd;

    while (instance->alive) {
        int ret = 0;
        FD_ZERO(&readfd);
        FD_SET(instance->rawsock, &readfd);
        ret = select(instance->rawsock + 1, &readfd, nullptr, nullptr, &tv);
        switch (ret) {
            case -1:
                break;
            case 0:
                break;
            default: {
                int size = recv(instance->rawsock, instance->recv_buff, sizeof(instance->recv_buff), 0);
                if (errno == EINTR) {
                    perror("recvfrom error");
                    continue;
                }
                ret = instance->unpackIcmp(instance->recv_buff, size);
                if (ret == -1) {
                    continue;
                }
            } break;
        }
    }
    return nullptr;
}

void Ping::sigintHandler(int signo) {
    instance->alive = false;
    gettimeofday(&instance->tv_end, nullptr);
    instance->tv_interval = timeDiff(instance->tv_end, instance->tv_begin);
}

unsigned short Ping::checksum(unsigned char* data, int len) {
    int sum = 0;
    int odd = len & 0x01;

    while (len & 0xfffe) {
        sum += *(unsigned short*)data;
        data += 2;
        len -= 2;
    }

    if (odd) {
        unsigned short tmp = ((*data) << 8) & 0xff00;
        sum += tmp;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return ~sum;
}

struct timeval Ping::timeDiff(struct timeval end, struct timeval begin) {
    struct timeval tv;
    tv.tv_sec = end.tv_sec - begin.tv_sec;
    tv.tv_usec = end.tv_usec - begin.tv_usec;
    if (tv.tv_usec < 0) {
        tv.tv_sec--;
        tv.tv_usec += 1000000;
    }
    return tv;
}

void Ping::packIcmp(struct icmp* icmph, int seq, struct timeval* tv, int length) {
    unsigned char i = 0;
    icmph->icmp_type = ICMP_ECHO;
    icmph->icmp_code = 0;
    icmph->icmp_cksum = 0;
    icmph->icmp_seq = seq;
    icmph->icmp_id = pid & 0xffff;
    for (i = 0; i < length; i++) {
        icmph->icmp_data[i] = i;
    }
    icmph->icmp_cksum = checksum((unsigned char*)icmph, length);
}

int Ping::unpackIcmp(char* buf, int len) {
    int iphdrlen;
    struct ip* ip = nullptr;
    struct icmp* icmp = nullptr;
    int rtt;

    ip = (struct ip*)buf;
    iphdrlen = ip->ip_hl * 4;
    icmp = (struct icmp*)(buf + iphdrlen);
    len -= iphdrlen;

    if (len < 8) {
        printf("ICMP packets' length is less than 8\n");
        return -1;
    }

    if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid)) {
        struct timeval tv_internel, tv_recv, tv_send;
        PingPacket* packet = findPacket(icmp->icmp_seq);
        if (packet == nullptr) {
            return -1;
        }
        packet->flag = 0;
        tv_send = packet->tv_begin;
        gettimeofday(&tv_recv, nullptr);
        tv_internel = timeDiff(tv_recv, tv_send);
        rtt = tv_internel.tv_sec * 1000 + tv_internel.tv_usec / 1000;
        printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%d ms\n",
               len,
               inet_ntoa(ip->ip_src),
               icmp->icmp_seq,
               ip->ip_ttl,
               rtt);

        packet_recv++;
    } else {
        return -1;
    }
    return 0;
}

Ping::PingPacket* Ping::findPacket(int seq) {
    for (auto& packet : pingPackets) {
        if (seq == -1 && packet.flag == 0) {
            return &packet;
        } else if (seq >= 0 && packet.seq == seq) {
            return &packet;
        }
    }
    return nullptr;
}

void Ping::printStatistics() {
    long time = (tv_interval.tv_sec * 1000) + (tv_interval.tv_usec / 1000);
    printf("--- %s ping statistics ---\n", target.c_str());
    printf("%d packets transmitted, %d received, %d%% packet loss, time %ldms\n",
           packet_send,
           packet_recv,
           (packet_send - packet_recv) * 100 / packet_send,
           time);
}
