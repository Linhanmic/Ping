#ifndef PING_H
#define PING_H

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>
#include <vector>

/**
 * @brief Ping 类，用于处理 ICMP 回显请求和响应。
 */
class Ping {
public:
    /**
     * @brief Ping 类的构造函数。
     * @param target 目标主机名或 IP 地址。
     */
    Ping(const std::string& target);

    /**
     * @brief Ping 类的析构函数。
     */
    ~Ping();

    /**
     * @brief 运行 ping 过程。
     */
    void run();

private:
    /**
     * @brief 结构体，用于存储 ping 包的信息。
     */
    struct PingPacket {
        struct timeval tv_begin;  // 发送时间
        struct timeval tv_end;    // 接收时间
        short seq;                // 序列号
        int flag;                 // 1 表示已发送但未接收，0 表示已接收
    };

    /**
     * @brief 发送 ICMP 包的线程函数。
     * @param arg 指向参数的指针（未使用）。
     * @return 指向结果的指针（未使用）。
     */
    static void* sendThread(void* arg);

    /**
     * @brief 接收 ICMP 包的线程函数。
     * @param arg 指向参数的指针（未使用）。
     * @return 指向结果的指针（未使用）。
     */
    static void* recvThread(void* arg);

    /**
     * @brief SIGINT 信号的处理函数。
     * @param signo 信号编号。
     */
    static void sigintHandler(int signo);

    /**
     * @brief 计算 ICMP 包的校验和。
     * @param data 指向数据的指针。
     * @param len 数据长度。
     * @return 计算出的校验和。
     */
    static unsigned short checksum(unsigned char* data, int len);

    /**
     * @brief 计算时间差。
     * @param end 结束时间。
     * @param begin 开始时间。
     * @return 时间差。
     */
    static struct timeval timeDiff(struct timeval end, struct timeval begin);

    /**
     * @brief 打包 ICMP 包。
     * @param icmph 指向 ICMP 头部的指针。
     * @param seq 序列号。
     * @param tv 指向 timeval 结构的指针。
     * @param length ICMP 包的长度。
     */
    void packIcmp(struct icmp* icmph, int seq, struct timeval* tv, int length);

    /**
     * @brief 解包 ICMP 包。
     * @param buf 指向缓冲区的指针。
     * @param len 缓冲区长度。
     * @return 成功返回 0，否则返回 -1。
     */
    int unpackIcmp(char* buf, int len);

    /**
     * @brief 根据序列号查找 ping 包。
     * @param seq 序列号。
     * @return 指向 PingPacket 结构的指针。
     */
    PingPacket* findPacket(int seq);

    /**
     * @brief 打印 ping 统计信息。
     */
    void printStatistics();

    std::string target;                // 目标主机名或 IP 地址
    int rawsock;                       // 原始套接字描述符
    pid_t pid;                         // 进程 ID
    bool alive;                        // 活跃标志
    short packet_send;                 // 发送的包数量
    short packet_recv;                 // 接收的包数量
    struct sockaddr_in dest;           // 目的地址
    std::vector<PingPacket> pingPackets; // ping 包的向量
    struct timeval tv_begin, tv_end, tv_interval; // 时间值
    pthread_t send_id, recv_id;        // 线程 ID
    static Ping* instance;             // 静态实例指针
    char send_buff[128];                 // 发送缓冲区
    char recv_buff[128];                 // 接收缓冲区

};

#endif // PING_H
