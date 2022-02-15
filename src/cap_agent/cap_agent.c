/******************************************
 * Filename : tracffic_hook.c
 * Time     : 2021-06-29 01:04
 * Author   : 小骆
 * Dcription: 
*******************************************/
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>

#include <pcap.h>
#include "cap_agent.h"

pcap_t *g_pcap = NULL;

// 统计收到的数据包个数
int packet_num = 0;

/*
 * 函数名：stop_work
 * 功能：信号处理函数回调，接收停止信号，将退出标志置位。
 * 参数：int sig；   传入的信号。
 * 返回值：无
 * */
void stop_work(int sig){
    if(SIGINT == sig){
        if(g_pcap != NULL){
            pcap_breakloop(g_pcap);
        }
    }
    return ;
}

/*
 * 函数名：parse_ip_pkt
 * 功能：解析数据包，主要把IP层的一些数据解析出来。
 * 参数：const u_char *sp; 传入数据报文指针（从IP层处开始）
 *      bpf_u_int32 len;  数据有效长度
 * 返回值：无
 * */
static void parse_ip_pkt(const u_char *sp, bpf_u_int32 len){
    ip_hdr *ih = (ip_hdr*)(sp);
    printf("version:[%d], tcp tot_len:[%u] ttl:[%d], protocol:[%02x]\n",
           ih->version, ntohs(ih->tot_len), ih->ttl, ih->protocol);
    return ;
}

static void Packet_handle(u_char *user, const struct pcap_pkthdr *h, u_char *sp){
    packet_num++;
    pcap_dumper_t *dumper = (pcap_dumper_t *)user;

    bpf_u_int32 len = h->caplen;

    eth_hdr *eh = (eth_hdr*)sp;
    // 解析数据包
    parse_ip_pkt(sp+sizeof(eth_hdr), len - sizeof(eth_hdr));

    // 将数据包写入文件
    pcap_dump(user, h, sp);

    // 刷新
    pcap_dump_flush(dumper);

    return ;
}

//主函数
int main(int argc, char *argv[]){

    int ret = -1;
    //参数校验，需要输入网口名和需要生成pcap数据包文件名字
    if(argc != 3){
        fprintf(stderr, "Usage:\n\t%s interface pcap_file_name \n", argv[0]);
        exit(1);
    }

    /* 注册信号处理函数，接收Ctrl+C停止信号退出循环 */
    signal(SIGINT, stop_work);

    const char *interface_name = argv[1];   //监听的网口名字例如ens33
    const char *pcap_file_name = argv[2];   //需要生成的数据包文件名，以.pcap结尾。

    /* 设置默认参数 */
    int snaplen = 65535;    //设置每个数据包的捕捉长度。
    int promisc = 1;        //是否打开混杂模式
    int to_ms = 1000;       //设置获取数据包的超时时间（ms）
    char ebuf[PCAP_ERRBUF_SIZE] = {0};  //存放错误信息的数组

    // 调用libpcap接口函数
    pcap_t *handle = pcap_open_live(interface_name, snaplen, promisc, to_ms, ebuf);
    if(handle == NULL){
        printf("pcap_open_live failed, %s.\n", ebuf);
        goto ERR;
    }

    printf("pcap_open_live success.\n");
    g_pcap = handle;

    //以下开始开始编译规则
    // 定义一个规则编译结构
    struct bpf_program program;
    /*
     * 以下字符串为规则可以修改
     * port 80     表示抓取监听源端口或者目的端口为80
     * dst port 22 表示抓取监听端口22的数据包
     * dst port 80 and dst port 443 表示监听目的为80和443端口的数据包
     * ....以此类推，具体怎么用可以查libpcap过滤规则怎么写
     * */
    char bpf_buf[512] = "port 80";  //指定抓取80端口的数据包
    int optimize = 0;               //是否需要优化表达式

    //调用libpcap接口对表达式进行编译
    if(pcap_compile(handle, &program, bpf_buf, optimize, 0) != 0){
        printf("pcap");
        goto ERR;
    }
    printf("pcap_compile success.\n");

    //调用libpcap接口设置过滤条件
    if (pcap_setfilter(handle,  &program) != 0){
        printf("pcap_setfilter failed, %s\n");
        goto ERR;
    }
    printf("pcap_setfilter success.\n");

    // 调用libpcap接口函数，获取句柄。
    pcap_dumper_t *dumper = pcap_dump_open(handle, pcap_file_name);
    if(dumper == NULL){
        printf("pcap_dump_open failed\n");
        goto ERR;
    }

    //主循环负责进行数据包的处理
    pcap_loop(handle, 0, Packet_handle, dumper);

    //刷新数据到数据包文件
    pcap_dump_flush(dumper);

    printf("\nStop capture the packet, total:[%d]\n""Program 3s will exit ...\n", packet_num);
    sleep(3);
    ret = 0;

// 释放资源
ERR:
    if(dumper != NULL){
        pcap_dump_close(dumper);
    }

    if (handle != NULL){
        pcap_close(handle);
    }

    return ret;
}
