/******************************************
 * Filename : tracffic_hook.h
 * Time     : 2021-06-29 01:04
 * Author   : 小骆
 * Dcription: 
*******************************************/

#ifndef HERA_PAS_TRACFFIC_HOOK_H
#define HERA_PAS_TRACFFIC_HOOK_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

// x86是小端存储
#ifndef __LITTLE_ENDIAN_BITFIELD
#define __LITTLE_ENDIAN_BITFIELD (1)
#else
#define __LITTLE_ENDIAN_BITFIELD
#endif

//Mac头部，总长度14字节
typedef struct _eth_hdr
{
    unsigned char dstmac[6]; //目标mac地址
    unsigned char srcmac[6]; //源mac地址
    unsigned short eth_type; //以太网类型
}eth_hdr;

/*
 * 0------4------8------------16------------24------------32
 * |  版本 | 头长 | 服务类型      |包裹总长                    |
 * --------------------------------------------------------
 * |        重组标识             |标识   |分片偏移            |
 * --------------------------------------------------------
 * |   生存时间   |     协议      |         头部校验和        |
 * --------------------------------------------------------
 * |                      32位源地址                        |
 * --------------------------------------------------------
 * |                      32位目的地址                      |
 * --------------------------------------------------------
 */
//IP头部，总长度20字节
typedef struct _ip_hdr
{
#ifdef __LITTLE_ENDIAN_BITFIELD
    unsigned char ihl:4;
    unsigned char version:4;
#else
    unsigned char version:4;    //版本
	unsigned char ihl:4;        //首部长度
#endif
    unsigned char tos;          //服务类型
    unsigned short tot_len;     //总长度
    unsigned short id:3;        //标志
    unsigned short frag_off:13; //分片偏移
    unsigned char ttl;          //生存时间
    unsigned char protocol;     //协议
    unsigned short chk_sum;     //检验和
    struct in_addr srcaddr;     //源IP地址
    struct in_addr dstaddr;     //目的IP地址
}ip_hdr;

//TCP头部，总长度20字节
typedef struct _tcp_hdr
{
    unsigned short src_port;    //源端口号
    unsigned short dst_port;    //目的端口号
    unsigned int seq_no;        //序列号
    unsigned int ack_no;        //确认号
#ifdef __LITTLE_ENDIAN_BITFIELD
    unsigned char reserved_1:4; //保留6位中的4位首部长度
    unsigned char thl:4;        //tcp头部长度
    unsigned char flag:6;    //6位标志
	unsigned char reseverd_2:2; //保留6位中的2位
#else
    unsigned char thl:4;        //tcp头部长度
	unsigned char reserved_1:4; //保留6位中的4位首部长度
	unsigned char reseverd_2:2; //保留6位中的2位
	unsigned char flag:6;       //6位标志
#endif
    unsigned short wnd_size;    //16位窗口大小
    unsigned short chk_sum;     //16位TCP检验和
    unsigned short urgt_p;      //16为紧急指针
}tcp_hdr;

//UDP头部，总长度8字节
typedef struct _udp_hdr
{
    unsigned short src_port; //远端口号
    unsigned short dst_port; //目的端口号
    unsigned short uhl;   //udp头部长度
    unsigned short chk_sum; //16位udp检验和
}udp_hdr;

//ICMP头部，总长度4字节
typedef struct _icmp_hdr
{
    unsigned char icmp_type;    //类型
    unsigned char code;         //代码
    unsigned short chk_sum;     //16位检验和
}icmp_hdr;

#endif
