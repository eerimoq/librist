/* librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#ifndef __SOCKET_SHIM_H
#define __SOCKET_SHIM_H

#ifdef _WIN32

#include <WinSock2.h>
#define _WINSOCKAPI_
#include <Windows.h>
#include <ws2tcpip.h>
#include <stdlib.h>

#define AF_LOCAL AF_UNSPEC

#define SOL_IP 0x0
#define SOL_IPV6 0x29
#define if_nametoindex(name)  atoi(name)

typedef int socklen_t;

#else /* Unix like OSes */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <net/if.h>

#endif

#endif