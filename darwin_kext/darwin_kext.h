//
//  darwin_kext.h
//  darwin_kext
//
//  Created by 徐志强 on 18/8/20.
//  Copyright © 2018年 徐志强. All rights reserved.
//

#ifndef darwin_kext_h
#define darwin_kext_h

#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/kern_control.h>
#include <kern/assert.h>
#include <netinet/in.h>
#include "sys/kpi_socketfilter.h"
#include "darwin_kext.h"

#define MYBUNDLEID "com.qtt.xuzhiqiang.gotproxy"

#define TPROXY_ON 1
#define TPROXY_OFF 2

#define GOTPROXY_TCP_FILTER_HANDLE		0x2e33678d

struct TProxyParam {
    int pid;
    uint16_t port;
};

struct TProxyParamUser {
    uint16_t port;
};

#pragma mark Customized printf function
#define LOG(format, ...) do {                      \
printf("[gotproxy2]: " format "\n", ## __VA_ARGS__); \
} while (0)

#endif /* darwin_kext_h */
