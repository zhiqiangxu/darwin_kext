//
//  main.c
//  control_client
//
//  Created by 徐志强 on 18/8/23.
//  Copyright © 2018年 徐志强. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>

#define MYBUNDLEID "com.qtt.xuzhiqiang.gotproxy"

#define TPROXY_ON 1
#define TPROXY_OFF 2

struct TProxyParamUser {
    uint16_t port;
};

int main(int argc, char* argv[]) {
    struct ctl_info ctl_info;
    struct sockaddr_ctl sc;
    
    int sock = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (sock < 0) return -1;
    
    bzero(&ctl_info, sizeof(ctl_info));
    strcpy(ctl_info.ctl_name, MYBUNDLEID);
    
    if (ioctl(sock, CTLIOCGINFO, &ctl_info) == -1) {
        perror("ioctl");
        return -1;
    }
    
    bzero(&sc, sizeof(sc));
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = SYSPROTO_CONTROL;
    sc.sc_id = ctl_info.ctl_id;
    sc.sc_unit = 0;
    
    if (connect(sock, (struct sockaddr*)&sc, sizeof(sc))) return -1;
    
    
    struct TProxyParamUser user_param = {8080};
    int ret = setsockopt(sock, SYSPROTO_CONTROL, TPROXY_ON, &user_param, sizeof(user_param));
    if (ret == -1) {
        perror("setsockopt on");
        return -1;
    }

    ret = setsockopt(sock, SYSPROTO_CONTROL, TPROXY_OFF, NULL, 0);
    if (ret == -1) {
        perror("setsockopt off");
        return -1;
    }

    close(sock);
    
    return 0;
}
