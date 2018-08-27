//
//  darwin_kext_filter.c
//  darwin_kext
//
//  Created by 徐志强 on 18/8/22.
//  Copyright © 2018年 徐志强. All rights reserved.
//



typedef struct gotproxy_cookie {
    union {
        struct sockaddr_in	addr4;		/* ipv4 remote addr */
        struct sockaddr_in6	addr6;		/* ipv6 remote addr */
    } remote_addr;
    bool redirected;
} gotproxy_cookie_t;

static errno_t gotproxy_tcp_attach_cb(void ** cookie, socket_t so)
{
    LOG("%d: enter gotproxy_tcp_attach_cb", so);
    // Check proximac mode
    lck_rw_lock_shared(g_param_lock);
    if (proxy_param.pid == 0)
    {
//        LOG("filter is off");
        lck_rw_unlock_shared(g_param_lock);
        return -1;
    }
//    LOG("filter is on");
    
    struct TProxyParam copy_param = proxy_param;
    lck_rw_unlock_shared(g_param_lock);
    
    if (copy_param.pid == proc_selfpid()) {
        return -1;
    }
    
//    LOG("attached");
    
    // Allocate cookie for this socket
    *cookie = _MALLOC(sizeof(gotproxy_cookie_t), M_TEMP, M_WAITOK | M_ZERO);
    if (NULL == *cookie)
    {
        LOG("%d: _MALLOC() error", so);
        return ENOMEM;
    }

    LOG("%d: gotproxy filter has been attached to a socket", so);
    return 0;
}

static void gotproxy_tcp_detach_cb(void * cookie, socket_t so)
{
    // free cookie
    _FREE(cookie, M_TEMP);
    LOG("%d: gotproxy filter has been detached from a socket", so);
}

static errno_t gotproxy_tcp_connect_out_cb(
                            void * cookie,
                            socket_t so,
                            const struct sockaddr * to){
    LOG("%d: enter gotproxy_tcp_connect_out_cb", so);
    gotproxy_cookie_t * gotproxy_cookie = (gotproxy_cookie_t *)cookie;
    
    lck_rw_lock_shared(g_param_lock);
    if (proxy_param.pid == 0)
    {
        lck_rw_unlock_shared(g_param_lock);
        return -1;
    }
    
    struct TProxyParam copy_param = proxy_param;
    lck_rw_unlock_shared(g_param_lock);
    
    // save original address then redirect
    if (to->sa_family == AF_INET) {
        gotproxy_cookie->redirected = true;
        bcopy(to, &(gotproxy_cookie->remote_addr), to->sa_len);
        struct sockaddr_in *remote_addr = (struct sockaddr_in*)to;
        
        // forbid directly access redirector port
        uint32_t redirectorAddr = htonl(INADDR_LOOPBACK);
        in_port_t redirectorPort = htons(copy_param.port);
        if (remote_addr->sin_port == redirectorPort && remote_addr->sin_addr.s_addr == redirectorAddr) {
            LOG("%d: directly access redirector port is forbid!", so);
            return -1;
        }
        
        remote_addr->sin_port = redirectorPort;
        remote_addr->sin_addr.s_addr = redirectorAddr;
    } else if (to->sa_family == AF_INET6) {
        gotproxy_cookie->redirected = true;
        bcopy(to, &(gotproxy_cookie->remote_addr), to->sa_len);
        struct sockaddr_in *remote_addr = (struct sockaddr_in*)to;
        
        // always redirect to ipv4 no matter what
        remote_addr->sin_family = AF_INET;
        remote_addr->sin_len = sizeof(struct sockaddr_in);
        remote_addr->sin_port = htons(copy_param.port);
        remote_addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
    
    
    
    return 0;
}

static	void gotproxy_tcp_notify_cb(void *cookie, socket_t so, sflt_event_t event, void *param) {
    LOG("%d: enter gotproxy_tcp_notify_cb", so);
    
    gotproxy_cookie_t * gotproxy_cookie = (gotproxy_cookie_t *)cookie;
    
    switch (event) {
        case sock_evt_connected:
        {
            unsigned char addrString[256] = {0};
            in_port_t		port;
            struct sockaddr *remote_addr = (struct sockaddr *)&gotproxy_cookie->remote_addr;
            if (remote_addr->sa_family == AF_INET) {
                inet_ntop(AF_INET, &gotproxy_cookie->remote_addr.addr4.sin_addr, (char*) addrString, sizeof(addrString));
                port = ntohs(gotproxy_cookie->remote_addr.addr4.sin_port);
            } else if (remote_addr->sa_family == AF_INET6) {
                addrString[0] = '[';
                inet_ntop(AF_INET, &gotproxy_cookie->remote_addr.addr6.sin6_addr, 1+(char*) addrString, sizeof(addrString)-2);
                size_t len = strlen((const char*)addrString);
                addrString[len] = ']';
                port = ntohs(gotproxy_cookie->remote_addr.addr6.sin6_port);
            }
            
            char addrlen = strlen((char*) addrString);
            LOG("%d: getsockopt addrString %s\n", so, addrString);
            int hdr_len = 1 + addrlen + sizeof(in_port_t);
            char* gotproxy_hdr = _MALLOC(hdr_len, M_TEMP, M_WAITOK| M_ZERO);
            gotproxy_hdr[0] = addrlen;
            memcpy(gotproxy_hdr + 1, addrString, addrlen);
            memcpy(gotproxy_hdr + 1 + addrlen, &port, sizeof(port));
            
            mbuf_t gotproxy_hdr_data = NULL;
            mbuf_t gotproxy_hdr_control = NULL;
            errno_t retval;
            // Allocate a mbuf chain for adding proximac header.
            // Note: default type and flags are fine; don't do further modification.
            retval = mbuf_allocpacket(MBUF_WAITOK, hdr_len, 0, &gotproxy_hdr_data);
            if (retval) {
                LOG("%d: mbuf_allocpacket failed errorno = %d", so, retval);
                goto failure;
            }
            retval = mbuf_copyback(gotproxy_hdr_data, 0, hdr_len, gotproxy_hdr, MBUF_WAITOK);
            if (retval) {
                LOG("%d: mbuf_copyback failed errorno = %d", so, retval);
                goto failure;
            }
            _FREE(gotproxy_hdr, M_TEMP);
            retval = sock_inject_data_out(so, NULL, gotproxy_hdr_data, gotproxy_hdr_control, 0);
            if (retval) {
                LOG("%d: sock_inject_data_out failed errorno = %d", so, retval);
                goto failure;
            }
            break;
        failure:
            sock_close(so);
            return;
        }
        default:
            break;
    }
}

// notify unregistered
void gotproxy_tcp_unregistered_cb (sflt_handle handle) {
    lck_rw_lock_exclusive(g_param_lock);
    kext_filter_unregistered = true;
    lck_rw_unlock_exclusive(g_param_lock);
}

const static struct sflt_filter gotproxy_tcp_filter = {
    GOTPROXY_TCP_FILTER_HANDLE,     /* sflt_handle */
    SFLT_GLOBAL,                    /* sf_flags */
    MYBUNDLEID,                     /* sf_name - cannot be nil else param err results */
    gotproxy_tcp_unregistered_cb,   /* sf_unregistered_func */
    gotproxy_tcp_attach_cb,         /* sf_attach_func - cannot be nil else param err results */
    gotproxy_tcp_detach_cb,         /* sf_detach_func - cannot be nil else param err results */
    gotproxy_tcp_notify_cb,         /* sf_notify_func */
    NULL,                           /* sf_getpeername_func */
    NULL,                           /* sf_getsockname_func */
    NULL,                           /* sf_data_in_func */
    NULL,                           /* sf_data_out_func */
    NULL,                           /* sf_connect_in_func */
    gotproxy_tcp_connect_out_cb,	/* sf_connect_out_func */
    NULL,                           /* sf_bind_func */
    NULL,                           /* sf_setoption_func */
    NULL,                           /* sf_getoption_func */
    NULL,                           /* sf_listen_func */
    NULL                            /* sf_ioctl_func */
};
