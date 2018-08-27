//
//  darwin_kext.c
//  darwin_kext
//
//  Created by 徐志强 on 18/8/20.
//  Copyright © 2018年 徐志强. All rights reserved.
//

#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/kern_control.h>
#include <kern/assert.h>
#include <netinet/in.h>
#include "sys/kpi_socketfilter.h"
#include "darwin_kext.h"

static kern_ctl_ref g_gotproxy_ctl_ref = NULL;

kern_return_t darwin_kext_start(kmod_info_t * ki, void *d);
kern_return_t darwin_kext_stop(kmod_info_t *ki, void *d);
static errno_t install_gotproxy_tcp_filter(int pid, uint16_t port);
static errno_t uninstall_gotproxy_tcp_filter();


static bool kext_stopping_started = false;
static bool kext_filter_unregistered = true;
static struct TProxyParam proxy_param = {0};

#include "darwin_kext_locks.c"

#pragma mark Controller-related functions
static errno_t gotproxy_ctl_setopt_cb(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len);
static errno_t gotproxy_ctl_connect_cb(kern_ctl_ref kctlref, struct sockaddr_ctl *sac, void **unitinfo);


static struct kern_ctl_reg gotproxy_ctl_reg = {
    MYBUNDLEID,				/* use a reverse dns name which includes a name unique to your comany */
    0,						/* set to 0 for dynamically assigned control ID - CTL_FLAG_REG_ID_UNIT not set */
    0,						/* ctl_unit - ignored when CTL_FLAG_REG_ID_UNIT not set */
    0,                      /* privileged access required to access this filter */
    0,						/* use default send size buffer */
    0,						/* use default receive size buffer */
    gotproxy_ctl_connect_cb,/* called when a connection request is accepted (requied field)*/
    NULL,					/* called when a connection becomes disconnected */
    NULL,					/* ctl_send_func - handles data sent from the client to kernel control */
    gotproxy_ctl_setopt_cb,	/* called when the user process makes the setsockopt call */
    NULL	/* called when the user process makes the getsockopt call */
};


static errno_t gotproxy_ctl_connect_cb(kern_ctl_ref kctlref, struct sockaddr_ctl *sac, void **unitinfo) {
    LOG("connected to client");
    return 0;
}

static errno_t gotproxy_ctl_setopt_cb(
                                      kern_ctl_ref kctlref,
                                      u_int32_t unit,
                                      void *unitinfo,
                                      int opt,
                                      void *data,
                                      size_t len)
{
    errno_t retval = 0;
    
    switch (opt) {
        case TPROXY_ON:
            if (len != sizeof(struct TProxyParamUser)) {
                retval = EINVAL;
                break;
            }

            struct TProxyParamUser* param_user = (struct TProxyParamUser*)data;
            retval = install_gotproxy_tcp_filter(proc_selfpid(), param_user->port);
            break;
        case TPROXY_OFF:
            retval = uninstall_gotproxy_tcp_filter();
            break;
        default:
            retval = EINVAL;
            break;
    }
    return retval;
}

static errno_t install_controller() {
    errno_t retval = 0;

    retval = init_locks();
    if (retval) {
        LOG("init_locks failed errorno = %d",retval);
        return retval;
    }
    
    if (g_gotproxy_ctl_ref) {
        LOG("gotproxy controller is already installed");
        return retval;
    }
    
    retval = ctl_register(&gotproxy_ctl_reg, &g_gotproxy_ctl_ref);
    
    if (0 == retval) {
        LOG("Controller has been installed successfully");
    } else {
        LOG("ctl_register failed errorno = %d",retval);
        release_locks();
    }
    
    return retval;
}

static errno_t uninstall_controller() {
    errno_t retval = 0;
    
    if (g_gotproxy_ctl_ref) {
        retval = ctl_deregister(g_gotproxy_ctl_ref);
        if (retval)
        {
            LOG("ctl_deregister() error errorno = %d", retval);
        }
        else
        {
            g_gotproxy_ctl_ref = NULL;
            LOG("gotproxy controller has been unregistered.");
        }
    }
    else
    {
        LOG("gotproxy controller has not been registered.");
    }
    
    return retval;
}


#include "darwin_kext_filter.c"

static errno_t install_gotproxy_tcp_filter(int pid, uint16_t port) {
    lck_rw_lock_exclusive(g_param_lock);
    if (kext_stopping_started) {
        LOG("gotproxy kext is being stopped");
        lck_rw_unlock_exclusive(g_param_lock);
        return EINVAL;
    }
    if (proxy_param.pid != 0 || proxy_param.port != 0) {
        LOG("gotproxy filter is already installed");
        lck_rw_unlock_exclusive(g_param_lock);
        return EINVAL;
    }
    proxy_param.pid = pid;
    proxy_param.port = port;
    
    errno_t retval = 0;
    
    retval = sflt_register(&gotproxy_tcp_filter, PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (retval) {
        proxy_param.pid = 0;
        proxy_param.port = 0;
        LOG("sflt_register error errorno = %d", retval);
    } else {
        LOG("sflt_register ok, pid = %d, port = %d", pid, port);
        kext_filter_unregistered = false;
    }
    
    lck_rw_unlock_exclusive(g_param_lock);

    return retval;
}

static errno_t uninstall_gotproxy_tcp_filter() {
    
    LOG("uninstall_gotproxy_tcp_filter enter");
    
    lck_rw_lock_shared(g_param_lock);
    
    LOG("uninstall_gotproxy_tcp_filter locked");
    
    if (proxy_param.pid == 0) {
        lck_rw_unlock_shared(g_param_lock);
        return 0;
    }
    lck_rw_unlock_shared(g_param_lock);
    
    LOG("uninstall_gotproxy_tcp_filter before sflt_unregister");
    errno_t retval = sflt_unregister(GOTPROXY_TCP_FILTER_HANDLE);
    if (retval) {
        LOG("sflt_unregister error errorno = %d", retval);
    } else {
        lck_rw_lock_exclusive(g_param_lock);
        proxy_param.pid = 0;
        proxy_param.port = 0;
        lck_rw_unlock_exclusive(g_param_lock);
        LOG("sflt_unregister ok");
    }
    
    LOG("uninstall_gotproxy_tcp_filter done");
    
    return retval;
}

kern_return_t darwin_kext_start(kmod_info_t * ki, void *d)
{
    errno_t retval = 0;

    retval = install_controller();
    if (retval) {
        LOG("controller install error = %d", retval);
        return KERN_FAILURE;
    }
    
    return KERN_SUCCESS;
    
}

kern_return_t darwin_kext_stop(kmod_info_t *ki, void *d)
{
    lck_rw_lock_exclusive(g_param_lock);
    kext_stopping_started = true;
    lck_rw_unlock_exclusive(g_param_lock);
    
    errno_t retval = 0;
    
    // uninstall filter
    retval = uninstall_gotproxy_tcp_filter();
    if (retval) {
        LOG("uninstall gotproxy filters error errorno = %d", retval);
        goto failure;
    }
    
    // wait for filter unregistered
    lck_rw_lock_exclusive(g_param_lock);
    if (!kext_filter_unregistered) {
        LOG("wait for kext_filter_unregistered");
        lck_rw_unlock_exclusive(g_param_lock);
        goto failure;
    }
    
    // uninstall controller
    retval = uninstall_controller();
    lck_rw_unlock_exclusive(g_param_lock);
    if (retval) {
        LOG("uninstall gotproxy controller error errorno = %d", retval);
        goto failure;
    }
    
    release_locks();
    LOG("gotproxy kext is now removed");
    return KERN_SUCCESS;
    
failure:
    return KERN_FAILURE;

}
