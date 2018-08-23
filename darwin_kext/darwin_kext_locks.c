//
//  darwin_kext_locks.c
//  darwin_kext
//
//  Created by 徐志强 on 18/8/22.
//  Copyright © 2018年 徐志强. All rights reserved.
//



// R/W locks
static lck_grp_t *g_lock_grp = NULL;
static lck_rw_t *g_param_lock = NULL;


static errno_t alloc_rwlock(lck_rw_t ** lock_ptr) {
    errno_t retval = 0;
    lck_attr_t * lock_attr = NULL;
    
    
    lock_attr = lck_attr_alloc_init();
    if (NULL == lock_attr)
    {
        LOG("lck_attr_alloc_init() failed");
        retval = ENOMEM;
        goto out;
    }
    
    *lock_ptr = lck_rw_alloc_init(g_lock_grp, lock_attr);
    if (NULL == *lock_ptr)
    {
        LOG("lck_rw_alloc_init() failed");
        retval = ENOMEM;
        goto out;
    }
    
out:
    if (lock_attr)
        lck_attr_free(lock_attr);
    
    return retval;
}

static errno_t init_lock_grp() {
    errno_t result = 0;
    
    // Lock group should be initialized only once.
    assert(NULL == g_lock_grp);
    
    lck_grp_attr_t * lock_grp_attr = lck_grp_attr_alloc_init();
    if (NULL == lock_grp_attr)
    {
        LOG("lck_grp_attr_alloc_init() failed");
        result = ENOMEM;
        goto out;
    }
    
    g_lock_grp = lck_grp_alloc_init("gotproxy", lock_grp_attr);
    if (NULL == g_lock_grp)
    {
        LOG("lck_grp_alloc_init() failed");
        result = ENOMEM;
        goto out;
    }
    
out:
    if (lock_grp_attr)
        lck_grp_attr_free(lock_grp_attr);
    
    return result;
}


static errno_t init_locks() {
    errno_t retval = 0;
    retval = init_lock_grp();
    if (retval) {
        LOG("init_lock_grp error errorno = %d", retval);
        return retval;
    }
    
    retval = alloc_rwlock(&g_param_lock);
    if (retval) {
        LOG("alloc_rwlock error for g_param_lock errorno = %d", retval);
        return retval;
    }
    
    return retval;
}

static void release_locks() {
    if (g_param_lock)
        lck_rw_free(g_param_lock, g_lock_grp);
    
    g_param_lock = NULL;
    
    if (g_lock_grp)
    {
        lck_grp_free(g_lock_grp);
        g_lock_grp = NULL;
    }
}
