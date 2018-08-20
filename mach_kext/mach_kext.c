//
//  mach_kext.c
//  mach_kext
//
//  Created by 徐志强 on 18/8/20.
//  Copyright © 2018年 徐志强. All rights reserved.
//

#include <mach/mach_types.h>

kern_return_t mach_kext_start(kmod_info_t * ki, void *d);
kern_return_t mach_kext_stop(kmod_info_t *ki, void *d);

kern_return_t mach_kext_start(kmod_info_t * ki, void *d)
{
    return KERN_SUCCESS;
}

kern_return_t mach_kext_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}
