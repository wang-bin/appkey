#ifndef LIMB_H
#define LIMB_H

#include <stdint.h>

#include "bitness.h"

#if (USE_64BIT+0)

typedef int64_t limb_t;
typedef __int128_t llimb_t;

#else

typedef int32_t limb_t;
typedef int64_t llimb_t;

#endif


#endif
