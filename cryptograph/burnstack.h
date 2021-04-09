#ifndef BURNSTACK_H
#define BURNSTACK_H

#ifdef USE_STACKCLEAN

void burnstack(int len);

#else

static inline void burnstack(int len) { (void)len; }

#endif

#endif
