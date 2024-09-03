#ifndef RING_H_
#define RING_H_
#ifndef _KERNEL
#include <stddef.h>
#include <stdio.h>
#endif

#define volatile_load(x) \
	({ __typeof__(x) ___x = volatile_access(x); ___x; })
#define volatile_store(x, val) \
	do { volatile_access(x) = (val); } while (0)

#ifndef rmb
#define rmb()
#endif
#ifndef wmb
#define wmb()
#endif

#ifdef RING_CONCURRENT
#define volatile_access(x) (*(volatile __typeof__(x) *)&(x))
#else /* !RING_CONCURRENT */
#define volatile_access(x) (*(__typeof__(x) *)&(x))
#undef rmb
#undef wmb
#define rmb()
#define wmb()
#endif

#define RING_INITIALIZER { .r = 0, .w = 0, }

#ifndef nelem
#define	nelem(x) (sizeof(x)/sizeof((x)[0]))
#endif

struct ring_pkt {
	char data[1500];
};

struct ring {
	unsigned int r;
	unsigned int w;
	char buf[1024][2048];
};

static inline void ring_init(struct ring *r)
{
	r->r = 0;
	r->w = 0;
}

static inline unsigned long
ring_mask(const struct ring *r, unsigned long val)
{
	return val & (nelem(r->buf) - 1);
}

static inline unsigned long
ring_len(const struct ring *r)
{
	return r->w - r->r;
}

static inline unsigned long
ring_unused(const struct ring *r)
{
	return nelem(r->buf) - (r->w - r->r);
}

static inline int
ring_full(const struct ring *r)
{
	return ring_len(r) == nelem(r->buf);
}

static inline int
ring_empty(const struct ring *r)
{
	return r->r == r->w;
}

static inline int
ring_put(struct ring *r, const void *p, unsigned int n)
{
	if (ring_full(r))
		return 0;

	memcpy(r->buf[ring_mask(r, r->w)], p, n);
	wmb();
	r->w++;
	return 1;
}

static inline int
ring_get(struct ring *r, void *p, unsigned int n)
{
	if (ring_empty(r))
		return 0;

	memcpy(p, r->buf[ring_mask(r, r->r)], n);
	wmb();
	r->r++;
	return 1;
}

#endif
