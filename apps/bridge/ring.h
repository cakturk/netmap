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

#ifndef __aligned
#define __aligned(x)	__attribute__((aligned(x)))
#endif

struct ring_pkt {
	unsigned int len;
	char data[2040];
};

struct ring {
	volatile unsigned int r __aligned(64);
	volatile unsigned int w __aligned(64);
	struct ring_pkt pkts[1024];
};

static inline void ring_init(struct ring *r)
{
	r->r = 0;
	r->w = 0;
}

static inline unsigned long
ring_mask(const struct ring *r, unsigned long val)
{
	return val & (nelem(r->pkts) - 1);
}

static inline unsigned long
ring_len(const struct ring *r)
{
	return r->w - r->r;
}

static inline unsigned long
ring_unused(const struct ring *r)
{
	return nelem(r->pkts) - (r->w - r->r);
}

static inline int
ring_full(const struct ring *r)
{
	return ring_len(r) == nelem(r->pkts);
}

static inline int
ring_empty(const struct ring *r)
{
	return r->r == r->w;
}

static inline int
ring_put(struct ring *r, const void *p, unsigned int n)
{
	struct ring_pkt *pkt;

	if (ring_full(r))
		return 0;

	pkt = &r->pkts[ring_mask(r, r->w)];
	pkt->len = n;
	memcpy(pkt->data, p, n);
	wmb();
	r->w++;
	return 1;
}

static inline unsigned long
ring_get(struct ring *r, void *p, unsigned int n)
{
	struct ring_pkt *pkt;

	if (ring_empty(r))
		return 0;

	pkt = &r->pkts[ring_mask(r, r->r)];
	if (pkt->len < n)
		n = pkt->len;

	memcpy(p, pkt->data, n);
	wmb();
	r->r++;
	return n;
}

#endif
