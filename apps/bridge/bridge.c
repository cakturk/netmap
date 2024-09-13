/*
 * (C) 2011-2014 Luigi Rizzo, Matteo Landi
 *
 * BSD license
 *
 * A netmap application to bridge two network interfaces,
 * or one interface and the host stack.
 *
 * $FreeBSD$
 */

#include <libnetmap.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "uinet_queue.h"
#include "ring.h"

#define eth_hdr(p) (struct ether_header *)((unsigned char *)p)
#define ip_hdr(p) (struct ip *)((unsigned char *)p)
#define tcp_hdr(p) (struct tcphdr *)((unsigned char *)p)
#define udp_hdr(p) (struct udphdr *)((unsigned char *)p)

#define __unused __attribute__((__unused__))

struct ifpair;
struct pkt_port;
struct shm_struct;

static void prepare_poll(struct ifpair *ifp);
static void do_poll(struct ifpair *ifp, u_int burst,
		    struct shm_struct *shm,
		    const char *msg_a2b,
		    const char *msg_b2a);

struct poll_port {
	struct nmport_d *nmport;
	struct pollfd *pfd;
};

struct ifpair {
	struct poll_port first;
	struct poll_port second;
	int first_index;
	int second_index;
};

struct netports {
	uint16_t sport;
	uint16_t dport;
};

static inline struct netports *to_netports(const void *vp)
{
	unsigned char *p = (unsigned char *)vp;
	return (struct netports *)(p);
}

static inline int ip_hdrlen(struct ip *ih)
{
	return ih->ip_hl * 4;
}

static void
die(const char *fmt, ...)
{
	va_list params;

	va_start(params, fmt);
	vfprintf(stderr, fmt, params);
	va_end(params);
}

static pid_t fork_or_die(void)
{
	pid_t pid;

	switch ((pid = fork())) {
	case 0:
		break;
	case -1:
		die("unable to fork: %s", strerror(errno));
	default:
	}
	return pid;
}

#if defined(_WIN32)
#define BUSYWAIT
#endif

static int verbose = 0;

static int do_abort = 0;
static int zerocopy = 1; /* enable zerocopy if possible */

static void
sigint_h(int sig)
{
	(void)sig;	/* UNUSED */
	do_abort = 1;
	signal(SIGINT, SIG_DFL);
}


/*
 * How many slots do we (user application) have on this
 * set of queues ?
 */
static int
rx_slots_avail(struct nmport_d *d)
{
	u_int i, tot = 0;

	for (i = d->first_rx_ring; i <= d->last_rx_ring; i++) {
		tot += nm_ring_space(NETMAP_RXRING(d->nifp, i));
	}

	return tot;
}

struct flow {
	UINET_LIST_ENTRY(flow) hash_link;
	struct in_addr *saddr, *daddr;
	uint16_t sport, dport;
	uint8_t proto;
};

UINET_LIST_HEAD(flow_head, flow);
static struct flow_head __unused tcp_tbl[1 << 10];
static struct flow_head __unused udp_tbl[1 << 10];

#define nelems(x) (sizeof(x) / sizeof((x)[0]))

static unsigned long flowhash(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport)
{
	unsigned long sum;

	sum = sip * 97 ^ dip * 97 ^ sport * 97 ^ dport * 97;
	return sum;
}

static void __unused flow_add(struct flow_head *fh, struct flow *f)
{
	unsigned long hash = flowhash(f->saddr->s_addr, f->daddr->s_addr,
				      f->sport, f->dport);
	struct flow_head *bkt = &fh[hash & (nelems(tcp_tbl) - 1)];

	UINET_LIST_INSERT_HEAD(bkt, f, hash_link);
}

static int
tx_slots_avail(struct nmport_d *d)
{
	u_int i, tot = 0;

	for (i = d->first_tx_ring; i <= d->last_tx_ring; i++) {
		tot += nm_ring_space(NETMAP_TXRING(d->nifp, i));
	}

	return tot;
}

#define FRAME_SIZE 1500
#define BUFFER_SIZE 10
#define NUM_ITEMS 20

typedef struct {
	int buffer[FRAME_SIZE*1024];
	int count;
	int in;
	int out;
	pthread_mutex_t mutex;
	pthread_cond_t not_empty;
	pthread_cond_t not_full;
} shared_data_t;

struct pkt_ring {
	char p_name[16];
	pthread_mutex_t p_mtx;
	pthread_cond_t p_wake;
	struct ring p_ring;
	struct netmap_ring *p_nmring;
};

/*
 * pkt_port type represents the hardware and software ring pair in
 * netmap jargon. For example, the hardware pkt_port structure holds the
 * data required for packets coming from (rx) and going to (tx) the
 * network adapter.
 */
struct pkt_port {
	struct pkt_ring pi_tx;
	struct pkt_ring pi_rx;
};

/*
 * shm_struct type represents netmap hardware and software interfaces.
 */
struct shm_struct {
	struct pkt_port s_pa;
	struct pkt_port s_pb;
};

static void
pkt_ring_init(struct pkt_ring *pr, int isrx, int ringnum)
{
	pthread_mutexattr_t mutex_attr;
	pthread_condattr_t cond_attr;

	snprintf(pr->p_name, sizeof(pr->p_name), "%s nmr %u",
		 isrx ? "rx" : "tx", ringnum);

	pthread_mutexattr_init(&mutex_attr);
	pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED);
	pthread_mutexattr_setrobust(&mutex_attr, PTHREAD_MUTEX_ROBUST);
	pthread_mutex_init(&pr->p_mtx, &mutex_attr);

	pthread_condattr_init(&cond_attr);
	pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED);
	pthread_cond_init(&pr->p_wake, &cond_attr);

	ring_init(&pr->p_ring);
}

static void
pkt_ring_wake(struct pkt_ring *pr)
{
	pthread_cond_signal(&pr->p_wake);
}

static void
pkt_ring_wait(struct pkt_ring *pr)
{
	pthread_mutex_lock(&pr->p_mtx);
	while (ring_len(&pr->p_ring) <= 0) {

		printf("%s: sleeping\n", __func__);
		pthread_cond_wait(&pr->p_wake, &pr->p_mtx);
		printf("%s: woken up\n", __func__);
	}
	pthread_mutex_unlock(&pr->p_mtx);
}

static void *
mem_init(int nconsumer)
{
	struct shm_struct *shm;
	int fd;

	if ((fd = shm_open("/pkt_memory", O_CREAT | O_RDWR, 0666)) < 0)
		die("failed to shm_open\n");
	if (ftruncate(fd, sizeof(*shm) * nconsumer) != 0)
		die("failed to ftruncate\n");
	shm = mmap(NULL, sizeof(*shm) * nconsumer,
		      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (shm == MAP_FAILED)
		die("%s: failed to mmap shared mem\n", __func__);
	close(fd);

	pkt_ring_init(&shm->s_pa.pi_tx, 0, 0);
	pkt_ring_init(&shm->s_pb.pi_rx, 1, 1);

	return shm;
}

static void
mem_destroy(void *shmem, int nrconsumer)
{
	struct pkt_ring *shring;

	shring = shmem;
	pthread_mutex_destroy(&shring->p_mtx);
	pthread_cond_destroy(&shring->p_wake);
	munmap(shring, sizeof(struct pkt_ring) * 2 * nrconsumer);
	shm_unlink("/pkt_memory");
}

static void parent_proc(void *shdata)
{
	char buf[1500];
	int got;
	struct pkt_port *ipr = shdata;
	struct ring *r = &ipr->pi_rx.p_ring;

	printf("parent running %d\n", getpid());
	printf("ring len: tx %lu rx %lu\n", ring_len(&ipr->pi_rx.p_ring), ring_len(&ipr->pi_tx.p_ring));

	pthread_mutex_lock(&ipr->pi_rx.p_mtx);
	while (ring_len(&ipr->pi_rx.p_ring) <= 0) {
		pthread_cond_wait(&ipr->pi_rx.p_wake, &ipr->pi_rx.p_mtx);
	}
	pthread_mutex_unlock(&ipr->pi_rx.p_mtx);
	got = ring_get(r, buf, 16);
	printf("parent: parent woken up got %d '%.*s'\n", got, 17, buf);
}

static void child_proc(void *shdata)
{
	struct pkt_port *ipr = shdata;
	struct ring *r = &ipr->pi_rx.p_ring;

	ring_put(r, "this is message", 16);
	/* strcpy(p, "this is message"); */
	printf("child: wake parent\n");
	pthread_mutex_lock(&ipr->pi_rx.p_mtx);
	pthread_cond_signal(&ipr->pi_rx.p_wake);
	pthread_mutex_unlock(&ipr->pi_rx.p_mtx);
}

static void pkt_port_init(struct pkt_port *p, struct nmport_d *nmp)
{
	p->pi_tx.p_nmring = NETMAP_RXRING(nmp->nifp, nmp->first_rx_ring);
	p->pi_rx.p_nmring = NETMAP_RXRING(nmp->nifp, nmp->first_tx_ring);
}

static void producer_proc(void *shdata, const char *ifa, const char *ifb)
{
	struct shm_struct *shm = shdata;
	char msg_a2b[256], msg_b2a[256];
	struct pollfd pollfd[2];
	u_int burst = 1024, wait_link = 4;
	struct nmport_d *pa = NULL, *pb = NULL;
	int pa_sw_rings, pb_sw_rings;
	int nifps = 0;

	pa = nmport_open(ifa);
	if (pa == NULL) {
		D("cannot open %s", ifa);
		exit(1);
	}
	/* try to reuse the mmap() of the first interface, if possible */
	pb = nmport_open(ifb);
	if (pb == NULL) {
		D("cannot open %s", ifb);
		nmport_close(pa);
		exit(1);
	}

	pkt_port_init(&shm->s_pa, pa);
	pkt_port_init(&shm->s_pb, pb);

	zerocopy = zerocopy && (pa->mem == pb->mem);
	D("------- zerocopy %ssupported", zerocopy ? "" : "NOT ");

	/* setup poll(2) array */
	memset(pollfd, 0, sizeof(pollfd));
	pollfd[0].fd = pa->fd;
	pollfd[1].fd = pb->fd;
	struct ifpair ifps[] = {
		{
			.first = {
				.nmport = pa,
				.pfd = &pollfd[0],
			},
			.second = {
				.nmport = pb,
				.pfd = &pollfd[1],
			},
		},
	};
	nifps = 1;

	D("Wait %d secs for link to come up...", wait_link);
	/* sleep(wait_link); */
	D("Ready to go, %s 0x%x/%d <-> %s 0x%x/%d.",
		pa->hdr.nr_name, pa->first_rx_ring, pa->reg.nr_rx_rings,
		pb->hdr.nr_name, pb->first_rx_ring, pb->reg.nr_rx_rings);

	pa_sw_rings = (pa->reg.nr_mode == NR_REG_SW ||
	    pa->reg.nr_mode == NR_REG_ONE_SW);
	pb_sw_rings = (pb->reg.nr_mode == NR_REG_SW ||
	    pb->reg.nr_mode == NR_REG_ONE_SW);

	snprintf(msg_a2b, sizeof(msg_a2b), "%s:%s --> %s:%s",
			pa->hdr.nr_name, pa_sw_rings ? "host" : "nic",
			pb->hdr.nr_name, pb_sw_rings ? "host" : "nic");

	snprintf(msg_b2a, sizeof(msg_b2a), "%s:%s --> %s:%s",
			pb->hdr.nr_name, pb_sw_rings ? "host" : "nic",
			pa->hdr.nr_name, pa_sw_rings ? "host" : "nic");

	/* main loop */
	signal(SIGINT, sigint_h);
	while (!do_abort) {
		int ret, i;

		for (i = 0; i < nifps; i++)
			prepare_poll(&ifps[i]);
#ifdef BUSYWAIT
		ret = 1;
#else  /* !defined(BUSYWAIT) */
		ret = poll(pollfd, 2, 2500);
#endif /* !defined(BUSYWAIT) */
		if (ret <= 0)
		if (ret <= 0 || verbose)
		    D("poll %s [0] ev %x %x rx %d@%d tx %d,"
			     " [1] ev %x %x rx %d@%d tx %d",
				ret <= 0 ? "timeout" : "ok",
				pollfd[0].events,
				pollfd[0].revents,
				rx_slots_avail(pa),
				NETMAP_RXRING(pa->nifp, pa->cur_rx_ring)->head,
				tx_slots_avail(pa),
				pollfd[1].events,
				pollfd[1].revents,
				rx_slots_avail(pb),
				NETMAP_RXRING(pb->nifp, pb->cur_rx_ring)->head,
				tx_slots_avail(pb)
			);
		if (ret < 0)
			continue;
		for (i = 0; i < nifps; i++)
			do_poll(&ifps[i], burst, shm, msg_a2b, msg_b2a);
	}
	nmport_close(pb);
	nmport_close(pa);
}

static void print_pkt(char *rxbuf, const char *msg, uint16_t rx_ring,
		      uint16_t tx_ring)
{
	struct ether_header *eh;
	struct ip *ih = NULL;
	struct netports *np = NULL;
	char sbuf[INET_ADDRSTRLEN], dbuf[INET_ADDRSTRLEN];
	int proto = 0;
	uint8_t *sh, *dh;

	if (!verbose)
		return;

	eh = eth_hdr(rxbuf);
	sh = eh->ether_shost;
	dh = eh->ether_dhost;
	switch (ntohs(eh->ether_type)) {
	case ETHERTYPE_IP:
		ih = ip_hdr(rxbuf + sizeof(*eh));
		inet_ntop(AF_INET, &ih->ip_src, sbuf, sizeof(sbuf));
		inet_ntop(AF_INET, &ih->ip_dst, dbuf, sizeof(dbuf));
		switch (ih->ip_p) {
		case IPPROTO_TCP:
			proto++;
			/* fallthrough */
		case IPPROTO_UDP:
			proto++;
			np = to_netports(rxbuf + sizeof(*eh) + ip_hdrlen(ih));
			break;
		default:
			return;
		}
		break;
	default:
		return;
	}
	printf("pkt: %s ring ( id %u -> %u ) %s%x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x"
	       " %s:%u -> %s:%u\n",
	       msg, rx_ring, tx_ring,
	       proto == 1 ? "udp " : proto == 2 ? "tcp " : "n/a",
	       sh[0], sh[1], sh[2], sh[3], sh[4], sh[5],
	       dh[0], dh[1], dh[2], dh[3], dh[4], dh[5],
	       sbuf, ntohs(np->sport), dbuf, ntohs(np->dport));
}

static void *producer_receive(void *shdata)
{
	struct pkt_port *ipr = shdata;

	printf("producer receive\n");
	return NULL;
}

static void consumer_proc(void *shdata)
{
	struct pkt_port *ipr = shdata;
	struct ring *r = &ipr->pi_rx.p_ring;
	struct ring *x = &ipr->pi_tx.p_ring;

	for (;;) {
		unsigned long len;
		char p[2048];


		pthread_mutex_lock(&ipr->pi_rx.p_mtx);
		while (ring_len(&ipr->pi_rx.p_ring) <= 0) {
			printf("%s: sleeping\n", __func__);
			pthread_cond_wait(&ipr->pi_rx.p_wake, &ipr->pi_rx.p_mtx);
			printf("%s: woken up\n", __func__);
		}
		pthread_mutex_unlock(&ipr->pi_rx.p_mtx);

		len = ring_get(r, p, sizeof(p));
		printf("%s: ring get %lu\n", __func__, len);
		if (!len)
			continue;
		ring_put(x, p, len);
		print_pkt(p, "consumer", 0, 0);
	}
}

/*
 * Move up to 'limit' pkts from rxring to txring, swapping buffers
 * if zerocopy is possible. Otherwise fall back on packet copying.
 */
static int
rings_move(struct netmap_ring *rxring, struct netmap_ring *txring,
	   struct shm_struct *shm, u_int limit, const char *msg)
{
	u_int j, k, m = 0;

	/* print a warning if any of the ring flags is set (e.g. NM_REINIT) */
	if (rxring->flags || txring->flags)
		D("%s rxflags %x txflags %x",
		    msg, rxring->flags, txring->flags);
	j = rxring->head; /* RX */
	k = txring->head; /* TX */
	m = nm_ring_space(rxring);
	if (m < limit)
		limit = m;
	m = nm_ring_space(txring);
	if (m < limit)
		limit = m;
	m = limit;
	while (limit-- > 0) {
		struct netmap_slot *rs = &rxring->slot[j];
		struct netmap_slot *ts = &txring->slot[k];

		if (ts->buf_idx < 2 || rs->buf_idx < 2) {
			RD(2, "wrong index rxr[%d] = %d  -> txr[%d] = %d",
			    j, rs->buf_idx, k, ts->buf_idx);
			sleep(2);
		}
		/* Copy the packet length. */
		if (rs->len > rxring->nr_buf_size) {
			RD(2,  "%s: invalid len %u, rxr[%d] -> txr[%d]",
			    msg, rs->len, j, k);
			rs->len = 0;
		} else if (verbose > 1) {
			D("%s: fwd len %u, rx[%d] -> tx[%d]",
			    msg, rs->len, j, k);
		}
		ts->len = rs->len;
		if (zerocopy) {
			char *rxbuf = NETMAP_BUF(rxring, rs->buf_idx);
			uint32_t pkt = ts->buf_idx;

			ts->buf_idx = rs->buf_idx;
			rs->buf_idx = pkt;
			/* report the buffer change. */
			ts->flags |= NS_BUF_CHANGED;
			rs->flags |= NS_BUF_CHANGED;
			print_pkt(rxbuf, msg, rxring->ringid, txring->ringid);
		} else {
			char *txbuf = NETMAP_BUF(txring, ts->buf_idx);
			char *rxbuf = NETMAP_BUF(rxring, rs->buf_idx);
			struct ring *r = &shm->s_pa.pi_rx.p_ring;
			struct ring *x = &shm->s_pa.pi_tx.p_ring;
			unsigned long len = 33;

			ring_put(r, rxbuf, ts->len);
			len = ring_get(r, txbuf, ts->len);
			/* printf("tx ring get len %lu %lu\n", len, ring_len(x)); */
			print_pkt(rxbuf, msg, rxring->ringid, txring->ringid);
			/* pkt_ring_wake(&ipr->pi_rx); */
			/* nm_pkt_copy(p, txbuf, ts->len); */
		}
		/*
		 * Copy the NS_MOREFRAG from rs to ts, leaving any
		 * other flags unchanged.
		 */
		ts->flags = (ts->flags & ~NS_MOREFRAG) | (rs->flags & NS_MOREFRAG);
		j = nm_ring_next(rxring, j);
		k = nm_ring_next(txring, k);
	}
	rxring->head = rxring->cur = j;
	txring->head = txring->cur = k;
	if (0)
	if (verbose && m > 0)
		D("%s fwd %d packets: rxring %u --> txring %u",
		    msg, m, rxring->ringid, txring->ringid);

	return (m);
}

/* Move packets from source port to destination port. */
static int
ports_move(struct nmport_d *src, struct nmport_d *dst, u_int limit,
	   struct shm_struct *shm, const char *msg)
{
	struct netmap_ring *txring, *rxring;
	u_int m = 0, si = src->first_rx_ring, di = dst->first_tx_ring;

	while (si <= src->last_rx_ring && di <= dst->last_tx_ring) {
		rxring = NETMAP_RXRING(src->nifp, si);
		txring = NETMAP_TXRING(dst->nifp, di);
		if (nm_ring_empty(rxring)) {
			si++;
			continue;
		}
		if (nm_ring_empty(txring)) {
			di++;
			continue;
		}
		m += rings_move(rxring, txring, shm, limit, msg);
	}
	return (m);
}


static void
usage(void)
{
	fprintf(stderr,
		"netmap bridge program: forward packets between two "
			"netmap ports\n"
		"    usage(1): bridge [-v] [-i ifa] [-i ifb] [-b burst] "
			"[-w wait_time] [-L]\n"
		"    usage(2): bridge [-v] [-w wait_time] [-L] "
			"[ifa [ifb [burst]]]\n"
		"\n"
		"    ifa and ifb are specified using the nm_open() syntax.\n"
		"    When ifb is missing (or is equal to ifa), bridge will\n"
		"    forward between between ifa and the host stack if -L\n"
		"    is not specified, otherwise loopback traffic on ifa.\n"
		"\n"
		"    example: bridge -w 10 -i netmap:eth3 -i netmap:eth1\n"
		"\n"
		"    If ifa and ifb are two interfaces, they must be in\n"
		"    promiscuous mode. Otherwise, if bridging with the \n"
		"    host stack, the interface must have the offloads \n"
		"    disabled.\n"
		);
	exit(1);
}

static void
prepare_poll(struct ifpair *ifp)
{
	struct pollfd *pfa, *pfb;
	struct nmport_d *pa, *pb;
	int n0, n1;

	pfa = ifp->first.pfd;
	pfb = ifp->second.pfd;
	pa = ifp->first.nmport;
	pb = ifp->second.nmport;

	pfa->events = pfb->events = 0;
	pfa->revents = pfb->revents = 0;
	n0 = rx_slots_avail(pa);
	n1 = rx_slots_avail(pb);
#ifdef BUSYWAIT
	if (n0) {
		pfb->revents = POLLOUT;
	} else {
		ioctl(pfa->fd, NIOCRXSYNC, NULL);
	}
	if (n1) {
		pfa->revents = POLLOUT;
	} else {
		ioctl(pfb->fd, NIOCRXSYNC, NULL);
	}
#else  /* !defined(BUSYWAIT) */
	if (n0)
		pfb->events |= POLLOUT;
	else
		pfa->events |= POLLIN;
	if (n1)
		pfa->events |= POLLOUT;
	else
		pfb->events |= POLLIN;

	/* poll() also cause kernel to txsync/rxsync the NICs */
#endif /* !defined(BUSYWAIT) */
}

static void
do_poll(struct ifpair *ifp, u_int burst,
	struct shm_struct *shm,
	const char *msg_a2b, const char *msg_b2a)
{
	struct pollfd *pfa, *pfb;
	struct nmport_d *pa, *pb;

	pfa = ifp->first.pfd;
	pfb = ifp->second.pfd;
	pa = ifp->first.nmport;
	pb = ifp->second.nmport;

	if (pfa->revents & POLLERR) {
		struct netmap_ring *rx = NETMAP_RXRING(pa->nifp,
						       pa->cur_rx_ring);
		D("error on fd0, rx [%d,%d,%d)",
		  rx->head, rx->cur, rx->tail);
	}
	if (pfb->revents & POLLERR) {
		struct netmap_ring *rx = NETMAP_RXRING(pb->nifp,
						       pb->cur_rx_ring);
		D("error on fd1, rx [%d,%d,%d)",
		  rx->head, rx->cur, rx->tail);
	}
	if (pfa->revents & POLLOUT) {
		ports_move(pb, pa, burst, shm, msg_b2a);
#ifdef BUSYWAIT
		ioctl(pfa->fd, NIOCTXSYNC, NULL);
#endif
	}

	if (pfb->revents & POLLOUT) {
		ports_move(pa, pb, burst, shm, msg_a2b);
#ifdef BUSYWAIT
		ioctl(pfb->fd, NIOCTXSYNC, NULL);
#endif
	}

	/*
	 * We don't need ioctl(NIOCTXSYNC) on the two file descriptors.
	 * here. The kernel will txsync on next poll().
	 */
}

static int __unused
scan_ifp(struct ifpair *ifplist, int npair)
{
	int i;

	for (i = 0; i < npair; i++) {
		struct ifpair *ifp = &ifplist[i];
		struct pollfd *pfa = ifp->first.pfd;
		struct pollfd *pfb = ifp->second.pfd;

		if (pfa->revents & POLLERR)
			goto gotevent;
		if (pfb->revents & POLLERR)
			goto gotevent;
		if (pfa->revents & POLLOUT)
			goto gotevent;
		if (pfb->revents & POLLOUT)
			goto gotevent;
	}
	return -1;
gotevent:
	return i & ~0x1U;
}

/*
 * bridge [-v] if1 [if2]
 *
 * If only one name, or the two interfaces are the same,
 * bridges userland and the adapter. Otherwise bridge
 * two intefaces.
 */
int
main(int argc, char **argv)
{
	u_int burst = 1024, wait_link = 4;
	char *ifa = NULL, *ifb = NULL;
	char ifabuf[64] = { 0 };
	int loopback = 0;
	int ch, ret;
	int __unused nqueues = 0;
	void *shmem;
	pthread_t th;

	while ((ch = getopt(argc, argv, "hb:ci:q:vw:L")) != -1) {
		switch (ch) {
		default:
			D("bad option %c %s", ch, optarg);
			/* fallthrough */
		case 'h':
			usage();
			break;
		case 'b':	/* burst */
			burst = atoi(optarg);
			break;
		case 'i':	/* interface */
			if (ifa == NULL)
				ifa = optarg;
			else if (ifb == NULL)
				ifb = optarg;
			else
				D("%s ignored, already have 2 interfaces",
					optarg);
			break;
		case 'c':
			zerocopy = 0; /* do not zerocopy */
			break;
		case 'q':
			nqueues = atoi(optarg);
			break;
		case 'v':
			verbose++;
			break;
		case 'w':
			wait_link = atoi(optarg);
			break;
		case 'L':
			loopback = 1;
			break;
		}

	}

	argc -= optind;
	argv += optind;

	if (argc > 0)
		ifa = argv[0];
	if (argc > 1)
		ifb = argv[1];
	if (argc > 2)
		burst = atoi(argv[2]);
	if (!ifb)
		ifb = ifa;
	if (!ifa) {
		D("missing interface");
		usage();
	}
	if (burst < 1 || burst > 8192) {
		D("invalid burst %d, set to 1024", burst);
		burst = 1024;
	}
	if (wait_link > 100) {
		D("invalid wait_link %d, set to 4", wait_link);
		wait_link = 4;
	}
	if (!strcmp(ifa, ifb)) {
		if (!loopback) {
			D("same interface, endpoint 0 goes to host");
			snprintf(ifabuf, sizeof(ifabuf) - 1, "%s^", ifa);
			ifa = ifabuf;
		} else {
			D("same interface, loopbacking traffic");
		}
	} else {
		/* two different interfaces. Take all rings on if1 */
	}
	shmem = mem_init(4);
	ret = pthread_create(&th, NULL, producer_receive, shmem);
	if (ret)
		die("failed to create thread\n");
	producer_proc(shmem, ifa, ifb);

	if (fork_or_die() == 0)
		consumer_proc(shmem);
	pthread_join(th, NULL);
	mem_destroy(shmem, 4);

	return (0);
}
