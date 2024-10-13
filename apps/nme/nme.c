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
#include <pthread.h>
#include <net/netmap_user.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define INTERFACE_NAME "netmap:eth0"  // Change this to your actual interface
#define BURST_SIZE 32                 // Number of packets to process per burst

// Thread data to pass the netmap interface details
struct ring_thread_data {
	struct nmport_d *rx_nmp;  // Separate netmap descriptor for RX ring
	struct nmport_d *tx_nmp;  // Separate netmap descriptor for TX ring
	int ring_idx;             // Index of the RX/TX ring
};

// Function to process and forward packets between RX and TX rings
void *process_ring(void *arg)
{
	struct ring_thread_data *data = (struct ring_thread_data *)arg;
	struct netmap_ring *rxring, *txring;
	struct pollfd fds[2];  // One for RX, one for TX
	int ret;

	// Get RX and TX rings based on the thread's ring index
	rxring = NETMAP_RXRING(data->rx_nmp->nifp, data->ring_idx);
	txring = NETMAP_TXRING(data->tx_nmp->nifp, data->ring_idx);

	fds[0].fd = data->rx_nmp->fd;
	fds[0].events = POLLIN;  // Only monitor RX for input

	fds[1].fd = data->tx_nmp->fd;
	fds[1].events = POLLOUT;  // Only monitor TX for output readiness

	while (1) {
		// Poll the file descriptors for incoming packets and TX availability
		ret = poll(fds, 2, 1000);
		if (ret < 0) {
			perror("poll");
			break;
		}

		if (fds[0].revents & POLLIN) {
			// Process up to BURST_SIZE packets from the RX ring
			int burst_count = 0;
			while (!nm_ring_empty(rxring) && burst_count < BURST_SIZE) {
				struct netmap_slot *rxslot = &rxring->slot[rxring->cur];
				char *rx_pkt = NETMAP_BUF(rxring, rxslot->buf_idx);

				// Process the packet (optional, you can manipulate it here)
				printf("Received packet on RX ring %d\n", data->ring_idx);

				// Check if the TX ring has space
				if (!nm_ring_empty(txring)) {
					// Get the next TX slot
					struct netmap_slot *txslot = &txring->slot[txring->cur];
					char *tx_pkt = NETMAP_BUF(txring, txslot->buf_idx);

					// Copy the received packet to the TX slot
					memcpy(tx_pkt, rx_pkt, rxslot->len);

					// Set the length of the transmitted packet
					txslot->len = rxslot->len;

					// Move to the next TX slot
					txring->cur = nm_ring_next(txring, txring->cur);

					// Notify netmap that the packet is ready to be sent
					txring->head = txring->cur;
				}

				// Move to the next RX slot
				rxring->cur = nm_ring_next(rxring, rxring->cur);
				rxring->head = rxring->cur;

				burst_count++;  // Increment burst counter
			}
		}

		if (fds[1].revents & POLLOUT) {
			// The TX ring is ready to accept more packets, send in bursts
			int burst_count = 0;
			while (!nm_ring_empty(txring) && burst_count < BURST_SIZE) {
				// Send more packets if available (e.g., retransmit if needed)
				txring->head = txring->cur;
				burst_count++;  // Increment burst counter
			}
		}
		// Optionally, you can sleep for a bit to prevent busy looping
	}

	return NULL;
}

int main(void)
{
	int num_rx_rings, num_tx_rings, i;
	pthread_t *threads;
	struct ring_thread_data *thread_data;
	char rx_interface_with_ring[64], tx_interface_with_ring[64];

	// Get number of RX and TX rings
	struct nmport_d *base_nmp = nmport_open(INTERFACE_NAME);
	if (!base_nmp) {
		perror("nmport_open");
		return -1;
	}
	num_rx_rings = base_nmp->nifp->ni_rx_rings;
	num_tx_rings = base_nmp->nifp->ni_tx_rings;
	printf("rx/tx %d/%d\n", num_rx_rings, num_tx_rings);
	nmport_close(base_nmp);  // Close after getting the ring counts

	// Ensure RX and TX rings match
	if (num_rx_rings != num_tx_rings) {
		fprintf(stderr, "RX and TX rings do not match\n");
		return -1;
	}

	threads = malloc(num_rx_rings * sizeof(pthread_t));
	thread_data = malloc(num_rx_rings * sizeof(struct ring_thread_data));

	// Create threads, one per ring
	for (i = 0; i < num_rx_rings; i++) {
		// Open a separate netmap port for each RX and TX ring
		snprintf(rx_interface_with_ring, sizeof(rx_interface_with_ring), "%s-%d/R", INTERFACE_NAME, i);
		thread_data[i].rx_nmp = nmport_open(rx_interface_with_ring);
		if (thread_data[i].rx_nmp == NULL) {
			printf("err 1\n");
			perror("nmport_open");
			return -1;
		}

		snprintf(tx_interface_with_ring, sizeof(tx_interface_with_ring), "%s-%d/T", INTERFACE_NAME, i);
		thread_data[i].tx_nmp = nmport_open(tx_interface_with_ring);
		if (thread_data[i].tx_nmp == NULL) {
			printf("err 2\n");
			perror("nmport_open");
			return -1;
		}

		// Set the correct ring index
		thread_data[i].ring_idx = i;

		if (pthread_create(&threads[i], NULL, process_ring, &thread_data[i]) != 0) {
			perror("pthread_create");
			return -1;
		}
	}

	// Wait for threads to finish (they won't, unless signaled to stop)
	for (i = 0; i < num_rx_rings; i++) {
		pthread_join(threads[i], NULL);
	}

	// Clean up
	for (i = 0; i < num_rx_rings; i++) {
		nmport_close(thread_data[i].rx_nmp);
		nmport_close(thread_data[i].tx_nmp);
	}
	free(threads);
	free(thread_data);

	return 0;
}
