#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

// Structure representing the ring buffer
struct ring_buffer {
	void **buffer;           // Array of pointers to data
	size_t size;             // Size of the buffer
	atomic_size_t write_index; // Write index (modified only by producer)
	atomic_size_t read_index;  // Read index (modified only by consumer)
};

// Initialize the ring buffer
struct ring_buffer *ring_buffer_init(size_t size)
{
	struct ring_buffer *rb = (struct ring_buffer *)malloc(sizeof(struct ring_buffer));

	assert(rb != NULL);
	rb->buffer = malloc(size * sizeof(void *));
	assert(rb->buffer != NULL);

	rb->size = size;
	atomic_store(&rb->write_index, 0);
	atomic_store(&rb->read_index, 0);

	return rb;
}

// Free the ring buffer memory
void ring_buffer_free(struct ring_buffer *rb)
{
	free(rb->buffer);
	free(rb);
}

// Helper function to increment index with wrap-around
static size_t increment_index(size_t index, size_t size)
{
	return (index + 1) % size;
}

// Producer puts data into the buffer
bool ring_buffer_put(struct ring_buffer *rb, void *data)
{
	size_t current_write = atomic_load_explicit(&rb->write_index,
						    memory_order_relaxed);
	size_t next_write = increment_index(current_write, rb->size);

	// Check if the buffer is full
	if (next_write == atomic_load_explicit(&rb->read_index,
					       memory_order_acquire)) {
		return false;  // Buffer is full
	}

	rb->buffer[current_write] = data;  // Store data in the buffer

	// Publish the write by updating the write index
	atomic_store_explicit(&rb->write_index, next_write,
			      memory_order_release);
	return true;
}

// Consumer gets data from the buffer
bool ring_buffer_get(struct ring_buffer *rb, void **data)
{
	size_t current_read = atomic_load_explicit(&rb->read_index,
						  memory_order_relaxed);

	// Check if the buffer is empty
	if (current_read == atomic_load_explicit(&rb->write_index,
						memory_order_acquire)) {
		return false;  // Buffer is empty
	}

	*data = rb->buffer[current_read];  // Retrieve data from the buffer

	// Move the read index forward
	atomic_store_explicit(&rb->read_index, increment_index(current_read,
							      rb->size),
			      memory_order_release);
	return true;
}

int main(void)
{
	// Create a ring buffer with space for 10 pointers
	struct ring_buffer *rb = ring_buffer_init(10);

	// Producer inserts data (example: pointer to an int)
	int x = 42;
	ring_buffer_put(rb, &x);

	// Consumer retrieves data
	void *data;
	if (ring_buffer_get(rb, &data)) {
		int *retrieved_value = (int *)data;
		printf("Retrieved: %d\n", *retrieved_value);
	}

	// Free the buffer
	ring_buffer_free(rb);

	return 0;
}
