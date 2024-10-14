# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	bridge
LIBNETMAP =

CLEANFILES = $(PROGS) *.o

SRCDIR ?= ../..
VPATH = $(SRCDIR)/apps/mqbridge

NO_MAN=
CFLAGS = -g -O2 -pipe
CFLAGS += -Wall -Wunused-function
CFLAGS += -Wno-unused-parameter
CFLAGS += -I $(SRCDIR)/sys -I $(SRCDIR)/apps/include -I$(SRCDIR)/libnetmap
CFLAGS += -Wextra

LDFLAGS += -L $(BUILDDIR)/build-libnetmap
$(info ldflags: $(LDFLAGS))
LDLIBS += -lnetmap
ifeq ($(shell uname),Linux)
	LDLIBS += -lrt	# on linux
endif

PREFIX ?= /usr/local
MAN_PREFIX = $(if $(filter-out /,$(PREFIX)),$(PREFIX),/usr)/share/man

all: $(PROGS)

clean:
	-@rm -rf $(CLEANFILES)

bridge.o: ring.h
# bridge-b: bridge-b.o

# bridge-b.o: bridge.c ring.h
# 	$(CC) $(CFLAGS) -DBUSYWAIT -c $< -o $@
