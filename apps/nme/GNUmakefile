# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	nme
LIBNETMAP =

CLEANFILES = $(PROGS) *.o

SRCDIR ?= ../..
VPATH = $(SRCDIR)/apps/nme

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

.PHONY: install
install: $(PROGS:%=install-%)

install-%:
	install -D $* $(DESTDIR)/$(PREFIX)/bin/$*
	-install -D -m 644 $(SRCDIR)/apps/bridge/bridge.8 $(DESTDIR)/$(MAN_PREFIX)/man8/bridge.8

nme.o: nme.c
	$(CC) $(CFLAGS) -DBUSYWAIT -c $< -o $@
