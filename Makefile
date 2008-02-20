# $Id$

WARN     = -Wall -Werror -Wpointer-arith -Wstrict-prototypes -O2
LIBS     = -lmilter -lpthread -lclamav
PROGNAME = lclamav-milter

INCDIRS  = /usr/include/libmilter/
LIBDIRS  = /usr/lib/

default all: main

main: lclamav-milter.c
	$(CC) $(WARN) $(CFLAGS) -D_REENTRANT lclamav-milter.c -o $(PROGNAME) $(LIBS) -I $(INCDIRS) -L $(LIBDIRS)

clean:
	[[ -e "$(PROGNAME)" ]] && rm -f $(PROGNAME)

install: main
	cp -a $(PROGNAME) /usr/local/sbin/$(PROGNAME)
	strip /usr/local/sbin/$(PROGNAME)
	install -m 755 -D $(PROGNAME) /usr/local/sbin/$(PROGNAME)
