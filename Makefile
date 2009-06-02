# $Id$

WARN     = -Wall -Wextra -Wpointer-arith -Wstrict-prototypes -O2
LIBS     = -lmilter -lpthread -lclamav
PROGNAME = lclamav-milter

INSTPATH = /usr/local/sbin/

INCDIRS  = /usr/include/libmilter/
LIBDIRS  = /usr/lib/

default all: main

main: lclamav-milter.c
	$(CC) $(WARN) $(CFLAGS) -D_REENTRANT lclamav-milter.c -o $(PROGNAME) $(LIBS) -I $(INCDIRS) -L $(LIBDIRS)

install: lclamav-milter
	[[ -e "$(INSTPATH)/$(PROGNAME)" ]] && cp -af "$(INSTPATH)/$(PROGNAME)" "$(INSTPATH)/$(PROGNAME).bak" || true
	install -m 755 -D $(PROGNAME) $(INSTPATH)/$(PROGNAME)
	strip $(INSTPATH)/$(PROGNAME)

clean:
	[[ -e "$(PROGNAME)" ]] && rm -f $(PROGNAME)
