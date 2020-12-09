sysconfdir=${prefix}/etc
piddir=/var/run
srcdir=.
top_srcdir=..


CC=cc
LD=cc
CFLAGS=-g -O2 -pipe -Wno-error=format-truncation -Wall -Wextra -Wpointer-arith -Wuninitialized -Wsign-compare -Wformat-security -Wsizeof-pointer-memaccess -Wno-pointer-sign -Wno-unused-parameter -Wno-unused-result -Wimplicit-fallthrough -fno-strict-aliasing -D_FORTIFY_SOURCE=2 -ftrapv -fno-builtin-memset -fstack-protector-strong -fPIE  
CFLAGS_NOPIE=-g -O2 -pipe -Wno-error=format-truncation -Wall -Wextra -Wpointer-arith -Wuninitialized -Wsign-compare -Wformat-security -Wsizeof-pointer-memaccess -Wno-pointer-sign -Wno-unused-parameter -Wno-unused-result -Wimplicit-fallthrough -fno-strict-aliasing -D_FORTIFY_SOURCE=2 -ftrapv -fno-builtin-memset -fstack-protector-strong  
CPPFLAGS=-I. -I.. -I$(srcdir) -I$(srcdir)/..  -D_XOPEN_SOURCE=600 -D_BSD_SOURCE -D_DEFAULT_SOURCE -DHAVE_CONFIG_H
PICFLAG=-fPIC
LIBS=-lcrypto -ldl -lutil -lz  -lcrypt -lresolv
AR=ar
RANLIB=ranlib
INSTALL=/usr/bin/install -c
LDFLAGS=-L.  -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -fstack-protector-strong -pie 
LDFLAGS_NOPIE=-L. -Lopenbsd-compat/  -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -fstack-protector-strong 

OPENBSD=base64.o \
	basename.o \
	bcrypt_pbkdf.o \
	bcrypt_pbkdf.o \
	bindresvport.o \
	blowfish.o \
	daemon.o \
	dirname.o \
	explicit_bzero.o \
	fmt_scaled.o \
	freezero.o \
	fnmatch.o \
	getcwd.o \
	getgrouplist.o \
	getopt_long.o \
	getrrsetbyname.o \
	glob.o \
	inet_aton.o \
	inet_ntoa.o \
	inet_ntop.o \
	md5.o \
	memmem.o \
	mktemp.o \
	pwcache.o \
	readpassphrase.o \
	reallocarray.o \
	recallocarray.o \
	rresvport.o \
	setenv.o \
	setproctitle.o \
	sha1.o \
	sha2.o \
	sigact.o \
	strcasestr.o \
	strlcat.o \
	strlcpy.o \
	strmode.o \
	strndup.o \
	strnlen.o \
	strptime.o \
	strsep.o \
	strtoll.o \
	strtonum.o \
	strtoull.o \
	strtoul.o \
	timingsafe_bcmp.o \
	vis.o

COMPAT=	arc4random.o \
	bsd-asprintf.o \
	bsd-closefrom.o \
	bsd-cygwin_util.o \
	bsd-err.o \
	bsd-flock.o \
	bsd-getline.o \
	bsd-getpagesize.o \
	bsd-getpeereid.o \
	bsd-malloc.o \
	bsd-misc.o \
	bsd-nextstep.o \
	bsd-openpty.o \
	bsd-poll.o \
	bsd-setres_id.o \
	bsd-signal.o \
	bsd-snprintf.o \
	bsd-statvfs.o \
	bsd-waitpid.o \
	fake-rfc2553.o \
	getrrsetbyname-ldns.o \
	kludge-fd_set.o \
	openssl-compat.o \
	libressl-api-compat.o \
	xcrypt.o

PORTS=	port-aix.o \
	port-irix.o \
	port-linux.o \
	port-solaris.o \
	port-net.o \
	port-uw.o

.c.o:
	$(CC) $(CFLAGS_NOPIE) $(PICFLAG) $(CPPFLAGS) -c $<

all: libopenbsd-compat.a

$(COMPAT): ../config.h
$(OPENBSD): ../config.h
$(PORTS): ../config.h

libopenbsd-compat.a:  $(COMPAT) $(OPENBSD) $(PORTS)
	$(AR) rv $@ $(COMPAT) $(OPENBSD) $(PORTS)
	$(RANLIB) $@

clean:
	rm -f *.o *.a core

distclean: clean
	rm -f Makefile *~
