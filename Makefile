#	$OpenBSD$

PROG=	spfwalk
SRCS=	spfwalk.c dns.c
MAN=	spfwalk.1

CFLAGS+= -I${.CURDIR}
CFLAGS+= -Wall
LDADD=	-levent

.include <bsd.prog.mk>
