#	$OpenBSD$

PROG=	spfwalk
SRCS=	spfwalk.c dns.c
MAN=	spfwalk.1
#NOMAN=

CFLAGS+= -I${.CURDIR}
CFLAGS+= -Wall
LDADD=	-levent
#DPADD=	${LIBEVENT}

.include <bsd.prog.mk>
