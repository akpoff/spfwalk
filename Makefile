#	$OpenBSD$

PROG=	spfwalk
#MAN=	doas.1 doas.conf.5
NOMAN=

CFLAGS+= -I${.CURDIR}
CFLAGS+= -Wall
LDADD=	-levent
#DPADD=	${LIBEVENT}

.include <bsd.prog.mk>
