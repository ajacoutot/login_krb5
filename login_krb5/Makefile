.include <bsd.own.mk>

PROG=		login_krb5
SRCS=		login.c login_krb5.c
MAN=		${PROG}.8

CPPFLAGS+=	-DKRB5
CPPFLAGS+=	-I${.CURDIR}/../login_passwd
CPPFLAGS+=	$$(/usr/local/heimdal/bin/krb5-config --cflags) -I/usr/local/include

LDADD+=		$$(/usr/local/heimdal/bin/krb5-config --libs) -L/usr/local/lib

.PATH:		${.CURDIR}/../login_passwd

.include <bsd.prog.mk>
