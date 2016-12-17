.include <bsd.own.mk>

PROG=		login_krb5
SRCS=		login.c login_krb5.c
MAN=		${PROG}.8

CPPFLAGS+=	-DKRB5
CPPFLAGS+=	-I${.CURDIR}/../login_passwd
CPPFLAGS+=	$$(/usr/local/heimdal/bin/krb5-config --cflags)

LDADD+=		$$(/usr/local/heimdal/bin/krb5-config --deps --libs)

.PATH:		${.CURDIR}/../login_passwd

.include <bsd.prog.mk>
