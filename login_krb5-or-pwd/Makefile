.include <bsd.own.mk>

PROG=		login_krb5-or-pwd
SRCS=		login.c login_passwd.c login_krb5.c
MAN=		${PROG}.8

CPPFLAGS+=	-DPASSWD
CPPFLAGS+=	-I${.CURDIR}/../login_passwd
CPPFLAGS+=	$$(/usr/local/heimdal/bin/krb5-config --cflags)

LDADD+=		$$(/usr/local/heimdal/bin/krb5-config --deps --libs)

.PATH:		${.CURDIR}/../login_passwd ${.CURDIR}/../login_krb5

.include <bsd.prog.mk>
