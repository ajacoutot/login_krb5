.include <bsd.own.mk>

PROG=		login_krb5-or-pwd
SRCS=		login.c login_passwd.c login_krb5.c
MAN=		${PROG}.8

CPPFLAGS+=	-DPASSWD -DKRB5
CPPFLAGS+=	-I${.CURDIR}/../login_passwd
CPPFLAGS+=	$$(/usr/local/heimdal/bin/krb5-config --cflags) -I/usr/local/include

LDADD+=		$$(/usr/local/heimdal/bin/krb5-config --libs) -L/usr/local/lib

.PATH:		${.CURDIR}/../login_passwd ${.CURDIR}/../login_krb5

.include <bsd.prog.mk>
