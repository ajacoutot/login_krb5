CPPFLAGS+=	-Wall
LDADD+=		-lutil

BINOWN=		root
BINGRP=		auth
BINMODE=	4555
BINDIR=		$(LOCALBASE)/libexec/auth

beforeinstall:
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m ${DIRMODE} \
		${DESTDIR}${BINDIR}
