# New ports collection makefile for:    mod_jail
# Date created:				October 25 2005
# Whom:					Igor Popov <igorpopov@newmail.ru>
#
# $$

PORTNAME=	mod_jail
PORTVERSION=	0.1
CATEGORIES=	www
MASTER_SITES=	http://igorpopov.newmail.ru/
EXTRACT_SUFX=	.tar.gz

MAINTAINER=	igorpopov@newmail.ru
COMMENT=	An Apache module for running httpd in a secure jail prison easy

DOCS=		INSTALL README TODO httpd.conf.add

WANT_APACHE=13
AP_GENPLIST=yes

WRKSRC =${WRKDIR}/${PORTNAME}

.if !defined(NOPORTDOCS)
post-install:
	@${INSTALL} -d -m 0755 ${DOCSDIR}
.for file in ${DOCS}
	@${INSTALL_DATA} ${WRKSRC}/${file} ${DOCSDIR}/
.endfor
.endif

.include <bsd.port.mk>
