# New ports collection makefile for:    mod_jail
# Date created:				October 25 2005
# Whom:					Igor Popov <igorpopov@newmail.ru>
#
# $Id$

PORTNAME=	mod_jail
PORTVERSION=	0.4
CATEGORIES=	www
MASTER_SITES=	http://igorpopov.newmail.ru/
DISTNAME=	${PORTNAME}-${PORTVERSION}
DIST_SUBDIR=	apache2

MAINTAINER=	igorpopov@newmail.ru
COMMENT=	An Apache2 module for running httpd in a secure jail prison without creating real jail environment

PORTDOCS=	INSTALL README TODO httpd.conf.add

USE_APACHE=	20+

AP_FAST_BUILD=	YES
AP_GENPLIST=	YES

WRKSRC =${WRKDIR}/${PORTNAME}

post-install:
.if !defined(NOPORTDOCS)
	@${MKDIR} ${DOCSDIR}
	@${INSTALL_DATA} ${WRKSRC}/${PORTDOCS} ${DOCSDIR}
.endif

.include <bsd.port.mk>
