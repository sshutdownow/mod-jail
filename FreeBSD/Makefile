PORTNAME=	mod_jail
DISTVERSION=	0.6
CATEGORIES=	www

USE_GITHUB=	yes
GH_ACCOUNT=	sshutdownow
GH_PROJECT=	mod-jail
GH_TAGNAM=	0.6

PKGNAMEPREFIX=	${APACHE_PKGNAMEPREFIX}

MAINTAINER=	ipopovi@gmail.com
COMMENT=	mod_jail is an apache module for running httpd in a secure jail prison without creating real jail environment
WWW=		https://github.com/sshutdownow/mod-jail

LICENSE=	APACHE20
LICENSE_FILE=	${WRKSRC}/LICENSE

LIB_DEPENDS=	

USES=		apache libtool

MODULENAME=	mod_jail

SUB_FILES=	001_mod_jail.conf
PORTDOCS=	INSTALL README TODO

OPTIONS_DEFINE=	DOCS

.include <bsd.port.pre.mk>

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/${APACHEMODDIR}
	${APXS} -i -n jail -S LIBEXECDIR=${STAGEDIR}${PREFIX}/${APACHEMODDIR} ${WRKSRC}/.libs/mod_jail.so
	${MKDIR} ${STAGEDIR}${PREFIX}/${APACHEETCDIR}/modules.d
	${INSTALL_DATA} ${WRKDIR}/001_mod_jail.conf \
		${STAGEDIR}${PREFIX}/${APACHEETCDIR}/modules.d/001_mod_jail.conf.sample

.include <bsd.port.post.mk>
