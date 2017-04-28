
PROG=		ctfconvert
SRCS=		ctfconvert.c parse.c elf.c dw.c generate.c hash.c xmalloc.c

CFLAGS+=	-W -Wall -Wno-unused -Wstrict-prototypes -Wno-unused-parameter

CFLAGS+=	-DZLIB
LDADD+=		-lz
DPADD+=		${LIBZ}

.include <bsd.prog.mk>
