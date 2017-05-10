
PROG=		ctfconvert
SRCS=		ctfconvert.c parse.c elf.c dw.c generate.c hash.c xmalloc.c

CFLAGS+=	-W -Wall -Wstrict-prototypes -Wno-unused -Wunused-variable

CFLAGS+=	-DZLIB
LDADD+=		-lz
DPADD+=		${LIBZ}

.include <bsd.prog.mk>
