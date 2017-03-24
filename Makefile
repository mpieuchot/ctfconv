
PROG=		ctfconvert
SRCS=		ctfconvert.c parse.c elf.c dw.c generate.c

CFLAGS+=	-Wall -Wno-unused -Werror

.include <bsd.prog.mk>
