
PROG=		ctfconvert
SRCS=		ctfconvert.c parse.c elf.c dw.c

CFLAGS+=	-Wall -Wno-unused -Werror

.include <bsd.prog.mk>
