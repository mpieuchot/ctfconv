/*
 * Copyright (c) 2016 Martin Pieuchot <mpi@openbsd.org>
 * Copyright (c) 2016 Jasper Lievisse Adriaanse <jasper@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Internal C type representation.
 *
 * Some bits of DWARF that we want to keep around.
 * for example to resolve types and variables to their
 * intrinsics.
 */

struct imember {
	TAILQ_ENTRY(imember)		 next;
	const char			*name;
	uint64_t			 ref;
	size_t				 loc;
	size_t				 refidx; /* map index -> CTF index */
};

struct itype {
	TAILQ_ENTRY(itype)		 next;
	TAILQ_HEAD(, imember)		 members;
	unsigned int			 flags;
#define	IF_UNRESOLVED		0x01
#define	IF_UNRESOLVED_MEMBERS	0x02
#define	IF_FUNCTION		0x04
	const char			*name;	/* type name */
	uint64_t			 size;
	uint64_t			 ref;	/* offset of referenced type */
	uint64_t			 nelems;
#define VARARGS	0xefef
	size_t				 off;	/* offset in abbrev section */
	size_t				 idx;	/* index in CTF type section */
	size_t				 refidx; /* map index -> CTF index */
	int				 type;	/* CTF type */
	uint16_t			 enc;
	uint16_t			 bits;
};

TAILQ_HEAD(itype_queue, itype);

extern struct itype_queue itypeq;
