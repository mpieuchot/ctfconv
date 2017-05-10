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

struct imember;

/*
 * Internal type representation.
 *
 * Some bits of DWARF that we want to keep around to resolve types and
 * variables to their intrinsics.
 */
struct itype {
	TAILQ_ENTRY(itype)	 it_next;   /* itype: global queue of types */
	TAILQ_ENTRY(itype)	 it_fnext;  /* itype: global queue of funcs */
	RB_ENTRY(itype)		 it_node;   /* itype: per-type tree of types */
	TAILQ_HEAD(, imember)	 it_members;

	size_t			 it_off;    /* DWARF: matching .abbrev offset */
	uint64_t		 it_ref;    /* DWARF: CU offset of ref. type */

	struct itype		*it_refp;   /* itype: resolved type */

	char			*it_name;   /* CTF: type name */
	uint32_t		 it_size;   /* CTF: size in byte or bits */
	uint32_t		 it_nelems; /* CTF: # of members or arguments */
	uint16_t		 it_enc;    /* CTF: base type encoding */
	uint16_t		 it_idx;    /* CTF: generated type ID */
	uint16_t		 it_type;   /* CTF: type */
	uint8_t			 __pad[2];

	unsigned int		 it_flags;  /* itype: parser flags */
#define	ITF_UNRESOLVED		0x01
#define	ITF_UNRESOLVED_MEMBERS	0x02
#define	ITF_FUNCTION		0x04
#define	ITF_VARARGS		0x08
};

/*
 * Member for types with a variable length (struct, array, etc).
 */
struct imember {
	TAILQ_ENTRY(imember)	 im_next;
	const char		*im_name;   /* struct or union field name */
	size_t			 im_ref;    /* CU offset of the field type */
	size_t			 im_off;    /* field offset in struct/union */
	struct itype		*im_refp;   /* resolved CTF type */
};

TAILQ_HEAD(itype_queue, itype);

extern struct itype_queue itypeq, ifuncq;   /* lists of types & functions */
extern uint16_t long_tidx;		    /* type ID for "long" */
