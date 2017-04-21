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
	TAILQ_ENTRY(itype)	 it_next;
	TAILQ_HEAD(, imember)	 it_members;
	unsigned int		 it_flags;
#define	ITF_UNRESOLVED		0x01
#define	ITF_UNRESOLVED_MEMBERS	0x02
#define	ITF_FUNCTION		0x04
#define	ITF_VARARGS		0x08
	char			*it_name;   /* type name */
	uint64_t		 it_size;   /* size for struct or union */
	uint64_t		 it_ref;    /* CU offset of referenced type */
	uint64_t		 it_nelems; /* # of members or arguments */
	size_t			 it_off;   /* off. of matching ABBREV section */
	size_t			 it_idx;   /* generated CTF type ID */
	struct itype		*it_refp;  /* resolved CTF type */
	int			 it_type;  /* CTF_K_* type */
	uint16_t		 it_enc;   /* CTF base type encoding */
	uint16_t		 it_bits;  /* CTF base type bits */
};

/*
 * Member for types with a variable length (struct, array, etc).
 */
struct imember {
	TAILQ_ENTRY(imember)	 im_next;
	const char		*im_name;   /* struct or union field name */
	uint64_t		 im_ref;    /* CU offset of the field type */
	size_t			 im_loc;    /* FIXME: field offset */
	struct itype		*im_refp;   /* resolved CTF type */
};

TAILQ_HEAD(itype_queue, itype);

extern struct itype_queue itypeq;	/* Global queue of internal types */
