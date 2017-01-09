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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/ctf.h>

#include <assert.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>

#include "dwarf.h"

#include "dw.h"
#include "itype.h"

#define DPRINTF(x...)	do { /*printf(x)*/ } while (0)

#define VOID_OFFSET	1	/* Fake offset for generating "void" type. */
#define	VOID_INDEX	1

void		 parse_cu(struct dwcu *, struct itype_queue *);
void		 resolve(struct itype *, struct itype_queue *, size_t);
void		 merge(struct itype_queue *, struct itype_queue *);

struct itype	*insert_void(unsigned int);
struct itype	*parse_base(struct dwdie *, size_t, unsigned int);
struct itype	*parse_refers(struct dwdie *, size_t, unsigned int, int);
struct itype	*parse_array(struct dwdie *, size_t, unsigned int);
struct itype	*parse_struct(struct dwdie *, size_t, unsigned int, int);
struct itype	*parse_function(struct dwdie *, size_t, unsigned int);
struct itype	*parse_funcptr(struct dwdie *, size_t, unsigned int);

void		 subparse_subrange(struct dwdie *, size_t, struct itype *);
void		 subparse_member(struct dwdie *, size_t, struct itype *);
void		 subparse_arguments(struct dwdie *, size_t, struct itype *);

uint64_t	 dav2val(struct dwaval *, size_t);
const char	*dav2str(struct dwaval *);
const char	*enc2name(unsigned short);

unsigned int	 tidx, fidx;	/* type and function indexes */

struct itype_queue *
dwarf_parse(const char *infobuf, size_t infolen, const char *abbuf,
    size_t ablen)
{
	struct dwbuf	 info = { .buf = infobuf, .len = infolen };
	struct dwbuf	 abbrev = { .buf = abbuf, .len = ablen };
	struct dwcu	*dcu = NULL;
	struct itype_queue *itypeq;
	struct itype	*itype;

	itypeq = calloc(1, sizeof(*itypeq));
	if (itypeq == NULL)
		err(1, "calloc");
	TAILQ_INIT(itypeq);

	tidx = fidx = 0;

	itype = insert_void(++tidx);
	TAILQ_INSERT_TAIL(itypeq, itype, next);

	while (dw_cu_parse(&info, &abbrev, infolen, &dcu) == 0) {
		struct itype_queue cu_itypeq;

		TAILQ_INIT(&cu_itypeq);

		/* Parse this CU */
		parse_cu(dcu, &cu_itypeq);

		/* Resolve its types. */
		TAILQ_FOREACH(itype, &cu_itypeq, next)
			resolve(itype, &cu_itypeq, dcu->dcu_offset);

		/* Merge them with the global type list. */
		merge(itypeq, &cu_itypeq);

		dw_dcu_free(dcu);
	}

	return itypeq;
}

#if 1
#include <stdio.h>
#endif

/*
 * Worst case it's a O(n*n) resolution lookup, with ``n'' being the number
 * of elements in ``itypeq''.
 */
void
resolve(struct itype *itype, struct itype_queue *itypeq, size_t offset)
{
	int		 toresolve = itype->nelems;
	struct itype	*tmp;

	if ((itype->flags & IF_UNRESOLVED_MEMBERS) &&
	    !TAILQ_EMPTY(&itype->members)) {
		struct imember	*imember;

		TAILQ_FOREACH(tmp, itypeq, next) {
			TAILQ_FOREACH(imember, &itype->members, next) {
				if (tmp->off == (imember->ref + offset)) {
					imember->refidx = tmp->idx;
					toresolve--;
				}
			}
		}

		if (toresolve == 0)
			itype->flags &= ~IF_UNRESOLVED_MEMBERS;
	}

	if (itype->flags & IF_UNRESOLVED) {
		TAILQ_FOREACH(tmp, itypeq, next) {
			if (tmp->off == (itype->ref + offset)) {
				itype->refidx = tmp->idx;
				itype->flags &= ~IF_UNRESOLVED;
				break;
			}
		}
	}

#if 1
	if (itype->flags & (IF_UNRESOLVED|IF_UNRESOLVED_MEMBERS)) {
		printf("0x%zx: %s: unresolved 0x%llx", itype->off, itype->name,
		    itype->ref);
		if (toresolve)
			printf(": %d members", toresolve);
		printf("\n");
	}
#endif
}

void
merge(struct itype_queue *itypeq, struct itype_queue *otherq)
{
#if 0
	struct itype *itype, *tmp;

	TAILQ_FOREACH(itype, otherq, next)
#endif
	TAILQ_CONCAT(itypeq, otherq, next);

}

void
parse_cu(struct dwcu *dcu, struct itype_queue *itypeq)
{
	struct itype *itype = NULL;
	struct dwdie *die;
	size_t psz = dcu->dcu_psize;

	SIMPLEQ_FOREACH(die, &dcu->dcu_dies, die_next) {
		uint64_t tag = die->die_dab->dab_tag;

		switch (tag) {
		case DW_TAG_array_type:
			itype = parse_array(die, dcu->dcu_psize, ++tidx);
			break;
		case DW_TAG_enumeration_type:
			++tidx;
			continue;
		case DW_TAG_pointer_type:
			itype = parse_refers(die, psz, ++tidx, CTF_K_POINTER);
			break;
		case DW_TAG_structure_type:
			itype = parse_struct(die, psz, ++tidx, CTF_K_STRUCT);
			break;
		case DW_TAG_typedef:
			itype = parse_refers(die, psz, ++tidx, CTF_K_TYPEDEF);
			break;
		case DW_TAG_union_type:
			itype = parse_struct(die, psz, ++tidx, CTF_K_UNION);
			break;
		case DW_TAG_base_type:
			itype = parse_base(die, psz, ++tidx);
			break;
		case DW_TAG_const_type:
			itype = parse_refers(die, psz, ++tidx, CTF_K_CONST);
			break;
		case DW_TAG_volatile_type:
			itype = parse_refers(die, psz, ++tidx, CTF_K_VOLATILE);
			break;
		case DW_TAG_restrict_type:
			itype = parse_refers(die, psz, ++tidx, CTF_K_RESTRICT);
			break;
		case DW_TAG_subprogram:
			itype = parse_function(die, psz, ++fidx);
			break;
		case DW_TAG_subroutine_type:
			itype = parse_funcptr(die, psz, ++tidx);
			break;
		/*
		 * Children are assumed to be right after their parent in
		 * the list.  The parent parsing function takes care of
		 * parsing them.
		 */
		 case DW_TAG_member:
			assert(itype->type == CTF_K_STRUCT ||
			    itype->type == CTF_K_UNION);
			continue;
		 case DW_TAG_subrange_type:
			assert(itype->type == CTF_K_ARRAY);
			continue;
		case DW_TAG_formal_parameter:
			assert(itype->type == CTF_K_FUNCTION);
			continue;
#if 1
		case DW_TAG_lexical_block:
		case DW_TAG_variable:
		case DW_TAG_inlined_subroutine:
			continue;
#endif
		case DW_TAG_compile_unit:
		default:
			DPRINTF("%s\n", dw_tag2name(tag));
			continue;
		}

		TAILQ_INSERT_TAIL(itypeq, itype, next);
	}
}

struct itype *
insert_void(unsigned int i)
{
	struct itype *itype;

	itype = calloc(1, sizeof(*itype));
	if (itype == NULL)
		err(1, "calloc");

	TAILQ_INIT(&itype->members);
	itype->flags = 0; /* Do not need to be resolved. */
	itype->off = VOID_OFFSET;
	itype->idx = i;
	itype->enc = CTF_INT_SIGNED;
	itype->type = CTF_K_INTEGER;
	itype->name = "void";
	itype->bits = 0;

	return itype;
}

struct itype *
parse_base(struct dwdie *die, size_t psz, unsigned int i)
{
	struct itype *itype;
	struct dwaval *dav;
	uint16_t encoding, enc = 0, bits = 0;
	int type;

	SIMPLEQ_FOREACH(dav, &die->die_avals, dav_next) {
		switch (dav->dav_dat->dat_attr) {
		case DW_AT_encoding:
			enc = dav2val(dav, psz);
			break;
		case DW_AT_byte_size:
			bits = 8 * dav2val(dav, psz);
			break;
		default:
			DPRINTF("%s\n", dw_at2name(dav->dav_dat->dat_attr));
			break;
		}
	}

	switch (enc) {
	case DW_ATE_unsigned:
	case DW_ATE_address:
		encoding = 0;
		type = CTF_K_INTEGER;
		break;
	case DW_ATE_unsigned_char:
		encoding = CTF_INT_CHAR;
		type = CTF_K_INTEGER;
		break;
	case DW_ATE_signed:
		encoding = CTF_INT_SIGNED;
		type = CTF_K_INTEGER;
		break;
	case DW_ATE_signed_char:
		encoding = CTF_INT_SIGNED | CTF_INT_CHAR;
		type = CTF_K_INTEGER;
		break;
	case DW_ATE_boolean:
		encoding = CTF_INT_SIGNED | CTF_INT_BOOL;
		type = CTF_K_INTEGER;
		break;
	case DW_ATE_float:
	case DW_ATE_complex_float:
	case DW_ATE_imaginary_float:
		encoding = 0; /* TODO */
		type = CTF_K_FLOAT;
		break;
	default:
		DPRINTF("unknown encoding: %d\n", enc);
		return (NULL);
	}

	itype = calloc(1, sizeof(*itype));
	if (itype == NULL)
		err(1, "calloc");

	TAILQ_INIT(&itype->members);
	itype->flags = 0; /* Do not need to be resolved. */
	itype->off = die->die_offset;
	itype->idx = i;
	itype->enc = encoding;
	itype->type = type;
	itype->name = enc2name(enc);
	itype->bits = bits;

	return itype;
}

struct itype *
parse_refers(struct dwdie *die, size_t psz, unsigned int i, int type)
{
	struct itype *itype;
	struct dwaval *dav;
	const char *name = "(anon)";
	uint64_t ref = 0, size = 0;

	SIMPLEQ_FOREACH(dav, &die->die_avals, dav_next) {
		switch (dav->dav_dat->dat_attr) {
		case DW_AT_name:
			name = dav2str(dav);
			break;
		case DW_AT_type:
			ref = dav2val(dav, psz);
			break;
		case DW_AT_byte_size:
			size = dav2val(dav, psz);
			break;
		default:
			DPRINTF("%s\n", dw_at2name(dav->dav_dat->dat_attr));
			break;
		}
	}

	itype = calloc(1, sizeof(*itype));
	if (itype == NULL)
		err(1, "calloc");

	TAILQ_INIT(&itype->members);
	itype->flags = IF_UNRESOLVED;
	itype->off = die->die_offset;
	itype->ref = ref;
	itype->idx = i;
	itype->size = size;
	itype->type = type;
	itype->name = strdup(name);
	if (itype->name == NULL)
		err(1, "strdup");

	if (itype->ref == 0 && itype->size == sizeof(void *)) {
		/* Work around GCC not emiting a type for void */
		itype->flags &= ~IF_UNRESOLVED;
		itype->ref = VOID_OFFSET;
		itype->refidx = VOID_INDEX;
	}

	return itype;
}

struct itype *
parse_array(struct dwdie *die, size_t psz, unsigned int i)
{
	struct itype *itype;
	struct dwaval *dav;
	const char *name = "(anon)";
	uint64_t ref = 0;

	SIMPLEQ_FOREACH(dav, &die->die_avals, dav_next) {
		switch (dav->dav_dat->dat_attr) {
		case DW_AT_name:
			name = dav2str(dav);
			break;
		case DW_AT_type:
			ref = dav2val(dav, psz);
			break;
		default:
			DPRINTF("%s\n", dw_at2name(dav->dav_dat->dat_attr));
			break;
		}
	}

	itype = calloc(1, sizeof(*itype));
	if (itype == NULL)
		err(1, "calloc");

	TAILQ_INIT(&itype->members);
	itype->flags = IF_UNRESOLVED;
	itype->off = die->die_offset;
	itype->ref = ref;
	itype->idx = i;
	itype->type = CTF_K_ARRAY;
	itype->name = strdup(name);
	if (itype->name == NULL)
		err(1, "strdup");

	subparse_subrange(die, psz, itype);

	return itype;
}

void
subparse_subrange(struct dwdie *die, size_t psz, struct itype *itype)
{
	struct dwaval *dav;

	assert(itype->type == CTF_K_ARRAY);

	if (die->die_dab->dab_children == DW_CHILDREN_no)
		return;

	/*
	 * This loop assumes that the children of a DIE are just
	 * after it on the list.
	 */
	while ((die = SIMPLEQ_NEXT(die, die_next)) != NULL) {
		uint64_t tag = die->die_dab->dab_tag;
		uint64_t nelems = 0;

		if (tag != DW_TAG_subrange_type)
			break;

		SIMPLEQ_FOREACH(dav, &die->die_avals, dav_next) {
			switch (dav->dav_dat->dat_attr) {
			case DW_AT_count:
				nelems = dav2val(dav, psz);
				break;
			case DW_AT_upper_bound:
				nelems = dav2val(dav, psz) + 1;
				break;
			default:
				DPRINTF("%s\n",
				    dw_at2name(dav->dav_dat->dat_attr));
				break;
			}
		}

		itype->nelems = nelems;
	}
}

struct itype *
parse_struct(struct dwdie *die, size_t psz, unsigned int i, int type)
{
	struct itype *itype;
	struct dwaval *dav;
	const char *name = "(anon)";
	uint64_t size = 0;

	SIMPLEQ_FOREACH(dav, &die->die_avals, dav_next) {
		switch (dav->dav_dat->dat_attr) {
		case DW_AT_byte_size:
			size = dav2val(dav, psz);
			break;
		case DW_AT_name:
			name = dav2str(dav);
			break;
		default:
			DPRINTF("%s\n", dw_at2name(dav->dav_dat->dat_attr));
			break;
		}
	}

	itype = calloc(1, sizeof(*itype));
	if (itype == NULL)
		err(1, "calloc");

	TAILQ_INIT(&itype->members);
	itype->flags = IF_UNRESOLVED_MEMBERS;
	itype->off = die->die_offset;
	itype->ref = 0;
	itype->idx = i;
	itype->size = size;
	itype->type = type;
	itype->name = strdup(name);
	if (itype->name == NULL)
		err(1, "strdup");

	subparse_member(die, psz, itype);

	return itype;
}

void
subparse_member(struct dwdie *die, size_t psz, struct itype *itype)
{
	struct imember *imember;
	struct dwaval *dav;
	const char *name = "unknown";
	uint64_t loc = 0, ref = 0;
	uint16_t bits;

	assert(itype->type == CTF_K_STRUCT || itype->type == CTF_K_UNION);

	if (die->die_dab->dab_children == DW_CHILDREN_no)
		return;

	/*
	 * This loop assumes that the children of a DIE are just
	 * after it on the list.
	 */
	while ((die = SIMPLEQ_NEXT(die, die_next)) != NULL) {
		uint64_t tag = die->die_dab->dab_tag;

		if (tag != DW_TAG_member)
			break;

		SIMPLEQ_FOREACH(dav, &die->die_avals, dav_next) {
			switch (dav->dav_dat->dat_attr) {
			case DW_AT_name:
				name = dav2str(dav);
				break;
			case DW_AT_type:
				ref = dav2val(dav, psz);
				break;
			case DW_AT_data_member_location:
				loc = 8 * dav2val(dav, psz);
				break;
			case DW_AT_bit_size:
				bits = dav2val(dav, psz);
				break;
			default:
				DPRINTF("%s\n",
				    dw_at2name(dav->dav_dat->dat_attr));
				break;
			}
		}

		imember = calloc(1, sizeof(*imember));
		if (imember == NULL)
			err(1, "calloc");

		imember->loc = loc;
		imember->ref = ref;
		imember->name = strdup(name);
		if (imember->name == NULL)
			err(1, "strdup");

		itype->nelems++;
		TAILQ_INSERT_TAIL(&itype->members, imember, next);
	}
}


void
subparse_arguments(struct dwdie *die, size_t psz, struct itype *itype)
{
	struct imember *imember;
	struct dwaval *dav;
	uint64_t ref = 0;

	assert(itype->type == CTF_K_FUNCTION);

	if (die->die_dab->dab_children == DW_CHILDREN_no)
		return;

	/*
	 * This loop assumes that the children of a DIE are just
	 * after it on the list.
	 */
	while ((die = SIMPLEQ_NEXT(die, die_next)) != NULL) {
		uint64_t tag = die->die_dab->dab_tag;

		if (tag == DW_TAG_unspecified_parameters) {
			itype->nelems = VARARGS;
			continue;
		}

		if (tag != DW_TAG_formal_parameter)
			break;

		itype->flags |= IF_UNRESOLVED_MEMBERS;

		SIMPLEQ_FOREACH(dav, &die->die_avals, dav_next) {
			switch (dav->dav_dat->dat_attr) {
			case DW_AT_type:
				ref = dav2val(dav, psz);
				break;
			default:
				DPRINTF("%s\n",
				    dw_at2name(dav->dav_dat->dat_attr));
				break;
			}
		}

		imember = calloc(1, sizeof(*imember));
		if (imember == NULL)
			err(1, "calloc");

		imember->ref = ref;
		itype->nelems++;
		TAILQ_INSERT_TAIL(&itype->members, imember, next);
	}
}

struct itype *
parse_function(struct dwdie *die, size_t psz, unsigned int i)
{
	struct itype *itype;
	struct dwaval *dav;
	const char *name = "unknown";
	uint64_t ref = 0;

	SIMPLEQ_FOREACH(dav, &die->die_avals, dav_next) {
		switch (dav->dav_dat->dat_attr) {
		case DW_AT_name:
			name = dav2str(dav);
			break;
		case DW_AT_type:
			ref = dav2val(dav, psz);
			break;
		default:
			DPRINTF("%s\n", dw_at2name(dav->dav_dat->dat_attr));
			break;
		}
	}

	itype = calloc(1, sizeof(*itype));
	if (itype == NULL)
		err(1, "calloc");

	TAILQ_INIT(&itype->members);
	itype->flags = IF_UNRESOLVED|IF_FUNCTION;
	itype->off = die->die_offset;
	itype->ref = ref;		/* return type */
	itype->idx = i;
	itype->type = CTF_K_FUNCTION;
	itype->name = strdup(name);

	subparse_arguments(die, psz, itype);

	if (itype->ref == 0) {
		/* Work around GCC not emiting a type for void */
		itype->flags &= ~IF_UNRESOLVED;
		itype->ref = VOID_OFFSET;
		itype->refidx = VOID_INDEX;
	}
	return itype;
}

struct itype *
parse_funcptr(struct dwdie *die, size_t psz, unsigned int i)
{
	struct itype *itype;
	struct dwaval *dav;
	const char *name = "anon";
	uint64_t ref = 0;

	SIMPLEQ_FOREACH(dav, &die->die_avals, dav_next) {
		switch (dav->dav_dat->dat_attr) {
		case DW_AT_name:
			name = dav2str(dav);
			break;
		case DW_AT_type:
			ref = dav2val(dav, psz);
			break;
		default:
			DPRINTF("%s\n", dw_at2name(dav->dav_dat->dat_attr));
			break;
		}
	}

	itype = calloc(1, sizeof(*itype));
	if (itype == NULL)
		err(1, "calloc");

	TAILQ_INIT(&itype->members);
	itype->flags = IF_UNRESOLVED;
	itype->off = die->die_offset;
	itype->ref = ref;
	itype->idx = i;
	itype->type = CTF_K_FUNCTION;
	itype->name = strdup(name);

	subparse_arguments(die, psz, itype);

	return itype;
}
uint64_t
dav2val(struct dwaval *dav, size_t psz)
{
	uint64_t val = (uint64_t)-1;

	switch (dav->dav_dat->dat_form) {
	case DW_FORM_addr:
	case DW_FORM_ref_addr:
		if (psz == sizeof(uint32_t))
			val = dav->dav_u32;
		else
			val = dav->dav_u64;
		break;
	case DW_FORM_block1:
	case DW_FORM_block2:
	case DW_FORM_block4:
	case DW_FORM_block:
		val = dav->dav_buf.len;
		break;
	case DW_FORM_flag:
	case DW_FORM_data1:
	case DW_FORM_ref1:
		val = dav->dav_u8;
		break;
	case DW_FORM_data2:
	case DW_FORM_ref2:
		val = dav->dav_u16;
		break;
	case DW_FORM_data4:
	case DW_FORM_ref4:
		val = dav->dav_u32;
		break;
	case DW_FORM_data8:
	case DW_FORM_ref8:
		val = dav->dav_u64;
		break;
	case DW_FORM_strp:
		val = dav->dav_u32;
		break;
	case DW_FORM_flag_present:
		val = 1;
		break;
	default:
		break;
	}

	return val;
}

const char *
dav2str(struct dwaval *dav)
{
	const char *str = NULL;
	extern const char *dstrbuf;

	switch (dav->dav_dat->dat_form) {
	case DW_FORM_string:
		str = dav->dav_str;
		break;
	case DW_FORM_strp:
		str = dstrbuf + dav->dav_u32;
		break;
	default:
		break;
	}

	return str;
}

const char *
enc2name(unsigned short enc)
{
	static const char *enc_name[] = { "address", "boolean", "complex float",
	    "float", "signed", "char", "unsigned", "unsigned char",
	    "imaginary float", "packed decimal", "numeric string", "edited",
	    "signed fixed", "unsigned fixed", "decimal float" };

	if (enc > 0 && enc <= nitems(enc_name))
		return enc_name[enc - 1];

	return "invalid";
}
