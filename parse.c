/*
 * Copyright (c) 2016-2017 Martin Pieuchot <mpi@openbsd.org>
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
 * DWARF to IT (internal type) representation parser.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/ctf.h>

#include <assert.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>

#include "ctfconvert.h"
#include "xmalloc.h"
#include "dwarf.h"
#include "dw.h"

#define DPRINTF(x...)	do { /*printf(x)*/ } while (0)

#define VOID_OFFSET	1	/* Fake offset for generating "void" type. */

void		 parse_cu(struct dwcu *, struct itype_queue *);
void		 resolve(struct itype *, struct itype_queue *, size_t);
void		 merge(struct itype_queue *, struct itype_queue *);

struct itype	*insert_void(unsigned int);
struct itype	*parse_base(struct dwdie *, size_t, unsigned int);
struct itype	*parse_refers(struct dwdie *, size_t, unsigned int, int);
struct itype	*parse_array(struct dwdie *, size_t, unsigned int);
struct itype	*parse_enum(struct dwdie *, size_t, unsigned int);
struct itype	*parse_struct(struct dwdie *, size_t, unsigned int, int);
struct itype	*parse_function(struct dwdie *, size_t, unsigned int);
struct itype	*parse_funcptr(struct dwdie *, size_t, unsigned int);

void		 subparse_subrange(struct dwdie *, size_t, struct itype *);
void		 subparse_member(struct dwdie *, size_t, struct itype *);
void		 subparse_arguments(struct dwdie *, size_t, struct itype *);

size_t		 dav2val(struct dwaval *, size_t);
const char	*dav2str(struct dwaval *);
const char	*enc2name(unsigned short);

int		 it_cmp(struct itype *, struct itype *);

RB_HEAD(itype_tree, itype)	 itypet[CTF_K_MAX];
struct itype			*void_it;
uint16_t			 tidx, fidx;	/* type and function indexes */
uint16_t			 long_tidx;	/* index of 'long', for array */


RB_GENERATE(itype_tree, itype, it_node, it_cmp);

/*
 * Construct a list of internal type and functions based on DWARF
 * INFO and ABBREV sections.
 *
 * Multiple CUs are supported.
 */
void
dwarf_parse(const char *infobuf, size_t infolen, const char *abbuf,
    size_t ablen)
{
	struct dwbuf		 info = { .buf = infobuf, .len = infolen };
	struct dwbuf		 abbrev = { .buf = abbuf, .len = ablen };
	struct dwcu		*dcu = NULL;
	struct itype		*it;
	int			 i;

	for (i = 0; i < CTF_K_MAX; i++)
		RB_INIT(&itypet[i]);

	tidx = fidx = 0;

	void_it = insert_void(++tidx);
	TAILQ_INSERT_TAIL(&itypeq, void_it, it_next);

	while (dw_cu_parse(&info, &abbrev, infolen, &dcu) == 0) {
		struct itype_queue	 cu_itypeq;

		TAILQ_INIT(&cu_itypeq);

		/* Parse this CU */
		parse_cu(dcu, &cu_itypeq);

		/* Resolve its types. */
		TAILQ_FOREACH(it, &cu_itypeq, it_next)
			resolve(it, &cu_itypeq, dcu->dcu_offset);

		/* Merge them with the common type list. */
		merge(&itypeq, &cu_itypeq);

		dw_dcu_free(dcu);
	}

	/* Find type "long" */
	RB_FOREACH(it, itype_tree, &itypet[CTF_K_INTEGER]) {
		if (it->it_name == NULL || it->it_size != (8 * sizeof(long)))
			continue;

		if (strcmp(it->it_name, "unsigned") == 0) {
			long_tidx = it->it_idx;
			break;
		}
	}
}

/*
 * Worst case it's a O(n*n) resolution lookup, with ``n'' being the number
 * of elements in ``itypeq''.
 */
void
resolve(struct itype *it, struct itype_queue *itypeq, size_t offset)
{
	int		 toresolve = it->it_nelems;
	struct itype	*tmp;

	if ((it->it_flags & ITF_UNRESOLVED_MEMBERS) &&
	    !TAILQ_EMPTY(&it->it_members)) {
		struct imember	*im;

		TAILQ_FOREACH(tmp, itypeq, it_next) {
			TAILQ_FOREACH(im, &it->it_members, im_next) {
				if (tmp->it_off == (im->im_ref + offset)) {
					im->im_refp = tmp;
					toresolve--;
				}
			}
		}
	}

	if (toresolve == 0)
		it->it_flags &= ~ITF_UNRESOLVED_MEMBERS;

	if (it->it_flags & ITF_UNRESOLVED) {
		TAILQ_FOREACH(tmp, itypeq, it_next) {
			if (tmp->it_off == (it->it_ref + offset)) {
				it->it_refp = tmp;
				it->it_flags &= ~ITF_UNRESOLVED;
				break;
			}
		}
	}

#ifdef DEBUG
	if (it->it_flags & (ITF_UNRESOLVED|ITF_UNRESOLVED_MEMBERS)) {
		printf("0x%zx: %s type=%d unresolved 0x%llx", it->it_off,
		    it->it_name, it->it_type, it->it_ref);
		if (toresolve)
			printf(": %d members", toresolve);
		printf("\n");
	}
#endif
}

void
it_free(struct itype *it)
{
	struct imember *im;

	if (it == NULL)
		return;

	while ((im = TAILQ_FIRST(&it->it_members)) != NULL) {
		TAILQ_REMOVE(&it->it_members, im, im_next);
		free(im);
	}


	free(it->it_name);
	free(it);
}

/*
 * Return 0 if ``a'' matches ``b''.
 */
int
it_cmp(struct itype *a, struct itype *b)
{
	int diff;

	if ((diff = (a->it_type - b->it_type)) != 0)
		return diff;

	if ((diff = (a->it_size - b->it_size)) != 0)
		return diff;

	if ((diff = (a->it_nelems - b->it_nelems)) != 0)
		return diff;

	/* Match by name */
	if ((a->it_name != NULL) && (b->it_name != NULL))
		return strcmp(a->it_name, b->it_name);

	/* Only one of them is anonym */
	if (a->it_name != b->it_name)
		return (a->it_name == NULL) ? -1 : 1;

	/* Match by reference */
	if ((a->it_refp != NULL) && (b->it_refp != NULL))
		return it_cmp(a->it_refp, b->it_refp);

	return 1;
}

/*
 * Merge type representation from a CU with already known types.
 *
 * This algorithm is in O(n*(m+n)) with:
 *   n = number of elements in ``otherq''
 *   m = number of elements in ``itypeq''
 */
void
merge(struct itype_queue *itypeq, struct itype_queue *otherq)
{
	struct itype *it, *nit;
	struct itype *prev, *last;

	/* Remember last of the existing types. */
	last = TAILQ_LAST(itypeq, itype_queue);
	if (last == NULL)
		return;

	/* First ``it'' that needs a duplicate check. */
	it = TAILQ_FIRST(otherq);
	if (it == NULL)
		return;

	TAILQ_CONCAT(itypeq, otherq, it_next);

	for (; it != NULL; it = nit) {
		nit = TAILQ_NEXT(it, it_next);

		/* We're looking for duplicated type only. */
		if (it->it_flags & ITF_FUNCTION)
			continue;

		/* Look if we already have this type. */
		prev = RB_FIND(itype_tree, &itypet[it->it_type], it);
		if (prev != NULL) {
			struct itype *old = it;

			/* Remove duplicate */
			TAILQ_REMOVE(itypeq, it, it_next);

			it = TAILQ_NEXT(last, it_next);
			while (it != NULL) {
				struct imember *im;

				/* Substitute references */
				if (it->it_refp == old)
					it->it_refp = prev;

				TAILQ_FOREACH(im, &it->it_members, im_next) {
					if (im->im_refp == old)
						im->im_refp = prev;
				}

				/* Adjust indexes, assume newidx < oldidx */
				if (it->it_idx > old->it_idx)
					it->it_idx--;

				it = TAILQ_NEXT(it, it_next);
			}

			it_free(old);
		} else {
			RB_INSERT(itype_tree, &itypet[it->it_type], it);
		}
	}

	/* Update global index to match removed entries. */
	it = TAILQ_LAST(itypeq, itype_queue);
	while (it != NULL && (it->it_flags & ITF_FUNCTION))
		it = TAILQ_PREV(it, itype_queue, it_next);

	if (it != NULL)
		tidx = it->it_idx;
}

void
parse_cu(struct dwcu *dcu, struct itype_queue *itypeq)
{
	struct itype *it = NULL;
	struct dwdie *die;
	size_t psz = dcu->dcu_psize;

	SIMPLEQ_FOREACH(die, &dcu->dcu_dies, die_next) {
		uint64_t tag = die->die_dab->dab_tag;

		switch (tag) {
		case DW_TAG_array_type:
			it = parse_array(die, dcu->dcu_psize, ++tidx);
			break;
		case DW_TAG_enumeration_type:
			it = parse_enum(die, dcu->dcu_psize, ++tidx);
			break;
		case DW_TAG_pointer_type:
			it = parse_refers(die, psz, ++tidx, CTF_K_POINTER);
			break;
		case DW_TAG_structure_type:
			it = parse_struct(die, psz, ++tidx, CTF_K_STRUCT);
			break;
		case DW_TAG_typedef:
			it = parse_refers(die, psz, ++tidx, CTF_K_TYPEDEF);
			break;
		case DW_TAG_union_type:
			it = parse_struct(die, psz, ++tidx, CTF_K_UNION);
			break;
		case DW_TAG_base_type:
			it = parse_base(die, psz, ++tidx);
			break;
		case DW_TAG_const_type:
			it = parse_refers(die, psz, ++tidx, CTF_K_CONST);
			break;
		case DW_TAG_volatile_type:
			it = parse_refers(die, psz, ++tidx, CTF_K_VOLATILE);
			break;
		case DW_TAG_restrict_type:
			it = parse_refers(die, psz, ++tidx, CTF_K_RESTRICT);
			break;
		case DW_TAG_subprogram:
			it = parse_function(die, psz, fidx++);
			if (it == NULL)
				continue;
			break;
		case DW_TAG_subroutine_type:
			it = parse_funcptr(die, psz, ++tidx);
			break;
		/*
		 * Children are assumed to be right after their parent in
		 * the list.  The parent parsing function takes care of
		 * parsing them.
		 */
		 case DW_TAG_member:
			 assert(it->it_type == CTF_K_STRUCT ||
			    it->it_type == CTF_K_UNION ||
			    it->it_type == CTF_K_ENUM);
			continue;
		 case DW_TAG_subrange_type:
			assert(it->it_type == CTF_K_ARRAY);
			continue;
		case DW_TAG_formal_parameter:
			/*
			 * If we skipped the second inline definition,
			 * skip its arguments.
			 */
			if (it == NULL)
				continue;

			/* See comment in subparse_arguments(). */
			if (it->it_type == CTF_K_STRUCT ||
			    it->it_type == CTF_K_UNION ||
			    it->it_type == CTF_K_ENUM ||
			    it->it_type == CTF_K_TYPEDEF)
				continue;

			assert(it->it_type == CTF_K_FUNCTION);
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

		TAILQ_INSERT_TAIL(itypeq, it, it_next);
	}
}

struct itype *
insert_void(unsigned int i)
{
	struct itype *it;

	it = xcalloc(1, sizeof(*it));
	TAILQ_INIT(&it->it_members);
	it->it_flags = 0; /* Do not need to be resolved. */
	it->it_off = VOID_OFFSET;
	it->it_idx = i;
	it->it_enc = CTF_INT_SIGNED;
	it->it_type = CTF_K_INTEGER;
	it->it_name = "void";
	it->it_size = 0;

	return it;
}

struct itype *
parse_base(struct dwdie *die, size_t psz, unsigned int i)
{
	struct itype *it;
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
		if (bits < psz)
			encoding = CTF_FP_SINGLE;
		else if (bits == psz)
			encoding = CTF_FP_DOUBLE;
		else
			encoding = CTF_FP_LDOUBLE;
		type = CTF_K_FLOAT;
		break;
	case DW_ATE_complex_float:
		if (bits < psz)
			encoding = CTF_FP_CPLX;
		else if (bits == psz)
			encoding = CTF_FP_DCPLX;
		else
			encoding = CTF_FP_LDCPLX;
		type = CTF_K_FLOAT;
		break;
	case DW_ATE_imaginary_float:
		if (bits < psz)
			encoding = CTF_FP_IMAGRY;
		else if (bits == psz)
			encoding = CTF_FP_DIMAGRY;
		else
			encoding = CTF_FP_LDIMAGRY;
		type = CTF_K_FLOAT;
		break;
	default:
		DPRINTF("unknown encoding: %d\n", enc);
		return (NULL);
	}

	it = xcalloc(1, sizeof(*it));
	TAILQ_INIT(&it->it_members);
	it->it_flags = 0; /* Do not need to be resolved. */
	it->it_off = die->die_offset;
	it->it_idx = i;
	it->it_enc = encoding;
	it->it_type = type;
	it->it_name = xstrdup(enc2name(enc));
	it->it_size = bits;

	return it;
}

struct itype *
parse_refers(struct dwdie *die, size_t psz, unsigned int i, int type)
{
	struct itype *it;
	struct dwaval *dav;
	char *name = NULL;
	size_t ref = 0, size = 0;

	SIMPLEQ_FOREACH(dav, &die->die_avals, dav_next) {
		switch (dav->dav_dat->dat_attr) {
		case DW_AT_name:
			name = xstrdup(dav2str(dav));
			break;
		case DW_AT_type:
			ref = dav2val(dav, psz);
			break;
		case DW_AT_byte_size:
			size = dav2val(dav, psz);
			assert(size < UINT_MAX);
			break;
		default:
			DPRINTF("%s\n", dw_at2name(dav->dav_dat->dat_attr));
			break;
		}
	}

	it = xcalloc(1, sizeof(*it));
	TAILQ_INIT(&it->it_members);
	it->it_flags = ITF_UNRESOLVED;
	it->it_off = die->die_offset;
	it->it_ref = ref;
	it->it_idx = i;
	it->it_size = size;
	it->it_type = type;
	it->it_name = name;

	if (it->it_ref == 0 && (it->it_size == sizeof(void *) ||
	    type == CTF_K_CONST || type == CTF_K_VOLATILE || CTF_K_POINTER)) {
		/* Work around GCC/clang not emiting a type for void */
		it->it_flags &= ~ITF_UNRESOLVED;
		it->it_ref = VOID_OFFSET;
		it->it_refp = void_it;
	}

	return it;
}

struct itype *
parse_array(struct dwdie *die, size_t psz, unsigned int i)
{
	struct itype *it;
	struct dwaval *dav;
	char *name = NULL;
	size_t ref = 0;

	SIMPLEQ_FOREACH(dav, &die->die_avals, dav_next) {
		switch (dav->dav_dat->dat_attr) {
		case DW_AT_name:
			name = xstrdup(dav2str(dav));
			break;
		case DW_AT_type:
			ref = dav2val(dav, psz);
			break;
		default:
			DPRINTF("%s\n", dw_at2name(dav->dav_dat->dat_attr));
			break;
		}
	}

	it = xcalloc(1, sizeof(*it));
	TAILQ_INIT(&it->it_members);
	it->it_flags = ITF_UNRESOLVED;
	it->it_off = die->die_offset;
	it->it_ref = ref;
	it->it_idx = i;
	it->it_type = CTF_K_ARRAY;
	it->it_name = name;

	subparse_subrange(die, psz, it);

	return it;
}

struct itype *
parse_enum(struct dwdie *die, size_t psz, unsigned int i)
{
	struct itype *it;
	struct dwaval *dav;
	char *name = NULL;
	size_t size = 0;

	SIMPLEQ_FOREACH(dav, &die->die_avals, dav_next) {
		switch (dav->dav_dat->dat_attr) {
		case DW_AT_byte_size:
			size = dav2val(dav, psz);
			assert(size < UINT_MAX);
			break;
		case DW_AT_name:
			name = xstrdup(dav2str(dav));
			break;
		default:
			DPRINTF("%s\n", dw_at2name(dav->dav_dat->dat_attr));
			break;
		}
	}

	it = xcalloc(1, sizeof(*it));
	TAILQ_INIT(&it->it_members);
	it->it_off = die->die_offset;
	it->it_ref = 0;
	it->it_idx = i;
	it->it_size = size;
	it->it_type = CTF_K_ENUM;
	it->it_name = name;

	return it;
}

void
subparse_subrange(struct dwdie *die, size_t psz, struct itype *it)
{
	struct dwaval *dav;

	assert(it->it_type == CTF_K_ARRAY);

	if (die->die_dab->dab_children == DW_CHILDREN_no)
		return;

	/*
	 * This loop assumes that the children of a DIE are just
	 * after it on the list.
	 */
	while ((die = SIMPLEQ_NEXT(die, die_next)) != NULL) {
		uint64_t tag = die->die_dab->dab_tag;
		size_t nelems = 0;

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

		assert(nelems < UINT_MAX);
		it->it_nelems = nelems;
	}
}

struct itype *
parse_struct(struct dwdie *die, size_t psz, unsigned int i, int type)
{
	struct itype *it;
	struct dwaval *dav;
	char *name = NULL;
	size_t size = 0;

	SIMPLEQ_FOREACH(dav, &die->die_avals, dav_next) {
		switch (dav->dav_dat->dat_attr) {
		case DW_AT_byte_size:
			size = dav2val(dav, psz);
			assert(size < UINT_MAX);
			break;
		case DW_AT_name:
			name = xstrdup(dav2str(dav));
			break;
		default:
			DPRINTF("%s\n", dw_at2name(dav->dav_dat->dat_attr));
			break;
		}
	}

	it = xcalloc(1, sizeof(*it));
	TAILQ_INIT(&it->it_members);
	it->it_flags = ITF_UNRESOLVED_MEMBERS;
	it->it_off = die->die_offset;
	it->it_ref = 0;
	it->it_idx = i;
	it->it_size = size;
	it->it_type = type;
	it->it_name = name;

	subparse_member(die, psz, it);

	return it;
}

void
subparse_member(struct dwdie *die, size_t psz, struct itype *it)
{
	struct imember *im;
	struct dwaval *dav;
	const char *name = NULL;
	size_t off = 0, ref = 0, bits = 0;
	uint8_t lvl = die->die_lvl;

	assert(it->it_type == CTF_K_STRUCT || it->it_type == CTF_K_UNION);

	if (die->die_dab->dab_children == DW_CHILDREN_no)
		return;

	/*
	 * This loop assumes that the children of a DIE are just
	 * after it on the list.
	 */
	while ((die = SIMPLEQ_NEXT(die, die_next)) != NULL) {
		if (die->die_lvl <= lvl)
			break;

		/* Skip members of members */
		if (die->die_lvl > lvl + 1)
			continue;

		SIMPLEQ_FOREACH(dav, &die->die_avals, dav_next) {
			switch (dav->dav_dat->dat_attr) {
			case DW_AT_name:
				name = xstrdup(dav2str(dav));
				break;
			case DW_AT_type:
				ref = dav2val(dav, psz);
				break;
			case DW_AT_data_member_location:
				off = dav2val(dav, psz);
				break;
			case DW_AT_bit_size:
				bits = dav2val(dav, psz);
				assert(bits < USHRT_MAX);
				break;
			default:
				DPRINTF("%s\n",
				    dw_at2name(dav->dav_dat->dat_attr));
				break;
			}
		}

		im = xcalloc(1, sizeof(*im));
		im->im_off = off;
		im->im_ref = ref;
		im->im_name = name;

		assert(it->it_nelems < UINT_MAX);
		it->it_nelems++;
		TAILQ_INSERT_TAIL(&it->it_members, im, im_next);
	}
}


void
subparse_arguments(struct dwdie *die, size_t psz, struct itype *it)
{
	struct imember *im;
	struct dwaval *dav;
	size_t ref = 0;

	assert(it->it_type == CTF_K_FUNCTION);

	if (die->die_dab->dab_children == DW_CHILDREN_no)
		return;

	/*
	 * This loop assumes that the children of a DIE are after it
	 * on the list.
	 */
	while ((die = SIMPLEQ_NEXT(die, die_next)) != NULL) {
		uint64_t tag = die->die_dab->dab_tag;

		if (tag == DW_TAG_unspecified_parameters) {
			it->it_flags |= ITF_VARARGS;
			continue;
		}

		/*
		 * Nested declaration.
		 *
		 * This matches the case where a ``struct'', ``union'',
		 * ``enum'' or ``typedef'' is first declared "inside" a
		 * function declaration.
		 */
		if (tag == DW_TAG_structure_type || tag == DW_TAG_union_type ||
		    tag == DW_TAG_enumeration_type || tag == DW_TAG_typedef)
			continue;

		if (tag != DW_TAG_formal_parameter)
			break;

		it->it_flags |= ITF_UNRESOLVED_MEMBERS;

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

		im = xcalloc(1, sizeof(*im));
		im->im_ref = ref;
		assert(it->it_nelems < UINT_MAX);
		it->it_nelems++;
		TAILQ_INSERT_TAIL(&it->it_members, im, im_next);
	}
}

struct itype *
parse_function(struct dwdie *die, size_t psz, unsigned int i)
{
	struct itype *it;
	struct dwaval *dav;
	char *name = NULL;
	size_t ref = 0;

	SIMPLEQ_FOREACH(dav, &die->die_avals, dav_next) {
		switch (dav->dav_dat->dat_attr) {
		case DW_AT_name:
			name = xstrdup(dav2str(dav));
			break;
		case DW_AT_type:
			ref = dav2val(dav, psz);
			break;
		case DW_AT_abstract_origin:
			/*
			 * Skip second empty definition for inline
			 * functions.
			 */
			free(name);
			return NULL;
		default:
			DPRINTF("%s\n", dw_at2name(dav->dav_dat->dat_attr));
			break;
		}
	}

	it = xcalloc(1, sizeof(*it));
	TAILQ_INIT(&it->it_members);
	it->it_flags = ITF_UNRESOLVED|ITF_FUNCTION;
	it->it_off = die->die_offset;
	it->it_ref = ref;		/* return type */
	it->it_idx = i;
	it->it_type = CTF_K_FUNCTION;
	it->it_name = name;

	subparse_arguments(die, psz, it);

	if (it->it_ref == 0) {
		/* Work around GCC not emiting a type for void */
		it->it_flags &= ~ITF_UNRESOLVED;
		it->it_ref = VOID_OFFSET;
		it->it_refp = void_it;
	}

	return it;
}

struct itype *
parse_funcptr(struct dwdie *die, size_t psz, unsigned int i)
{
	struct itype *it;
	struct dwaval *dav;
	char *name = NULL;
	size_t ref = 0;

	SIMPLEQ_FOREACH(dav, &die->die_avals, dav_next) {
		switch (dav->dav_dat->dat_attr) {
		case DW_AT_name:
			name = xstrdup(dav2str(dav));
			break;
		case DW_AT_type:
			ref = dav2val(dav, psz);
			break;
		default:
			DPRINTF("%s\n", dw_at2name(dav->dav_dat->dat_attr));
			break;
		}
	}

	it = xcalloc(1, sizeof(*it));
	TAILQ_INIT(&it->it_members);
	it->it_flags = ITF_UNRESOLVED;
	it->it_off = die->die_offset;
	it->it_ref = ref;
	it->it_idx = i;
	it->it_type = CTF_K_FUNCTION;
	it->it_name = name;

	subparse_arguments(die, psz, it);

	if (it->it_ref == 0) {
		/* Work around GCC not emiting a type for void */
		it->it_flags &= ~ITF_UNRESOLVED;
		it->it_ref = VOID_OFFSET;
		it->it_refp = void_it;
	}

	return it;
}

size_t
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
		dw_loc_parse(&dav->dav_buf, NULL, &val, NULL);
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
