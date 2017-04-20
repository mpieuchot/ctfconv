/*
 * Copyright (c) 2017 Martin Pieuchot
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/ctf.h>

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "itype.h"

/*
 * Dynamic buffer, used for content & string table.
 */
struct dbuf {
	char		*data;	/* start data buffer */
	size_t		 size;	/* size of the buffer */

	char		*cptr; /* position in [data, data + size] */
	size_t		 coff; /* number of written bytes */
};

/* In-memory representation of a CTF section. */
struct imcs {
	struct dbuf	 body;
	struct dbuf	 stab;	/* corresponding string table */
};

#define ROUNDUP(x, y) ((((x) + (y) - 1) / (y)) * (y))

#define DBUF_CHUNKSZ	(64 * 1024)

int
dbuf_realloc(struct dbuf *dbuf, size_t len)
{
	assert(dbuf != NULL);
	assert(len != 0);

	dbuf->data = realloc(dbuf->data, dbuf->size + len);
	if (dbuf->data == NULL)
		return -1; /* errno set */

	dbuf->size += len;
	dbuf->cptr = dbuf->data + dbuf->coff;

	return 0;
}

int
dbuf_copy(struct dbuf *dbuf, void const *data, size_t len)
{
	off_t coff, left;
	int error;

	assert(dbuf->cptr != NULL);
	assert(dbuf->data != NULL);
	assert(dbuf->size != 0);

	if (len == 0)
		return 0;

	left = dbuf->size - dbuf->coff;
	if (left < len) {
		error = dbuf_realloc(dbuf, ROUNDUP((len - left), DBUF_CHUNKSZ));
		if (error)
			return error;
	}

	memcpy(dbuf->cptr, data, len);
	dbuf->cptr += len;
	dbuf->coff += len;

	return 0;
}

size_t
dbuf_pad(struct dbuf *dbuf, int align)
{
	int i = (align - (dbuf->coff % align)) % align;

	while (i-- > 0)
		dbuf_copy(dbuf, "", 1);

	return dbuf->coff;
}

size_t
imcs_add_string(struct imcs *imcs, const char *str)
{
	size_t coff = imcs->stab.coff;

	if (str == NULL)
		return 0;

	if (dbuf_copy(&imcs->stab, str, strlen(str) + 1))
		err(1, "dbuf_copy");

	return coff;
}

void
imcs_add_func(struct imcs *imcs, struct itype *it)
{
	unsigned short		 func, arg;
	struct imember		*im;
	int			 kind, root, vlen;
	int			 i;

	kind = it->it_type;
	root = 0;
	vlen = it->it_nelems;

	func = (kind << 11) | (root << 10) | (vlen & CTF_MAX_VLEN);
	if (dbuf_copy(&imcs->body, &func, sizeof(func)))
		err(1, "dbuf_copy");

	func = it->it_refp->it_idx;
	if (dbuf_copy(&imcs->body, &func, sizeof(func)))
		err(1, "dbuf_copy");

	TAILQ_FOREACH(im, &it->it_members, im_next) {
		arg = im->im_refp->it_idx;
		if (dbuf_copy(&imcs->body, &arg, sizeof(arg)))
			err(1, "dbuf_copy");
	}
}

void
imcs_add_type(struct imcs *imcs, struct itype *it)
{
	struct imember		*im;
	struct ctf_stype	 cts;
	struct ctf_array	 cta;
	unsigned int		 eob;
	size_t			 size;
	int			 kind, root, vlen;

	size = sizeof(cts); /* FIXME */
	kind = it->it_type;
	root = 0;
	/* Function pointers abuse it_nelems for # arguments. */
	vlen = (kind != CTF_K_FUNCTION) ? it->it_nelems : 0;

	cts.cts_name = imcs_add_string(imcs, it->it_name);
	cts.cts_info = (kind << 11) | (root << 10) | (vlen & CTF_MAX_VLEN);
	cts.cts_size = size;
	cts.cts_type = (it->it_refp != NULL) ? it->it_refp->it_idx : 0;

	if (dbuf_copy(&imcs->body, &cts, sizeof(cts)))
		err(1, "dbuf_copy");

	switch (kind) {
	case CTF_K_INTEGER:
	case CTF_K_FLOAT:
		eob = 0; /* FIXME */
		if (dbuf_copy(&imcs->body, &eob, sizeof(eob)))
			err(1, "dbuf_copy");
		break;
	case CTF_K_ARRAY:
		memset(&cta, 0, sizeof(cta));
		if (dbuf_copy(&imcs->body, &cta, sizeof(cta)))
			err(1, "dbuf_copy");
		break;
	case CTF_K_STRUCT:
	case CTF_K_UNION:
		if (size < CTF_LSTRUCT_THRESH) {
			struct ctf_member	 ctm;

			memset(&ctm, 0, sizeof(ctm));
			TAILQ_FOREACH(im, &it->it_members, im_next) {
				ctm.ctm_name =
				    imcs_add_string(imcs, im->im_name);
				ctm.ctm_type = im->im_refp->it_idx;
				ctm.ctm_offset = im->im_loc;

				if (dbuf_copy(&imcs->body, &ctm, sizeof(ctm)))
					err(1, "dbuf_copy");
			}
		} else {
			struct ctf_lmember	 ctlm;

			memset(&ctlm, 0, sizeof(ctlm));
			TAILQ_FOREACH(im, &it->it_members, im_next) {
				ctlm.ctlm_name =
				    imcs_add_string(imcs, im->im_name);
				ctlm.ctlm_type = im->im_refp->it_idx;
				ctlm.ctlm_offsetlo = im->im_loc; /* FIXME */

				if (dbuf_copy(&imcs->body, &ctlm, sizeof(ctlm)))
					err(1, "dbuf_copy");
			}
		}
		break;
	default:
		break;
	}
}

int
imcs_init(struct imcs *imcs)
{
	int error;

	memset(imcs, 0, sizeof(*imcs));

	error = dbuf_realloc(&imcs->body, DBUF_CHUNKSZ);
	if (error)
		return error;

	error = dbuf_realloc(&imcs->stab, DBUF_CHUNKSZ);
	if (error)
		return error;

	/* Add empty string */
	imcs_add_string(imcs, "");

	return 0;
}

/*
 * Generate a CTF buffer from the internal type representation.
 */
int
generate(const char *path, const char *label, uint8_t flags)
{
	struct ctf_header	 cth = { CTF_MAGIC, CTF_VERSION };
	struct imcs		 imcs;
	int			 error, fd;
	struct ctf_lblent	 ctl;
	struct itype		 *it;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd == -1) {
		warn("open %s", path);
		return 1;
	}

	error = imcs_init(&imcs);
	if (error)
		goto out;

	cth.cth_flags = flags;

	/* FIXME */
	cth.cth_parlabel = 0;
	cth.cth_parname = 0;

	/*
	 * Insert label
	 */
	cth.cth_lbloff = 0;

	ctl.ctl_label = imcs_add_string(&imcs, label);
	ctl.ctl_typeidx = 42; /* FIXME */

	/* Fill the buffer */
	error = dbuf_copy(&imcs.body, &ctl, sizeof(ctl));
	if (error)
		goto out;

	/* FIXME */
	cth.cth_objtoff = dbuf_pad(&imcs.body, 2);

	/*
	 * Insert functions
	 */
	cth.cth_funcoff = dbuf_pad(&imcs.body, 2);
	TAILQ_FOREACH(it, &itypeq, it_next) {
		if (!(it->it_flags & ITF_FUNCTION))
			continue;

		imcs_add_func(&imcs, it);
	}

	/*
	 * Insert types
	 */
	cth.cth_typeoff = dbuf_pad(&imcs.body, 4);
	TAILQ_FOREACH(it, &itypeq, it_next) {
		if (it->it_flags & ITF_FUNCTION)
			continue;

		imcs_add_type(&imcs, it);
	}

	/* String table is written from its own buffer. */
	cth.cth_stroff = imcs.body.coff;
	cth.cth_strlen = imcs.stab.coff;

	/* Write header */
	if (write(fd, &cth, sizeof(cth)) != sizeof(cth)) {
		warn("unable to write %zu bytes for %s", sizeof(cth), path);
		return -1;
	}

	/* Write buffer */
	if (write(fd, imcs.body.data, imcs.body.coff) != imcs.body.coff) {
		warn("unable to write %zu bytes for %s", imcs.body.coff, path);
		return -1;
	}

	/* Write string table */
	if (write(fd, imcs.stab.data, imcs.stab.coff) != imcs.stab.coff) {
		warn("unable to write %zu bytes for %s", imcs.stab.coff, path);
		return -1;
	}

out:
	close(fd);
	return error;
}
