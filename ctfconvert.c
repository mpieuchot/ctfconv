/*
 * Copyright (c) 2016-2017 Martin Pieuchot
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
#include <sys/stat.h>
#include <sys/exec_elf.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/ctf.h>

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <locale.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "itype.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#define DEBUG_ABBREV	".debug_abbrev"
#define DEBUG_INFO	".debug_info"
#define DEBUG_LINE	".debug_line"
#define DEBUG_STR	".debug_str"

#define DUMP		(1 << 0)	/* ctfdump(1) like SUNW_ctf sections */

__dead void	 usage(void);
int		 convert(const char *);
int		 generate(const char *, const char *, uint8_t);
int		 elf_convert(char *, size_t);
void		 dump_type(struct itype *);
void		 dump_func(struct itype *);

/* elf.c */
int		 iself(const char *, size_t);
int		 elf_getshstab(const char *, size_t, const char **, size_t *);
ssize_t		 elf_getsymtab(const char *, const char *, size_t,
		     const Elf_Sym **, size_t *);
ssize_t		 elf_getsection(char *, const char *, const char *,
		     size_t, const char **, size_t *);

/* parse.c */
struct itype_queue *dwarf_parse(const char *, size_t, const char *, size_t);

const char	*ctf_enc2name(unsigned short);

/* list of parsed types and functions */
struct itype_queue itypeq = TAILQ_HEAD_INITIALIZER(itypeq);

__dead void
usage(void)
{
	fprintf(stderr, "usage: %s [-d] -l label [-o outfile] file ...\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *filename, *label = NULL, *outfile = NULL;
	uint8_t flags = 0;
	int ch, error = 0;
	struct itype *it;

	setlocale(LC_ALL, "");

	while ((ch = getopt(argc, argv, "dl:o:")) != -1) {
		switch (ch) {
		case 'd':
			flags |= DUMP;
			break;
		case 'l':
			if (label != NULL)
				usage();
			label = optarg;
			break;
		case 'o':
			if (outfile != NULL)
				usage();
			outfile = optarg;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc <= 0)
		usage();

	while ((filename = *argv++) != NULL) {
		error = convert(filename);
		if (error != 0)
			return error;
	}

	if (flags & DUMP) {
		TAILQ_FOREACH(it, &itypeq, it_next) {
			if (!(it->it_flags & ITF_FUNCTION))
				continue;

			dump_func(it);
		}
		printf("\n");
		TAILQ_FOREACH(it, &itypeq, it_next) {
			if (it->it_flags & ITF_FUNCTION)
				continue;

			dump_type(it);
		}
	}

	if (outfile != NULL) {
		error = generate(outfile, label, 0);
		if (error != 0)
			return error;
	}

	return 0;
}

int
convert(const char *path)
{
	struct stat		 st;
	int			 fd, error = 1;
	char			*p;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		warn("open %s", path);
		return 1;
	}
	if (fstat(fd, &st) == -1) {
		warn("fstat %s", path);
		return 1;
	}
	if ((uintmax_t)st.st_size > SIZE_MAX) {
		warnx("file too big to fit memory");
		return 1;
	}

	p = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED)
		err(1, "mmap");

	if (iself(p, st.st_size))
		error = elf_convert(p, st.st_size);

	munmap(p, st.st_size);
	close(fd);

	return error;
}

const char		*dstrbuf;
size_t			 dstrlen;

int
elf_convert(char *p, size_t filesize)
{
	Elf_Ehdr		*eh = (Elf_Ehdr *)p;
	Elf_Shdr		*sh;
	const char		*shstab;
	const char		*infobuf, *abbuf;
	size_t			 infolen, ablen;
	size_t			 i, shstabsz;
	struct itype_queue	*file_typeq;

	/* Find section header string table location and size. */
	if (elf_getshstab(p, filesize, &shstab, &shstabsz))
		return 1;

	/* Find abbreviation location and size. */
	if (elf_getsection(p, DEBUG_ABBREV, shstab, shstabsz, &abbuf,
	    &ablen) == -1) {
		warnx("%s section not found", DEBUG_ABBREV);
		return 1;
	}

	if (elf_getsection(p, DEBUG_INFO, shstab, shstabsz, &infobuf,
	    &infolen) == -1) {
		warnx("%s section not found", DEBUG_INFO);
		return 1;
	}

	/* Find string table location and size. */
	if (elf_getsection(p, DEBUG_STR, shstab, shstabsz, &dstrbuf,
	    &dstrlen) == -1)
		warnx("%s section not found", DEBUG_STR);

	file_typeq = dwarf_parse(infobuf, infolen, abbuf, ablen);
	if (file_typeq == NULL)
		return 1;

	TAILQ_CONCAT(&itypeq, file_typeq, it_next);

	free(file_typeq);

	return 0;
}


/* Display parsed types a la ctfdump(1) */
void
dump_type(struct itype *it)
{
	struct imember *im;

	switch (it->it_type) {
	case CTF_K_FLOAT:
	case CTF_K_INTEGER:
		printf("  [%zd] %s %s encoding=%s offset=0 bits=%d\n",
		    it->it_idx,
		    (it->it_type == CTF_K_INTEGER) ? "INTEGER" : "FLOAT",
		    it->it_name, ctf_enc2name(it->it_enc), it->it_bits);
		break;
	case CTF_K_POINTER:
		printf("  <%zd> POINTER %s refers to %zd\n", it->it_idx,
		    (it->it_name != NULL) ? it->it_name : "(anon)",
		    it->it_refp->it_idx);
		break;
	case CTF_K_TYPEDEF:
		printf("  <%zd> TYPEDEF %s refers to %zd\n",
		    it->it_idx, it->it_name, it->it_refp->it_idx);
		break;
	case CTF_K_VOLATILE:
		printf("  <%zd> VOLATILE %s refers to %zd\n", it->it_idx,
		    it->it_name, it->it_refp->it_idx);
		break;
	case CTF_K_CONST:
		printf("  <%zd> CONST %s refers to %zd\n", it->it_idx,
		    (it->it_name != NULL) ? it->it_name : "(anon)",
		    it->it_refp->it_idx);
		break;
	case CTF_K_RESTRICT:
		printf("  <%zd> RESTRICT %s refers to %zd\n", it->it_idx,
		    it->it_name, it->it_refp->it_idx);
		break;
	case CTF_K_ARRAY:
		printf("  [%zd] ARRAY %s content: %zd index: ?? nelems: %lld\n",
		    it->it_idx, (it->it_name != NULL) ? it->it_name : "(anon)",
		    it->it_refp->it_idx, it->it_nelems);
		printf("\n");
		break;
	case CTF_K_STRUCT:
	case CTF_K_UNION:
		printf("  [%zd] %s %s (%lld bytes)\n", it->it_idx,
		    (it->it_type == CTF_K_STRUCT) ? "STRUCT" : "UNION",
		    (it->it_name != NULL) ? it->it_name : "(anon)",
		    it->it_size);
		TAILQ_FOREACH(im, &it->it_members, im_next) {
			printf("\t%s type=%zd (0x%llx) off=%zd\n",
			    (im->im_name != NULL) ? im->im_name : "unknown",
			    im->im_refp->it_idx, im->im_ref, im->im_loc);
		}
		printf("\n");
		break;
	case CTF_K_ENUM:
		printf("  [%zd] ENUM\n", it->it_idx);
		break;
	case CTF_K_FUNCTION:
		printf("  [%zd] FUNCTION (%s) returns: %zd args: (",
		    it->it_idx, (it->it_name != NULL) ? it->it_name : "anon",
		    it->it_refp->it_idx);
		TAILQ_FOREACH(im, &it->it_members, im_next) {
			printf("%zd%s", im->im_refp->it_idx,
			    TAILQ_NEXT(im, im_next) ? ", " : "");
		}
		printf(")\n");
		break;
	default:
		assert(0 == 1);
	}
}

void
dump_func(struct itype *it)
{
	struct imember *im;

	printf("  [%zd] FUNC (%s) returns: %zd args: (",
	    it->it_idx,  (it->it_name != NULL) ? it->it_name : "unknown",
	    it->it_refp->it_idx);
	TAILQ_FOREACH(im, &it->it_members, im_next) {
		printf("%zd%s", im->im_refp->it_idx,
		    TAILQ_NEXT(im, im_next) ? ", " : "");
	}
	printf(")\n");
}

const char *
ctf_enc2name(unsigned short enc)
{
	static const char *enc_name[] = { "SIGNED", "CHAR", "SIGNED CHAR",
	    "BOOL", "SIGNED BOOL" };
	static char invalid[7];

	if (enc == CTF_INT_VARARGS)
		return "VARARGS";

	if (enc > 0 && enc < nitems(enc_name))
		return enc_name[enc - 1];

	snprintf(invalid, sizeof(invalid), "0x%x", enc);
	return invalid;
}
