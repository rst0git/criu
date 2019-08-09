#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "uapi/compel/compel.h"

#include "version.h"
#include "piegen.h"
#include "log.h"
#include "../flog/include/flog.h"


#define BUF_SIZE (1<<20)
#define MAGIC 0xABCDABCD

static char _mbuf[BUF_SIZE];
static char *mbuf = _mbuf;
static char *fbuf;
static uint64_t fsize;
static uint64_t mbuf_size = sizeof(_mbuf);

#define CFLAGS_DEFAULT_SET					\
	"-Wstrict-prototypes "					\
	"-fno-stack-protector -nostdlib -fomit-frame-pointer "

#define COMPEL_CFLAGS_PIE	CFLAGS_DEFAULT_SET "-fpie"
#define COMPEL_CFLAGS_NOPIC	CFLAGS_DEFAULT_SET "-fno-pic"

#ifdef NO_RELOCS
#define COMPEL_LDFLAGS_COMMON	"-z noexecstack -T "
#else
#define COMPEL_LDFLAGS_COMMON	"-r -z noexecstack -T "
#endif

typedef struct {
	const char	*arch;		// dir name under arch/
	const char	*cflags;
	const char	*cflags_compat;
} flags_t;

static const flags_t flags = {
#if defined CONFIG_X86_64
	.arch		= "x86",
	.cflags		= COMPEL_CFLAGS_PIE,
	.cflags_compat	= COMPEL_CFLAGS_NOPIC,
#elif defined CONFIG_AARCH64
	.arch		= "aarch64",
	.cflags		= COMPEL_CFLAGS_PIE,
#elif defined(CONFIG_ARMV6) || defined(CONFIG_ARMV7)
	.arch		= "arm",
	.cflags		= COMPEL_CFLAGS_PIE,
#elif defined CONFIG_PPC64
	.arch		= "ppc64",
	.cflags		= COMPEL_CFLAGS_PIE,
#elif defined CONFIG_S390
	.arch		= "s390",
	.cflags		= COMPEL_CFLAGS_PIE,
#else
#error "CONFIG_<ARCH> not defined, or unsupported ARCH"
#endif
};

const char *uninst_root;

static int piegen(void)
{
	struct stat st;
	void *mem;
	int fd, ret = -1;

	fd = open(opts.input_filename, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open file %s", opts.input_filename);
		return -1;
	}

	if (fstat(fd, &st)) {
		pr_perror("Can't stat file %s", opts.input_filename);
		goto err;
	}

	opts.fout = fopen(opts.output_filename, "w");
	if (opts.fout == NULL) {
		pr_perror("Can't open %s", opts.output_filename);
		goto err;
	}

	mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FILE, fd, 0);
	if (mem == MAP_FAILED) {
		pr_perror("Can't mmap file %s", opts.input_filename);
		goto err;
	}

	if (handle_binary(mem, st.st_size)) {
		close(fd), fd = -1;
		unlink(opts.output_filename);
		goto err;
	}

	ret = 0;

err:
	if (fd >= 0)
		close(fd);
	if (opts.fout)
		fclose(opts.fout);
	if (!ret)
		pr_info("%s generated successfully.\n", opts.output_filename);
	return ret;
}

static void cli_log(unsigned int lvl, const char *fmt, unsigned int nargs, unsigned int mask, va_list parms)//себе такую
{
	FILE *f = stdout;

	if (pr_quelled(lvl))
		return;

	if ((lvl == COMPEL_LOG_ERROR) || (lvl == COMPEL_LOG_WARN))
		f = stderr;

	vfprintf(f, fmt, parms);// обращение к флог
}

/* Pre-allocate a buffer in a file and map it into memory. */
int flog_map_buf(int fdout)
{
	uint64_t off = 0;
	void *addr;

	/*
	 * Two buffers are mmaped into memory. A new one is mapped when a first
	 * one is completly filled.
	 */
	if (fbuf && (mbuf - fbuf < BUF_SIZE))
		return 0;

	if (fbuf) {
		if (munmap(fbuf, BUF_SIZE * 2)) {
			fprintf(stderr, "Unable to unmap a buffer: %m");
			return -1;
		}
		off = mbuf - fbuf - BUF_SIZE;
		fbuf = NULL;
	}

	if (fsize == 0)
		fsize += BUF_SIZE;
	fsize += BUF_SIZE;

	if (ftruncate(fdout, fsize)) {
		fprintf(stderr, "Unable to truncate a file: %m");
		return -1;
	}

	if (!fbuf)
		addr = mmap(NULL, BUF_SIZE * 2, PROT_WRITE | PROT_READ,
			    MAP_FILE | MAP_SHARED, fdout, fsize - 2 * BUF_SIZE);
	else
		addr = mremap(fbuf + BUF_SIZE, BUF_SIZE,
				BUF_SIZE * 2, MREMAP_FIXED, fbuf);
	if (addr == MAP_FAILED) {
		fprintf(stderr, "Unable to map a buffer: %m");
		return -1;
	}

	fbuf = addr;
	mbuf = fbuf + off;
	mbuf_size = 2 * BUF_SIZE;

	return 0;
}

static void bin_log(unsigned int lvl, const char *format, unsigned int nargs, unsigned int mask, va_list argptr)//себе такую
{	printf("sdf\n");
	flog_msg_t *m = (void *)mbuf;
	char *str_start, *p;
	//va_list argptr;
	size_t i;

	m->nargs = nargs;
	m->mask = mask;

	str_start = (void *)m->args + sizeof(m->args[0]) * nargs;
	p = memccpy(str_start, format, 0, mbuf_size - (str_start - mbuf));
	if (!p) {
		printf("memcpu error %d", 1);
		return;
	}
	m->fmt = str_start - mbuf;
	str_start = p;

	//va_start(argptr, format);
	for (i = 0; i < nargs; i++) {
		m->args[i] = (long)va_arg(argptr, long);
		/*
		 * If we got a string, we should either
		 * reference it when in rodata, or make
		 * a copy (FIXME implement rodata refs).
		 */
		if (mask & (1u << i)) {
			p = memccpy(str_start, (void *)m->args[i], 0, mbuf_size - (str_start - mbuf));
			if (!p) {
				printf("memcpu error %d", 2);
				return;
			}
			m->args[i] = str_start - mbuf;
			str_start = p;
		}
	}
	//va_end(argptr);
	m->size = str_start - mbuf;

	/*
	 * A magic is required to know where we stop writing into a log file,
	 * if it was not properly closed.  The file is mapped into memory, so a
	 * space in the file is allocated in advance and at the end it can have
	 * some unused tail.
	 */
	m->magic = FLOG_MAGIC;
	m->version = FLOG_VERSION;

	m->size = round_up(m->size, 8);

	mbuf += m->size;
	mbuf_size -= m->size;


}

static int usage(int rc) {
	FILE *out = (rc == 0) ? stdout : stderr;

	fprintf(out,
"Usage:\n"
"  compel [--compat] includes | cflags | ldflags\n"
"  compel plugins [PLUGIN_NAME ...]\n"
"  compel [--compat] [--static] libs\n"
"  compel -f FILE -o FILE [-p NAME] [-l N] hgen\n"
"    -f, --file FILE		input (parasite object) file name\n"
"    -o, --output FILE		output (header) file name\n"
"    -p, --prefix NAME		prefix for var names\n"
"    -l, --log-level NUM		log level (default: %d)\n"
"    -b, --binlog FILE      file to write binary log\n"
"  compel -h|--help\n"
"  compel -V|--version\n"
, COMPEL_DEFAULT_LOGLEVEL
);

	return rc;
}

static void print_includes(void)
{
	int i;
	/* list of standard include dirs (built into C preprocessor) */
	const char *standard_includes[] = {
		"/usr/include",
		"/usr/local/include",
	};

	/* I am not installed, called via a wrapper */
	if (uninst_root) {
		printf("-I %s/include/uapi\n", uninst_root);
		return;
	}

	/* I am installed
	 * Make sure to not print banalities */
	for (i = 0; i < ARRAY_SIZE(standard_includes); i++)
		if (strcmp(INCLUDEDIR, standard_includes[i]) == 0)
			return;

	/* Finally, print our non-standard include path */
	printf("%s\n", "-I " INCLUDEDIR);
}

static void print_cflags(bool compat)
{
	printf("%s\n", compat ? flags.cflags_compat : flags.cflags);
	print_includes();
}

static void print_ldflags(bool compat)
{
	const char *compat_str = (compat) ? "-compat" : "";

	printf("%s", COMPEL_LDFLAGS_COMMON);

	if (uninst_root) {
		printf("%s/arch/%s/scripts/compel-pack%s.lds.S\n",
				uninst_root, flags.arch, compat_str);
	}
	else {
		printf("%s/compel/scripts/compel-pack%s.lds.S\n",
				LIBEXECDIR, compat_str);

	}
}

static void print_plugin(const char *name)
{
	const char suffix[] = ".lib.a";

	if (uninst_root)
		printf("%s/plugins/%s%s\n",
				uninst_root, name, suffix);
	else
		printf("%s/compel/%s%s\n", LIBEXECDIR, name, suffix);
}

static void print_plugins(char *const list[])
{
	char *builtin_list[] = { "std", NULL };
	char **p = builtin_list;

	while (*p != NULL)
		print_plugin(*p++);

	while (*list != NULL)
		print_plugin(*list++);
}

static int print_libs(bool is_static)
{
	if (uninst_root) {
		if (!is_static) {
			fprintf(stderr, "Compel is not installed, can "
					"only link with static libraries "
					"(use --static)\n");
			return 1;
		}
		printf("%s/%s\n", uninst_root, STATIC_LIB);
	}
	else {
		printf("%s/%s\n", LIBDIR, (is_static) ? STATIC_LIB : DYN_LIB);
	}

	return 0;
}

/* Extracts the file name (removing directory path and suffix,
 * and checks the result for being a valid C identifier
 * (replacing - with _ along the way).
 *
 * If everything went fine, return the resulting string,
 * otherwise NULL.
 *
 * Example: get_prefix("./some/path/to/file.c") ==> "file"
 */
static char *gen_prefix(const char *path)
{
	const char *p1 = NULL, *p2 = NULL;
	size_t len;
	int i;
	char *p, *ret;

	len = strlen(path);
	if (len == 0)
		return NULL;

	// Find the last slash (p1)
	// and  the first dot after it (p2)
	for (i = len - 1; i >= 0; i--) {
		if (!p1 && path[i] == '.') {
			p2 = path + i - 1;
		}
		else if (!p1 && path[i] == '/') {
			p1 = path + i + 1;
			break;
		}
	}

	if (!p1) // no slash in path
		p1 = path;
	if (!p2) // no dot (after slash)
		p2 = path + len;

	len = p2 - p1 + 1;
	if (len < 1)
		return NULL;

	ret = strndup(p1, len);

	// Now, check if we got a valid C identifier. We don't need to care
	// about C reserved keywords, as this is only used as a prefix.
	for (p = ret; *p != '\0'; p++) {
		if (isalpha(*p))
			continue;
		// digit is fine, except the first character
		if (isdigit(*p) && p > ret)
			continue;
		// only allowed special character is _
		if (*p == '_')
			continue;
		// as a courtesy, replace - with _
		if (*p == '-') {
			*p = '_';
			continue;
		}
		// invalid character!
		free(ret);
		return NULL;
	}

	return ret;
}

int main(int argc, char *argv[])
{
	int log_level = COMPEL_DEFAULT_LOGLEVEL;
	bool compat = false;
	bool is_static = false;
	int opt, idx;
	char *action;

//for flog
int fdout = STDOUT_FILENO;

	static const char short_opts[] = "csf:o:p:hVl:b:";
	static struct option long_opts[] = {
		{ "compat",	no_argument,		0, 'c' },
		{ "static",	no_argument,		0, 's' },
		{ "file",	required_argument,	0, 'f' },
		{ "output",	required_argument,	0, 'o' },
		{ "prefix",	required_argument,	0, 'p' },
		{ "help",	no_argument,		0, 'h' },
		{ "version",	no_argument,		0, 'V' },
		{ "log-level",	required_argument,	0, 'l' },
		{ "binlog",	required_argument,	0, 'b' },
		{ },
	};

	uninst_root = getenv("COMPEL_UNINSTALLED_ROOTDIR");

	while (1) {
		idx = -1;
		opt = getopt_long(argc, argv, short_opts, long_opts, &idx);
		if (opt == -1)
			break;
		switch (opt) {
		case 'c':
			compat = true;
			break;
		case 's':
			is_static = true;
			break;
		case 'f':
			opts.input_filename = optarg;
			break;
		case 'o':
			opts.output_filename = optarg;
			break;
		case 'p':
			opts.prefix = optarg;
			break;
		case 'l':
			log_level = atoi(optarg);
			break;
		case 'h':
			return usage(0);
		case 'V':
			printf("Version: %d.%d.%d\n",
				   COMPEL_SO_VERSION_MAJOR,
				   COMPEL_SO_VERSION_MINOR,
				   COMPEL_SO_VERSION_SUBLEVEL);
			exit(0);
			break;
		case 'b':
			opts.binlog_filename = optarg;
			break;
		default: // '?'
			// error message already printed by getopt_long()
			return usage(1);
			break;
		}
	}

	if (opts.binlog_filename) {
			// initialize binary log here:
			fdout = open(opts.binlog_filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
			if (fdout < 0) {
				fprintf(stderr, "Can't open %s to save binary log: %s\n",
					opts.binlog_filename, strerror(errno));
				return 1;
			}
			else if (flog_map_buf(fdout))//инициализация буфера
				return 1;
			compel_log_init(&bin_log, log_level);//подсунуть другую функцию
			pr_info("writing to binlog that binlog %s generated successfully.\n", opts.binlog_filename);
			for (int i=0; i<10; i++) {
				pr_info("writing to the log for the %d time.\n", i+1);
			}
		}
		else {

			compel_log_init(&cli_log, log_level);//подсунуть другую функцию
			pr_info("binlog %s generated successfully.\n", "exit");

		}

	if (optind >= argc) {
		fprintf(stderr, "Error: action argument required\n");
		if (opts.binlog_filename)
			pr_info("writing to binlog for the last time\n");
		return usage(1);
	}
	action = argv[optind++];

	if (!strcmp(action, "includes")) {
		print_includes();
		return 0;
	}
	if (!strcmp(action, "cflags")) {
		print_cflags(compat);
		return 0;
	}

	if (!strcmp(action, "ldflags")) {
		print_ldflags(compat);
		return 0;
	}

	if (!strcmp(action, "plugins")) {
		print_plugins(argv + optind);
		return 0;
	}

	if (!strcmp(action, "libs")) {
		return print_libs(is_static);
	}

	if (!strcmp(action, "hgen")) {
		if (!opts.input_filename) {
			fprintf(stderr, "Error: option --file required\n");
			return usage(1);
		}
		if (!opts.output_filename) {
			fprintf(stderr, "Error: option --output required\n");
			return usage(1);
		}
		if (!opts.prefix) {
			// prefix not provided, let's autogenerate
			opts.prefix = gen_prefix(opts.input_filename);
			if (!opts.prefix)
				opts.prefix = gen_prefix(opts.output_filename);
			if (!opts.prefix) {
				fprintf(stderr, "Error: can't autogenerate "
						"prefix (supply --prefix)");
				return 2;
			}
		}


		return piegen();
	}

	fprintf(stderr, "Error: unknown action '%s'\n", action);
	return usage(1);
}
