#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

#include "zdtmtst.h"

#define DEFAULT_MEM_SIZE_MB 4096UL

const char *test_doc = "Benchmark large private anonymous mappings";
const char *test_author = "Radostin Stoyanov <rstoyanov@fedoraproject.org>";

static unsigned long mem_size_mb = DEFAULT_MEM_SIZE_MB;
TEST_OPTION(mem_size_mb, ulong, "mapped memory size in MiB", 0);

static unsigned char page_value(uint64_t page)
{
	return (unsigned char)(((page * 131) + 17) & 0xff);
}

int main(int argc, char **argv)
{
	uint64_t map_size64;
	uint64_t nr_pages;
	char *m;
	uint64_t i;
	size_t map_size;

	test_init(argc, argv);

	map_size64 = mem_size_mb * 1024ULL * 1024ULL;
	if (map_size64 == 0 || map_size64 > SIZE_MAX) {
		fail("Invalid mapping size: %lu MiB", mem_size_mb);
		return 1;
	}

	map_size = (size_t)map_size64;
	nr_pages = map_size / PAGE_SIZE;

	m = mmap(NULL, map_size, PROT_WRITE | PROT_READ,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (m == MAP_FAILED) {
		pr_perror("mmap");
		return 1;
	}

	for (i = 0; i < nr_pages; i++)
		m[(size_t)i * PAGE_SIZE] = page_value(i);

	test_msg("mapped %lu MiB in %llu pages\n", mem_size_mb, (unsigned long long)nr_pages);

	test_daemon();
	test_waitsig();

	for (i = 0; i < nr_pages; i++) {
		unsigned char want = page_value(i);
		unsigned char got = m[(size_t)i * PAGE_SIZE];

		if (got != want) {
			fail("Page %llu corrupted: got %#x want %#x",
			     (unsigned long long)i, got, want);
			return 1;
		}
	}

	pass();
	return 0;
}
