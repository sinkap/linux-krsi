// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "trace_helpers.h"

#define DEBUGFS "/sys/kernel/debug/tracing/"

#define MAX_SYMS 300000
static struct ksym syms[MAX_SYMS];
static int sym_cnt;

static inline ssize_t copy_file_range(int fd_in, loff_t *off_in, int fd_out,
				      loff_t *off_out, size_t len,
				      unsigned int flags)
{
	return syscall(__NR_copy_file_range, fd_in, off_in, fd_out, off_out,
		       len, flags);
}

static int ksym_cmp(const void *p1, const void *p2)
{
	return ((struct ksym *)p1)->addr - ((struct ksym *)p2)->addr;
}

int load_kallsyms(void)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char func[256], buf[256];
	char symbol;
	void *addr;
	int i = 0;

	if (!f)
		return -ENOENT;

	while (fgets(buf, sizeof(buf), f)) {
		if (sscanf(buf, "%p %c %s", &addr, &symbol, func) != 3)
			break;
		if (!addr)
			continue;
		syms[i].addr = (long) addr;
		syms[i].name = strdup(func);
		i++;
	}
	fclose(f);
	sym_cnt = i;
	qsort(syms, sym_cnt, sizeof(struct ksym), ksym_cmp);
	return 0;
}

struct ksym *ksym_search(long key)
{
	int start = 0, end = sym_cnt;
	int result;

	/* kallsyms not loaded. return NULL */
	if (sym_cnt <= 0)
		return NULL;

	while (start < end) {
		size_t mid = start + (end - start) / 2;

		result = key - syms[mid].addr;
		if (result < 0)
			end = mid;
		else if (result > 0)
			start = mid + 1;
		else
			return &syms[mid];
	}

	if (start >= 1 && syms[start - 1].addr < key &&
	    key < syms[start].addr)
		/* valid ksym */
		return &syms[start - 1];

	/* out of range. return _stext */
	return &syms[0];
}

long ksym_get_addr(const char *name)
{
	int i;

	for (i = 0; i < sym_cnt; i++) {
		if (strcmp(syms[i].name, name) == 0)
			return syms[i].addr;
	}

	return 0;
}

/* open kallsyms and read symbol addresses on the fly. Without caching all symbols,
 * this is faster than load + find.
 */
int kallsyms_find(const char *sym, unsigned long long *addr)
{
	char type, name[500];
	unsigned long long value;
	int err = 0;
	FILE *f;

	f = fopen("/proc/kallsyms", "r");
	if (!f)
		return -EINVAL;

	while (fscanf(f, "%llx %c %499s%*[^\n]\n", &value, &type, name) > 0) {
		if (strcmp(name, sym) == 0) {
			*addr = value;
			goto out;
		}
	}
	err = -ENOENT;

out:
	fclose(f);
	return err;
}

void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	while (1) {
		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
}

static int do_copy_file(const char *src, int dest_fd)
{
	int fd_in, ret = 0;
	struct stat stat;

	fd_in = open(src, O_RDONLY);
	if (fd_in < 0)
		return -errno;

	ret = fstat(fd_in, &stat);
	if (ret == -1) {
		ret = -errno;
		goto out;
	}

	ret = copy_file_range(fd_in, NULL, dest_fd, NULL, stat.st_size, 0);
	if (ret == -1)
		ret = -errno;

out:
	close(fd_in);
	return ret;
}

int copy_file(const char *src, const char *dest)
{
	int dest_fd, ret;

	dest_fd = open(dest, O_WRONLY);
	if (dest_fd < 0)
		return -errno;

	ret = do_copy_file(src, dest_fd);
	close(dest_fd);
	return ret;
}

int copy_file_temp(const char *src, char *dest_template)
{
	int dest_fd, ret;

	dest_fd = mkstemp(dest_template);
	if (dest_fd < 0)
		return -errno;

	ret = do_copy_file(src, dest_fd);
	close(dest_fd);
	return ret;
}
