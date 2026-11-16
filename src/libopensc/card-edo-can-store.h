/*
 * Private per-user CAN storage for the Polish eID driver.
 *
 * This file is part of OpenSC, under the GNU Lesser General Public
 * License, version 2.1 or (at your option) any later version.
 */
#ifndef OPENSC_EDO_CAN_STORE_H
#define OPENSC_EDO_CAN_STORE_H

#if defined(__linux__)

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

/* Pin the directory; reject symlinks for HOME itself and its private child. */
static int edo_store_dir(int create)
{
	const char *home = getenv("HOME");
	struct stat st;
	int parent = -1, dir = -1, saved_errno;

	if (getuid() != geteuid() || getgid() != getegid()
			|| !home || home[0] != '/') {
		errno = EPERM;
		return -1;
	}
	parent = open(home, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (parent < 0)
		return -1;
	if (fstat(parent, &st) < 0)
		goto fail;
	if (st.st_uid != geteuid() || (st.st_mode & 0022)) {
		errno = EPERM;
		goto fail;
	}
	if (create && mkdirat(parent, ".opensc-edo", 0700) < 0
			&& errno != EEXIST)
		goto fail;
	dir = openat(parent, ".opensc-edo",
		O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (dir < 0)
		goto fail;
	if (fstat(dir, &st) < 0)
		goto fail;
	if (st.st_uid != geteuid() || (st.st_mode & 07777) != 0700) {
		errno = EPERM;
		goto fail;
	}
	close(parent);
	return dir;

fail:
	saved_errno = errno;
	if (dir >= 0)
		close(dir);
	close(parent);
	errno = saved_errno;
	return -1;
}

static int edo_store_digits(const char *can)
{
	size_t i;

	for (i = 0; i < 6; ++i)
		if (can[i] < '0' || can[i] > '9')
			return 0;
	return can[6] == '\0';
}

static int edo_can_store_read(char can[7])
{
	struct stat st;
	char record[8] = {0};
	size_t used = 0;
	int dir = -1, fd = -1;
	int r = SC_ERROR_INTERNAL;

	sc_mem_clear(can, 7);
	dir = edo_store_dir(0);
	if (dir < 0)
		return errno == ENOENT
			? SC_ERROR_OBJECT_NOT_FOUND : SC_ERROR_INTERNAL;

	/* NONBLOCK avoids hanging on a FIFO before its type is checked. */
	fd = openat(dir, "can",
		O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0) {
		if (errno == ENOENT)
			r = SC_ERROR_OBJECT_NOT_FOUND;
		goto done;
	}
	if (fstat(fd, &st) < 0)
		goto done;
	/* Reject shared or substituted entries before reading any stored CAN. */
	if (!S_ISREG(st.st_mode) || st.st_uid != geteuid()
			|| (st.st_mode & 07777) != 0600
			|| st.st_nlink != 1 || st.st_size != 7) {
		r = SC_ERROR_INVALID_DATA;
		goto done;
	}
	while (used < sizeof(record)) {
		ssize_t n = read(fd, record + used, sizeof(record) - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			goto done;
		if (!n)
			break;
		used += (size_t)n;
	}
	if (used != 7 || record[6] != '\n') {
		r = SC_ERROR_INVALID_DATA;
		goto done;
	}
	record[6] = '\0';
	if (!edo_store_digits(record)) {
		r = SC_ERROR_INVALID_DATA;
		goto done;
	}
	memcpy(can, record, 7);
	r = SC_SUCCESS;

done:
	sc_mem_clear(record, sizeof(record));
	if (fd >= 0)
		close(fd);
	close(dir);
	return r;
}

static int edo_can_store_write(const char can[7])
{
	static const char hex[] = "0123456789abcdef";
	unsigned char random[16] = {0};
	char temporary[sizeof(".can-") + 32];
	char record[7] = {0};
	size_t used = 0, i;
	int dir = -1, fd = -1, created = 0;
	int r = SC_ERROR_INTERNAL;

	if (!edo_store_digits(can))
		return SC_ERROR_INVALID_DATA;
	dir = edo_store_dir(1);
	if (dir < 0)
		return SC_ERROR_INTERNAL;

	while (used < sizeof(random)) {
		ssize_t n = getrandom(random + used, sizeof(random) - used, 0);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			goto done;
		used += (size_t)n;
	}
	memcpy(temporary, ".can-", 5);
	for (i = 0; i < sizeof(random); ++i) {
		temporary[5 + 2 * i] = hex[random[i] >> 4];
		temporary[6 + 2 * i] = hex[random[i] & 15];
	}
	temporary[37] = '\0';

	fd = openat(dir, temporary,
		O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		goto done;
	created = 1;
	/* Apply exact private permissions even with a restrictive umask. */
	if (fchmod(fd, 0600) < 0)
		goto done;
	memcpy(record, can, 6);
	record[6] = '\n';
	used = 0;
	while (used < sizeof(record)) {
		ssize_t n = write(fd, record + used, sizeof(record) - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			goto done;
		used += (size_t)n;
	}
	if (fsync(fd) < 0)
		goto done;
	if (close(fd) < 0) {
		fd = -1;
		goto done;
	}
	fd = -1;
	/* Replace the directory entry, never follow a destination symlink. */
	if (renameat(dir, temporary, dir, "can") < 0)
		goto done;
	created = 0;
	if (fsync(dir) < 0)
		goto done;
	r = SC_SUCCESS;

done:
	if (fd >= 0)
		close(fd);
	if (created)
		unlinkat(dir, temporary, 0);
	if (dir >= 0)
		close(dir);
	sc_mem_clear(record, sizeof(record));
	sc_mem_clear(random, sizeof(random));
	return r;
}

#else

static int edo_can_store_read(char can[7])
{
	sc_mem_clear(can, 7);
	return SC_ERROR_NOT_SUPPORTED;
}

static int edo_can_store_write(const char can[7])
{
	(void)can;
	return SC_ERROR_NOT_SUPPORTED;
}

#endif
#endif
