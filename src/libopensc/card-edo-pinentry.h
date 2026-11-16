/*
 * Private pinentry transport for the Polish eID driver.
 *
 * This file is part of OpenSC, under the GNU Lesser General Public
 * License, version 2.1 or (at your option) any later version.
 *
 * No public API. Included only by card-edo.c.
 */
#ifndef OPENSC_EDO_PINENTRY_H
#define OPENSC_EDO_PINENTRY_H

#if defined(__linux__)

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

struct edo_pinentry {
	int fd;
	pid_t pid;
	struct timespec deadline;
};

static int edo_pe_wait(struct edo_pinentry *pe, short events)
{
	struct timespec now;
	struct pollfd pfd;
	long long remaining;
	int r;

	for (;;) {
		if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
			return SC_ERROR_INTERNAL;
		remaining = (long long)(pe->deadline.tv_sec - now.tv_sec)
			* 1000 + (pe->deadline.tv_nsec - now.tv_nsec) / 1000000;
		if (remaining <= 0)
			return SC_ERROR_INTERNAL;

		pfd.fd = pe->fd;
		pfd.events = events;
		pfd.revents = 0;
		r = poll(&pfd, 1,
			remaining > INT_MAX ? INT_MAX : (int)remaining);
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			return SC_ERROR_INTERNAL;
		if (pfd.revents & events)
			return SC_SUCCESS;
		return SC_ERROR_INTERNAL;
	}
}

static int edo_pe_write(struct edo_pinentry *pe, const char *text)
{
	size_t left = strlen(text);

	while (left) {
		ssize_t n;
		int r = edo_pe_wait(pe, POLLOUT);
		if (r < 0)
			return r;
		n = send(pe->fd, text, left, MSG_NOSIGNAL | MSG_DONTWAIT);
		if (n < 0 && (errno == EINTR || errno == EAGAIN
				|| errno == EWOULDBLOCK))
			continue;
		if (n <= 0)
			return SC_ERROR_INTERNAL;
		text += n;
		left -= (size_t)n;
	}
	return SC_SUCCESS;
}

static int edo_pe_line(struct edo_pinentry *pe, char *line, size_t size)
{
	size_t used = 0;

	while (used + 1 < size) {
		char c;
		ssize_t n;
		int r = edo_pe_wait(pe, POLLIN);
		if (r < 0)
			return r;
		n = recv(pe->fd, &c, 1, MSG_DONTWAIT);
		if (n < 0 && (errno == EINTR || errno == EAGAIN
				|| errno == EWOULDBLOCK))
			continue;
		if (n != 1 || c == '\0')
			return SC_ERROR_INTERNAL;
		if (c == '\n') {
			if (used && line[used - 1] == '\r')
				--used;
			line[used] = '\0';
			return SC_SUCCESS;
		}
		line[used++] = c;
	}
	return SC_ERROR_INVALID_DATA;
}

static int edo_pe_hex(unsigned char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* Assuan errors contain a source field; the low 16 bits are the code. */
static int edo_pe_error(const char *text)
{
	unsigned long code;
	char *end;

	if (*text < '0' || *text > '9')
		return SC_ERROR_INVALID_DATA;
	errno = 0;
	code = strtoul(text, &end, 10);
	if (errno || code > UINT_MAX || (*end && *end != ' '))
		return SC_ERROR_INVALID_DATA;

	switch (code & 0xffffUL) {
	case 99:  /* GPG_ERR_CANCELED */
	case 198: /* GPG_ERR_FULLY_CANCELED */
		return SC_ERROR_KEYPAD_CANCELLED;
	case 114: /* GPG_ERR_NOT_CONFIRMED */
		return SC_ERROR_NOT_ALLOWED;
	default:
		return SC_ERROR_INTERNAL;
	}
}

/* Consume the complete response, including status and data lines. */
static int edo_pe_response(struct edo_pinentry *pe, char *can)
{
	char line[1002] = {0};
	size_t used = 0;
	int invalid = 0;
	int r;

	for (;;) {
		r = edo_pe_line(pe, line, sizeof(line));
		if (r < 0)
			break;

		if (!strcmp(line, "OK") || !strncmp(line, "OK ", 3)) {
			r = invalid || (can && used != 6)
				? SC_ERROR_INVALID_DATA : SC_SUCCESS;
			if (r == SC_SUCCESS && can)
				can[6] = '\0';
			break;
		}
		if (!strncmp(line, "ERR ", 4)) {
			r = edo_pe_error(line + 4);
			break;
		}
		if (!strncmp(line, "D ", 2)) {
			const unsigned char *p =
				(const unsigned char *)line + 2;

			while (*p) {
				unsigned char c = *p++;
				if (c == '%') {
					int hi, lo;
					if (!p[0] || !p[1]) {
						invalid = 1;
						break;
					}
					hi = edo_pe_hex(p[0]);
					lo = edo_pe_hex(p[1]);
					if (hi < 0 || lo < 0) {
						invalid = 1;
						break;
					}
					c = (unsigned char)((hi << 4) | lo);
					p += 2;
				}
				if (!can || used >= 6 || c < '0' || c > '9')
					invalid = 1;
				else
					can[used++] = (char)c;
			}
		} else if (line[0] == '#' || !line[0]
				|| !strncmp(line, "S ", 2)) {
			/* Comments, empty lines and status messages carry no CAN. */
		} else {
			/* No inquiries are requested by this client. */
			r = SC_ERROR_INVALID_DATA;
			break;
		}
		sc_mem_clear(line, sizeof(line));
	}
	sc_mem_clear(line, sizeof(line));
	return r;
}

/* Only UI text is sent; percent-escape Assuan command arguments. */
static int edo_pe_command(struct edo_pinentry *pe,
		const char *command, const char *value, char *can)
{
	static const char hex[] = "0123456789ABCDEF";
	char line[1002];
	size_t used = strlen(command);
	const unsigned char *p = (const unsigned char *)value;
	int r;

	if (used >= sizeof(line) - 2)
		return SC_ERROR_INVALID_ARGUMENTS;
	memcpy(line, command, used);
	if (p)
		line[used++] = ' ';
	while (p && *p) {
		unsigned char c = *p++;
		if (used + 4 >= sizeof(line))
			return SC_ERROR_INVALID_ARGUMENTS;
		if (c == '%' || c == '\r' || c == '\n') {
			line[used++] = '%';
			line[used++] = hex[c >> 4];
			line[used++] = hex[c & 15];
		} else {
			line[used++] = (char)c;
		}
	}
	line[used++] = '\n';
	line[used] = '\0';

	if (clock_gettime(CLOCK_MONOTONIC, &pe->deadline) < 0)
		return SC_ERROR_INTERNAL;
	pe->deadline.tv_sec += 300;

	r = edo_pe_write(pe, line);
	sc_mem_clear(line, sizeof(line));
	if (r < 0)
		return r;
	return edo_pe_response(pe, can);
}

static void edo_pe_close(struct edo_pinentry *pe)
{
	if (pe->fd >= 0) {
		shutdown(pe->fd, SHUT_RDWR);
		close(pe->fd);
		pe->fd = -1;
	}
	if (pe->pid > 0) {
		int status, i;
		pid_t r = 0;

		/* EOF normally terminates pinentry; allow bounded cleanup. */
		for (i = 0; i < 50; ++i) {
			r = waitpid(pe->pid, &status, WNOHANG);
			if (r == pe->pid || (r < 0 && errno != EINTR))
				break;
			poll(NULL, 0, 10);
		}
		if (r == 0 || (r < 0 && errno == EINTR)) {
			kill(pe->pid, SIGKILL);
			do {
				r = waitpid(pe->pid, &status, 0);
			} while (r < 0 && errno == EINTR);
		}
		pe->pid = -1;
	}
}

static int edo_pe_open(struct edo_pinentry *pe)
{
	posix_spawn_file_actions_t actions;
	char *const argv[] = { (char *)"/usr/bin/pinentry", NULL };
	int pair[2], i, r;

	pe->fd = -1;
	pe->pid = -1;
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) < 0)
		return SC_ERROR_INTERNAL;

	/* Keep transport descriptors separate from stdin/stdout/stderr. */
	for (i = 0; i < 2; ++i) {
		if (pair[i] <= STDERR_FILENO) {
			int fd = fcntl(pair[i], F_DUPFD_CLOEXEC, 3);
			if (fd < 0) {
				close(pair[0]);
				close(pair[1]);
				return SC_ERROR_INTERNAL;
			}
			close(pair[i]);
			pair[i] = fd;
		}
	}

	/* Avoid running fork handlers inside a multithreaded PKCS#11 client. */
	r = posix_spawn_file_actions_init(&actions);
	if (!r) {
		r = posix_spawn_file_actions_adddup2(
			&actions, pair[1], STDIN_FILENO);
		if (!r)
			r = posix_spawn_file_actions_adddup2(
				&actions, pair[1], STDOUT_FILENO);
		if (!r)
			r = posix_spawn_file_actions_addclose(&actions, pair[0]);
		if (!r)
			r = posix_spawn_file_actions_addclose(&actions, pair[1]);
		if (!r)
			r = posix_spawn(&pe->pid, argv[0], &actions,
				NULL, argv, environ);
		posix_spawn_file_actions_destroy(&actions);
	}
	close(pair[1]);
	if (r) {
		close(pair[0]);
		pe->pid = -1;
		return SC_ERROR_INTERNAL;
	}
	pe->fd = pair[0];
	if (clock_gettime(CLOCK_MONOTONIC, &pe->deadline) < 0)
		return SC_ERROR_INTERNAL;
	pe->deadline.tv_sec += 10;
	return edo_pe_response(pe, NULL);
}

/*
 * can != NULL: GETPIN, exactly six ASCII digits.
 * can == NULL: CONFIRM; NOT_ALLOWED means the "other" button.
 * Cancellation is distinct from "other" and transport failures.
 */
static int edo_pinentry_request(sc_card_t *card, const char *description,
		const char *ok, const char *other, char *can)
{
	struct edo_pinentry pe;
	int r;

	if (can)
		sc_mem_clear(can, 7);
	/* Headless callers must not unexpectedly acquire a GUI dependency. */
	if (card->ctx->flags & SC_CTX_FLAG_DISABLE_POPUPS)
		return SC_ERROR_NOT_SUPPORTED;

	r = edo_pe_open(&pe);
	if (r == SC_SUCCESS)
		r = edo_pe_command(&pe, "SETTITLE",
			"OpenSC — CAN e-dowodu", NULL);
	if (r == SC_SUCCESS)
		r = edo_pe_command(&pe, "SETDESC", description, NULL);
	if (r == SC_SUCCESS && can)
		r = edo_pe_command(&pe, "SETPROMPT",
			"CAN z dowodu osobistego:", NULL);
	if (r == SC_SUCCESS)
		r = edo_pe_command(&pe, "SETOK", ok, NULL);
	if (r == SC_SUCCESS && other && !can)
		r = edo_pe_command(&pe, "SETNOTOK", other, NULL);
	if (r == SC_SUCCESS)
		r = edo_pe_command(&pe, "SETCANCEL", "Anuluj", NULL);
	if (r == SC_SUCCESS)
		r = edo_pe_command(&pe, "SETTIMEOUT", "300", NULL);
	if (r == SC_SUCCESS)
		r = edo_pe_command(&pe, can ? "GETPIN" : "CONFIRM",
			NULL, can);
	edo_pe_close(&pe);
	if (r < 0 && can)
		sc_mem_clear(can, 7);
	return r;
}

#else

static int edo_pinentry_request(sc_card_t *card, const char *description,
		const char *ok, const char *other, char *can)
{
	(void)card;
	(void)description;
	(void)ok;
	(void)other;
	if (can)
		sc_mem_clear(can, 7);
	return SC_ERROR_NOT_SUPPORTED;
}

#endif
#endif
