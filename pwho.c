/* parallel whois tool (1.0 i guess)

Geo Carncross <geocar@internetconnection.net>
              <geocar@gmail.com>

*/

#include <sys/types.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>

#include "ht.h"

#define THREADS		(32)
static int using_threads = THREADS;

struct whoisbuf {
	int fd;	/* sanity */
	unsigned id;
	char *data;
	unsigned len, max;
};
static ht a;

static int whoisbuf_ondel(void *x)
{
	struct whoisbuf *hx;
	hx = (struct whoisbuf *)x;
	free(hx->data);
}

static jmp_buf jtimebuf;
static void jtimebuf_timeout(int sig)
{
	longjmp(jtimebuf, sig);
}
static int startwhois(char *ptr, unsigned len, unsigned ctr)
{
	struct sockaddr_in lsin, rsin;
	unsigned long host_ip;
	char *ws, *whoserver;
	int fd;
	int ttcp;

	/* whois.crsnic.net */
	whoserver = "198.41.3.54";

	for (ws = ptr; *ws && !isspace(*ws); ws++);
	if (*ws == '\r' || *ws == '\n') {
		*ws = 0;
		for (len = 0; ptr[len]; len++);
	} else if (*ws && isspace(*ws)) {
		*ws = 0;
		for (len = 0; ptr[len]; len++);
		ws++;len++;
		while (isspace(*ws))
			ws++;
		if (*ws) {
			whoserver = ws;
		}
	}
	len--;	/* ick */

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;
	if (setjmp(jtimebuf) == 0) {
		signal(SIGALRM, jtimebuf_timeout);
		alarm(300);
		rsin.sin_family = AF_INET;
		rsin.sin_port = htons(43); /* whois */
		rsin.sin_addr.s_addr = inet_addr(whoserver);
		lsin.sin_family = AF_INET;
		lsin.sin_port = 0;
		lsin.sin_addr.s_addr = 0;
		if (bind(fd, (struct sockaddr *)&lsin, sizeof(struct sockaddr_in)) < 0) {
			printf("%u 1 localfail\n", ctr);
			goto timer_exit;
		}
#ifdef MSG_EOF
		ttcp = 1;
		if (setsockopt(fd, IPPROTO_TCP, TCP_NOPUSH, (char *)&ttcp, sizeof(ttcp)) < 0) {
			if (errno == ENOPROTOOPT) {
				/* recovered by connect */
				goto do_connect;
			}
			printf("%u 2 localfail\n", ctr);
			goto timer_exit;
		}
		if (sendto(fd, ptr, len, MSG_EOF, (struct sockaddr *)&rsin, sizeof(struct sockaddr_in)) != len) {
			if (errno == ENOTCONN) {
				/* recovered by connect */
				goto do_connect;
			}
			printf("%u 3 localfail\n", ctr);
			goto timer_exit;
		}
		goto sendto_ok;

do_connect:
#endif
		if (connect(fd, (struct sockaddr *)&rsin, sizeof(struct sockaddr_in)) < 0) {
			if (errno != ECONNREFUSED && errno != ECONNRESET) {
				/* connection error... log later */
				printf("%u 9 remotefail\n", ctr);
			} else
				printf("%u 1 remotefail\n", ctr);
			goto timer_exit;
		}
		if (write(fd, ptr, len) != len) {
			printf("%u 2 remotefail\n", ctr);
			goto timer_exit;
		}
		write(fd, "\r\n", 2); /* jik */

		if (shutdown(fd, 1) < 0) {
			printf("%u 3 remotefail\n", ctr);
			goto timer_exit;
		}
sendto_ok:
		alarm(0);
		return fd;
timer_exit:
		alarm(0);
		close(fd);
	}
	return -1;
}
static int read_whoisbuf(int fd, struct pollfd *xptr)
{
	struct whoisbuf *x;
	unsigned i;
	int r;

	x = (struct whoisbuf *)ht_fetch(&a, (void *)xptr, sizeof(void *));
	if (!x)
		return -1; /* no record */
	if (x->fd != fd)
		return -1; /* this is bad... */
	if (x->max < x->len + 256) {
		void *q = (void *)realloc(x->data, x->max = x->len + 256);
		if (!q)
			return -1;
		x->data = q;
	}

	do {
		r = read(fd, x->data + x->len, 256);
	} while (r == -1 && errno == EINTR);

	if (r < 1) {
		/* connection closed */
		struct search_s {
			const char *s;
		} dp[] = {
			{ "Status:         AVAIL " },
			{ "No match for \"" },
			{ "No match. If you want to register this domain, please check Whois for defensive registrations first." },
			{ "Not found: " },
			{ "not found." },
			{ "NOT FOUND" },
			{ 0 },
		};
		int sptr, s_len, t1;

		if (r == -1) {
			printf("%u 0 remotefail\n", x->id);
			return -1;
		}

		for (sptr = t1 = 0; dp[sptr].s; sptr++) {
			s_len = strlen(dp[sptr].s);
			if (s_len > x->len)
				continue;
			t1++;
			for (i = 0; i < x->len - s_len; i++) {
				if (memcmp(x->data+i, dp[sptr].s, s_len) == 0) {
					printf("%u 0 permfail\n", x->id);
					return -1;
				}
			}
		}
		if (t1 == 0) {
			printf("%u 0 permfail\n", x->id);
			return -1;
		}

		x->data = 0;

		printf("%u 0 ok\n", x->id);
		return -1; /* this is fine... we're shutting down */
	}

	x->len += r;

	return 1;
}

static unsigned long whois_hash(void *d, unsigned dl)
{
	/* "key" is a pointer */
	return (unsigned long)d;
}
int main(int argc, char *argv[])
{
	const int bad_fd = -1;
	static struct pollfd ptr[THREADS];
	unsigned inuse, i;
	char dn[577];
	unsigned dn_ptr, dn_len;
	unsigned ctr;
	int j;

	if (ht_init(&a, 31, whois_hash) == -1)
		exit (1);
	if (ht_ondelete(&a, whoisbuf_ondel) == -1)
		exit (1);
	
	dn_ptr = 0;
	dn_len = 0;
	ctr = 0;
	inuse = 1;
	for (i = 1; i < THREADS; i++) {
		ptr[i].fd = bad_fd;
		ptr[i].events = 0;
		ptr[i].revents = 0;
	}

	ptr[0].fd = fileno(stdin);
	ptr[0].events = POLLIN | POLLPRI;
	ptr[0].revents = 0;

	using_threads = THREADS;
	while (inuse > 0) {
		j = poll(ptr, using_threads, -1);
		if (j == -1) {
			if (errno == EINTR)
				continue;
			else if (errno == EINVAL) {
				using_threads--;
				printf("backoff=%d\n", using_threads);
				if (using_threads < 2)
					break;
				continue;
			}
			break;

		}

		for (i = 0; i < using_threads; i++) {
			if (ptr[i].fd == bad_fd)
				continue;
			ptr[i].events = POLLIN|POLLPRI;
			if (ptr[i].revents & (POLLERR|POLLHUP|POLLNVAL|POLLIN|POLLPRI)) {
				if (ptr[i].fd == fileno(stdin)) {
					int r;

					/* block */
					if (sizeof(dn) - dn_len == 0)
						continue;

					do {
						r = read(ptr[i].fd, dn + dn_len,
							sizeof(dn) - dn_len);
					} while (r == -1 && errno == EINTR);
					if (r < 1) {
						close(ptr[i].fd);
						ptr[i].fd = bad_fd;
						ptr[i].events = 0;
						ptr[i].revents = 0;
						inuse--;
						continue;	/* close STDIN */
					}
					dn_len += r;
				} else
				if (read_whoisbuf(ptr[i].fd, &ptr[i]) == -1) {
					(void) ht_delete(&a, &ptr[i], sizeof(void *));
					close(ptr[i].fd);
					ptr[i].fd = bad_fd;
					ptr[i].events = 0;
					ptr[i].revents = 0;
					inuse--;
				}
			}
		}

		/* no more room... */
get_next_domain_l:
		if (inuse > using_threads-2)
			continue;

		if (dn_len < 1)
			continue;

		for (i = 0; i < dn_len; i++) {
			if (dn[i] == '\n') {
				int fd;

				if (i == 0) {
					memmove(dn, dn+1, dn_len - 1);
					continue;
				}

				fd = startwhois(dn, i+1, ctr);

				memmove(dn, dn+i+1, (dn_len - i) -1);
				dn_len -= i;
				if (fd > -1) {
					struct whoisbuf y;

					inuse++;
					y.fd = fd;
					y.id = ctr;
					ctr++;

					y.data = 0;
					y.len = y.max = 0;

					for (j = 0; j < using_threads; j++) {
						if (ptr[j].fd == -1)
							break;
						if (ptr[j].events = 0)
							break;
					}
					if (j >= using_threads) {
						/* should never happen */
						fprintf(stderr, "LOST SYNC\n");
						exit(1);
					}

					if (ht_storecopy(&a, &ptr[j], sizeof(void *), &y, sizeof(struct whoisbuf)) != -1) {
						ptr[j].fd = fd;
						ptr[j].events = POLLIN | POLLPRI;
						ptr[j].revents = 0;
					} else {
						close(fd);
						printf("%u 0 localfail\n", y.id);
						inuse--;
					}
				} else {
					ctr++;
				}
				goto get_next_domain_l;

			}

		}
	}

	fflush(stdout);
	return 0;
}
