/*
 * Minimal deterministic reproducer for the libslirp 4.7.0 hang that froze our
 * VPS guests: sorecvfrom() performs a BLOCKING recvfrom() whenever poll revents
 * claim readability, without checking that data is actually pending
 * (FIONREAD==0 is not guarded, no MSG_DONTWAIT, host socket is blocking).
 *
 * This mirrors the QEMU failure mode with zero QEMU involvement:
 *   - slirp_input() of a fake guest->outside UDP datagram makes udp_attach()
 *     create a real blocking host UDP socket (exactly what a guest's
 *     DNS/NTP/avahi traffic does through the NAT NIC);
 *   - slirp_pollfds_poll() is then called with a get_revents callback that
 *     *lies* about readability ("lie" mode), simulating the spurious/stale
 *     revents we observed in the wild (POLLERR with drained error queue or
 *     crossed pollfds_idx);
 *   - sorecvfrom() then blocks forever in recvfrom() on the empty socket.
 *
 * "honest" mode (get_revents reports nothing) is the control: no hang.
 * In "lie" mode the process hangs inside recvfrom(); sending 1 UDP byte to
 * the printed socket port unblocks it -- the same rescue proven on the hung
 * QEMU (pid 9540) in this run's evidence.
 *
 * Build (needs libslirp-dev, libglib2.0-dev):
 *   gcc -O0 -g slirp_repro.c -o slirp_repro $(pkg-config --cflags --libs libslirp glib-2.0)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <glib.h>
#include <slirp/libslirp.h>

/* ---- SlirpCb boilerplate (timers/poll registration unused) ---- */
static ssize_t send_packet(const void *buf, size_t len, void *opaque)
{
    (void)buf; (void)opaque;
    return (ssize_t)len;
}
static void guest_error(const char *msg, void *opaque)
{
    (void)opaque;
    fprintf(stderr, "[slirp guest_error] %s\n", msg);
}
static int64_t clock_get_ns(void *opaque)
{
    struct timespec ts;
    (void)opaque;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}
struct dummy_timer { SlirpTimerCb cb; void *cb_opaque; };
static void *timer_new(SlirpTimerCb cb, void *cb_opaque, void *opaque)
{
    struct dummy_timer *t = calloc(1, sizeof(*t));
    (void)opaque;
    t->cb = cb; t->cb_opaque = cb_opaque;
    return t;
}
static void timer_free(void *timer, void *opaque) { (void)opaque; free(timer); }
static void timer_mod(void *timer, int64_t expire_time, void *opaque)
{
    (void)timer; (void)expire_time; (void)opaque;
}
static void register_poll_fd(int fd, void *opaque) { (void)fd; (void)opaque; }
static void unregister_poll_fd(int fd, void *opaque) { (void)fd; (void)opaque; }
static void notify_cb(void *opaque) { (void)opaque; }

/* ---- pollfds bookkeeping: record what slirp wants polled, then lie ---- */
struct pfd_rec { int fd; int events; };
static struct pfd_rec pfds[64];
static int npfds;
static int lie;

static int add_poll(int fd, int events, void *opaque)
{
    (void)opaque;
    if (npfds < (int)(sizeof(pfds) / sizeof(pfds[0]))) {
        pfds[npfds].fd = fd;
        pfds[npfds].events = events;
    }
    return npfds++;
}
static int get_revents(int idx, void *opaque)
{
    (void)opaque;
    if (!lie || idx < 0 || idx >= npfds)
        return 0;
    return pfds[idx].events; /* lie: everything slirp asked about is "ready" */
}

static uint16_t ip_checksum(const void *data, size_t len)
{
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

int main(int argc, char **argv)
{
    lie = (argc > 1 && strcmp(argv[1], "lie") == 0);
    printf("pid=%d mode=%s libslirp=%s\n", getpid(),
           lie ? "lie(spurious-readable)" : "honest", slirp_version_string());
    fflush(stdout);

    SlirpConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.version = 1;
    cfg.in_enabled = true;
    cfg.vnetwork.s_addr = htonl(0x0a000200);    /* 10.0.2.0/24 */
    cfg.vnetmask.s_addr = htonl(0xffffff00);
    cfg.vhost.s_addr = htonl(0x0a000202);       /* 10.0.2.2 */
    cfg.vdhcp_start.s_addr = htonl(0x0a00020f); /* 10.0.2.15 */
    cfg.vnameserver.s_addr = htonl(0x0a000203); /* 10.0.2.3 */

    SlirpCb cb;
    memset(&cb, 0, sizeof(cb));
    cb.send_packet = send_packet;
    cb.guest_error = guest_error;
    cb.clock_get_ns = clock_get_ns;
    cb.timer_new = timer_new;
    cb.timer_free = timer_free;
    cb.timer_mod = timer_mod;
    cb.register_poll_fd = register_poll_fd;
    cb.unregister_poll_fd = unregister_poll_fd;
    cb.notify = notify_cb;

    Slirp *slirp = slirp_new(&cfg, &cb, NULL);
    if (!slirp) { fprintf(stderr, "slirp_new failed\n"); return 2; }

    /* Fake guest->outside UDP datagram (eth + ipv4 + udp):
     * 10.0.2.15:12345 -> 192.0.2.123:9999 (TEST-NET-1, no real peer needed) */
    const char payload[] = "hello";
    uint8_t pkt[14 + 20 + 8 + sizeof(payload) - 1];
    uint8_t *eth = pkt, *ip = pkt + 14, *udp = pkt + 14 + 20;
    static const uint8_t slirp_mac[6] = {0x52, 0x55, 0x0a, 0x00, 0x02, 0x02};
    static const uint8_t guest_mac[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
    memset(pkt, 0, sizeof(pkt));
    memcpy(eth, slirp_mac, 6);
    memcpy(eth + 6, guest_mac, 6);
    eth[12] = 0x08; eth[13] = 0x00;
    ip[0] = 0x45;
    uint16_t tot = htons(20 + 8 + (uint16_t)sizeof(payload) - 1);
    memcpy(ip + 2, &tot, 2);
    ip[8] = 64; ip[9] = 17;
    inet_pton(AF_INET, "10.0.2.15", ip + 12);
    inet_pton(AF_INET, "192.0.2.123", ip + 16);
    uint16_t csum = ip_checksum(ip, 20);
    memcpy(ip + 10, &csum, 2);
    uint16_t sport = htons(12345), dport = htons(9999);
    uint16_t ulen = htons(8 + (uint16_t)sizeof(payload) - 1);
    memcpy(udp + 0, &sport, 2);
    memcpy(udp + 2, &dport, 2);
    memcpy(udp + 4, &ulen, 2);
    memcpy(udp + 8, payload, sizeof(payload) - 1);

    /* udp_attach() now creates a real BLOCKING host UDP socket */
    slirp_input(slirp, pkt, sizeof(pkt));
    printf("injected fake guest UDP datagram -> udp_attach created host socket\n");
    fflush(stdout);

    uint32_t timeout = 1000;
    slirp_pollfds_fill(slirp, &timeout, add_poll, NULL);
    printf("pollfds_fill registered %d fd(s):", npfds);
    for (int i = 0; i < npfds; i++)
        printf(" [fd=%d events=0x%x]", pfds[i].fd, pfds[i].events);
    printf("\ncalling slirp_pollfds_poll(get_revents=%s) ...\n",
           lie ? "LIE" : "honest");
    fflush(stdout);

    slirp_pollfds_poll(slirp, 0, get_revents, NULL);

    /* Reached in honest mode; in lie mode only after a byte is injected
     * into the stuck socket from outside. */
    printf("slirp_pollfds_poll RETURNED (no hang)\n");
    return 0;
}
