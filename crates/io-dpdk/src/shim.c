/*
 * Non-inline entry points for the handful of DPDK calls that the headers
 * define as `static inline` (rx/tx burst, mbuf alloc/free/append/field
 * reads). Those have no linkable symbol, so ruster-io-dpdk's Rust `sys`
 * module cannot declare them as `extern "C"` directly; this shim gives each
 * one a real symbol that `build.rs` compiles and archives, and every other
 * DPDK call the crate needs is a genuine exported function declared straight
 * from Rust.
 *
 * Struct field access also stays in this file rather than in a `#[repr(C)]`
 * Rust re-declaration of `struct rte_mbuf`/`struct rte_eth_stats`: those
 * layouts are large, version-sensitive, and not part of DPDK's stable ABI
 * contract, so every read goes through the real headers here instead of a
 * hand-copied guess on the Rust side.
 */

#include <string.h>

#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

int
ruster_dpdk_eth_dev_configure(uint16_t port_id, uint16_t nb_rx_q, uint16_t nb_tx_q)
{
	struct rte_eth_conf conf;
	memset(&conf, 0, sizeof(conf));
	return rte_eth_dev_configure(port_id, nb_rx_q, nb_tx_q, &conf);
}

int
ruster_dpdk_eth_rx_queue_setup(uint16_t port_id, uint16_t queue_id,
		uint16_t nb_desc, struct rte_mempool *pool)
{
	int socket_id = rte_eth_dev_socket_id(port_id);
	if (socket_id < 0)
		socket_id = SOCKET_ID_ANY;
	return rte_eth_rx_queue_setup(port_id, queue_id, nb_desc, socket_id, NULL, pool);
}

int
ruster_dpdk_eth_tx_queue_setup(uint16_t port_id, uint16_t queue_id, uint16_t nb_desc)
{
	int socket_id = rte_eth_dev_socket_id(port_id);
	if (socket_id < 0)
		socket_id = SOCKET_ID_ANY;
	return rte_eth_tx_queue_setup(port_id, queue_id, nb_desc, socket_id, NULL);
}

uint16_t
ruster_dpdk_rx_burst(uint16_t port_id, uint16_t queue_id,
		struct rte_mbuf **pkts, uint16_t nb_pkts)
{
	return rte_eth_rx_burst(port_id, queue_id, pkts, nb_pkts);
}

uint16_t
ruster_dpdk_tx_burst(uint16_t port_id, uint16_t queue_id,
		struct rte_mbuf **pkts, uint16_t nb_pkts)
{
	return rte_eth_tx_burst(port_id, queue_id, pkts, nb_pkts);
}

struct rte_mbuf *
ruster_dpdk_pktmbuf_alloc(struct rte_mempool *pool)
{
	return rte_pktmbuf_alloc(pool);
}

void
ruster_dpdk_pktmbuf_free(struct rte_mbuf *mbuf)
{
	rte_pktmbuf_free(mbuf);
}

unsigned char *
ruster_dpdk_pktmbuf_append(struct rte_mbuf *mbuf, uint16_t len)
{
	return (unsigned char *)rte_pktmbuf_append(mbuf, len);
}

unsigned char *
ruster_dpdk_pktmbuf_data(struct rte_mbuf *mbuf)
{
	return rte_pktmbuf_mtod(mbuf, unsigned char *);
}

uint16_t
ruster_dpdk_pktmbuf_data_len(const struct rte_mbuf *mbuf)
{
	return mbuf->data_len;
}

unsigned
ruster_dpdk_mempool_avail_count(const struct rte_mempool *pool)
{
	return rte_mempool_avail_count(pool);
}

int
ruster_dpdk_rte_errno(void)
{
	return rte_errno;
}
