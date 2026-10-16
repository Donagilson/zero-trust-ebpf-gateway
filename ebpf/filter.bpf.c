#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct flow_key {
	__be32 client_ipv4;
	__be32 destination_ipv4;
	__be16 destination_port;
	__u8 protocol;
	__u8 padding;
};

struct transport_ports {
	__be16 source;
	__be16 destination;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_key);
	__type(value, __u8);
} allowed_flows SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

SEC("classifier")
int filter_packets(struct __sk_buff *skb)
{
	struct iphdr ip = {};
	struct transport_ports ports = {};
	struct flow_key key = {};
	__u32 network_offset;
	__u32 ip_header_length;
	__u16 total_length;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_SHOT;

	if (skb->network_header < skb->mac_header)
		return TC_ACT_SHOT;

	network_offset = skb->network_header - skb->mac_header;
	if (bpf_skb_load_bytes(skb, network_offset, &ip, sizeof(ip)) < 0)
		return TC_ACT_SHOT;

	if (ip.version != 4 || ip.ihl < 5)
		return TC_ACT_SHOT;

	ip_header_length = (__u32)ip.ihl * 4;
	total_length = bpf_ntohs(ip.tot_len);
	if (total_length < ip_header_length + sizeof(ports))
		return TC_ACT_SHOT;

	/* Fragmented datagrams do not carry ports in every packet. */
	if (bpf_ntohs(ip.frag_off) & (IP_MF | IP_OFFSET))
		return TC_ACT_SHOT;

	if (ip.protocol != IPPROTO_TCP && ip.protocol != IPPROTO_UDP)
		return TC_ACT_SHOT;

	if (bpf_skb_load_bytes(skb, network_offset + ip_header_length,
			       &ports, sizeof(ports)) < 0)
		return TC_ACT_SHOT;

	key.client_ipv4 = ip.saddr;
	key.destination_ipv4 = ip.daddr;
	key.destination_port = ports.destination;
	key.protocol = ip.protocol;

	if (bpf_map_lookup_elem(&allowed_flows, &key))
		return TC_ACT_OK;

	return TC_ACT_SHOT;
}
