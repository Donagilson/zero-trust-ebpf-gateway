#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int filter_packets(struct xdp_md *ctx)
{
    (void)ctx;
    /* Default deny until the policy map and packet matching are implemented. */
    return XDP_DROP;
}
