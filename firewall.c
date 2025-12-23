#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("gesinski");
MODULE_DESCRIPTION("Simple firewall module");
MODULE_VERSION("1.1");

static struct nf_hook_ops *nfho = NULL;

static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct udphdr *udph;
	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (ntohs(udph->dest) == 53) {
			return NF_ACCEPT;
		}
	}
	else if (iph->protocol == IPPROTO_TCP) {
		return NF_DROP;
	}
	
	return NF_ACCEPT;
}

static int __init firewall_init(void)
{
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	
	nfho->hook 	= (nf_hookfn*)hfunc;		
	nfho->hooknum 	= NF_INET_PRE_ROUTING;		
	nfho->pf 	= PF_INET;			
	nfho->priority 	= NF_IP_PRI_FIRST;		
	
	nf_register_net_hook(&init_net, nfho);
    return 0;
}

static void __exit firewall_exit(void)
{
	nf_unregister_net_hook(&init_net, nfho);
	kfree(nfho);
}

module_init(firewall_init);
module_exit(firewall_exit);