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
MODULE_DESCRIPTION("Simple firewall");
MODULE_VERSION("1.2");

static struct nf_hook_ops *nfho = NULL;

static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
    struct tcphdr *tcph;
	struct udphdr *udph;

	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if(!iph)
		return NF_DROP;

	if (!pskb_may_pull(skb, iph->ihl*4))
        return NF_DROP;

	switch (iph->protocol) {
        case IPPROTO_ICMP:
            return NF_ACCEPT;

        case IPPROTO_UDP:
			if (!pskb_may_pull(skb, iph->ihl*4 + sizeof(struct udphdr)))
                return NF_DROP;

            udph = udp_hdr(skb);

            if (ntohs(udph->dest) == 53 || ntohs(udph->source) == 53) 
                return NF_ACCEPT;
			else 
				printk(KERN_INFO "Dropped packet: src=%pI4 dst=%pI4 proto=%d port=%d\n",
					   &iph->saddr, &iph->daddr, iph->protocol, ntohs(udph->dest));
            break;

        case IPPROTO_TCP:
			if (!pskb_may_pull(skb, iph->ihl*4 + sizeof(struct tcphdr)))
				return NF_DROP;

            tcph = tcp_hdr(skb);

            if (ntohs(tcph->dest) == 22 || ntohs(tcph->dest) == 80 || ntohs(tcph->dest) == 443)
                return NF_ACCEPT;
			else 
				printk(KERN_INFO "Dropped packet: src=%pI4 dst=%pI4 proto=%d port=%d\n",
               		   &iph->saddr, &iph->daddr, iph->protocol, ntohs(tcph->dest));
            break;
    }

	printk(KERN_INFO "Dropped packet: src=%pI4 dst=%pI4 proto=%d\n",
    	   &iph->saddr, &iph->daddr, iph->protocol);

    return NF_DROP;
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