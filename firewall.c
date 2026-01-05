#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/inet.h>
#include <net/netfilter/nf_conntrack.h>

#define IP_OFFSET 0x1FFF
#define IP_MF 0x2000
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80


MODULE_LICENSE("GPL");
MODULE_AUTHOR("gesinski");
MODULE_DESCRIPTION("Simple firewall");
MODULE_VERSION("2.1");

static struct nf_hook_ops *nfho = NULL;

static bool is_spoofed_ip(__be32 src_ip) {
    struct {
        const char *net;
        __be32 mask;
    } ranges[] = {
        { "127.0.0.0", htonl(0xFF000000) },
        { "10.0.0.0", htonl(0xFF000000) },
        { "172.16.0.0", htonl(0xFFF00000) },
        { "224.0.0.0", htonl(0xF0000000) },
        { "255.255.255.255", htonl(0xFFFFFFFF) }
    };

    for (int i = 0; i < sizeof(ranges)/sizeof(ranges[0]); i++) {
        __be32 net = in_aton(ranges[i].net);
        if ((src_ip & ranges[i].mask) == (net & ranges[i].mask))
            return true;
    }
    return false;
}

static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	
	struct iphdr *iph;
    struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;
	u16 tcpflags;

	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if(!iph)
		return NF_DROP;

	if (!pskb_may_pull(skb, iph->ihl*4))
        return NF_DROP;

	if (is_spoofed_ip(iph->saddr)) {
		printk_ratelimited(KERN_INFO "Dropped spoofing packet: src=%pI4 dst=%pI4 proto=%d\n",
			   &iph->saddr, &iph->daddr, iph->protocol);
		return NF_DROP;
	}

	if ((ntohs(iph->frag_off) & IP_OFFSET) != 0 || (ntohs(iph->frag_off) & IP_MF) != 0) {
		printk_ratelimited(KERN_INFO "Dropped fragmented packet: src=%pI4 dst=%pI4 proto=%d\n",
			   &iph->saddr, &iph->daddr, iph->protocol);
		return NF_DROP;
	}

	switch (iph->protocol) {
        case IPPROTO_ICMP:
			if (!pskb_may_pull(skb, iph->ihl*4 + sizeof(struct icmphdr)))
				return NF_DROP;

			icmph = icmp_hdr(skb);

			if (icmph->type == ICMP_ECHO) {

				printk_ratelimited(KERN_INFO "Dropped icmp packet: src=%pI4 dst=%pI4 proto=%d\n",
    	   			   &iph->saddr, &iph->daddr, iph->protocol);
				
				return NF_DROP;
			} else 
    			return NF_ACCEPT;
            break;

        case IPPROTO_UDP:
			if (!pskb_may_pull(skb, iph->ihl*4 + sizeof(struct udphdr)))
                return NF_DROP;

            udph = udp_hdr(skb);

            if (ntohs(udph->dest) != 53 && ntohs(udph->source) != 53) { 

				printk_ratelimited(KERN_INFO "Dropped udp packet: src=%pI4 dst=%pI4 proto=%d port=%d\n",
					   &iph->saddr, &iph->daddr, iph->protocol, ntohs(udph->dest));

                return NF_DROP;
			} else 
				return NF_ACCEPT;
            break;

        case IPPROTO_TCP:
			if (!pskb_may_pull(skb, iph->ihl*4 + sizeof(struct tcphdr)))
				return NF_DROP;

			tcph = tcp_hdr(skb);
            tcpflags = tcp_flag_word(tcph);

			// NULL scan
            if (tcpflags == 0) {
                printk_ratelimited(KERN_INFO "Dropped TCP NULL scan: src=%pI4 dst=%pI4 sport=%d dport=%d\n",
                    &iph->saddr, &iph->daddr, ntohs(tcph->source), ntohs(tcph->dest));
                return NF_DROP;
            }

            // SYN+FIN
            if ((tcpflags & (TH_SYN | TH_FIN)) == (TH_SYN | TH_FIN)) {
                printk_ratelimited(KERN_INFO "Dropped TCP SYN+FIN scan: src=%pI4 dst=%pI4\n",
                    &iph->saddr, &iph->daddr);
                return NF_DROP;
            }

            // SYN+RST
            if ((tcpflags & (TH_SYN | TH_RST)) == (TH_SYN | TH_RST)) {
                printk_ratelimited(KERN_INFO "Dropped TCP SYN+RST scan: src=%pI4 dst=%pI4\n",
                    &iph->saddr, &iph->daddr);
                return NF_DROP;
            }

            // Xmas scan
            if ((tcpflags & (TH_FIN | TH_PSH | TH_URG)) == (TH_FIN | TH_PSH | TH_URG)) {
                printk_ratelimited(KERN_INFO "Dropped TCP Xmas scan: src=%pI4 dst=%pI4\n",
                    &iph->saddr, &iph->daddr);
                return NF_DROP;
            }

            // ACK-only scans (not part of established connection)
            if ((tcpflags & (TH_ACK | TH_SYN | TH_FIN | TH_RST | TH_PSH | TH_URG)) == TH_ACK) {
				struct nf_conn *ct;
				enum ip_conntrack_info ctinfo;

				ct = nf_ct_get(skb, &ctinfo);

				if (ct && (ct->status & IPS_CONFIRMED))
				    return NF_ACCEPT;

				printk_ratelimited(KERN_INFO "Dropped suspicious ACK-only packet: src=%pI4 dst=%pI4\n",
					&iph->saddr, &iph->daddr);
				return NF_DROP;
			}
            break;
	}
    
	return NF_ACCEPT;
}

static int __init firewall_init(void) {
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	
	nfho->hook 	= (nf_hookfn*)hfunc;		
	nfho->hooknum 	= NF_INET_PRE_ROUTING;		
	nfho->pf 	= PF_INET;			
	nfho->priority 	= NF_IP_PRI_FIRST;		
	
	nf_register_net_hook(&init_net, nfho);
    printk(KERN_INFO "Firewall module loaded\n");
    return 0;
}

static void __exit firewall_exit(void) {
	nf_unregister_net_hook(&init_net, nfho);
	kfree(nfho);
    printk(KERN_INFO "Firewall module unloaded\n");
}

module_init(firewall_init);
module_exit(firewall_exit);