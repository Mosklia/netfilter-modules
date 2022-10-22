#include <linux/in.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static struct nf_hook_ops hook_1, hook_2;

unsigned int hook_func(void *priv, struct sk_buff *buff,
                       const struct nf_hook_state *state) {
  // struct iphdr *hdr = ip_hdr(buff);
  struct iphdr *iph = (struct iphdr *)(skb_network_header(buff));
  // printk(KERN_INFO "Package captured: daddr %d. Expected: %d.\n", iph->daddr,
  // 0X01020304U); if (iph->daddr == 0X04030201U)
  // {
  //     iph->daddr = 0XE05DD00AU;
  //     printk(KERN_INFO "A package was redirected!\n");
  //     return NF_ACCEPT;
  // }

  if (iph->saddr == 0XE05DD00AU) {
    printk(KERN_INFO "A package from localhost was detected!\n");
    // return NF_ACCEPT;

    if (iph->protocol == IPPROTO_TCP) {
      printk(KERN_INFO "TCP package target port: %d.\n",
             htons(tcp_hdr(buff)->dest));
      printk(KERN_INFO "TCP package source port: %d.\n",
             ntohs(tcp_hdr(buff)->source));
    } else if (iph->protocol == IPPROTO_UDP) {
      printk(KERN_INFO "UDP package target port: %d.\n",
             htons(((struct udphdr *)skb_transport_header(buff))->source));
    }
  }

  if (iph->protocol == IPPROTO_ICMP) {
    printk(KERN_INFO "Pining package dropped: target %d, source %d.\n",
           iph->daddr, iph->saddr);
    // return NF_DROP;
  }
  return NF_ACCEPT;
}

unsigned int hook_func_2(void *priv, struct sk_buff *buff,
                       const struct nf_hook_state *state) {
  struct iphdr *iph = (struct iphdr *)(skb_network_header(buff));

  if (iph->saddr == 0XE05DD00AU) {
    printk(KERN_INFO "A package to localhost was detected!\n");
    // return NF_ACCEPT;

    if (iph->protocol == IPPROTO_TCP) {
      printk(KERN_INFO "TCP package target port: %d.\n",
             ntohs(tcp_hdr(buff)->dest));
      printk(KERN_INFO "TCP package source port: %d.\n",
             ntohs(tcp_hdr(buff)->source));
    } else if (iph->protocol == IPPROTO_UDP) {
      printk(KERN_INFO "UDP package target port: %d.\n",
             htons(((struct udphdr *)skb_transport_header(buff))->source));
    }
  }

  return NF_ACCEPT;
}

int fwfilter_init(void) {
  hook_1.hook = hook_func;
  hook_1.pf = PF_INET;
  hook_1.priority = NF_IP_PRI_FIRST;
  hook_1.hooknum = NF_INET_LOCAL_OUT;

  hook_2.hook = hook_func_2;
  hook_2.pf = PF_INET;
  hook_2.priority = NF_IP_PRI_FIRST;
  hook_2.hooknum = NF_INET_LOCAL_IN;

  nf_register_net_hook(&init_net, &hook_1);
  nf_register_net_hook(&init_net, &hook_2);
  printk(KERN_INFO "Loading module fwfilter.\n");

  return 0;
}

void fwfilter_exit(void) {
  nf_unregister_net_hook(&init_net, &hook_1);
  nf_unregister_net_hook(&init_net, &hook_2);
  printk(KERN_INFO "Unloading module fwfilter.\n");
}

module_init(fwfilter_init);
module_exit(fwfilter_exit);

MODULE_DESCRIPTION("Module to test NetFilter.");
MODULE_LICENSE("GPL");
