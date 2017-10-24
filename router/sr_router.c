/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */);

void sr_handlepacket_IP(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface);

void sr_forwardpacket_IP(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface,
        struct sr_ip_hdr *IP_hdr);

void sr_handlepacket_ICMP(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface);

void sr_handlepacket_ARP(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface);

void sr_sendpacket_ICMP(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        uint8_t type,
        uint8_t code);


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  /* Verify minimum packet length */
  if (len < sizeof(sr_ethernet_hdr_t)) {
    /* Too short */
    return;
  }

  print_hdrs(packet, len);
  /* Check if it's an IP packet or an ARP packet */ 
  if (ethertype_ip == ethertype(packet)) {
    printf("IP\n");
    sr_handlepacket_IP(sr, packet, len, interface);
  } else {
    printf("ARP\n");
    sr_handlepacket_ARP(sr, packet, len, interface);
  }
  
}/* end sr_ForwardPacket */

void sr_handlepacket_IP(struct sr_instance* sr,
        uint8_t * packet,
	unsigned int len,
	char* interface)
{
  sr_ip_hdr_t *IP_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
 
 /* Verify minimum IP packet length */
 if (len < sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr)) {
   return;
 }

 /* Verify IPv4 */
 if (IP_hdr->ip_v != 4) {
   printf("not ipv4\n");
   return;
 }
 /* Verify checksum */
  uint16_t given_cksum = IP_hdr->ip_sum;
  IP_hdr->ip_sum = 0;
  uint16_t expected_cksum = cksum(IP_hdr, sizeof(sr_ip_hdr_t));
  if (given_cksum != expected_cksum) {
    printf("cksum wrong\n");
    printf("%d\n", given_cksum);
    printf("%d\n", expected_cksum);
    return;
  }

  /* Check if the packet is for this router */
  struct sr_if *interface_list = sr->if_list;
  int packet_for_this_router = 0;
  while (interface_list) {
    if (interface_list->ip == IP_hdr->ip_dst) {
      /* the packet is for this router */
      packet_for_this_router = 1;
    }
    interface_list = interface_list->next;
  }

  if (packet_for_this_router == 1) {
    if (IP_hdr->ip_p == ip_protocol_icmp) {
      printf("handle ICMP\n");
      sr_handlepacket_ICMP(sr, packet, len, interface);
    } else {
      return;
      printf("send ICMP\n");
      /*sr_send_ICMP()*/
    }
  } else {
    printf("forward packet\n");
    sr_forwardpacket_IP(sr, packet, len, interface, IP_hdr);
  }
  
}

void sr_forwardpacket_IP(struct sr_instance* sr,
        uint8_t * packet,
	unsigned int len,
	char* interface,
	struct sr_ip_hdr *IP_hdr)
{
  /* Decrement TTL by 1 */
  IP_hdr->ip_ttl--;

  /* Recompute checksum */
  IP_hdr->ip_sum = 0;
  IP_hdr->ip_sum = cksum(IP_hdr, sizeof(sr_ip_hdr_t));
 
  printf("Longest prefix match\n"); 
  /* Longest prefix match */
  uint32_t dest_ip = IP_hdr->ip_dst;
  struct sr_rt* rt = sr->routing_table;
  unsigned long int longest_match_len = 0;
  struct sr_rt* match = 0;

  while (rt) {
    if ((dest_ip & rt->mask.s_addr) == (rt->dest.s_addr & rt->mask.s_addr)) {
        if (longest_match_len <= rt->mask.s_addr) {
          longest_match_len = rt->mask.s_addr;
	  match = rt;
	}
    }
    rt = rt->next;
  }

  /* TODO if rt == 0  send ICMP unreachable*/
  struct sr_if *out_interface = sr_get_interface(sr, match->interface);
  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, match->gw.s_addr);
  if (arp_entry) {
    uint8_t *sr_packet = (uint8_t *) malloc(len);
    memcpy(sr_packet, packet, len);
    sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *) sr_packet;
    memcpy(ethernet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
    memcpy(ethernet_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);

    printf("printing ip packet before send\n");
    print_hdrs(sr_packet, len);
    sr_send_packet(sr, sr_packet, len, match->interface);
    free(arp_entry);
  } else {
    printf("Not in the cache\n");
    sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *) packet;
    memcpy(ethernet_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
    sr_arpcache_queuereq(&sr->cache, dest_ip, packet, len, match->interface);
  }
  free(match);
}

void sr_handlepacket_ICMP(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface)
{
  sr_ip_hdr_t *IP_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *ICMP_hdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  /* Verify checksum */
  uint16_t given_cksum = ICMP_hdr->icmp_sum;
  ICMP_hdr->icmp_sum = 0;
  uint16_t expected_cksum = cksum(ICMP_hdr, ntohs(IP_hdr->ip_len) - sizeof(sr_ip_hdr_t));
  if (given_cksum != expected_cksum) {
    printf("cksum wrong\n");
    return;
  }
  sr_sendpacket_ICMP(sr, packet, len, 0, 0);
}

void sr_sendpacket_ICMP(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        uint8_t type,
        uint8_t code)
{
  if (type == 0) {
    uint8_t *sr_packet = (uint8_t *) malloc(len);
    memcpy(sr_packet, packet, len);
    sr_ip_hdr_t *ICMP_IP_hdr = (sr_ip_hdr_t *) (sr_packet + sizeof(sr_ethernet_hdr_t));

    sr_icmp_hdr_t *ICMP_hdr = (sr_icmp_hdr_t *) (sr_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    ICMP_hdr->icmp_type = type;
    ICMP_hdr->icmp_code = code;
    ICMP_hdr->icmp_sum = 0;
    ICMP_hdr->icmp_sum = cksum(ICMP_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

    uint32_t dest = ICMP_IP_hdr->ip_src;
    ICMP_IP_hdr->ip_src = ICMP_IP_hdr->ip_dst;
    ICMP_IP_hdr->ip_dst = dest;

    /* Longest prefix match */
    struct sr_rt* rt = sr->routing_table;
    unsigned long int longest_match_len = 0;
    struct sr_rt* match = 0;
 
    while (rt) {
      if ((ICMP_IP_hdr->ip_dst & rt->mask.s_addr) == (rt->dest.s_addr & rt->mask.s_addr)) {
          if (longest_match_len <= rt->mask.s_addr) {
            longest_match_len = rt->mask.s_addr;
            match = rt;
          }
      }
      rt = rt->next;
    }

    if (match) {
      struct sr_if *out_interface = sr_get_interface(sr, match->interface);
      ICMP_IP_hdr->ip_ttl = 64;
      ICMP_IP_hdr->ip_p = 1;
      ICMP_IP_hdr->ip_sum = 0;
      ICMP_IP_hdr->ip_sum = cksum(ICMP_IP_hdr, sizeof(sr_ip_hdr_t));
      
      struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), match->gw.s_addr);
      if (arp_entry) {
        sr_ethernet_hdr_t *ethnet_hdr = (sr_ethernet_hdr_t *) sr_packet;
        memcpy(ethnet_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
	memcpy(ethnet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        sr_send_packet(sr, sr_packet, len, match->interface);
      } else {
        printf("Not in cache\n");
      }
    }
  }
}

void sr_handlepacket_ARP(struct sr_instance* sr,
 	uint8_t * packet,
	unsigned int len,
	char* interface)
{
  sr_arp_hdr_t *ARP_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  /* Check length */
  if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr)) {
    printf("Too short\n");
    return;
  }

  /* Check if it is for this router*/ 
  struct sr_if* intface = sr_get_interface(sr, interface);
   if (ARP_hdr->ar_tip != intface->ip) {
    printf("Not for this router\n");
    printf("%d\n", htons(ARP_hdr->ar_tip));
    printf("%d\n", htons(intface->ip));
    return;
  }
  
  /* Check if arp request or reply */
  if (ntohs(ARP_hdr->ar_op) == arp_op_request) {
    printf("ARP request\n");
    printf("%d\n", arp_op_reply);
    printf("%d\n", arp_op_request);

    uint8_t *sr_packet = (uint8_t *) malloc(len);
    memcpy(sr_packet, packet, len);
    /* Get reply ethernet and arp headers */
    sr_ethernet_hdr_t *r_ethnet_hdr = (sr_ethernet_hdr_t *) sr_packet;
    sr_arp_hdr_t *r_arp_hdr = (sr_arp_hdr_t *) (sr_packet + sizeof(sr_ethernet_hdr_t));
    
    memcpy(r_ethnet_hdr->ether_dhost, r_ethnet_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(r_ethnet_hdr->ether_shost, intface->addr, ETHER_ADDR_LEN);

    r_arp_hdr->ar_op = htons(arp_op_reply);
    r_arp_hdr->ar_sip = intface->ip;
    r_arp_hdr->ar_tip = ARP_hdr->ar_sip;
    memcpy(r_arp_hdr->ar_sha, intface->addr, ETHER_ADDR_LEN);
    memcpy(r_arp_hdr->ar_tha, ARP_hdr->ar_sha, ETHER_ADDR_LEN);
    
    print_hdrs(sr_packet, len);
    int ret =  sr_send_packet(sr, sr_packet, len, interface);
    printf("RETURN IS ");
    printf("%d\n", ret);
    free(sr_packet);
    printf("Reply sent\n");
     
  } else {
    printf("ARP reply\n");
    
    /* Cache reply */
    struct sr_arpreq *was_cached; 
    was_cached = sr_arpcache_insert(&sr->cache,ARP_hdr->ar_sha, ARP_hdr->ar_sip);
    
    if (was_cached) {
      struct sr_if* out_interface;
      struct sr_packet *ARP_packet = was_cached->packets;
      sr_ethernet_hdr_t *ethnet_hdr;

      while (ARP_packet) {
        out_interface = sr_get_interface(sr, ARP_packet->iface);

        ethnet_hdr = (sr_ethernet_hdr_t *) (ARP_packet->buf);
        memcpy(ethnet_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
        memcpy(ethnet_hdr->ether_dhost, ARP_hdr->ar_sha, ETHER_ADDR_LEN);
        
        print_hdrs(ARP_packet->buf, ARP_packet->len);    
        sr_send_packet(sr, ARP_packet->buf, ARP_packet->len, ARP_packet->iface);
        
        ARP_packet = ARP_packet->next;
      }

      sr_arpreq_destroy(&sr->cache, was_cached);
    }
  }
}
