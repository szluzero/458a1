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
    return;
  }

  print_hdrs(packet, len);
  printf("%d", ethertype_ip);
  /* Check if it's an IP packet or an ARP packet */ 
  if (ethertype_ip == ethertype(packet)) {
    printf("IP\n");
    sr_handlepacket_IP(sr, packet, len, interface);
  } else {
    sr_handlepacket_ARP(sr, packet, len, interface);
  }
  
}/* end sr_ForwardPacket */

void sr_handlepacket_IP(struct sr_instance* sr,
        uint8_t * packet,
	unsigned int len,
	char* interface)
{
  sr_ip_hdr_t *IP_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
 
 /* Verify minimum IP packet length */
 if (len < sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr)) {
   return;
 }

 /* Verify IPv4 */
 if (IP_hdr->ip_v != 4) {
   return;
 }
 /* Verify checksum */
  uint16_t given_cksum = IP_hdr->ip_sum;
  uint16_t expected_cksum = cksum(IP_hdr, sizeof(sr_ip_hdr_t));
  if (given_cksum != expected_cksum) {
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
      sr_handlepacket_ICMP(sr, packet, len, interface);
    } else {
      return;
      /*sr_send_ICMP()*/
    }
  } else {
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

    sr_send_packet(sr, sr_packet, len, match->interface);
    free(arp_entry);
  } else {
    sr_arpcache_queuereq(&sr->cache, match->gw.s_addr, packet, len, match->interface);
  }
  free(match);
}

void sr_handlepacket_ICMP(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface)
{   }

void sr_handlepacket_ARP(struct sr_instance* sr,
 	uint8_t * packet,
	unsigned int len,
	char* interface)
{   }
