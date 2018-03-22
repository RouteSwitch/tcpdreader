#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <dnet.h> // libdnet
#include <pcap.h> // pcap
#include "tcpdreader.h"


int main(int argc, char *argv[]) {
   struct pcap_file_header pcapheader;
   struct packetHeader packetHeader;
   struct eth_hdr ethernetHeader;
   struct addr address; // libdnet addr structure for unpacking eth_src/dst
   int logfd, numread, firsttime, readLength;
   int b_usec, c_usec;
   int packetNum, result;
   unsigned int b_sec, c_sec;

   if(argc != 2) {
      printf("Usage: %s <log_file>\n", argv[0]);
      return 0;
   }

   logfd = open(argv[1], O_RDONLY);
   if(logfd < 0) {
      perror("Could not open file for reading");
      return 0;
   }

   while((numread = read(logfd, &pcapheader, HDRLENGTH)) == -1 && errno == EINTR)
      ;
   if(numread != HDRLENGTH) {
      perror("Unable to read PCAP File Header");
      close(logfd);
      return 0;
   }
   // To-do: Switch-case for PCAP magic
   // For now, all are PCAP_MAGIC
   printf("PCAP_MAGIC (0x%X)\n", pcapheader.magic);
   printf("Version major number = %d\n", pcapheader.version_major);
   printf("Version minor number = %d\n", pcapheader.version_minor);
   printf("GMT to local correction = %d\n", pcapheader.thiszone);
   printf("Timestamp accuracy = %d\n", pcapheader.sigfigs);
   printf("Snaplen = %d\n", pcapheader.snaplen);
   printf("Linktype = %d\n\n", pcapheader.linktype);

   firsttime = 1;
   packetNum = 0;

   // For each packet header
   while((numread = read(logfd, &packetHeader, sizeof(packetHeader)))) {
      if(numread == -1 && errno == EINTR)
         continue;
      else if((numread == -1 && errno != EINTR)) {
         perror("Fatal read error on packet header");
         break;
      }
      else if(numread == 0)
         break;
      else {
         if(firsttime) {
            firsttime = 0;
            b_sec = packetHeader.ts.tv_sec;
            b_usec = packetHeader.ts.tv_usec;
         }
         c_sec = (unsigned) packetHeader.ts.tv_sec - b_sec;
         c_usec = (unsigned) packetHeader.ts.tv_usec - b_usec;
         while(c_usec < 0) {
            c_usec += 1000000;
            c_sec--;
         }

         printf("Packet %d\n", packetNum++);
         // Print packet header information
         printf("%05u.%06u\n", (unsigned) c_sec, (unsigned) c_usec);
         printf("Captured Packet Length = %d\n", packetHeader.caplen);
         printf("Actual Packet Length = %d\n", packetHeader.len);

         // Read the ethernet header
         while((numread = read(logfd, &ethernetHeader, sizeof(ethernetHeader))) == -1 
               && errno == EINTR)
            ;
         if(numread == -1 && errno != EINTR) {
            perror("Fatal read error occurred on ethernet header (read result -1)");
            break;
         }
         else if(numread == 0) {
            printf("Read 0 bytes?\n");
            break;
         }
         else if(numread < sizeof(ethernetHeader)) {
            perror("Fatal read error occurred on ethernet header");
            break;
         }

         printf("Ethernet Header\n");
         addr_pack(&address, ADDR_TYPE_ETH, ETH_ADDR_BITS, &(ethernetHeader.eth_src), ETH_ADDR_LEN);
         printf("   eth_src = %s\n", addr_ntoa(&address));
         addr_pack(&address, ADDR_TYPE_ETH, ETH_ADDR_BITS, &(ethernetHeader.eth_dst), ETH_ADDR_LEN);
         printf("   eth_dst = %s\n", addr_ntoa(&address));

         readLength = packetHeader.caplen - numread;
         result = 0;

         // Function needs to be cleaned up, just to test for now
         switch (ntohs(ethernetHeader.eth_type)) {
            case ETH_TYPE_IP:
               result = printIPInformation(logfd, &readLength);
               if(result == -1) {
                  perror("Fatal read error on IP header");
               }
               break;
            case ETH_TYPE_ARP:
               result = printARPInformation(logfd, &readLength);
               if(result == -1) {
                  perror("Fatal read error on ARP header");
               }
               break;
            default:
               printf("   OTHER\n");
         }
         // If error on reading IP/ARP header, break packet reading
         if(result == -1)
            break;
         // Skip over the rest of the packet
         lseek(logfd, readLength, SEEK_CUR);
         printf("\n");
      }
   }

   close(logfd);
   return 0;
}

//returns -1 on error, 0 on success
int printIPInformation(int fd, int *readLength) {
   printf("   IP\n");
   struct ip_hdr iphdr;
   int numread;
   // Keep trying to read sizeof(iphdr) bytes while we're being interrupted
   while((numread = read(fd, &iphdr, sizeof(iphdr))) == -1 && errno == EINTR)
      ;
   // Once we read some num of bytes, make sure it's the right num or else err
   if(numread != sizeof(iphdr))
      return -1;

   *readLength -= sizeof(iphdr);

   struct addr address;
   addr_pack(&address, ADDR_TYPE_IP, IP_ADDR_BITS, &(iphdr.ip_src), IP_ADDR_LEN);
   printf("      ip len = %d\n", ntohs(iphdr.ip_len));
   printf("      ip_src = %s\n", addr_ntoa(&address));
   addr_pack(&address, ADDR_TYPE_IP, IP_ADDR_BITS, &(iphdr.ip_dst), IP_ADDR_LEN);
   printf("      ip_dst = %s\n", addr_ntoa(&address));
   // Single byte, don't need ntoh()
   // TO-DO: Add error handling for interrupt during reads
   switch(iphdr.ip_p) {
      case IP_PROTO_ICMP:
         {
            printf("      ICMP\n");
            struct icmp_hdr i;
            numread = read(fd, &i, sizeof(i));
            if(numread != sizeof(i)) {
               return -1;
            }
            *readLength -= sizeof(i);
            // This list taken from here
            // https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
            char *types[] = {"Echo Reply", "", "", "Destination Unreachable",
                 "Source Quench", "Redirect", "Alternate Host", "", "Echo", 
                 "Router Advertisement", "Router Selection", "Time Exceeded",
                 "Parameter problem", "Timestamp", "Timestamp Reply", "Info Request",
                 "Info Reply", "Address Mask Req", "Address Mask Reply", "", 
                 "", "", "", "", "", "", "", "", "", "", "Traceroute",
                 "Datagram Conversion Error", "Mobile Host Redirect",
                 "IpV6 Where are You?", "IPv6 I-Am-Here", "Mobile Reg. Request",
                 "Mobile Reg. Reply", "Domain Name Request", "Domain Name Reply",
                 "SKIP", "Photuris", "", "Extended Echo Request", "Extended Echo Reply"};
            // Check for valid index range
            if(i.icmp_type < sizeof(types)/sizeof(types[0]))
               printf("         Type: %s\n", types[i.icmp_type]);
            else
               printf("         Type: %s\n", "Unknown");
            break;
         }
     case IP_PROTO_IGMP:
         printf("      IGMP\n");
         break;
     case IP_PROTO_TCP:
         {   
            printf("      TCP\n");
            struct tcp_hdr t;
            numread = read(fd, &t, sizeof(t));
            if(numread != sizeof(t))
               return -1;
            printf("         Src Port = %d\n", ntohs(t.th_sport));
            printf("         Dst Port = %d\n", ntohs(t.th_dport));
            printf("         Seq = %u\n", ntohl(t.th_seq));
            printf("         Ack = %u\n", ntohl(t.th_ack));
            *readLength -= sizeof(t);
            break;
         }
     case IP_PROTO_UDP:
         {
            printf("      UDP\n");
            struct udp_hdr u;
            read(fd, &u, sizeof(u));
            printf("         Src Port = %u\n", ntohs(u.uh_sport));
            printf("         Dst Port = %u\n", ntohs(u.uh_dport));
            *readLength -= sizeof(u);
            break;
         }
     default: //unrecognized
         printf("      OTHER\n");
   }
   return 0;
}

int printARPInformation(int fd, int *readLength) {
   printf("   ARP\n");
   struct arp_hdr a;
   int numread;
   while((numread = read(fd, &a, sizeof(a))) == -1 && errno == EINTR)
      ;
   // Encompasses both read error == -1 and reads < sizeof(a)
   if(numread != sizeof(a))
      return -1;
   *readLength -= sizeof(a);  
   switch(ntohs(a.ar_op)) {
      case ARP_OP_REQUEST:
         printf("      Arp Request\n");
         break;
      case ARP_OP_REPLY:
         printf("      Arp Reply\n");
         break;
      case ARP_OP_REVREQUEST:
         printf("      Arp Reverse Request\n");
         break;
      case ARP_OP_REVREPLY:
         printf("      Arp Reverse Reply\n");
         break;
      default:
         printf("      Unknown Arp Operation\n");
   }
   return 0;
}
