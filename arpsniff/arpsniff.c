#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include "./uthash.h"

struct ether_arp {
  unsigned short arp_hrd;
  unsigned short arp_pro;
  unsigned char arp_hln;
  unsigned char arp_pln;
  unsigned short arp_op;
  unsigned char arp_sha[6];
  unsigned char arp_spa[4];
  unsigned char arp_tha[6];
  unsigned char arp_tpa[4];
};

unsigned char  netmask[4]={0};
unsigned char  maskip[4];

#define MAXIP 20
#define MAXMAC 20
#define ONLINE_CNT_FILE "/tmp/online_cnt.arp"
static int deauth_timeout=300;
static int json_output_period=120;
static int last_ts=0;
static unsigned int count=0;
typedef struct _client_struct {
  unsigned char ip[MAXIP]; //key
  unsigned char mac[MAXMAC];
  time_t ts;
  time_t arp_cmd_ts;
  UT_hash_handle hh;         /* makes this structure hashable */
} client_struct;

client_struct* client_list=NULL;
client_struct* offline_client=NULL;

void output_json_users(time_t ts) {
  client_struct* s=NULL;
  client_struct* tmp=NULL;
  FILE *output_json_fp=NULL;
  char out_file_name[32]={0};
  char command[64]={0};
  int comma=0;
  snprintf(out_file_name, sizeof(out_file_name), "%s.%d", ONLINE_CNT_FILE, ts);

  output_json_fp=fopen(out_file_name, "w+");
  if (output_json_fp) {
    HASH_ITER(hh, client_list, s, tmp) {
      if (comma) {
        fprintf(output_json_fp,  ",{\"ip\":\"%s\",\"mac\":\"%s\",\"ts\":%d}\n",
                s->ip, s->mac, s->ts);
      }
      else {
        fprintf(output_json_fp,  "{\"ip\":\"%s\",\"mac\":\"%s\",\"ts\":%d}\n",
                s->ip, s->mac, s->ts);
      }
      comma=1;
    }
    fclose(output_json_fp);
    last_ts=ts;
  }
  snprintf(command, sizeof(command), "mv %s %s", out_file_name, ONLINE_CNT_FILE);
  system(command);
}

void list_users() {
  client_struct *s=NULL;
  printf("=======================================\n");
  for(s=client_list; s != NULL; s=s->hh.next) {
    printf("{\"ip\":\"%s\",\"mac\":\"%s\",\"ts\":%d}\n",
           s->ip, s->mac, s->ts);
  }
}

void check_users(time_t ts) {
  client_struct* s=NULL;
  client_struct* tmp=NULL;

  HASH_ITER(hh, client_list, s, tmp) {
    //update ts
    if ((s->ts==0) & (ts>120)) {
      s->ts=ts;
    }
    if (ts-(s->ts) > (deauth_timeout/2)) {
      //delete arp entry to let client send arp again
      if (s->arp_cmd_ts==0) {
        char cmd[128]={0};
        snprintf(cmd, sizeof(cmd), "arp -d %s 2>/dev/null", s->ip);
        system(cmd);
        s->arp_cmd_ts=ts;
      }
    }

    //flush wifi client if arp timeout
    if (ts-(s->ts) > deauth_timeout) {
      if (ts>1400000) {
        HASH_DEL(client_list, s);  /* delete; users advances to next */
        free(s); /* optional- if you want to free  */
      }
    }

  }
}

void get_lan_domain(char* dev) {
  int fd;
  struct ifreq ifr;
  int i=0;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  /* I want to get an IPv4 IP address */
  ifr.ifr_addr.sa_family = AF_INET;

  /* I want IP address attached to "eth0" */
  strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

  /* display result */
  ioctl(fd, SIOCGIFADDR, &ifr);
  strncpy(maskip, (unsigned char*)(&(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr)), sizeof(maskip));

  ioctl(fd, SIOCGIFNETMASK, &ifr);
  strncpy(netmask, (unsigned char*)(&(((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr)), sizeof(netmask));
  close(fd);

  for (i=0; i<sizeof(netmask); i++) {
    maskip[i]=maskip[i] & netmask[i];
  }
}

int main(int argc, char* argv[])
{
    int sock;
    fd_set fds;
    unsigned int maxfd=0;
    struct timeval timeout={5,0};
    char *dev = "br1";

    get_lan_domain(dev);

    if (argc>1) {
      deauth_timeout =atoi(argv[1]);
    }
    if (argc>2) {
      json_output_period =atoi(argv[2]);
    }

    /* buf is buffer containing the ethernet frame */
    char buf[65535];
    struct ether_arp *arp_frame;



    /* skipping the 14 bytes of ethernet frame header */
    arp_frame = (struct ether_arp *) (buf + 14);

    if ((sock = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ARP))) < 0) {
        perror ("socket() failed ");
        exit (EXIT_FAILURE);
    }

   setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, dev, 4);

   FILE *arp_fp=NULL;
   arp_fp=fopen("/proc/net/arp", "rb");
   if (arp_fp) {
     char buffer[100];
     //skip first line
     if (!feof(arp_fp)) {
       fgets(buffer, sizeof(buffer), arp_fp);
     }
     while (!feof(arp_fp)) {
       char ip[MAXIP]={0};
       char hw[20]={0};
       char flag[20]={0};
       char mac[MAXMAC]={0};
       char mask[20]={0};
       char device[20]={0};
       fscanf(arp_fp, "%s\t%s\t%s\t%s\t%s\t%s\n", ip, hw, flag, mac, mask, device);
       if (strcmp(device, dev)==0 && strcmp(flag, "0x0")) {
         client_struct* s=NULL;

         //printf("%s, %s, %s\n", ip, mac, device);
         HASH_FIND_STR( client_list, ip, s);
         if (!s) {
           s = (client_struct*)malloc(sizeof(client_struct));
           memset(s, 0x0, sizeof(client_struct));
           strncpy(s->ip, ip, sizeof(ip));
           strncpy(s->mac, mac, sizeof(mac));
           s->ts=0;
           HASH_ADD_STR( client_list, ip, s );
         }
       }
     }
     fclose(arp_fp);
   }

   while(1)
   {
        FD_ZERO(&fds);
        FD_SET(sock,&fds);
        maxfd=sock+1;
        time_t ts=time(NULL);

        switch(select(maxfd,&fds,&fds,NULL,&timeout))
        {
            case -1:
              exit(-1);
              break;
            case 0:
              break;
            default:
              if(FD_ISSET(sock,&fds)) {
                int size=recv(sock, buf, sizeof(buf), 0);

                if (size >= 20) {
                  client_struct *s=NULL, *tmp = NULL;
                  char client_ip[MAXIP]={0};
                  char client_mac[MAXMAC]={0};


                  /* skip to the next frame if it's not an ARP packet */
                  if ((((buf[12]) << 8) + buf[13]) != ETH_P_ARP)
                      continue;

                  /* skip to the next frame if it's not an ARP REPLY */
                  if (ntohs (arp_frame->arp_op) != ARPOP_REPLY)
                      continue;

                  if ( ((arp_frame->arp_spa[0] & netmask[0])!=maskip[0]) ||
                       ((arp_frame->arp_spa[1] & netmask[1])!=maskip[1]) ||
                       ((arp_frame->arp_spa[2] & netmask[2])!=maskip[2]) ||
                       ((arp_frame->arp_spa[3] & netmask[3])!=maskip[3])
                       ) {
                    break;
                  }
                  snprintf(client_ip, sizeof(client_ip), "%u.%u.%u.%u",
                           arp_frame->arp_spa[0],
                           arp_frame->arp_spa[1],
                           arp_frame->arp_spa[2],
                           arp_frame->arp_spa[3]);
                  snprintf(client_mac, sizeof(client_mac), "%02x.%02x.%02x.%02x.%02x.%02x",
                           arp_frame->arp_sha[0],
                           arp_frame->arp_sha[1],
                           arp_frame->arp_sha[2],
                           arp_frame->arp_sha[3],
                           arp_frame->arp_sha[4],
                           arp_frame->arp_sha[5]);



                  HASH_FIND_STR( client_list, client_ip, s);
                  if (!s) {
                    s = (client_struct*)malloc(sizeof(client_struct));
                    memset(s, 0x0, sizeof(client_struct));
                    strncpy(s->ip, client_ip, sizeof(client_ip));
                    strncpy(s->mac, client_mac, sizeof(client_mac));
                    s->ts=ts;
                    HASH_ADD_STR( client_list, ip, s );
                  }
                  else {
                    s->ts=ts;
                  }

                }
              }
        }// end switch

        check_users(ts);
        if (ts - last_ts > json_output_period) {
          //list_users();
          output_json_users(ts);
        }
    }//end while
}
