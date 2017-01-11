#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <linux/filter.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>

#define LOG_FILE "/tmp/dnssniff.log"
#define LINE_COUNT 20000

int setFilter(int sock) {
    struct sock_fprog filter;
    struct sock_filter BPF_code[]={

{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 8, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 0, 6, 0x00000011 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 4, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x48, 0, 0, 0x00000010 },
{ 0x15, 0, 1, 0x00000035 },
{ 0x6, 0, 0, 0x00000200 },
{ 0x6, 0, 0, 0x00000000 }

    };


    filter.len = 11;
    filter.filter = BPF_code;

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) < 0) {
      return -1;
    }
}

int main() {
    int sock;
    fd_set fds;
    unsigned int maxfd=0;
    unsigned int count=0;
    struct timeval timeout={5,0};
    FILE *fp=fopen(LOG_FILE, "w+");

    /* buf is buffer containing the ethernet frame */
    unsigned char buf[65535];

    if (( sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
      perror ("socket() failed ");
      exit (EXIT_FAILURE);
    }

    if (setFilter(sock) < 0) {
      perror("setsockopt error: ");
      exit (EXIT_FAILURE);
    }

    while(1) {
     int i=0;
     FD_ZERO(&fds);
     FD_SET(sock,&fds);
     maxfd=sock+1;
     switch(select(maxfd,&fds,&fds,NULL,&timeout)) {
         case -1:
           exit(-1);
           break;
         case 0:
           break;
         default:
           if(FD_ISSET(sock, &fds)) {
             int size=recv(sock, buf, sizeof(buf), 0);
             if ((size > 57) && (buf[37] == 53) && fp) {
               unsigned int ts=time(NULL);
               for (i=54; i<54+strlen(buf+54);) {
                 unsigned char offset=buf[i];
                 buf[i]=0x2e;
                 i += offset + 1;
               }
               fprintf(fp, "%u %02x:%02x:%02x:%02x:%02x:%02x %s\n",
                       ts, buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf+55);
               count ++;
             }

             if (count > LINE_COUNT) {
               if (fp) {
                 char command[128]={0};
                 fclose(fp);
                 snprintf(command, sizeof(command), "mv %s %s.1", LOG_FILE, LOG_FILE);
                 system(command);
               }
               fp=fopen(LOG_FILE, "w+");
               count=0;
             }
           }
     }
   }

}
