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

int setFilter(int sock) {
       struct sock_filter BPF_code[]={

         { 0x28, 0, 0, 0x0000000c },
         { 0x15, 0, 7, 0x000086dd },
         { 0x30, 0, 0, 0x00000014 },
         { 0x15, 17, 0, 0x00000084 },
         { 0x15, 0, 16, 0x00000006 },
         { 0x28, 0, 0, 0x00000036 },
         { 0x15, 13, 0, 0x00000050 },
         { 0x28, 0, 0, 0x00000038 },
         { 0x15, 11, 12, 0x00000050 },
         { 0x15, 0, 11, 0x00000800 },
         { 0x30, 0, 0, 0x00000017 },
         { 0x15, 9, 0, 0x00000084 },
         { 0x15, 0, 8, 0x00000006 },
         { 0x28, 0, 0, 0x00000014 },
         { 0x45, 6, 0, 0x00001fff },
         { 0xb1, 0, 0, 0x0000000e },
         { 0x48, 0, 0, 0x0000000e },
         { 0x15, 2, 0, 0x00000050 },
         { 0x48, 0, 0, 0x00000010 },
         { 0x15, 0, 1, 0x00000050 },
         { 0x6, 0, 0, 0x0000ffff },
         { 0x6, 0, 0, 0x00000000 },



       };


    struct sock_fprog filter;


    filter.len = 22;
    filter.filter = BPF_code;

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) < 0) {
      return -1;
    }
    else {
      printf("OK!\n");
    }

}
int main() {
    int sock;
    fd_set fds;
    unsigned int maxfd=0;
    struct timeval timeout={5,0};

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
             printf("%d\n", size);
           }
     }
   }

}
