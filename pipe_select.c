#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <errno.h>
#include <signal.h>
#include <string.h>

void send_event(int, int, int, char*);

/* Async event queue */
struct event_desc {
	int event, data, msg_sz;
};

static volatile int pipewrite;
static volatile int piperead;

#define EVENT_DUMP 2

static void sig_handler(int sig)
{
	int event;

	if (sig == SIGUSR1) {
	  event = EVENT_DUMP;
	  send_event(pipewrite, event, 0, NULL);
	}
}



void send_event(int fd, int event, int data, char *msg)
{
	struct event_desc ev;
	struct iovec iov[2];

	ev.event = event;
	ev.data = data;
	ev.msg_sz = msg ? strlen(msg) : 0;

	iov[0].iov_base = &ev;
	iov[0].iov_len = sizeof(ev);
	iov[1].iov_base = msg;
	iov[1].iov_len = ev.msg_sz;

	/* error pipe, debug mode. */
	if (fd == -1) {
		return;
	} else {
		/* pipe is non-blocking and struct event_desc is smaller than
		 *            PIPE_BUF, so this either fails or writes everything */
		while (writev(fd, iov, msg ? 2 : 1) == -1 && errno == EINTR);
	}
}

/* rc is return from sendto and friends.
 * Return 1 if we should retry.
 * Set errno to zero if we succeeded. */
int retry_send(ssize_t rc)
{
	static int retries = 0;
	struct timespec waiter;

	if (rc != -1) {
		retries = 0;
		errno = 0;
		return 0;
	}

	/* Linux kernels can return EAGAIN in perpetuity when calling
	 * sendmsg() and the relevant interface has gone. Here we loop
	 * retrying in EAGAIN for 1 second max, to avoid this hanging
	 * dnsmasq. */

	if (errno == EAGAIN || errno == EWOULDBLOCK) {
		waiter.tv_sec = 0;
		waiter.tv_nsec = 10000;
		nanosleep(&waiter, NULL);
		if (retries++ < 1000)
			return 1;
	}

	retries = 0;

	if (errno == EINTR)
		return 1;

	return 0;
}

int read_write(int fd, unsigned char *packet, int size, int rw)
{
	ssize_t n, done;

	for (done = 0; done < size; done += n) {
		do {
			if (rw)
				n = read(fd, &packet[done], (size_t)(size - done));
			else
				n = write(fd, &packet[done], (size_t)(size - done));

			if (n == 0)
				return 0;

		} while (retry_send(n) || errno == ENOMEM || errno == ENOBUFS);

		if (errno != 0)
			return 0;
	}

	return 1;
}


/* NOTE: the memory used to return msg is leaked: use msgs in events only
 *    to describe fatal errors. */
static int read_event(int fd, struct event_desc *evp, char **msg)
{
	char *buf;

	if (!read_write(fd, (unsigned char *)evp, sizeof(struct event_desc), 1))
		return 0;

	*msg = NULL;

	if (evp->msg_sz != 0 && (buf = malloc(evp->msg_sz + 1)) &&
	    read_write(fd, (unsigned char *)buf, evp->msg_sz, 1)) {
		buf[evp->msg_sz] = 0;
		*msg = buf;
	}

	return 1;
}

int main(void)
{
  fd_set fds;
  unsigned int maxfd=0;
  struct timeval timeout={5,0};
	int pipefd[2];

	// Install the signal handler
	struct sigaction s;
	s.sa_handler = sig_handler;
	sigemptyset(&s.sa_mask);
	s.sa_flags = 0;
	sigaction(SIGUSR1, &s, NULL);

	if (pipe(pipefd) <0) {
	  printf("unable to open pipe\n");
	  exit(-1);
	}

  piperead = pipefd[0];
  pipewrite = pipefd[1];

  while (1) {
     FD_ZERO(&fds);
     FD_SET(piperead,&fds);
     maxfd=piperead+1;
     switch(select(maxfd, &fds, NULL, NULL, &timeout)) {
         case -1:
           exit(-1);
           break;
         case 0:
           break;
         default:
           if(FD_ISSET(piperead, &fds)) {
             struct event_desc ev;
             char *msg;
             read_event(piperead, &ev, &msg);
             printf("%d\n", ev.event);
           }
     }
  }

#if 0
	if((childpid = fork()) == -1) {
		perror("fork");
		exit(1);
	}

	if(childpid == 0) {
		/* Child process closes up input side of pipe */
		close(fd[0]);

		/* Send "string" through the output side of pipe */
		write(fd[1], string, (strlen(string)+1));
		exit(0);
	} else {
		/* Parent process closes up output side of pipe */
		close(fd[1]);

		/* Read in a string from the pipe */
		nbytes = read(fd[0], readbuffer, sizeof(readbuffer));
		printf("Received string: %s", readbuffer);
	}
#endif
	return(0);
}
