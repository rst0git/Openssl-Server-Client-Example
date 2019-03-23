#include "common.h"

int main(int argc, char *argv[])
{
	int port = PORT;
	struct sockaddr_in addr;
	struct pollfd fdset[2];

	if (argc == 2) {
		port = atoi(argv[1]);
		if (port <= 0) {
			printf("Invalid port number %s\n", argv[1]);
			return -1;
		}
	} else if (argc > 2) {
		printf("Usage: %s [PORT]\n", argv[0]);
		return -1;
	}

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket()");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (inet_pton(AF_INET, LOCALHOST, &(addr.sin_addr)) <= 0) {
		perror("inet_pton()");
		return -1;
	}

	if (connect(sockfd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
		perror("connect()");
		return -1;
	}

	ssl_init(NULL, NULL);
	ssl_client_init(&client, sockfd, SSLMODE_CLIENT);
	do_ssl_handshake();

	memset(&fdset, 0, sizeof(fdset));
	fdset[0].fd = STDIN_FILENO;
	fdset[0].events = POLLIN;
	fdset[1].fd = sockfd;
	fdset[1].events = POLLEVENTS;

	while (1) {
		fdset[1].events &= ~POLLOUT;
		if (ssl_client_want_write(&client))
			fdset[1].events |= POLLOUT;

		int nready = poll(&fdset[0], 2, -1);

		if (nready == 0)
			continue; /* no fd ready */

		int revents = fdset[1].revents;
		if (revents & POLLIN)
			if (do_sock_read() == -1)
				break;
		if (revents & POLLOUT)
			if (do_sock_write() == -1)
				break;
		if (revents & (POLLERR | POLLHUP | POLLNVAL))
			break;
#ifdef POLLRDHUP
		if (revents & POLLRDHUP)
			break;
#endif
		if (fdset[0].revents & POLLIN)
			do_stdin_read();
		if (client.encrypt_len>0)
			do_encrypt();
	}

	close(fdset[1].fd);
	ssl_client_cleanup(&client);

	return 0;
}

