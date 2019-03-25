#include "common.h"

#define CRT "server.crt"
#define KEY "server.key"

int main(int argc, char *argv[])
{
	struct sockaddr_in servaddr;
	char str[INET_ADDRSTRLEN];
	int s_fd;
	int c_fd;
	int port = PORT;
	int one = 1;
	struct pollfd fdset[2];
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);

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

	s_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (s_fd < 0) {
		perror("socket()");
		return -1;
	}

	if (setsockopt(s_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
		perror("setsockopt(SO_REUSEADDR)");
		return -1;
	}

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);

	if (bind(s_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		perror("bind()");
		return -1;
	}

	if (listen(s_fd, 128) < 0) {
		perror("listen()");
		return -1;
	}

	memset(&fdset, 0, sizeof(fdset));
	fdset[0].fd = STDIN_FILENO;
	fdset[0].events = POLLIN;

	ssl_init(CRT, KEY);

	while (1) {
		printf("Waiting for connection on port %d ...\n", port);

		c_fd = accept(s_fd, (struct sockaddr *)&addr, &addr_len);
		if (c_fd < 0) {
			perror("accept()");
			return -1;
		}

		ssl_client_init(&client, c_fd, 1);

		inet_ntop(addr.sin_family, &addr.sin_addr, str,
			INET_ADDRSTRLEN);

		printf("New connection established %s:%d\n",
			str, ntohs(addr.sin_port));

		fdset[1].fd = c_fd;
		fdset[1].events = POLLEVENTS;

		while (1) {
			int nready;
			int revents;

			fdset[1].events &= ~POLLOUT;
			fdset[1].events |= (ssl_client_want_write(&client)? POLLOUT : 0);

			nready = poll(&fdset[0], 2, -1);
			if (nready == 0)
				continue; /* no fd ready */

			revents = fdset[1].revents;
			if (revents & POLLIN)
				if (do_sock_read() == -1)
					break;

			if (revents & POLLOUT)
				if (do_sock_write() == -1)
					break;

			if (revents & (POLLEVENTS & ~POLLIN))
				break;

			if (fdset[0].revents & POLLIN)
				do_stdin_read();

			if (client.encrypt_len>0)
				do_encrypt();
		}

		close(fdset[1].fd);
		ssl_client_cleanup(&client);
	}

	return 0;
}
