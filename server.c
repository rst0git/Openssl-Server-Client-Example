#include "common.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>

#define CERTFILE "certificate.pem"
#define KEYFILE  "private.pem"
#define RSA_NBITS 2048

/* Sign cert */
int do_X509_sign(X509 *cert, EVP_PKEY *pkey, const EVP_MD *md)
{
	int rv;
	EVP_MD_CTX *mctx = NULL;
	EVP_PKEY_CTX *pkctx = NULL;

	mctx = EVP_MD_CTX_new();
	EVP_MD_CTX_init(mctx);
	rv = EVP_DigestSignInit(mctx, &pkctx, md, NULL, pkey);

	if (rv > 0)
		rv = X509_sign_ctx(cert, mctx);
	EVP_MD_CTX_free(mctx);
	return rv > 0 ? 1 : 0;
}

RSA *ssl_gen_rsa_key(void)
{
	RSA *r = NULL;
	BIGNUM *bne = BN_new();
	if (!BN_set_word(bne, RSA_F4)) {
		printf("Failed to set BIGNUM\n");
		return NULL;
	}

	r = RSA_new();
	if (!RSA_generate_key_ex(r, RSA_NBITS, bne, NULL)) {
		printf("Failed to generate RSA key\n");
		return NULL;
	}

	return r;
}

static inline int ssl_save_private_key(RSA *r)
{
	BIO *bp = BIO_new_file(KEYFILE, "w");
	int ret = PEM_write_bio_RSAPrivateKey(bp, r, NULL, NULL, 0, NULL, NULL);
	BIO_free_all(bp);
	return ret;
}

static inline int ssl_save_certificate(X509 *cert)
{
	BIO *bp = BIO_new_file(CERTFILE, "w");
	int ret = PEM_write_bio_X509(bp, cert);
	BIO_free_all(bp);
	return ret;
}

static int ssl_set_issuer(X509 *cert)
{
	int ret;
	const char *org = "Organization";
	const char *cn = "localhost";

	X509_NAME *x509_name = X509_get_subject_name(cert);

	ret = X509_NAME_add_entry_by_txt(x509_name,"O", MBSTRING_ASC, (const unsigned char*)org, -1, -1, 0);
	if (ret != 1) {
		printf("Failed to set X509 org name\n");
		return -1;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name,"CN", MBSTRING_ASC, (const unsigned char*)cn, -1, -1, 0);
	if (ret != 1) {
		printf("Failed to set X509 common name\n");
		return -1;
	}

	ret = X509_set_issuer_name(cert, x509_name);
	if (ret != 1) {
		printf("Failed to set X509 issuer\n");
		return -1;
	}

	return 0;
}

X509 *ssl_gen_cert(RSA *r)
{
	int serial = 1;
	long days = 3650 * 24 * 3600; /* 10 years */

	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;

	cert = X509_new();
	if (!cert) {
		printf("Failed to create X509 cert\n");
		return NULL;
	}

	/* Set version to X509 v3 certificate */
	if (!X509_set_version(cert, 2)) {
		printf("Failed to set X509 version\n");
		return NULL;
	}

	/* Set serial */
	ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);

	/* Set time */
	X509_gmtime_adj(X509_get_notBefore(cert), 0);
	X509_gmtime_adj(X509_get_notAfter(cert), days);

	/* Set issuer name */
	if (ssl_set_issuer(cert)) {
		printf("Failed to set issuer\n");
		return NULL;
	}

	pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey, r);

	/* Set public key */
	if (!X509_set_pubkey(cert, pkey)) {
		printf("Failed to set pkey\n");
		EVP_PKEY_free(pkey);
		return NULL;
	}

	/* Sign certificate */
	if (!do_X509_sign(cert, pkey, EVP_sha1())) {
		printf("Failed to sign certificate\n");
		EVP_PKEY_free(pkey);
		return NULL;
	}

	return cert;
}

int ssl_gen_and_load_cert(void)
{
	int ret = -1;
	RSA *r;
	X509 *cert;

	printf("Generating private key\n");
	r = ssl_gen_rsa_key();
	if (!r) {
		printf("Failed to generate RSA key\n");
		goto err;
	}

	if (!ssl_save_private_key(r)) {
		printf("Failed to save private key\n");
		goto err;
	}

	printf("Generating certificate\n");
	cert = ssl_gen_cert(r);
	if (!cert) {
		printf("Failed to create certificate\n");
		goto err;
	}

	if (!ssl_save_certificate(cert)) {
		printf("Failed to save certificate\n");
		goto err;
	}

	if (!SSL_CTX_use_certificate(ctx, cert)) {
		printf("Failed to load certificate\n");
		goto err;
	}

	if (!SSL_CTX_use_RSAPrivateKey(ctx, r)) {
		printf("Failed to load private key\n");
		goto err;
	}

	ret = 0;
err:
	X509_free(cert);
	return ret;
}

int ssl_load_cert()
{
	int ret;
	struct stat st;

	ret = stat(CERTFILE, &st);
	if (ret) {
		if (errno == ENOENT) {
			ssl_gen_and_load_cert();
			goto verify;
		}
		printf("Can't open %s\n", CERTFILE);
		return -1;
	}

	ret = stat(KEYFILE, &st);
	if (ret) {
		if (errno == ENOENT) {
			ssl_gen_and_load_cert();
			goto verify;
		}
		printf("Can't open %s\n", KEYFILE);
		return -1;
	}

	if (!SSL_CTX_use_certificate_file(ctx, CERTFILE,  SSL_FILETYPE_PEM)) {
		printf("SSL_CTX_use_certificate_file() failed");
		return -1;
	}

	if (!SSL_CTX_use_PrivateKey_file(ctx, KEYFILE, SSL_FILETYPE_PEM)) {
		printf("SSL_CTX_use_PrivateKey_filei() failed\n");
		return -1;
	}

verify:
	if (SSL_CTX_check_private_key(ctx) != 1) {
		printf("SSL_CTX_check_private_key() failed\n");
		return -1;
	}

	printf("Certificate and private key verified\n");
	return 0;
}

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

	ssl_create_context();
	if (ssl_load_cert())
		exit(-1);

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
