// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Google LLC.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <err.h>
#include <arpa/inet.h>
#include <openssl/opensslv.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>

/*
 * OpenSSL 3.0 deprecates the OpenSSL's ENGINE API.
 *
 * Remove this if/when that API is no longer used
 */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include "main.h"

static void display_openssl_errors(int l)
{
	const char *file;
	char buf[120];
	int e, line;

	if (ERR_peek_error() == 0)
		return;
	fprintf(stderr, "At main.c:%d:\n", l);

	while ((e = ERR_get_error_line(&file, &line))) {
		ERR_error_string(e, buf);
		fprintf(stderr, "- SSL %s: %s:%d\n", buf, file, line);
	}
}

static void drain_openssl_errors(void)
{
	const char *file;
	int line;

	if (ERR_peek_error() == 0)
		return;
	while (ERR_get_error_line(&file, &line))
		continue;
}

#define ERR(cond, fmt, ...)                         \
	do {                                        \
		bool __cond = (cond);               \
		display_openssl_errors(__LINE__);   \
		if (__cond) {                       \
			err(1, fmt, ##__VA_ARGS__); \
		}                                   \
	} while (0)

static const char *key_pass;

static int pem_pw_cb(char *buf, int len, int w, void *v)
{
	int pwlen;

	if (!key_pass)
		return -1;

	pwlen = strlen(key_pass);
	if (pwlen >= len)
		return -1;

	strcpy(buf, key_pass);

	/* If it's wrong, don't keep trying it. */
	key_pass = NULL;

	return pwlen;
}

static EVP_PKEY *read_private_key(const char *pkey_path)
{
	EVP_PKEY *private_key;

	if (!strncmp(pkey_path, "pkcs11:", 7)) {
		ENGINE *e;

		ENGINE_load_builtin_engines();
		drain_openssl_errors();
		e = ENGINE_by_id("pkcs11");
		ERR(!e, "Load PKCS#11 ENGINE");
		if (ENGINE_init(e))
			drain_openssl_errors();
		else
			ERR(1, "ENGINE_init");
		if (key_pass)
			ERR(!ENGINE_ctrl_cmd_string(e, "PIN", key_pass, 0),
			    "Set PKCS#11 PIN");
		private_key = ENGINE_load_private_key(e, pkey_path, NULL,
						      NULL);
		ERR(!private_key, "%s", pkey_path);
	} else {
		BIO *b;

		b = BIO_new_file(pkey_path, "rb");
		ERR(!b, "%s", pkey_path);
		private_key = PEM_read_bio_PrivateKey(b, NULL, pem_pw_cb, NULL);
		ERR(!private_key, "%s", pkey_path);
		BIO_free(b);
	}

	return private_key;
}

static X509 *read_x509(const char *x509_cert_path)
{
	unsigned char buf[2];
	X509 *x509;
	BIO *b;
	int n;

	b = BIO_new_file(x509_cert_path, "rb");
	ERR(!b, "%s", x509_cert_path);

	/* Look at the first two bytes of the file to determine the encoding */
	n = BIO_read(b, buf, 2);
	if (n != 2) {
		if (BIO_should_retry(b)) {
			fprintf(stderr, "%s: Read wanted retry\n",
				x509_cert_path);
			exit(1);
		}
		if (n >= 0) {
			fprintf(stderr, "%s: Short read\n", x509_cert_path);
			exit(1);
		}
		ERR(1, "%s", x509_cert_path);
	}

	ERR(BIO_reset(b) != 0, "%s", x509_cert_path);

	if (buf[0] == 0x30 && buf[1] >= 0x81 && buf[1] <= 0x84)
		/* Assume raw DER encoded X.509 */
		x509 = d2i_X509_bio(b, NULL);
	else
		/* Assume PEM encoded X.509 */
		x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);

	BIO_free(b);
	ERR(!x509, "%s", x509_cert_path);

	return x509;
}

__s64 bpf_data_sign(const char *pkey_path, const char *x509_cert_path,
		  const void *module, size_t module_size, void *sig_buf,
		  size_t max_sig_len)
{
	unsigned long sig_size;
	const EVP_MD *digest_algo;
	EVP_PKEY *private_key;
	PKCS7 *pkcs7 = NULL;
	BIO *bd, *bm;
	void *data;
	__s64 len;
	X509 *x509;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	ERR_clear_error();

	bm = BIO_new_mem_buf(module, module_size);
	ERR(!bm, "bpf_data_sign");

	/* Read the private key and the X.509 cert the PKCS#7 message
	 * will point to.
	 */
	private_key = read_private_key(pkey_path);
	x509 = read_x509(x509_cert_path);

	/* Digest the program data. */
	OpenSSL_add_all_digests();
	display_openssl_errors(__LINE__);
	digest_algo = EVP_get_digestbyname("sha1");
	ERR(!digest_algo, "EVP_get_digestbyname");

	pkcs7 = PKCS7_sign(x509, private_key, NULL, bm,
			   PKCS7_NOCERTS | PKCS7_BINARY | PKCS7_DETACHED |
				   PKCS7_NOATTR);
	ERR(!pkcs7, "PKCS7_sign");

	bd = BIO_new(BIO_s_mem());
	ERR(!bd, "dest buffer");
	ERR(i2d_PKCS7_bio(bd, pkcs7) < 0, "serializing signature");

	len = BIO_get_mem_data(bd, &data);
	if (len < 0) {
		BIO_free(bd);
		return -1;
	}

	memcpy(sig_buf, data, len);
	sig_size = BIO_number_written(bd);

	if (BIO_number_written(bd) > max_sig_len)
		return -ENOSPC;

	BIO_free(bd);
	BIO_free(bm);
	return sig_size;
}
