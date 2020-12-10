/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $OpenBSD: cipher-chachapoly-libcrypto.c,v 1.1 2020/04/03 04:32:21 djm Exp $ */

#include "includes.h"
#ifdef WITH_OPENSSL
#include "openbsd-compat/openssl-compat.h"
#endif

#if defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#include <sys/types.h>
#include <stdarg.h> /* needed for log.h */
#include <string.h>
#include <stdio.h>  /* needed for misc.h */

#include <openssl/evp.h>

#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "cipher-chachapoly.h"

struct chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *header_evp;
};

struct chachathread {
	u_char *dest;
	u_char *src;
	u_int len;
	u_int aadlen;
	u_int srcaadlen;
	u_int curpos;
	u_char *seqbuf;
	struct chachapoly_ctx *ctx;
	int response;
} chachathread;

int total = 0;

pthread_mutex_t lock;

struct chachapoly_ctx *
chachapoly_new(const u_char *key, u_int keylen)
{
	struct chachapoly_ctx *ctx;

	if (keylen != (32 + 32)) /* 2 x 256 bit keys */
		return NULL;
	if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return NULL;
	if ((ctx->main_evp = EVP_CIPHER_CTX_new()) == NULL ||
	    (ctx->header_evp = EVP_CIPHER_CTX_new()) == NULL)
		goto fail;
	if (!EVP_CipherInit(ctx->main_evp, EVP_chacha20(), key, NULL, 1))
		goto fail;
	if (!EVP_CipherInit(ctx->header_evp, EVP_chacha20(), key + 32, NULL, 1))
		goto fail;
	if (EVP_CIPHER_CTX_iv_length(ctx->header_evp) != 16)
		goto fail;
	return ctx;
 fail:
	chachapoly_free(ctx);
	return NULL;
}

void
chachapoly_free(struct chachapoly_ctx *cpctx)
{
	if (cpctx == NULL)
		return;
	EVP_CIPHER_CTX_free(cpctx->main_evp);
	EVP_CIPHER_CTX_free(cpctx->header_evp);
	freezero(cpctx, sizeof(*cpctx));
}

/* threaded function */
void *chachapoly_thread_work(void *thread) {
	total++;
	struct chachathread *localthread = (struct chachathread *)thread;
	int ret = 0;
	fprintf(stderr, "Made thread!\n");
	pthread_mutex_lock(&lock);
	if (EVP_Cipher(localthread->ctx->main_evp, localthread->dest + localthread->aadlen + localthread->curpos, localthread->src + localthread->srcaadlen, localthread->len) < 0) {
		fprintf(stderr, "Fail cipher\n");
		localthread->response = SSH_ERR_LIBCRYPTO_ERROR;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		pthread_exit(&ret);
		return NULL;
	}
	pthread_mutex_unlock(&lock);
	//fprintf(stderr, "%lu, src is %s\n", pthread_self(), localthread->src);
	//fprintf(stderr, "%lu, dest is %s\n", pthread_self(), localthread->dest);	
	free((void *)localthread->src);
	//fprintf (stderr, "Total is %d\n", total);
	fprintf(stderr, "Leaving %lu\n", pthread_self());		
	pthread_exit(&ret);
	return NULL;
}

/*
 * chachapoly_crypt() operates as following:
 * En/decrypt with header key 'aadlen' bytes from 'src', storing result
 * to 'dest'. The ciphertext here is treated as additional authenticated
 * data for MAC calculation.
 * En/decrypt 'len' bytes at offset 'aadlen' from 'src' to 'dest'. Use
 * POLY1305_TAGLEN bytes at offset 'len'+'aadlen' as the authentication
 * tag. This tag is written on encryption and verified on decryption.
 */
int
chachapoly_crypt(struct chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    const u_char *src, u_int len, u_int aadlen, u_int authlen, int do_encrypt)
{
	u_char seqbuf[16]; /* layout: u64 counter || u64 seqno */
	int r = SSH_ERR_INTERNAL_ERROR;
	u_char expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN];
	struct chachathread thread[5];
	pthread_t threadlist[5];
	pthread_mutex_init(&lock, NULL);
	
	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(seqbuf, 0, sizeof(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	memset(poly_key, 0, sizeof(poly_key));
	if (!EVP_CipherInit(ctx->main_evp, NULL, NULL, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, poly_key,
	    poly_key, sizeof(poly_key)) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* If decrypting, check tag before anything else */
	if (!do_encrypt) {
		const u_char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_key);
		if (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			goto out;
		}
	}

	/* Crypt additional data */
	if (aadlen) {
	  if (!EVP_CipherInit(ctx->header_evp, NULL, NULL, seqbuf, 1) ||
		    EVP_Cipher(ctx->header_evp, dest, src, aadlen) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	}

	fprintf(stderr, "1: len = %d, aadlen = %d seqnr= %d\n", len, aadlen, seqnr);
	
	/* max len of the inbound data is 32k. first pass break any len > 8192 into
	   chunks and submit each chunk to a new thread.
	   Determining the block number (for the counter)
	   blocks seem to be 64 bytes (512 bits). So if we move
	   8192 bytes into the keystream we should have to increase the block
	   counter by 128 (8192/64) so ctrnum1 = 1, ctrnum2=129, ctrnum3 = 257,
	   ctrnum4 = 385. Right now I have a dumb way of doing it. Note: seqbuf is a 
	   16 byte char array that is used to hold 2 64 byte values. Think of it as
	   2 8 byte registers. You need to roll over each register as it hits 255. */
	   
	/* the next chunk of code is where all the magic happens in terms of the crypto
	   cipher init sets things up at the specific block counter
	   EVP_Cipher actually runs the code.
	   the chachathread struct holds the data passed to the thread 
	   for reference: 
	   struct chachathread {
	     u_char *dest;
	     const u_char *src;
	     u_int len;
	     u_int aadlen;
	     u_int srcaadlen;
	     u_int curpos;
	     u_char *seqbuf;
	     struct chachapoly_ctx *ctx;
	     int response;
	   } chachathread;*/
	
	/* 
	   basic premise. You have an inbound 'src' and an outbound 'dest'
	   src has the enclear data and dest holds the crypto data. Take the 
	   src data and break it down into chunks and process each of those chunk 
	   in parallel. The resulting crypto'd chunk can then just be slotted into 
	   dest at the appropriate byte location. 
	 */

	u_int chunk = 8196; // 8k +1 bytes
	// this chunk size is based on the maximum length passed which is
	// 32784 bytes. Thats 32k +4 bytes. The 4 bytes are the aad 

	if (len >= chunk) { /* if the length of the inbound datagram is less than */
		            /* the chunk size don't bother with threading. */ 
		//char *srcblk[4];
		fprintf(stderr,"1: len is > chunk\n");

		u_int bufptr = 0; // track where we are in the buffer
		int i = 0; // iterator
		int k = 0; // holds max iterator value
		seqbuf[0] = 1; // set the cc20 sequence counter to 1
		// we only need to initialize once.
		if (!EVP_CipherInit(ctx->main_evp, NULL, NULL, seqbuf, 1)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		while (bufptr < len) {
			fprintf(stderr,"2: bufptr < len\n");

			fprintf(stderr, "aad: %d Len: %d, Buffptr: %d, Chunk: %d Diff: %d\n", aadlen, len, bufptr, chunk, (len-bufptr));
			if ((len - bufptr) >= chunk) {
				fprintf(stderr,"3: len-buftr > chunk\n");

				thread[i].src = calloc(chunk, 1);
				memcpy(thread[i].src, src+bufptr, chunk);
				fprintf(stderr, "bufptr is %d of %d diff %d\n", bufptr, len, (len - bufptr));
				thread[i].curpos = bufptr;
				thread[i].len = chunk;
				bufptr += chunk;
			} else {
				fprintf(stderr,"4: len - bufptr < chunk\n");
	
				thread[i].src = calloc(len-bufptr, sizeof(char));
				memcpy(thread[i].src, src+bufptr, (len-bufptr));
				fprintf(stderr,"bufptr1 is %d of %d diff %d\n", bufptr, len, (len - bufptr));
				thread[i].curpos = bufptr;
				thread[i].len = len-bufptr;
				bufptr = len;
			}
			if (bufptr == len) {
				fprintf(stderr, "bfptr and len match\n");
			}
			i++;
			k = i;
			fprintf(stderr,"5: leaving chunking \n");

		}
		for (i = 0; i < k; i++) {
			fprintf(stderr,"6: building structs\n");

			// not the right way to do this but
			// we use this to set the chacha counter to the correct
			// value based on how many 512bit blocks we are passing.
			// this assumes we are using 8196 byte chunks.
			if (i == 0) {
				seqbuf[0] = 1; // is this correct? 
			}
			if (i == 1) {
				seqbuf[0] = 127;
			}
			if (i == 2) {
				seqbuf[0] = 255;
				seqbuf[1] = 1;
			}
			if (i == 3) {
				seqbuf[0] = 255;
				seqbuf[1] = 127;
			}
			//for (int j = 0; j < 16; j++) {
			//	fprintf(stderr, "%d: seqbuf[%d] = %d\n", i, j, seqbuf[j]);
			//}
					
			//fprintf(stderr, "i is %d, len is %d, srcblk[%d] is %d\n", i, len, i, thread[i].len);
			
			//fill the struct for the thread
			thread[i].dest = dest; // this is the u_char dest var passed into this function
			thread[i].aadlen = aadlen;
			// the first chunk of the src has 4 bytes (aad) that we need to
			// track subsequent chunks do not so set the aadlen to 0
			if (i == 0)
				thread[i].srcaadlen = aadlen;
			else
				thread[i].srcaadlen = 0;
			thread[i].seqbuf = seqbuf;
			thread[i].ctx = ctx;
			thread[i].response = 0;
			//fprintf (stderr, "creating thread %lu\n", threadlist[i]);
			//pthread_create(&threadlist[i], NULL, chachapoly_thread_work, (void *)&thread[i]);
		}

		for (i=0; i < k; i++) {
			// moved from prior loop as a test. 
			pthread_create(&threadlist[i], NULL, chachapoly_thread_work, (void *)&thread[i]);
			fprintf(stderr,"%d of %d %lu MADE\n", i, k, threadlist[i]);
			if (pthread_kill(threadlist[i],0) != 0) {
				//fprintf(stderr, "Couldn't kill TID: %lu\n", threadlist[i]);
			}
			if (pthread_join(threadlist[i], NULL) != 0) {
				fprintf(stderr, "Failed joining TID: %lu\n", threadlist[i]);
			}
			fprintf(stderr,"%d of %d %lu JOIN\n", i, k, threadlist[i]);
			// probably don't need this as we can get the return value from
			// pthread_join. fix this later. 
			//if (thread[i].response == SSH_ERR_LIBCRYPTO_ERROR) {
			//	fprintf(stderr,"Whoops!\n");
			//	goto out;
			//}
			fprintf(stderr, "Exiting join loop\n");
		}
	} else { /*non threaded cc20 method*/
		/* Set Chacha's block counter to 1 */
		seqbuf[0] = 1;
		if (!EVP_CipherInit(ctx->main_evp, NULL, NULL, seqbuf, 1) ||
		    EVP_Cipher(ctx->main_evp, dest + aadlen, src + aadlen, len) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	}
	fprintf(stderr, "Exiting chunk loop\n");

	/* If encrypting, calculate and append tag */
	if (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_key);
	}
	r = 0;
 out:
	explicit_bzero(expected_tag, sizeof(expected_tag));
	explicit_bzero(seqbuf, sizeof(seqbuf));
	explicit_bzero(poly_key, sizeof(poly_key));
	fprintf(stderr, "Exiting function loop\n");	
	return r;
}

/* Decrypt and extract the encrypted packet length */
int
chachapoly_get_length(struct chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, const u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[16];

	if (len < 4)
		return SSH_ERR_MESSAGE_INCOMPLETE;
	memset(seqbuf, 0, sizeof(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	if (!EVP_CipherInit(ctx->header_evp, NULL, NULL, seqbuf, 0))
		return SSH_ERR_LIBCRYPTO_ERROR;
	if (EVP_Cipher(ctx->header_evp, buf, (u_char *)cp, sizeof(buf)) < 0)
		return SSH_ERR_LIBCRYPTO_ERROR;
	*plenp = PEEK_U32(buf);
	return 0;
}
#endif /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
