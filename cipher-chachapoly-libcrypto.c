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

#define LVL_INDENT  "  "
#define MAX_THREADS 4
#define findent(file, lvl, str) for (int c=0;c<lvl;c++) fprintf(file, "%s", str);

struct chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *header_evp;
};

struct chachathread {
	u_char *dest;
	u_char *src;
	u_int len;
	u_int aadlen;
	u_int curpos;
	pthread_t tid;
	u_char *seqbuf;
	struct chachapoly_ctx *ctx;
	int response;
} chachathread;

pthread_mutex_t lock;
pthread_cond_t cond;
int threadcount;
int test_val; // just to track things in the thread func
int chunk_num;

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
    struct chachathread *localthread = (struct chachathread *)thread;
    int val = 0;
    findent(stderr, 0, LVL_INDENT);
    fprintf(stderr, "00: Thread id %lu running successfully!\n", pthread_self());
    fflush(stderr);
    pthread_mutex_lock(&lock);
    val = EVP_Cipher(localthread->ctx->main_evp, localthread->dest + localthread->aadlen + localthread->curpos,
                     localthread->src + localthread->aadlen, localthread->len);
    pthread_mutex_unlock(&lock);
    if (val < 0) {
        findent(stderr, 1, LVL_INDENT);
        fprintf(stderr, ".01: Thread id %lu cipher fail!\n", pthread_self());
        fflush(stderr);
        localthread->response = SSH_ERR_LIBCRYPTO_ERROR;
    }
    free((void *)localthread->src);
    findent(stderr, 0, LVL_INDENT);
    fprintf(stderr, "01: Thread id %lu exiting!\n", pthread_self());
    fflush(stderr);
    pthread_mutex_lock(&lock);
    findent(stderr, 1, LVL_INDENT);
    fprintf(stderr, ".01: Threadcount is %d of %d\n", threadcount, test_val);
    fflush(stderr);
    threadcount++;
    findent(stderr, 1, LVL_INDENT);
    fprintf(stderr, ".01: Threadcount is now %d of %d\n", threadcount, test_val);
    fflush(stderr);
    pthread_mutex_unlock(&lock);
    pthread_exit(NULL);
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
	struct chachathread thread[MAX_THREADS];

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

        fprintf(stderr, "------------------------------\n");
        findent(stderr, 1, LVL_INDENT);
        fprintf(stderr, "01: len = %d, aadlen = %d seqnr= %d\n", len, aadlen, seqnr);
        fflush(stderr);

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
                   u_char *src;
                   u_int len;
                   u_int aadlen;
                   u_int curpos;
                   pthread_t tid;
                   u_char *seqbuf;
                   struct chachapoly_ctx *ctx;
                   int response;
                } chachathread; */

	/*
	   basic premise. You have an inbound 'src' and an outbound 'dest'
	   src has the enclear data and dest holds the crypto data. Take the
	   src data and break it down into chunks and process each of those chunk
	   in parallel. The resulting crypto'd chunk can then just be slotted into
	   dest at the appropriate byte location.
	 */

	u_int chunk = 8196; // 8k bytes
	// this chunk size is based on the maximum length passed which is
	// 32784 bytes. Thats 32k +4 bytes. The 4 bytes are the aad

	if (len >= chunk) {
            /* if the length of the inbound datagram is less than */
            /* the chunk size don't bother with threading. */
            //char *srcblk[4];
            findent(stderr, 2, LVL_INDENT);
            fprintf(stderr,".01: len (%d) is > chunk (%d)\n", len, chunk);
            fflush(stderr);

            u_int bufptr = 0; // track where we are in the buffer
            int i = 0; // iterator
            int total_chunks = 0; // holds total number of chunks made
            int joined = 0; // number of threads successfullyj joined
	    threadcount = 0; 
            seqbuf[0] = 1; // set the cc20 sequence counter to 1
            // we only need to initialize once.
            if (!EVP_CipherInit(ctx->main_evp, NULL, NULL, seqbuf, 1)) {
                r = SSH_ERR_LIBCRYPTO_ERROR;
                goto out;
            }


            while (bufptr < len) {
                findent(stderr, 3, LVL_INDENT);
                fprintf(stderr,".01: bufptr < len\n");
                fflush(stderr);
		total_chunks++;
                findent(stderr, 3, LVL_INDENT);
                fprintf(stderr, ".02: aad: %d Len: %d, Buffptr: %d, Chunk: %d Diff: %d total_chunks %d\n", aadlen,
			len, bufptr, chunk, (len-bufptr), total_chunks);
                fflush(stderr);

                if ((len - bufptr) >= chunk) {
                    findent(stderr, 4, LVL_INDENT);
                    fprintf(stderr,".01: len-buftr > chunk\n");
                    fflush(stderr);
                    thread[i].src = malloc(chunk);
                    memcpy(thread[i].src, src+bufptr, chunk);
                    findent(stderr, 4, LVL_INDENT);
                    fprintf(stderr, ".02: bufptr is %d of %d diff %d\n", bufptr, len, (len - bufptr));
                    fflush(stderr);
                    thread[i].curpos = bufptr;
                    thread[i].len = sizeof(thread[i].src);
                    bufptr += chunk;
                } else {
                    findent(stderr, 4, LVL_INDENT);
                    fprintf(stderr,".03: len - bufptr < chunk\n");
                    fflush(stderr);
                    thread[i].src = malloc(len-bufptr);
                    memcpy(thread[i].src, src+bufptr, (len-bufptr));
                    findent(stderr, 4, LVL_INDENT);
                    fprintf(stderr,".04: bufptr1 is %d of %d diff %d\n", bufptr, len, (len - bufptr));
                    fflush(stderr);
                    thread[i].curpos = bufptr;
                    thread[i].len = sizeof(thread[i].src);
                    bufptr = len;
                }

                if (bufptr == len) {
                    findent(stderr, 4, LVL_INDENT);
                    fprintf(stderr, ".05: bfptr and len match\n");
                    fflush(stderr);
                }
                findent(stderr, 3, LVL_INDENT);
                fprintf(stderr,".03: chunk %d of size %d made\n", i, thread[i].len);
                fflush(stderr);
                i++;
                //total_chunks++;
            } /* while  */
	    test_val = total_chunks; /* global to use in thread fun to compare thread count*/
	                             /* get rid of this later */
            for (i = 0; i < total_chunks; i++) {
                findent(stderr, 3, LVL_INDENT);
                fprintf(stderr,".04: building struct %d\n", i);
                fflush(stderr);

                // not the right way to do this but
                // we use this to set the chacha counter to the correct
                // value based on how many 512bit blocks we are passing.
                // this assumes we are using 8196 byte chunks.
                switch (i) {
                case 0:
                    seqbuf[0] = 1;
                    break;
                case 1:
                    seqbuf[0] = 127;
                    break;
                case 2:
                    seqbuf[0] = 255;
                    seqbuf[1] = 1;
                    break;
                case 3:
                    seqbuf[0] = 255;
                    seqbuf[1] = 127;
                    break;
                default:
                    findent(stderr, 4, LVL_INDENT);
                    fprintf(stderr, ".01: unexpected number of chunks %d\n", i);
                    fflush(stderr);
                }

                //fill the struct for the thread
                thread[i].dest = dest; // this is the u_char dest var passed into this function
                thread[i].aadlen = aadlen;
                thread[i].seqbuf = seqbuf;
                thread[i].ctx = ctx;
                thread[i].response = 0;
            } /* for  */

            for (i=0; i < total_chunks; i++) {
                // moved from prior loop as a test.
                findent(stderr, 3, LVL_INDENT);
                fprintf(stderr,".05: attempting to make thread id %lu (%d of %d)\n", thread[i].tid, i+1, total_chunks);
                fflush(stderr);
                pthread_create(&thread[i].tid, NULL, &chachapoly_thread_work, (void *)&thread[i]);
                findent(stderr, 3, LVL_INDENT);
                fprintf(stderr,".05: %d of %d %lu MADE\n", i+1, total_chunks, thread[i].tid);
                fflush(stderr);
                findent(stderr, 3, LVL_INDENT);
                fprintf(stderr, ".06: attempting to join any remaining threads\n");
                fflush(stderr);
                int ptk_result;
                if ((ptk_result = pthread_kill(thread[i].tid, 0)) != 0) {
                    switch (ptk_result) {
                    case ESRCH:
                        findent(stderr, 4, LVL_INDENT);
                        fprintf(stderr, ".01: pthread_kill failure: No thread id %lu in %s\n", thread[i].tid, __FUNCTION__);
                        fflush(stderr);
                        break;
                    case EINVAL:
                        findent(stderr, 4, LVL_INDENT);
                        fprintf(stderr,".02: pthread_kill failure: Invalid thread id %lu in %s\n", thread[i].tid, __FUNCTION__);
                        fflush(stderr);
                        break;
                    default:
                        findent(stderr, 4, LVL_INDENT);
                        debug (".03: joining %lu\n", thread[i].tid);
                        fflush(stderr);
                        switch (pthread_join(thread[i].tid, NULL)) {
                        case EDEADLK:
                            findent(stderr, 5, LVL_INDENT);
                            fprintf(stderr,".01 pthread_join failure: Thread id %lu deadlock detected in %s\n, ", thread[i].tid, __FUNCTION__);
                            fflush(stderr);
                            break;
                        case EINVAL:
                            findent(stderr, 5, LVL_INDENT);
                            fprintf(stderr, ".02 pthread_join failure: Invalid thread id %lu in %s\n", thread[i].tid, __FUNCTION__);
                            fflush(stderr);
                            break;
                        case ESRCH:
                            findent(stderr, 5, LVL_INDENT);
                            fprintf(stderr, ".03 pthread_join failure: No thread id %lu in %s\n", thread[i].tid, __FUNCTION__);
                            fflush(stderr);
                            break;
                        default:
                            findent(stderr, 5, LVL_INDENT);
                            fprintf(stderr, ".04 pthread_join success: joined thread id %lu in %s\n", thread[i].tid, __FUNCTION__);
                            fflush(stderr);
                            joined++;
                        }
                    }
                }

                findent(stderr, 3, LVL_INDENT);
                fprintf(stderr,".07: %d of %d %lu JOIN\n", i, total_chunks, thread[i].tid);
                fflush(stderr);
                //if (thread[i].response == SSH_ERR_LIBCRYPTO_ERROR) {
                //	fprintf(stderr,"Whoops!\n");
                //	goto out;
                //}
                findent(stderr, 3, LVL_INDENT);
                fprintf(stderr, ".08: Exiting join loop\ntotal: %d joined %d\n", total_chunks, joined);
                fflush(stderr);
            } /* for  */
	    pthread_mutex_lock(&lock);
	    while (threadcount < total_chunks) {
		    findent(stderr, 0, LVL_INDENT);
		    fprintf(stderr, "09: In while loop - TCOUNT %d and CHUNKS %d\n", threadcount, total_chunks);
		    fflush(stderr);
		    pthread_cond_wait(&cond, &lock);
	    }
	    pthread_mutex_unlock(&lock);
	} else { /*non threaded cc20 method*/
		findent(stderr, 2, LVL_INDENT);
		fprintf(stderr, ".02: len %d too small for threading\n", len);
		fflush(stderr);
		/* Set Chacha's block counter to 1 */
            seqbuf[0] = 1;
            if (!EVP_CipherInit(ctx->main_evp, NULL, NULL, seqbuf, 1) ||
                EVP_Cipher(ctx->main_evp, dest + aadlen, src + aadlen, len) < 0) {
		    r = SSH_ERR_LIBCRYPTO_ERROR;
		    goto out;
            }
	}
	
        findent(stderr, 1, LVL_INDENT);
	fprintf(stderr, "02: Exiting chunk loop\n");
        fflush(stderr);
	
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
        findent(stderr, 1, LVL_INDENT);
	fprintf(stderr, "03: Exiting function loop\n");
        fflush(stderr);
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
