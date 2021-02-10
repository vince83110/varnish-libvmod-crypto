/*-
 * Copyright 2018 UPLEX - Nils Goroll Systemoptimierung
 * All rights reserved
 *
 * Author: Nils Goroll <nils.goroll@uplex.de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"

#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
#ifndef OPENSSL_THREADS
#error "Need thread support in libcrypto"
#endif


#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <cache/cache.h>
#include <vcl.h>

#include "vcc_crypto_if.h"

#include "md.h"

/*
 * ------------------------------------------------------------
 * libcryto housekeeping
 *
 * XXX unclear how this works if another vmod was to use libcrypto also
 *     - namespace it?
 */


static unsigned long
crypto_thread_id(void)
{
	return ((unsigned long)pthread_self());
}

static pthread_mutex_t *crypto_locks = NULL;
static size_t crypto_locks_n = 0;

static void
crypto_lock(int mode, size_t n, const char *file, int line)
{
	(void) file;
	(void) line;

	AN(crypto_locks);
	assert(n < crypto_locks_n);

	if (mode & CRYPTO_LOCK)
		AZ(pthread_mutex_lock(&crypto_locks[n]));
	else
		AZ(pthread_mutex_unlock(&crypto_locks[n]));
}

static __attribute__((constructor)) void
init(void)
{
	size_t i, n;

	md_init();

	n = CRYPTO_num_locks();
	crypto_locks = calloc(n, sizeof(pthread_mutex_t));
	AN(crypto_locks);
	crypto_locks_n = n;

	for (i = 0; i < n; i++)
		AZ(pthread_mutex_init(&crypto_locks[i], NULL));

	CRYPTO_set_id_callback(crypto_thread_id);
	CRYPTO_set_locking_callback(crypto_lock);

	// deprecated in newer OpenSSL/libressl
	OpenSSL_add_all_algorithms();
}

static __attribute__((destructor)) void
fini(void)
{
	size_t i;

	AN(crypto_locks);

	EVP_cleanup();

	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);

	for (i = 0; i < crypto_locks_n; i++)
		AZ(pthread_mutex_destroy(&crypto_locks[i]));

	free(TRUST_ME(crypto_locks));
	crypto_locks = NULL;
	crypto_locks_n = 0;
}

/*
 * ------------------------------------------------------------
 * libcryto compat
 */

#ifndef HAVE_EVP_MD_CTX_FREE
#define EVP_MD_CTX_free(x) EVP_MD_CTX_destroy(x)
#define EVP_MD_CTX_new() EVP_MD_CTX_create()
#endif

#ifndef HAVE_RSA_SET0_KEY
/* from openssl crypto/rsa/rsa_lib.c */
static int
RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.	 d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL)
	|| (r->e == NULL && e == NULL))
	return 0;

    if (n != NULL) {
	BN_free(r->n);
	r->n = n;
    }
    if (e != NULL) {
	BN_free(r->e);
	r->e = e;
    }
    if (d != NULL) {
	BN_clear_free(r->d);
	r->d = d;
	BN_set_flags(r->d, BN_FLG_CONSTTIME);
    }

    return 1;
}
#endif

/*
 * ------------------------------------------------------------
 * $Object key()
 */

struct VPFX(crypto_key) {
	unsigned	magic;
#define VMOD_CRYPTO_KEY_MAGIC		0x32c81a50
	const char	*vcl_name;
	EVP_PKEY	*pkey;
};

#define CRYPTO_KEY_BLOB		0x32c81a51

static void
key_free(VRT_CTX, void *ptr)
{
	struct VPFX(crypto_key) *k;

	(void) ctx;
	CAST_OBJ_NOTNULL(k, ptr, VMOD_CRYPTO_KEY_MAGIC);

	if (k->pkey != NULL)
		EVP_PKEY_free(k->pkey);

	memset(k, 0, sizeof *k);
}

static const struct vmod_priv_methods init_priv_task_methods[1] = {{
		.magic = VMOD_PRIV_METHODS_MAGIC,
		.type = "vmod_crypto_init_priv_task",
		.fini = key_free
}};

VCL_VOID
vmod_key__init(VRT_CTX,
    struct VPFX(crypto_key) **kp, const char *vcl_name,
    struct vmod_priv *priv)
{
	struct VPFX(crypto_key) *k;

	AN(kp);
	AZ(*kp);

	assert(ctx->method == VCL_MET_INIT);

	k = WS_Alloc(ctx->ws, sizeof *k);
	INIT_OBJ(k, VMOD_CRYPTO_KEY_MAGIC);

	k->vcl_name = vcl_name;

	/* use PRIV_TASK to free key after vcl_init */
	priv->priv = k;
	priv->methods = init_priv_task_methods;

	*kp = k;
}

VCL_VOID
vmod_key__fini(struct VPFX(crypto_key) **kp)
{
	*kp = NULL;
}

static int
key_ctx_ok(VRT_CTX)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	if (ctx->method == VCL_MET_INIT)
		return (1);

	VRT_fail(ctx, "key methods can only be used in vcl_init {}");
	return (0);
}

VCL_BLOB
vmod_key_use(VRT_CTX, struct VPFX(crypto_key) *k)
{
	if (! key_ctx_ok(ctx))
		return (NULL);

	CHECK_OBJ_NOTNULL(k, VMOD_CRYPTO_KEY_MAGIC);
	return (VRT_blob(ctx, "xkey.use()", k, sizeof *k, CRYPTO_KEY_BLOB));
}

static EVP_PKEY *
pkey_blob(VRT_CTX, VCL_BLOB blob)
{
	struct VPFX(crypto_key) *k;

	if (blob && blob->type == CRYPTO_KEY_BLOB &&
	    blob->blob != NULL &&
	    blob->len == sizeof(*k)) {
		CAST_OBJ_NOTNULL(k, TRUST_ME(blob->blob),
		    VMOD_CRYPTO_KEY_MAGIC);
		return (k->pkey);
	}
	VRT_fail(ctx, "invalid key blob");
	return (NULL);
}

/* to be freed by caller */
static EVP_PKEY *
pkey_pem(VRT_CTX, VCL_STRING pem)
{
	EVP_PKEY *pkey;
	BIO *bio;

	ERR_clear_error();

	bio = BIO_new_mem_buf(pem, -1);
	if (bio == NULL) {
		VRT_fail(ctx, "key bio failed");
		return (NULL);
	}

	pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	BIO_free_all(bio);

	if (pkey != NULL)
		return (pkey);

	VRT_fail(ctx, "read public key failed, error 0x%lx",
	    ERR_get_error());

	return (NULL);
}

VCL_VOID
vmod_key_pem_pubkey(VRT_CTX, struct VPFX(crypto_key) *k,
    VCL_STRING pem)
{
	if (! key_ctx_ok(ctx))
		return;

	CHECK_OBJ_NOTNULL(k, VMOD_CRYPTO_KEY_MAGIC);

	if (k->pkey != NULL) {
		VRT_fail(ctx, "xkey.pem_pubkey(): key already defined");
		return;
	}

	k->pkey = pkey_pem(ctx, pem);
}

VCL_VOID
vmod_key_rsa(VRT_CTX, struct VPFX(crypto_key) *k, struct VARGS(key_rsa) *args) {
	BIGNUM *n = NULL, *e = NULL, *d = NULL;
	EVP_PKEY *pkey;
	RSA *rsa;

	if (! key_ctx_ok(ctx))
		return;

	CHECK_OBJ_NOTNULL(k, VMOD_CRYPTO_KEY_MAGIC);

	if (k->pkey != NULL) {
		VRT_fail(ctx, "xkey.rsa(): key already defined");
		return;
	}

	AN(args);

	ERR_clear_error();

	if (args->n && args->n->len > 0)
		n = BN_bin2bn(args->n->blob, args->n->len, NULL);

	if (args->e && args->e->len > 0)
		e = BN_bin2bn(args->e->blob, args->e->len, NULL);

	if (args->valid_d && args->d && args->d->len > 0)
		d = BN_bin2bn(args->d->blob, args->d->len, NULL);

	if (n == NULL || e == NULL) {
		VRT_fail(ctx, "xkey.rsa(): n and/or e missing, error 0x%lx",
		    ERR_get_error());
		goto err_bn;
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		VRT_fail(ctx, "xkey.rsa(): pkey alloc failed, error 0x%lx",
		    ERR_get_error());
		goto err_bn;
	}

	rsa = RSA_new();
	if (rsa == NULL) {
		VRT_fail(ctx, "xkey.rsa(): rsa alloc failed, error 0x%lx",
		    ERR_get_error());
		goto err_pkey;
	}

	if (RSA_set0_key(rsa, n, e, d) != 1) {
		VRT_fail(ctx, "xkey.rsa(): RSA_set0_key failed, error 0x%lx",
		    ERR_get_error());
		goto err_rsa;
	}

	EVP_PKEY_assign_RSA(pkey, rsa);

	k->pkey = pkey;
	return;

  err_rsa:
	RSA_free(rsa);

  err_pkey:
	EVP_PKEY_free(pkey);

  err_bn:
	if (n != NULL) BN_free(n);
	if (e != NULL) BN_free(e);
	if (d != NULL) BN_free(d);
}


/*
 * ------------------------------------------------------------
 * $Object verfier()
 */

struct vmod_crypto_verifier {
	unsigned	magic;
#define VMOD_CRYPTO_VERIFIER_MAGIC		0x32c81a57
	char		*vcl_name;
	EVP_MD_CTX	*evpctx;
};

struct vmod_crypto_verifier_task {
	unsigned	magic;
#define VMOD_CRYPTO_VERIFIER_TASK_MAGIC	0x32c81a58
	EVP_MD_CTX	*evpctx;
};

VCL_VOID
vmod_verifier__init(VRT_CTX,
    struct vmod_crypto_verifier **vcvp, const char *vcl_name,
    struct VARGS(verifier__init) *args)
{
	struct vmod_crypto_verifier *vcv;
	const EVP_MD *md = md_evp(md_parse(args->digest));
	EVP_PKEY *pkey;

	if (md == NULL) {
		VRT_fail(ctx, "digest %s not supported", args->digest);
		return;
	}

	if (args->valid_pem ^ args->valid_key == 0) {
		VRT_fail(ctx, "Need either pem or key, but not both");
		return;
	}

	AN(vcvp);
	AZ(*vcvp);

	ALLOC_OBJ(vcv, VMOD_CRYPTO_VERIFIER_MAGIC);
	if (vcv == NULL) {
		VRT_fail(ctx, "obj alloc failed");
		return;
	}

	REPLACE(vcv->vcl_name, vcl_name);
	if (vcv->vcl_name == NULL) {
		VRT_fail(ctx, "dup vcl_name failed");
		goto err_dup;
	}

	ERR_clear_error();

	vcv->evpctx = EVP_MD_CTX_new();
	if (vcv->evpctx == NULL) {
		VRT_fail(ctx, "EVP_MD_CTX_new failed, error 0x%lx",
		    ERR_get_error());
		goto err_evpctx;
	}

	if (EVP_DigestInit_ex(vcv->evpctx, md, NULL) != 1) {
		VRT_fail(ctx, "EVP_DigestInit_ex failed, error 0x%lx",
		    ERR_get_error());
		goto err_digest;
	}

	if (args->valid_pem)
		pkey = pkey_pem(ctx, args->pem);
	else if (args->valid_key)
		pkey = pkey_blob(ctx, args->key);
	else
		INCOMPL();

	if (pkey == NULL)
		goto err_digest;

	if (EVP_DigestVerifyInit(vcv->evpctx, NULL, md, NULL, pkey) !=1) {
		VRT_fail(ctx, "EVP_DigestVerifyInit failed, error 0x%lx",
		    ERR_get_error());
		EVP_PKEY_free(pkey);
		goto err_digest;
	}

	if (args->valid_pem)
		EVP_PKEY_free(pkey);

	*vcvp = vcv;
	return;

  err_digest:
	EVP_MD_CTX_free(vcv->evpctx);
	vcv->evpctx = NULL;
  err_evpctx:
	free(vcv->vcl_name);
  err_dup:
	FREE_OBJ(vcv);
}

VCL_VOID
vmod_verifier__fini(struct vmod_crypto_verifier **vcvp)
{
	struct vmod_crypto_verifier *vcv = *vcvp;

	*vcvp = NULL;
	if (vcv == NULL)
		return;

	CHECK_OBJ(vcv, VMOD_CRYPTO_VERIFIER_MAGIC);

	EVP_MD_CTX_free(vcv->evpctx);
	vcv->evpctx = NULL;
	free(vcv->vcl_name);
	FREE_OBJ(vcv);
}

static void
free_crypto_verifier_task(VRT_CTX, void *ptr)
{
	struct vmod_crypto_verifier_task *vcvt;

	(void) ctx;
	CAST_OBJ_NOTNULL(vcvt, ptr, VMOD_CRYPTO_VERIFIER_TASK_MAGIC);
	if (vcvt->evpctx)
		EVP_MD_CTX_free(vcvt->evpctx);
	vcvt->evpctx = NULL;
}

static const struct vmod_priv_methods verifier_priv_task_methods[1] = {{
		.magic = VMOD_PRIV_METHODS_MAGIC,
		.type = "vmod_crypto_verifier_priv_task",
		.fini = free_crypto_verifier_task
}};

static EVP_MD_CTX *
crypto_verifier_task_md_ctx(VRT_CTX,
    const struct vmod_crypto_verifier *vcv, int reset)
{
	struct vmod_crypto_verifier_task *vcvt;
	struct vmod_priv *task;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(vcv, VMOD_CRYPTO_VERIFIER_MAGIC);

	task = VRT_priv_task(ctx, vcv);

	if (task == NULL) {
		VRT_fail(ctx, "no priv_task");
		return (NULL);
	}

	if (task->priv) {
		CAST_OBJ_NOTNULL(vcvt, task->priv,
		    VMOD_CRYPTO_VERIFIER_TASK_MAGIC);
		AN(vcvt->evpctx);
		if (! reset)
			return (vcvt->evpctx);
	} else {
		vcvt = WS_Alloc(ctx->ws, sizeof *vcvt);
		if (vcvt == NULL) {
			VRT_fail(ctx,
			    "vmod_crypto_verifier_task WS_Alloc failed");
			return (NULL);
		}
		INIT_OBJ(vcvt, VMOD_CRYPTO_VERIFIER_TASK_MAGIC);

		vcvt->evpctx = EVP_MD_CTX_new();
		if (vcvt->evpctx == NULL) {
			VRT_fail(ctx,
			    "vmod_crypto_verifier_task EVP_MD_CTX_new()"
			    " failed, error 0x%lx", ERR_get_error());
			return (NULL);
		}

		task->priv = vcvt;
		task->methods = verifier_priv_task_methods;
	}

	if (EVP_MD_CTX_copy_ex(vcvt->evpctx, vcv->evpctx) != 1) {
		VRT_fail(ctx, "vmod_crypto_verifier_task copy"
		    " failed, error 0x%lx", ERR_get_error());
		EVP_MD_CTX_free(vcvt->evpctx);
		vcvt->evpctx = NULL;
		return (NULL);
	}

	return (vcvt->evpctx);
}

VCL_BOOL
vmod_verifier_update(VRT_CTX, struct vmod_crypto_verifier *vcv,
    VCL_STRANDS str)
{
	EVP_MD_CTX *evpctx = crypto_verifier_task_md_ctx(ctx, vcv, 0);
	const char *s;
	int i;

	if (evpctx == NULL)
		return (0);

	AN(str);

	ERR_clear_error();

	for (i = 0; i < str->n; i++) {
		s = str->p[i];

		if (s == NULL || *s == '\0')
			continue;

		if (EVP_DigestVerifyUpdate(evpctx, s, strlen(s)) != 1) {
			VRT_fail(ctx, "EVP_DigestVerifyUpdate"
			    " failed, error 0x%lx", ERR_get_error());
			return (0);
		}
	}

	return (1);
}
VCL_BOOL
vmod_verifier_update_blob(VRT_CTX, struct vmod_crypto_verifier *vcv,
    VCL_BLOB blob)
{
	EVP_MD_CTX *evpctx = crypto_verifier_task_md_ctx(ctx, vcv, 0);

	if (evpctx == NULL)
		return (0);

	ERR_clear_error();
	if (blob && blob->len > 0) {
		AN(blob->blob);
		if (EVP_DigestVerifyUpdate(evpctx,
			blob->blob, blob->len) != 1) {
			VRT_fail(ctx, "EVP_DigestVerifyUpdate"
			    " failed, error 0x%lx", ERR_get_error());
			return (0);
		}
	}
	return (1);
}

VCL_BOOL vmod_verifier_reset(VRT_CTX,
    struct vmod_crypto_verifier *vcv)
{
	return (!! crypto_verifier_task_md_ctx(ctx, vcv, 1));
}

static int
crypto_err_cb(const char *s, size_t l, void *u)
{
	VRT_CTX;
	CAST_OBJ_NOTNULL(ctx, u, VRT_CTX_MAGIC);
	VSLb(ctx->vsl, SLT_Debug, "crypto %.*s", l, s);
	return (0);
}


VCL_BOOL vmod_verifier_valid(VRT_CTX,
    struct vmod_crypto_verifier *vcv, VCL_BLOB sig)
{
	EVP_MD_CTX *evpctx = crypto_verifier_task_md_ctx(ctx, vcv, 0);
	VCL_BOOL r;

	if (evpctx == NULL)
		return (0);

	if (sig == NULL || sig->len == 0 || sig->blob == NULL)
		return (0);

	ERR_clear_error();
	r = !! EVP_DigestVerifyFinal(evpctx, sig->blob, sig->len);

	if (! r) {
		VSLb(ctx->vsl, SLT_Debug, "%s.valid() failed", vcv->vcl_name);
		ERR_print_errors_cb(crypto_err_cb, (void *)ctx);
	}
	return (r);
}
