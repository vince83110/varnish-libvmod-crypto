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

#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <cache/cache.h>

#include "vcc_crypto_if.h"

#include "md.h"

static __attribute__((constructor)) void
init(void)
{
	md_init();
	OpenSSL_add_all_algorithms();
}

static __attribute__((destructor)) void
fini(void)
{

}

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
    struct vmod_crypto_verifier **vcvp, const char *vcl_name, VCL_ENUM md_s,
    VCL_STRING key_s)
{
	struct vmod_crypto_verifier *vcv;
	const EVP_MD *md = md_evp(md_parse(md_s));
	EVP_PKEY *pkey;
	BIO *bio;

	if (md == NULL) {
		VRT_fail(ctx, "digest %s not supported", md_s);
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

	bio = BIO_new_mem_buf(key_s, -1);
	if (bio == NULL) {
		VRT_fail(ctx, "key bio failed");
		goto err_digest;
	}

	pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (pkey == NULL) {
		VRT_fail(ctx, "read public key failed, error 0x%lx",
		    ERR_get_error());
		BIO_free_all(bio);
		goto err_digest;
	}
	BIO_free_all(bio);

	if (EVP_DigestVerifyInit(vcv->evpctx, NULL, md, NULL, pkey) !=1) {
		VRT_fail(ctx, "EVP_DigestVerifyInit failed, error 0x%lx",
		    ERR_get_error());
		EVP_PKEY_free(pkey);
		goto err_digest;
	}
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
free_crypto_verifier_task(void *ptr)
{
	struct vmod_crypto_verifier_task *vcvt;

	CAST_OBJ_NOTNULL(vcvt, ptr, VMOD_CRYPTO_VERIFIER_TASK_MAGIC);
	if (vcvt->evpctx)
		EVP_MD_CTX_free(vcvt->evpctx);
	vcvt->evpctx = NULL;
}

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
		task->free = free_crypto_verifier_task;
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
    const char *s, ...)
{
	EVP_MD_CTX *evpctx = crypto_verifier_task_md_ctx(ctx, vcv, 0);
	va_list ap;

	if (evpctx == NULL)
		return (0);

	ERR_clear_error();

	va_start(ap, s);
	while (s != vrt_magic_string_end) {
		if (s && *s &&
		    EVP_DigestVerifyUpdate(evpctx, s, strlen(s)) != 1) {
			VRT_fail(ctx, "EVP_DigestVerifyUpdate"
			    " failed, error 0x%lx", ERR_get_error());
			return (0);
		}
		s = va_arg(ap, const char *);
	}
	va_end(ap);

	return (1);
}
VCL_BOOL
vmod_verifier_update_blob(VRT_CTX, struct vmod_crypto_verifier *vcv,
    VCL_BLOB blob)
{
	EVP_MD_CTX *evpctx = crypto_verifier_task_md_ctx(ctx, vcv, 0);
	va_list ap;

	if (evpctx == NULL)
		return (0);

	ERR_clear_error();
	if (blob && blob->len > 0) {
		AN(blob->priv);
		if (EVP_DigestVerifyUpdate(evpctx,
			blob->priv, blob->len) != 1) {
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

VCL_BOOL vmod_verifier_valid(VRT_CTX,
    struct vmod_crypto_verifier *vcv, VCL_BLOB sig)
{
	EVP_MD_CTX *evpctx = crypto_verifier_task_md_ctx(ctx, vcv, 0);

	if (evpctx == NULL)
		return (0);

	if (sig == NULL || sig->len == 0 || sig->priv == NULL)
		return (0);

	ERR_clear_error();
	return (!! EVP_DigestVerifyFinal(evpctx, sig->priv, sig->len));
}
