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

#include <openssl/evp.h>
#include <cache/cache.h>
#include <vas.h>
#include "md.h"

#include "vcc_crypto_if.h"

static const EVP_MD *mdtbl[_MD_E_MAX];

void
md_init (void) {
	mdtbl[md_null] = EVP_md_null();
#ifndef OPENSSL_NO_MD4
	mdtbl[md4] = EVP_md4();
#endif
#ifndef OPENSSL_NO_MD5
	mdtbl[md5] = EVP_md5();
#endif
#ifndef OPENSSL_NO_SHA
	mdtbl[sha1] = EVP_sha1();
//	mdtbl[dss] = EVP_dss();
//	mdtbl[dss1] = EVP_dss1();
//	mdtbl[ecdsa] = EVP_ecdsa();
#endif
#ifndef OPENSSL_NO_SHA256
	mdtbl[sha224] = EVP_sha224();
	mdtbl[sha256] = EVP_sha256();
#endif
#ifndef OPENSSL_NO_SHA512
	mdtbl[sha384] = EVP_sha384();
	mdtbl[sha512] = EVP_sha512();
#endif
#ifndef OPENSSL_NO_RIPEMD
	mdtbl[ripemd160] = EVP_ripemd160();
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
	mdtbl[whirlpool] = EVP_whirlpool();
#endif
#ifndef OPENSSL_NO_GOST
//	mdtbl[gostr341194] = EVP_gostr341194();
//	mdtbl[gost2814789imit] = EVP_gost2814789imit();
//	mdtbl[streebog256] = EVP_streebog256();
//	mdtbl[streebog512] = EVP_streebog512();
#endif
}

const EVP_MD *
md_evp(enum md_e md) {
	assert(md < _MD_E_MAX);
	return (mdtbl[md]);
}

enum md_e
md_parse(VCL_ENUM e) {
	#define VMODENUM(n) if (e == vmod_enum_ ## n) return(n);
#include "tbl_md.h"
	// additional aliases
	if (e == vmod_enum_rmd160 ) return (ripemd160);
	WRONG("illegal md enum");
}
