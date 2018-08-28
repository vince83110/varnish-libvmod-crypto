#!/bin/bash

# https://www.openssl.org/docs/man1.0.2/apps/dgst.html

set -eux

cd $(dirname $0)

typeset -ra mds=(
	md4
	md5
	rmd160
	sha1
	sha224
	sha256
	sha384
	sha512
)

typeset -ra lens=(
    11
    83
    241
    512
    617
    1283
    2003
    2048
    7919
    8192
)

function gensig() {
    local len=$1
    d=${alg}_${bits}.pem
    e=${alg}_${bits}.pub.pem
    f=${alg}_${bits}_${md}_${len}.sig
    if [[ -f ${f} ]] ; then
	touch ${f}
    else
	if ! ( rm -f ${f}.b64;
	       openssl dgst -${md} -sign ../keys/${d} -out ${f} \
		       ../data/${len} && \
	       openssl dgst -${md} -verify ../keys/${e} -signature ${f} \
		       ../data/${len}
	     ) ; then
	    rm -f ${f}
	    return 1
	fi
    fi
    if [[ -f ${f}.b64 ]] ; then
	touch ${f}.b64
    else
	base64 ${f} >${f}.b64
    fi
}

function genvtc {
    f=../${alg}_${bits}_${md}_${l1}.vtc
    half=$((l1 / 2))

    if [[ -f ${f} ]] ; then
	touch ${f}
    else
	sed <../vmod_crypto.tpl >${f} \
	    -e "s:§{ALG}:${alg}:g" \
	    -e "s:§{BITS}:${bits}:g" \
	    -e "s:§{MD}:${md}:g" \
	    -e "s:§{LEN}:${l1}:g" \
	    -e "s:§{HALF}:${half}:g"
    fi
}
for l1 in ${lens[@]} ; do
    for md in ${mds[@]} ; do
	alg=RSA
	for bits in 512 1024 2048 3072 4096 7680 15360 ; do
	    if gensig ${l1} && gensig ${l1}_$((l1 / 2)) ; then
		genvtc
	    fi
	done
	alg=DSA
	for bits in 512 1024 2048 ; do
	    if gensig ${l1} && gensig ${l1}_$((l1 / 2)) ; then
		genvtc
	    fi
	done
    done
done
