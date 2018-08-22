#!/bin/bash

set -eux

typeset -air sz=(
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

for i in ${sz[@]} ; do
    blk=$(((i + 16) & ~15))
    [[ -f ${i} ]] || \
	dd if=/dev/zero bs=${blk} count=1 | \
	    openssl aes-128-cbc -k $i -nosalt -nopad | \
	    dd of=${i} bs=${i} count=1
    [[ -f ${i}.b64 ]] || \
	base64 ${i} >${i}.b64
    j=$((i / 2))
    [[ -f ${i}_${j} ]] || \
	dd if=${i} of=${i}_${j} bs=${j} count=1
    [[ -f ${i}_${j}.b64 ]] || \
	base64 ${i}_${j} >${i}_${j}.b64
done
