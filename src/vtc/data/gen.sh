#!/bin/bash

set -eux

cd $(dirname $0)

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

    if [[ -f ${i} ]] ; then
	touch ${i}
    else
	dd if=/dev/zero iflag=fullblock bs=${blk} count=1 | \
	    openssl aes-128-cbc -k $i -nosalt -nopad | \
	    dd iflag=fullblock of=${i} bs=${i} count=1
    fi

    if [[ -f ${i}.b64 ]] ; then
	touch ${i}.b64
    else
	base64 ${i} >${i}.b64
    fi

    j=$((i / 2))

    if [[ -f ${i}_${j} ]] ; then
	touch ${i}_${j}
    else
	dd if=${i} iflag=fullblock of=${i}_${j} bs=${j} count=1
    fi

    if [[ -f ${i}_${j}.b64 ]] ; then
	touch ${i}_${j}.b64
    else
	base64 ${i}_${j} >${i}_${j}.b64
    fi
done
