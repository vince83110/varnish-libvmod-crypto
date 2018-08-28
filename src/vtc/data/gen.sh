#!/bin/bash

set -eux

cd $(dirname $0)

# size key iv
typeset -ar sz=(
    11
    4FC82B26AECB47D2868C4EFBE3581732
    A3E7CBCC6C2EFB32062C08170A05EEB8

    83
    BBB965AB0C80D6538CF2184BABAD2A56
    4A010376712012BD07B0AF92DCD3097D

    241
    749FC650CACB0F06547520D53C31505C
    8156E0A3BE07073EDDB2EF3AD9E383BA

    512
    94F8607915DFF25F013E45FC0642FB98
    30B0FB25AB0AB46D477EAF1061DEF379

    617
    85EA151B8C5B5AB0D3349100E441BD4B
    8DC20740D429C16C3B85B77066386E75

    1283
    C47AFFB712A521D4FDD0D9AF6CB0E4D4
    55EB9A241716A6456C4F093480F56DF0

    2003
    77459B9B941BCB4714D0C121313C900E
    CF30541D158EB2B9B178CDB8ECA6457E

    2048
    BFA0EC8BDF2946547879D50A68687EA3
    2E2FA628DB187357415858B633D194D9

    7919
    A8054EF7FC192135DD8DC07D4D9832C9
    FA9BD39D01BA383E29E378F5CC72CACD

    8192
    864A936A35324151E1C79C44A2E903FF
    2497F52FA892282D340585F493C637F0
)

for ((a = 0; a < ${#sz[@]}; a+=3)) ; do
    typeset -i i=${sz[${a}]}
    typeset key=${sz[a+1]}
    typeset iv=${sz[a+2]}
    typeset blk=$(((i + 16) & ~15))

    if [[ -f ${i} ]] ; then
	touch ${i}
    else
	dd if=/dev/zero iflag=fullblock bs=${blk} count=1 | \
	    openssl aes-128-cbc -K ${key} -iv ${iv} -nopad | \
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
