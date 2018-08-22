# https://www.openssl.org/docs/manmaster/man1/genpkey.html
# https://www.openssl.org/docs/manmaster/man1/pkey.html

set -eux

cd $(dirname $0)

alg=RSA
for bits in 512 1024 2048 3072 4096 7680 15360 ; do
	d=${alg}_${bits}.pem
	[[ -f ${d} ]] || \
	  openssl genpkey -algorithm ${alg} \
		  -pkeyopt rsa_keygen_bits:${bits} -out ${d}
	e=${alg}_${bits}.pub.pem
	[[ -f ${e} ]] || \
	  openssl pkey -in ${d} -pubout -out ${e}
done

alg=DSA
for bits in 512 1024 2048 ; do
	p=${alg}_${bits}.param.pem
	[[ -f ${p} ]] || \
	  openssl genpkey -genparam -algorithm ${alg} \
		  -pkeyopt dsa_paramgen_bits:${bits} -out ${p}

	d=${alg}_${bits}.pem
	[[ -f ${d} ]] || \
	  openssl genpkey -paramfile ${p} -out ${d}

	e=${alg}_${bits}.pub.pem
	[[ -f ${e} ]] || \
	  openssl pkey -in ${d} -pubout -out ${e}
done
