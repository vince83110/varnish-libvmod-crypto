#include "config.h"

#include <cache/cache.h>
#include <vdef.h>
#include <vrt.h>
#include <vcl.h>

#include "vcc_crypto_if.h"

VCL_STRING __match_proto__(td_crypto_hello)
vmod_hello(VRT_CTX)
{

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	return ("vmod-crypto");
}
