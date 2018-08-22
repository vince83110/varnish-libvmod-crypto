enum md_e {
	_MD_E_INVALID = 0,
#define VMODENUM(x) x,
#include "tbl_md.h"
	_MD_E_MAX
};

void md_init (void);
const EVP_MD *md_evp(enum md_e);
enum md_e md_parse(VCL_ENUM);
