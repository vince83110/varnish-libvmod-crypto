AM_CFLAGS = $(VARNISHAPI_CFLAGS)

# Modules

vmod_LTLIBRARIES = \
	libvmod_crypto.la

libvmod_crypto_la_LDFLAGS = $(VMOD_LDFLAGS)
libvmod_crypto_la_SOURCES = vmod_crypto.c
nodist_libvmod_crypto_la_SOURCES = \
	vcc_crypto_if.c \
	vcc_crypto_if.h

@BUILD_VMOD_CRYPTO@

# Test suite

AM_TESTS_ENVIRONMENT = \
	PATH="$(abs_builddir):$(VARNISH_TEST_PATH):$(PATH)" \
	LD_LIBRARY_PATH="$(VARNISH_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
VTC_LOG_COMPILER = varnishtest -v
AM_VTC_LOG_FLAGS = \
	-p vcl_path="$(abs_top_srcdir)/vcl" \
	-p vmod_path="$(abs_builddir)/.libs:$(vmoddir)"

TESTS = \
	vtc/vmod_crypto.vtc

# Documentation

dist_doc_DATA = \
	vmod_crypto.vcc \
	$(TESTS)

dist_man_MANS = \
	vmod_crypto.3


.rst.1:
	$(AM_V_GEN) $(RST2MAN) $< $@
