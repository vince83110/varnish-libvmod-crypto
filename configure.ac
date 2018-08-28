AC_PREREQ([2.68])
AC_INIT([libvmod-crypto], [0.1])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADER([config.h])

AM_INIT_AUTOMAKE([1.12 -Wall -Werror foreign parallel-tests])
AM_SILENT_RULES([yes])
AM_PROG_AR

LT_PREREQ([2.2.6])
LT_INIT([dlopen disable-static])

AC_ARG_WITH([rst2man],
	AS_HELP_STRING(
		[--with-rst2man=PATH],
		[Location of rst2man (auto)]),
	[RST2MAN="$withval"],
	AC_CHECK_PROGS(RST2MAN, [rst2man rst2man.py], []))

AC_CHECK_LIB([crypto], [PEM_read_RSA_PUBKEY])
test "$ac_cv_lib_crypto_PEM_read_RSA_PUBKEY" == "no" && \
AC_MSG_ERROR([Need libcrypto.])

AC_CHECK_PROGS(BASE64, [base64], [no])
test "$BASE64" == "no" && AC_MSG_ERROR([Required program 'base64' not found.])

AC_CHECK_PROGS(OPENSSL, [openssl], [no])
test "$OPENSSL" == "no" && AC_MSG_ERROR([Required program 'openssl' not found.])

AC_CHECK_PROGS(SED, [sed], [no])
test "$SED" == "no" && AC_MSG_ERROR([Required program 'sed' not found.])

AC_CHECK_PROGS(DD, [dd], [no])
test "$DD" == "no" && AC_MSG_ERROR([Required program 'dd' not found.])

AC_CHECK_PROGS(BASH, [bash], [no])
test "$BASH" == "no" && AC_MSG_ERROR([Required program 'bash' not found.])


VARNISH_PREREQ([5.2.0])
VARNISH_VMODS([crypto])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])

AC_OUTPUT

AS_ECHO("
	==== $PACKAGE_STRING ====

	varnish:      $VARNISH_VERSION
	prefix:       $prefix
	vmoddir:      $vmoddir
	vcldir:       $vcldir
	pkgvcldir:    $pkgvcldir

	compiler:     $CC
	cflags:       $CFLAGS
	ldflags:      $LDFLAGS
")
