..
.. NB:  This file is machine generated, DO NOT EDIT!
..
.. Edit vmod.vcc and run make instead
..


:tocdepth: 1

.. _vmod_crypto(3):

======================================================
VMOD crypto - Public Key hash verification for Varnish
======================================================

SYNOPSIS
========

.. parsed-literal::

  import crypto [as name] [from "path"]
  
  :ref:`crypto.key()`
  
      :ref:`xkey.use()`
  
      :ref:`xkey.pem_pubkey()`
  
      :ref:`xkey.rsa()`
  
  :ref:`crypto.verifier()`
  
      :ref:`xverifier.update()`
  
      :ref:`xverifier.update_blob()`
  
      :ref:`xverifier.reset()`
  
      :ref:`xverifier.valid()`
  

DESCRIPTION
===========

This vmod provides VCL access to cryptographic functions from the
_crypt_ library.

Example
    ::

	import crypto;

	sub vcl_init {
	    new v = crypto.verifier(sha256, {"
	-----BEGIN PUBLIC KEY-----
	...
	-----END PUBLIC KEY-----
	"});
	}
	sub vcl_deliver {
	    if (! v.update("data")) {
		return (synth(500, "vmod_crypto error"));
	    }
	    if (! v.valid(blob.encode(BASE64URLNOPAD, "base64"))) {
		return (synth(400, "invalid signature"));
	    }
	}
} -start

.. _crypto.key():

new xkey = crypto.key()
-----------------------

Create a generic key object. The algorithm gets defined by the method
called upon it.

Any methods on `crypto.key()`_ may only be used in ``sub vcl_init {}``.

.. _xkey.use():

BLOB xkey.use()
---------------

Wrap the key in a blob to be passed to `crypto.verifier()`_

.. _xkey.pem_pubkey():

VOID xkey.pem_pubkey(STRING)
----------------------------

Create a key from the PEM-encoded public key.

The cryptographic method to be used and the key length are
automatically determined from _pem_. Typically supported methods
comprise RSA and DSA.

Any error is fatal to vcl initialization.

.. _xkey.rsa():

VOID xkey.rsa(BLOB n, BLOB e, [BLOB d])
---------------------------------------

Create an RSA key from the parameters n, e, and optionally d.

Any error is fatal to vcl initialization.

.. _crypto.verifier():

new xverifier = crypto.verifier(ENUM digest, [STRING pem], [BLOB key])
----------------------------------------------------------------------

::

   new xverifier = crypto.verifier(
      ENUM {md_null, md4, md5, sha1, sha224, sha256, sha384, sha512, ripemd160, rmd160, whirlpool} digest,
      [STRING pem],
      [BLOB key]
   )

Create an object to verify signatures created using _digest_ and
_key_.

The _key_ argument should be a call to `xkey.use()`_ on the respective
`crypto.key()`_ object.

Alternatively to _key_, the _pem_ argument may be used to pass a
PEM-encoded public key specification. Use of the _pem_ argument is
deprecated.

Either the _key_ or the _pem_ argument must be given.

.. _xverifier.update():

BOOL xverifier.update(STRING)
-----------------------------

Add strings to the data to be verfied with the verifier object.

.. _xverifier.update_blob():

BOOL xverifier.update_blob(BLOB)
--------------------------------

Add a blob to the data to be verified with the verifier object.

.. _xverifier.reset():

BOOL xverifier.reset()
----------------------

Reset the verfication state as if previous calls to the update methods
had not happened.

.. _xverifier.valid():

BOOL xverifier.valid(BLOB signature)
------------------------------------

Check if _signature_ is a valid signature for the _verifier_ object
given the previous updates.

Note that after calling .valid(), .update can be called again to add
additional data, which can then be validated against a (different)
signature using another call to .valid().


SEE ALSO
========vcl\(7),varnishd\(1)

COPYRIGHT
=========

::

  Copyright 2018 UPLEX Nils Goroll Systemoptimierung
  All rights reserved
 
  Author: Nils Goroll <nils.goroll@uplex.de>
 
  See LICENSE
 
