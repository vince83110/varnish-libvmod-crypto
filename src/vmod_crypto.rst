..
.. NB:  This file is machine generated, DO NOT EDIT!
..
.. Edit vmod.vcc and run make instead
..

.. role:: ref(emphasis)

.. _vmod_crypto(3):

===========
vmod_crypto
===========

---------------------
Varnish crypto Module
---------------------

:Manual section: 3

SYNOPSIS
========


::

   import crypto [from "path"] ;
   
   new xverifier = crypto.verifier(ENUM digest, STRING key)
  
      BOOL xverifier.update(STRING)
  
      BOOL xverifier.update_blob(BLOB)
  
      BOOL xverifier.reset()
  
      BOOL xverifier.valid(BLOB signature)
  


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

CONTENTS
========

* :ref:`obj_verifier`
* :ref:`func_verifier.reset`
* :ref:`func_verifier.update`
* :ref:`func_verifier.update_blob`
* :ref:`func_verifier.valid`


.. _obj_verifier:

new xverifier = crypto.verifier(ENUM digest, STRING key)
--------------------------------------------------------

::

   new xverifier = crypto.verifier(
      ENUM {md_null, md4, md5, sha1, sha224, sha256, sha384, sha512, ripemd160, rmd160, whirlpool} digest,
      STRING key
   )

Create an object to verify signatures created using _digest_ and
_key_.

The _key_ argument is a PEM-encoded public key specification.

The cryptographic method to be used and the key length are
automatically determined from _key_. Typically supported methods
comprise RSA and DSA.

.. _func_verifier.update:

BOOL xverifier.update(STRING)
-----------------------------

Add strings to the data to be verfied with the verifier object.


.. _func_verifier.update_blob:

BOOL xverifier.update_blob(BLOB)
--------------------------------

Add a blob to the data to be verified with the verifier object.


.. _func_verifier.reset:

BOOL xverifier.reset()
----------------------

Reset the verfication state as if previous calls to the update methods
had not happened.


.. _func_verifier.valid:

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
 
