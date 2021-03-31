varnishtest "test vmod-crypto §{ALG} §{BITS} §{MD} §{LEN} §{HALF}"

server s1 {
	rxreq
	txresp
} -start

varnish v1 -vcl+backend {
	import crypto;
	import blob;
	import std;

	sub vcl_init {
	    new v = crypto.verifier(§{MD},
		    std.fileread("${vtc_dir}/keys/§{ALG}_§{BITS}.pub.pem"));
	    new s = crypto.signer(§{MD},
		    std.fileread("${vtc_dir}/keys/§{ALG}_§{BITS}.pem"));
	    new sig = blob.blob(
		BASE64, encoded=regsuball(
		    std.fileread(
			"${vtc_dir}/sigs/§{ALG}_§{BITS}_§{MD}_§{LEN}.sig.b64"),
		    "\s", ""));
	    new sig_part = blob.blob(
		BASE64, encoded=regsuball(
		    std.fileread(
			"${vtc_dir}/sigs/§{ALG}_§{BITS}_§{MD}_§{LEN}_§{HALF}.sig.b64"),
		    "\s", ""));
	    new data = blob.blob(
		BASE64, encoded=regsuball(
		    std.fileread("${vtc_dir}/data/§{LEN}.b64"),
		    "\s", ""));
	}

	sub vcl_deliver {
	    # verify first half
	    set resp.http.up1a = v.update_blob(
	      blob.sub(data.get(), §{HALF}B));
	    if (v.valid(sig_part.get())) {
		set resp.http.ok1a = "true";
	    } else {
		return (synth(400, "verify 1st half failed"));
	    }
	    # sign first half
	    set resp.http.sup1a = s.update_blob(
	      blob.sub(data.get(), §{HALF}B));
	    if (blob.equal(s.final(), sig_part.get())) {
		set resp.http.sok1a = "true";
	    } else if (v.valid(s.final())) {
		# DSA has entropy in the signature
		set resp.http.sok1a = "true";
	    } else {
		return (synth(400, "own sig 1st half does not match/verify"));
	    }
	    # update and check full sig
	    set resp.http.up1b = v.update_blob(
	      blob.sub(data.get(), §{LEN}B - §{HALF}B, §{HALF}B));
	    if (v.valid(sig.get())) {
		set resp.http.ok1b = "true";
	    } else {
		return (synth(400, "verify 2nd half failed"));
	    }
	    # update and sign full
	    set resp.http.sup1b = s.update_blob(
	      blob.sub(data.get(), §{LEN}B - §{HALF}B, §{HALF}B));
	    if (blob.equal(s.final(), sig.get())) {
		set resp.http.sok1b = "true";
	    } else if (v.valid(s.final())) {
		# DSA has entropy in the signature
		set resp.http.sok1b = "true";
	    } else {
		return (synth(400, "own sig 2nd half does not match/verify"));
	    }
	    # check full sig in one go
	    v.reset();
	    set resp.http.up = v.update_blob(data.get());
	    if (v.valid(sig.get())) {
		set resp.http.ok = "true";
	    } else {
		return (synth(400, "verify full failed"));
	    }
	}
} -start

client c0 -repeat 2 -keepalive {
	txreq
	rxresp
	expect resp.status == 200
	expect resp.http.up1a == true
	expect resp.http.up1b == true
	expect resp.http.ok1a == true
	expect resp.http.ok1b == true
	expect resp.http.up == true
	expect resp.http.ok == true
} -run
client c1 -repeat 2 -keepalive {
	txreq
	rxresp
	expect resp.status == 200
	expect resp.http.up1a == true
	expect resp.http.up1b == true
	expect resp.http.ok1a == true
	expect resp.http.ok1b == true
	expect resp.http.up == true
	expect resp.http.ok == true
} -run
client c10 -repeat 2 -keepalive {
	txreq
	rxresp
	expect resp.status == 200
	expect resp.http.up1a == true
	expect resp.http.up1b == true
	expect resp.http.ok1a == true
	expect resp.http.ok1b == true
	expect resp.http.up == true
	expect resp.http.ok == true
} -run
client c11 -repeat 2 -keepalive {
	txreq
	rxresp
	expect resp.status == 200
	expect resp.http.up1a == true
	expect resp.http.up1b == true
	expect resp.http.ok1a == true
	expect resp.http.ok1b == true
	expect resp.http.up == true
	expect resp.http.ok == true
} -run
client c110 -repeat 2 -keepalive {
	txreq
	rxresp
	expect resp.status == 200
	expect resp.http.up1a == true
	expect resp.http.up1b == true
	expect resp.http.ok1a == true
	expect resp.http.ok1b == true
	expect resp.http.up == true
	expect resp.http.ok == true
} -run
client c111 -repeat 2 -keepalive {
	txreq
	rxresp
	expect resp.status == 200
	expect resp.http.up1a == true
	expect resp.http.up1b == true
	expect resp.http.ok1a == true
	expect resp.http.ok1b == true
	expect resp.http.up == true
	expect resp.http.ok == true
} -run
client c1010 -repeat 2 -keepalive {
	txreq
	rxresp
	expect resp.status == 200
	expect resp.http.up1a == true
	expect resp.http.up1b == true
	expect resp.http.ok1a == true
	expect resp.http.ok1b == true
	expect resp.http.up == true
	expect resp.http.ok == true
} -run
client c1011 -repeat 2 -keepalive {
	txreq
	rxresp
	expect resp.status == 200
	expect resp.http.up1a == true
	expect resp.http.up1b == true
	expect resp.http.ok1a == true
	expect resp.http.ok1b == true
	expect resp.http.up == true
	expect resp.http.ok == true
} -run
