var azn = azn || {};
azn.jws = (function() {
	return {
		verify: function (x,jws){
			var alg = {};
			jws = jws.split(".");
			var sig = jws[2];
			sig = azn.b64url.decode(sig);
			var data = jws[0] + "." + jws[1];
			data = (new TextEncoder()).encode(data);
			var header = JSON.parse(atob(jws[0]));
			if(header.alg == "RS256"){
				alg.name = "RSASSA-PKCS1-v1_5";
				alg.hash = "SHA-256";
			} else if(header.alg == "RS384"){
				alg.name = "RSASSA-PKCS1-v1_5";
				alg.hash = "SHA-384";
			} else if(header.alg == "RS512"){
				alg.name = "RSASSA-PKCS1-v1_5";
				alg.hash = "SHA-512";
			} else if(header.alg == "HS256"){
				alg.name = "HMAC";
				alg.hash = "SHA-256";
			} else if(header.alg == "HS384"){
				alg.name = "HMAC";
				alg.hash = "SHA-384";
			} else if(header.alg == "HS512"){
				alg.name = "HMAC";
				alg.hash = "SHA-512";
			} else {
				throw new Error("unsupported signature algorithm");
			}
			if(alg.name == "RSASSA-PKCS1-v1_5"){
			x = JSON.parse(x);
			x = { e: x.e,n: x.n,kty: x.kty };//filter unnecessary value
			return crypto.subtle.importKey("jwk",
				x,
				alg,
				true,
				["verify"]
				).then(function(key){
					return crypto.subtle.verify(alg.name,key,sig,data);
				});
			} else if (alg.name == "HMAC") {
				x = (new TextEncoder()).encode(x);
				return crypto.subtle.importKey("raw",
						x,
						alg,
						true,
						["verify"]
						).then(function(key){
							return crypto.subtle.verify(alg.name,key,sig,data);
						});
			}
		},
	};
})();
