"use strict";
var azn = azn || {};
azn.jws = (function() {
	function parsealg(input){
		var output = {};
			if(input == "RS256"){
				output.name = "RSASSA-PKCS1-v1_5";
				output.hash = "SHA-256";
			} else if(input == "RS384"){
				output.name = "RSASSA-PKCS1-v1_5";
				output.hash = "SHA-384";
			} else if(input == "RS512"){
				output.name = "RSASSA-PKCS1-v1_5";
				output.hash = "SHA-512";
			} else if(input == "HS256"){
				output.name = "HMAC";
				output.hash = "SHA-256";
			} else if(input == "HS384"){
				output.name = "HMAC";
				output.hash = "SHA-384";
			} else if(input == "HS512"){
				output.name = "HMAC";
				output.hash = "SHA-512";
			} else {
				throw new Error("unsupported signature algorithm");
			}
			return output;
	}
	return {
		verify: function (x,jws){
			jws = jws.split(".");
			var sig = jws[2];
			sig = azn.b64url.decode(sig);
			var data = jws[0] + "." + jws[1];
			data = (new TextEncoder()).encode(data);
			var header = JSON.parse(atob(jws[0]));
			var alg = parsealg(header.alg);
			if(alg.name == "RSASSA-PKCS1-v1_5"){
				if(typeof x == "string" || x.toString().slice(8,-1) == "Object") {
					if(typeof x == "string"){
						x = JSON.parse(x);
					}
					x = { e: x.e,n: x.n,kty: x.kty };//filter unnecessary value
					return crypto.subtle.importKey("jwk",
							x,
							alg,
							true,
							["verify"]
							).then(function(key){
								return crypto.subtle.verify(alg.name,key,sig,data);
							});
				} else if (x.toString().slice(8,-1) == "CryptoKey") {
					return crypto.subtle.verify(alg.name,x,sig,data);
				} else {
					throw new Error("invalid key for verify");
				}
			} else if (alg.name == "HMAC") {
				if(typeof x == "string"){
					x = (new TextEncoder()).encode(x);
					return crypto.subtle.importKey("raw",
							x,
							alg,
							true,
							["verify"]
							).then(function(key){
								return crypto.subtle.verify(alg.name,key,sig,data);
							});
				} else if (x.toString().slice(8,-1) == "CryptoKey") {
					return crypto.subtle.verify(alg.name,x,sig,data);
				} else {
					throw new Error("invalid key for verify");
				}

			}
		},
		sign: function(key,_alg,data){
			var alg = parsealg(_alg);
			var header = { alg: _alg };
			header = JSON.stringify(header);
			header = btoa(header).replace(/\+/g,"-").replace(/\//g,"_").replace(/=/g,"");
			data = JSON.stringify(data);
			data = btoa(data).replace(/\+/g,"-").replace(/\//g,"_").replace(/=/g,"");
			var signinput = header + "." + data;
			var signinputstr = signinput;
			signinput = (new TextEncoder()).encode(signinput);
			if(alg.name == "RSASSA-PKCS1-v1_5"){
				if(typeof key == "string" || key.toString().slice(8,-1) == "Object") {
					if(typeof key == "string"){
						key = JSON.parse(key);
					}
					key.alg = _alg;//TODO: autodetect alg
					return crypto.subtle.importKey("jwk",
							key,
							alg,
							false,
							["sign"]
							).then(function(key){
								return crypto.subtle.sign(alg.name,key,signinput);
							}).then(function(sign){
								return new Promise(function(resolve, reject){
									sign = new Uint8Array(sign);
									resolve(signinputstr+"."+azn.b64url.encode(sign));
								});
							});
				} else if (key.toString().slice(8,-1) == "CryptoKey") {
					return crypto.subtle.sign(alg.name,key,signinput)
						.then(function(sign){
							return new Promise(function(resolve, reject){
								sign = new Uint8Array(sign);
								resolve(signinputstr+"."+azn.b64url.encode(sign));
							});
						});
				} else {
					throw new Error("invalid key for sign");
				}
			} else if (alg.name == "HMAC") {
				if(typeof key == "string"){
				key = (new TextEncoder()).encode(key);
				return crypto.subtle.importKey("raw",
						key,
						alg,
						false,
						["sign"]
						).then(function(key){
							return crypto.subtle.sign(alg.name,key,signinput);
						}).then(function(sign){
							return new Promise(function(resolve, reject){
								sign = new Uint8Array(sign);
								resolve(signinputstr+"."+azn.b64url.encode(sign));
							});
						});
				} else if (key.toString().slice(8,-1) == "CryptoKey") {
							return crypto.subtle.sign(alg.name,key,signinput).then(function(sign){
								return new Promise(function(resolve, reject){
									sign = new Uint8Array(sign);
									resolve(signinputstr+"."+azn.b64url.encode(sign));
								});
							});
				} else {
					throw new Error("invalid key for sign");
				}
			}
		},
	};
})();
