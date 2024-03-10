const lib = require("../");
const fs = require("fs");
const assert = require("assert");

// first key + cert without a passphrase
const cert1 = fs.readFileSync("1cert");
const key1 = fs.readFileSync("1key");
const mod1 = fs.readFileSync("1mod");

// second key
const key2 = fs.readFileSync("2key");
const mod2 = fs.readFileSync("2mod");

// third key with passphrase and cert
const cert3 = fs.readFileSync("3cert");
const key3 = fs.readFileSync("3key");
const passphrase3 = fs.readFileSync("3passphrase");
const mod3 = fs.readFileSync("3mod");

let result;

// key must be string
try {
  result = lib.RSAPrivateKey(key1);
} catch (e) {
  assert(e.message.indexOf("Failed to parse string") === 0);
}

// cert must be string
try {
  result = lib.X509PublicKey(cert1);
} catch (e) {
  assert(e.message.indexOf("Failed to parse string") === 0);
}

// check modulus of first cert matches modulus calculated using openssl command line
result = lib.X509PublicKey(cert1.toString());
assert(result.n === mod1.toString());

// check modulus of first key matches modulus calculated using openssl command line
result = lib.RSAPrivateKey(key1.toString());
assert(result.n === mod1.toString());

// check modulus of second key matches modulus calculated using openssl command line
result = lib.RSAPrivateKey(key2.toString());
assert(result.n === mod2.toString());

// check modulus of third cert matches modulus calculated using openssl command line
// dont need to pass in passphrase here
result = lib.X509PublicKey(cert3.toString());
assert(result.n === mod3.toString());

// check modulus of third key matches modulus calculated using openssl command line
// has passphrase, lets try without passing it in
try {
  result = lib.RSAPrivateKey(key3.toString());
} catch (e) {
  assert(e.message.indexOf("Failed to read private key") === 0);
}

// check bad passphrase
try {
  result = lib.RSAPrivateKey(key3.toString(), "badpassphrase");
} catch (e) {
  assert(e.message.indexOf("Failed to read private key") === 0);
}

// check good passphrase
result = lib.RSAPrivateKey(key3.toString(), "r1pj4r");
assert(result.n === mod3.toString());

console.log("Tests passed!");
