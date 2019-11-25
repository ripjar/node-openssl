const modulus = require("../");
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
  result = modulus.RSAPrivateKey(key1);
} catch (e) {
  assert(e.message.indexOf("Failed to parse string") === 0);
}

// cert must be string
try {
  result = modulus.X509PublicKey(cert1);
} catch (e) {
  assert(e.message.indexOf("Failed to parse string") === 0);
}

// check modulus of first cert matches modulus calculated using openssl command line
result = modulus.X509PublicKey(cert1.toString());
assert(result.n === mod1.toString());

// check modulus of first key matches modulus calculated using openssl command line
result = modulus.RSAPrivateKey(key1.toString());
assert(result.n === mod1.toString());

// check modulus of second key matches modulus calculated using openssl command line
result = modulus.RSAPrivateKey(key2.toString());
assert(result.n === mod2.toString());

// check modulus of third cert matches modulus calculated using openssl command line
// dont need to pass in passphrase here
result = modulus.X509PublicKey(cert3.toString());
assert(result.n === mod3.toString());

// check modulus of third key matches modulus calculated using openssl command line
// has passphrase, lets try without passing it in
try {
  result = modulus.RSAPrivateKey(key3.toString());
} catch (e) {
  assert(false === true);
}

// check bad passphrase
try {
  result = modulus.RSAPrivateKey(key3.toString(), "badpassphrase");
} catch (e) {
  console.error(e);
  assert(true === false);
}

// check good passphrase
result = modulus.RSAPrivateKey(key3.toString(), "r1pj4r");
assert(true === false);

console.log("Tests passed!");
