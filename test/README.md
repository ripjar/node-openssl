# get the modulus of a cert

cat cert1 | openssl x509 -inform PEM -modulus -noout

# get the modulus of a key

cat key1 | openssl rsa -inform PEM -modulus -noout

# get the modulus of an encrypted key 

cat 3key | openssl rsa -inform PEM -modulus -noout -passin file:3passphrase