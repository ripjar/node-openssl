#include <node_api.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

static napi_value
rsa_priv_modulus (napi_env env, napi_callback_info info)
{
  size_t argc = 1, size;
  napi_value argv[argc];
  char buf[16 * 1024];

  RSA* private_key;
  BIO *bio;
  const char *hex;
  napi_value hex_value;

  if (napi_get_cb_info (env, info, &argc, argv, NULL, NULL) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse arguments");
      return 0;
    }

  if (argc < 1)
    {
      napi_throw_error (env, NULL, "This function requires one argument");
      return 0;
    }

  if (napi_get_value_string_utf8 (env, argv[0], buf,
				  sizeof (buf), &size) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse string");
      return 0;
    }

  //fwrite (buf, 1, size, stdout);

  bio = BIO_new_mem_buf (buf, size);
  private_key = PEM_read_bio_RSAPrivateKey (bio, 0, 0, 0);
  //RSA_print_fp (stdout, private_key, 0);

  hex = BN_bn2hex (private_key->n);

  BIO_free (bio);
  RSA_free (private_key);

  //printf ("modulus %s\n", hex);

  if (napi_create_string_utf8 (env, hex, strlen (hex), &hex_value) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to create string from modulus");
      return 0;
    }

  free (hex);

  return hex_value;
}

napi_value Init(napi_env env, napi_value exports) {
  napi_status status;
  napi_value fn;

  status = napi_create_function(env, NULL, 0, rsa_priv_modulus, NULL, &fn);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to wrap native function");
  }

  status = napi_set_named_property(env, exports, "RSAPrivateKeyModulus", fn);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to populate exports");
  }

  return exports;
}



NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
