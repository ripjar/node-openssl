#include <node_api.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include <string.h>

static napi_value
rsa_priv_key (napi_env env, napi_callback_info info)
{
  size_t argc = 1, size;
  napi_value argv[argc];
  char buf[16 * 1024];
  napi_status status = napi_ok;

  RSA* private_key;
  BIO *bio;
  char *n_hex, *e_hex, *d_hex, *p_hex, *q_hex, *dmp1_hex, *dmq1_hex, *iqmp_hex;
  napi_value n_val, e_val, d_val, p_val, q_val, dmp1_val, dmq1_val, iqmp_val;
  napi_value obj;

  if (napi_get_cb_info (env, info, &argc, argv, NULL, NULL) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse arguments");
      return NULL;
    }

  if (argc < 1)
    {
      napi_throw_error (env, NULL, "This function requires one argument");
      return NULL;
    }

  if (napi_get_value_string_utf8 (env, argv[0], buf,
				  sizeof (buf), &size) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse string");
      return NULL;
    }

  bio = BIO_new_mem_buf (buf, size);
  private_key = PEM_read_bio_RSAPrivateKey (bio, 0, 0, 0);

  n_hex = BN_bn2hex (private_key->n);
  e_hex = BN_bn2hex (private_key->e);
  d_hex = BN_bn2hex (private_key->d);
  p_hex = BN_bn2hex (private_key->p);
  q_hex = BN_bn2hex (private_key->q);
  dmp1_hex = BN_bn2hex (private_key->dmp1);
  dmq1_hex = BN_bn2hex (private_key->dmq1);
  iqmp_hex = BN_bn2hex (private_key->iqmp);

  BIO_free (bio);
  RSA_free (private_key);

  status |= napi_create_string_utf8 (env, n_hex, strlen (n_hex), &n_val);
  status |= napi_create_string_utf8 (env, e_hex, strlen (e_hex), &e_val);
  status |= napi_create_string_utf8 (env, d_hex, strlen (d_hex), &d_val);
  status |= napi_create_string_utf8 (env, p_hex, strlen (p_hex), &p_val);
  status |= napi_create_string_utf8 (env, q_hex, strlen (q_hex), &q_val);
  status |= napi_create_string_utf8 (env, dmp1_hex, strlen (dmp1_hex), &dmp1_val);
  status |= napi_create_string_utf8 (env, dmq1_hex, strlen (dmq1_hex), &dmq1_val);
  status |= napi_create_string_utf8 (env, iqmp_hex, strlen (iqmp_hex), &iqmp_val);
  status |= napi_create_object (env, &obj);

  free (n_hex);
  free (e_hex);
  free (d_hex);
  free (p_hex);
  free (q_hex);
  free (dmp1_hex);
  free (dmq1_hex);
  free (iqmp_hex);

  if (status != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to create return object");
      return NULL;
    }

  status |= napi_set_named_property (env, obj, "n", n_val);
  status |= napi_set_named_property (env, obj, "e", e_val);
  status |= napi_set_named_property (env, obj, "d", d_val);
  status |= napi_set_named_property (env, obj, "p", p_val);
  status |= napi_set_named_property (env, obj, "q", q_val);
  status |= napi_set_named_property (env, obj, "dmp1", dmp1_val);
  status |= napi_set_named_property (env, obj, "dmq1", dmq1_val);
  status |= napi_set_named_property (env, obj, "iqmp", iqmp_val);

  if (status != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to assign properties to object");
      return NULL;
    }

  return obj;
}

static napi_value
init(napi_env env, napi_value exports) {
  napi_status status;
  napi_value fn;

  status = napi_create_function(env, NULL, 0, rsa_priv_key, NULL, &fn);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to wrap native function");
  }

  status = napi_set_named_property(env, exports, "RSAPrivateKey", fn);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to populate exports");
  }

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)