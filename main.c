/**
 * Copyright (C) 2019 Ripjar Limited
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 * or see see <https://www.gnu.org/licenses/>.
 */

#include <node_api.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#include <string.h>

static napi_value
x509_cert_pub_key (napi_env env, napi_callback_info info)
{
  size_t argc = 1, size;
  napi_value argv[argc];
  char *buf;
  napi_status status = napi_ok;

  BIO *bio;
  X509 *x509;
  EVP_PKEY *evp_pubkey;
  RSA *public_key;
  char *n_hex, *e_hex;
  napi_value n_val, e_val;
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
  if (napi_get_value_string_utf8 (env, argv[0], NULL, 0, &size) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse string");
      return NULL;
    }
  if ((buf = malloc (++size)) == NULL)
    {
      napi_throw_error (env, NULL, "Failed to allocate memory");
      return NULL;
    }
  if (napi_get_value_string_utf8 (env, argv[0], buf,
				  size, &size) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse string");
      free (buf);
      return NULL;
    }

  if ((bio = BIO_new_mem_buf (buf, size)) == NULL)
    {
      napi_throw_error (env, NULL, "Failed to copy cert into buffer");
      free (buf);
      return NULL;
    }
  if ((x509 = PEM_read_bio_X509 (bio, 0, 0, 0)) == NULL)
    {
      napi_throw_error (env, NULL, "Failed to read x509 from bio");
      BIO_free (bio);
      free (buf);
      return NULL;
    }
  if ((evp_pubkey = X509_get_pubkey (x509)) == NULL)
    {
      napi_throw_error (env, NULL, "Failed to extract public key");
      X509_free (x509);
      BIO_free (bio);
      free (buf);
      return NULL;
    }
  if ((public_key = EVP_PKEY_get1_RSA (evp_pubkey)) == NULL)
    {
      napi_throw_error (env, NULL, "Faild to extract rsa key");
      EVP_PKEY_free (evp_pubkey);
      X509_free (x509);
      BIO_free (bio);
      free (buf);
      return NULL;
    }

  if (public_key->n == NULL || public_key->e == NULL)
    {
      napi_throw_error (env, NULL, "One or more required values in the "
                        "public key is null");
      RSA_free (public_key);
      EVP_PKEY_free (evp_pubkey);
      X509_free (x509);
      BIO_free (bio);
      free (buf);
      return NULL;
    }

  n_hex = BN_bn2hex (public_key->n);
  e_hex = BN_bn2hex (public_key->e);

  RSA_free (public_key);
  EVP_PKEY_free (evp_pubkey);
  X509_free (x509);
  BIO_free (bio);
  free (buf);

  status |= napi_create_string_utf8 (env, n_hex, strlen (n_hex), &n_val);
  status |= napi_create_string_utf8 (env, e_hex, strlen (e_hex), &e_val);
  status |= napi_create_object (env, &obj);

  free (n_hex);
  free (e_hex);

  if (status != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to create return object");
      return NULL;
    }

  status |= napi_set_named_property (env, obj, "n", n_val);
  status |= napi_set_named_property (env, obj, "e", e_val);

  if (status != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to assign properties to object");
      return NULL;
    }

  return obj;
}

static napi_value
rsa_priv_key (napi_env env, napi_callback_info info)
{
  size_t argc = 1, size;
  napi_value argv[argc];
  char *buf;
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
  if (napi_get_value_string_utf8 (env, argv[0], NULL, 0, &size) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse string");
      return NULL;
    }
  if ((buf = malloc (++size)) == NULL)
    {
      napi_throw_error (env, NULL, "Failed to allocate memory");
      return NULL;
    }
  if (napi_get_value_string_utf8 (env, argv[0], buf,
				  size, &size) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse string");
      free (buf);
      return NULL;
    }
  if ((bio = BIO_new_mem_buf (buf, size)) == NULL)
    {
      napi_throw_error (env, NULL, "Failed to copy key into buffer");
      free (buf);
      return NULL;
    }
  if ((private_key = PEM_read_bio_RSAPrivateKey (bio, 0, 0, 0)) == NULL)
    {
      napi_throw_error (env, NULL, "Failed to read key from bio");
      BIO_free (bio);
      free (buf);
      return NULL;
    }

  if (private_key->n == NULL || private_key->e == NULL ||
      private_key->d == NULL || private_key->p == NULL ||
      private_key->q == NULL || private_key->dmp1 == NULL ||
      private_key->dmq1 == NULL || private_key->iqmp == NULL)
    {
      napi_throw_error (env, NULL, "One or more required values in the "
                        "private key is null");
      RSA_free (private_key);
      BIO_free (bio);
      free (buf);
      return NULL;
    }

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
  free (buf);

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
init (napi_env env, napi_value exports) {
  napi_value rsa_fn, x509_fn;

  if (napi_create_function (env, NULL, 0, rsa_priv_key,
                            NULL, &rsa_fn) != napi_ok)
    napi_throw_error (env, NULL, "Unable to wrap native rsa function");
  if (napi_create_function (env, NULL, 0, x509_cert_pub_key,
                            NULL, &x509_fn) != napi_ok)
    napi_throw_error (env, NULL, "Unable to wrap native x509 function");

  if (napi_set_named_property (env, exports, "RSAPrivateKey",
                               rsa_fn) != napi_ok)
    napi_throw_error (env, NULL, "Unable to populate exports with rsa");
  if (napi_set_named_property (env, exports, "X509PublicKey",
                               x509_fn) != napi_ok)
    napi_throw_error (env, NULL, "Unable to populate exports with x509");

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
