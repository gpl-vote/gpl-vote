#ifndef CRYPT_RSAH
#define CRYPT_RSAH

#include <stddef.h>
#include <stdint.h>
#include <gcrypt.h>

#include <iostream>

#include "ext/array.h"
#include "gcrypt/hash.h"

namespace gcrypt
{
namespace rsa
{

class key_t
{
protected:
gcry_sexp_t m_key;

public:
inline  operator gcry_sexp_t& ()
    {
    return m_key;
    }

inline operator const gcry_sexp_t& () const
    {
    return m_key;
    }
};

template <size_t keysize>
class pub_t:
    public key_t
{
protected:
using key_t::m_key;

public:
typedef unsigned int    e_t;

template <class n_t>
inline      pub_t(const n_t& n, const e_t& e)
    {
    gcry_mpi_t  mpi_n;
    gcry_error_t err;
    err = gcry_mpi_scan( &mpi_n, GCRYMPI_FMT_USG, &n, keysize/8, NULL );
    if ( 0 != err )
        {
        throw;
        }
    err = gcry_sexp_build( &m_key, NULL, "(public-key(rsa(n%m)(e%d)))", mpi_n, e );
    if ( 0 != err )
        {
        throw;
        }
    gcry_mpi_release( mpi_n );
    }
inline      ~pub_t()
    {
    gcry_sexp_release( m_key );
    }

};

class priv_t:
    public key_t
{

};

template <class hash_t>
void fingerprint(const key_t& key, hash_t& hash)
{
gcry_sexp_t n = gcry_sexp_find_token( key, "n", 1 );
  if (!n)
    throw;

size_t datalen;
const void* data = gcry_sexp_nth_data (n, 1, &datalen);
  if (!data)
    {
      gcry_sexp_release( n );
      throw;
    }

hash::make mh;
mh.enable( hash );
mh.write( data, datalen );
mh.read( hash );

gcry_sexp_release( n );
}

} //namespace rsa
} //namespace crypt

#endif

