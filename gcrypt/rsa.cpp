#include "rsa.h"

namespace gcrypt
{
namespace rsa
{

void fingerprint(const gcry_sexp_t& key, int algo, void* dst, size_t size) throw(std::runtime_error,std::invalid_argument)
{
gcry_sexp_t n = gcry_sexp_find_token( key, "n", 1 );
if ( NULL == n )
    {
    throw std::invalid_argument( "key don't contain a 'n' number" );
    }

size_t datalen;
const void* data = gcry_sexp_nth_data( n, 1, &datalen );
if ( NULL == data )
    {
    gcry_sexp_release( n );
    throw std::invalid_argument( "key don't contain a 'n' number value" );
    }

try
    {
    hash::make mh;
    mh.enable( algo );
    mh.write( data, datalen );
    mh.read( algo, dst, size );
    }
catch (std::runtime_error& e)
    {
    gcry_sexp_release( n );
    throw e;
    }
catch (std::invalid_argument& e)
    {
    gcry_sexp_release( n );
    throw e;
    }
gcry_sexp_release( n );
}

} //namespace rsa
} //namespace gcrypt

