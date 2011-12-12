#ifndef GCRYPT_INITH
#define GCRYPT_INITH

#include <errno.h>
#include <stdexcept>
#include <gcrypt.h>

extern "C" 
{
GCRY_THREAD_OPTION_PTHREAD_IMPL;
}

namespace gcrypt
{

inline void init(int secmem) throw(std::runtime_error)
{
gcry_error_t err;
/* Enabl pthread support */
err = gcry_control( GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread );
if ( 0 != err )
    {
    throw std::runtime_error( "libgcrypt set threads support" );
    }
/* Version check should be the very first call because it
 * makes sure that important subsystems are intialized. */
if ( !gcry_check_version( GCRYPT_VERSION ) )
    {
    throw std::runtime_error( "libgcrypt version mismatch" );
    }
/* Allocate a pool of 16k secure memory.  This make the secure memory
 *           available and also drops privileges where needed.  */
err = gcry_control( GCRYCTL_INIT_SECMEM, secmem, 0 );
if ( 0 != err )
    {
    throw std::runtime_error( "libgcrypt init secure memory" );
    }
/* ... If required, other initialization goes here.
 * Tell Libgcrypt that initialization has completed. */
err = gcry_control( GCRYCTL_INITIALIZATION_FINISHED, 0 );
if ( 0 != err )
    {
    throw std::runtime_error( "libgcrypt initialization" );
    }
}

} //namespace gcrypt

#endif

