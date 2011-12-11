#include <stdio.h>

#include "gcrypt/hash.h"
#include "gcrypt/rsa.h"

template <class T>
void print(const T* begin, const T* end)
{
typedef const unsigned char cuc;
print( reinterpret_cast<cuc*>( begin ), reinterpret_cast<cuc*>( end ) );
}

template <>
void print<unsigned char>(const unsigned char* b, const unsigned char* e)
{
for (; b != e; ++b)
    {
    fprintf( stdout, "%02x", *b );
    }
fprintf( stdout, "\n" );
}

int main()
{
/* Version check should be the very first call because it
 * makes sure that important subsystems are intialized. */
if (!gcry_check_version (GCRYPT_VERSION))
    {
    std::cerr << "libgcrypt version mismatch" << std::endl;
    exit (2);
    }
/* Disable secure memory. */
gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
/* ... If required, other initialization goes here.
 * Tell Libgcrypt that initialization has completed. */
gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

using namespace gcrypt;
hash::make mh;

hash::md5_t md5;
hash::sha512_t sha512;

mh.enable( md5 );
mh.enable( sha512 );

mh.write( "test", 4 );

mh.read( md5 );
mh.read( sha512 );

print( md5.begin(), md5.end() );
print( sha512.begin(), sha512.end() ); 
return 0;
}

