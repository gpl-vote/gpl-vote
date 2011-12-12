#include <stdio.h>

#include "gcrypt/init.h"
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
using namespace gcrypt;
init( 16*1024 );
ext::array<char,128> buff;
buff.fill( 0xFF );

rsa::pub_t<1024> key( buff, 3U );

hash::sha256_t hash;
key.fingerprint( hash );

print( hash.begin(), hash.end() );
return 0;
}

