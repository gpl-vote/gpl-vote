#ifndef GCRYPT_HASHH
#define GCRYPT_HASHH

#include <stdint.h>
#include <stdexcept>
#include <gcrypt.h>

#include "ext/array.h"

namespace gcrypt
{
namespace hash
{

template <int md_algo>
struct hash_t
{
};

template <>
struct hash_t<GCRY_MD_RMD160>:
    public ext::array<uint32_t,5>
{
enum { algo = GCRY_MD_RMD160 };
};

template <>
struct hash_t<GCRY_MD_TIGER>:
    public ext::array<size_t,24/sizeof(size_t)>
{
enum { algo = GCRY_MD_TIGER };
};

template <>
struct hash_t<GCRY_MD_TIGER1>:
    public ext::array<size_t,24/sizeof(size_t)>
{
enum { algo = GCRY_MD_TIGER1 };
};

template <>
struct hash_t<GCRY_MD_TIGER2>:
    public ext::array<size_t,24/sizeof(size_t)>
{
enum { algo = GCRY_MD_TIGER2 };
};

template <>
struct hash_t<GCRY_MD_HAVAL>:
    public ext::array<uint32_t,5>
{
enum { algo = GCRY_MD_HAVAL };
};

template <>
struct hash_t<GCRY_MD_MD2>:
    public ext::array<size_t,16/sizeof(size_t)>
{
enum { algo = GCRY_MD_MD2 };
};

template <>
struct hash_t<GCRY_MD_MD4>:
    public ext::array<size_t,16/sizeof(size_t)>
{
enum { algo = GCRY_MD_MD4 };
};

template <>
struct hash_t<GCRY_MD_MD5>:
    public ext::array<size_t,16/sizeof(size_t)>
{
enum { algo = GCRY_MD_MD5 };
};

template <>
struct hash_t<GCRY_MD_SHA1>:
    public ext::array<uint32_t,5>
{
enum { algo = GCRY_MD_SHA1 };
};

template <>
struct hash_t<GCRY_MD_SHA224>:
    public ext::array<uint32_t,7>
{
enum { algo = GCRY_MD_SHA224 };
};

template <>
struct hash_t<GCRY_MD_SHA256>:
    public ext::array<size_t,32/sizeof(size_t)>
{
enum { algo = GCRY_MD_SHA256 };
};

template <>
struct hash_t<GCRY_MD_SHA384>:
    public ext::array<size_t,48/sizeof(size_t)>
{
enum { algo = GCRY_MD_SHA384 };
};

template <>
struct hash_t<GCRY_MD_SHA512>:
    public ext::array<size_t,64/sizeof(size_t)>
{
enum { algo = GCRY_MD_SHA512 };
};

struct make
{
protected:
gcry_md_hd_t    m_md;

public:
inline  make()
    {
    gcry_error_t err = gcry_md_open( &m_md, GCRY_MD_NONE, 0 );
    if ( 0 != err )
        {
        throw std::domain_error( "gcry_md_open()" );
        }
    }
inline  make(const char* key, size_t size)
    {
    gcry_error_t err = gcry_md_open( &m_md, GCRY_MD_NONE, GCRY_MD_FLAG_HMAC );
    if ( 0 != err )
        {
        throw std::domain_error( "gcry_md_open()" );
        }
    err = gcry_md_setkey( m_md, key, size );
    if ( 0 != err )
        {
        gcry_md_close( m_md );
        throw std::domain_error( "gcry_md_setkey()" );
        }
    }
inline ~make()
    {
    gcry_md_close( m_md );
    }
inline void reset()
    {
    gcry_md_reset( m_md );
    }
template <int algo>
inline void enable(const hash_t<algo>& hash)
    {
    enable( algo );
    }
inline void enable(int algo)
    {
    gcry_error_t err = gcry_md_enable( m_md, algo );
    if ( 0 != err )
        {
        throw std::invalid_argument( "gcry_md_enable() unknown md algo" );
        }
    }
    
inline void write(const void* data, size_t size)
    {
    gcry_md_write( m_md, data, size );
    }

template <int algo>
inline void read(hash_t<algo>& hash) const
    {
    const void* data = gcry_md_read( m_md, algo );
    if ( NULL == data )
        {
        throw std::logic_error( "gcry_md_read() algo not enabled" );
        }
    memcpy( &hash, data, hash.size() * sizeof(typename hash_t<algo>::type) );
    }
};

typedef hash_t<GCRY_MD_RMD160>  rmd160;
typedef hash_t<GCRY_MD_TIGER>   tiger_t;
typedef hash_t<GCRY_MD_TIGER1>  tiger1_t;
typedef hash_t<GCRY_MD_TIGER2>  tiger2_t;
typedef hash_t<GCRY_MD_HAVAL>   haval_t;

typedef hash_t<GCRY_MD_MD2>     md2_t;
typedef hash_t<GCRY_MD_MD4>     md4_t;
typedef hash_t<GCRY_MD_MD5>     md5_t;

typedef hash_t<GCRY_MD_SHA1>    sha1_t;
typedef hash_t<GCRY_MD_SHA224>  sha224_t;
typedef hash_t<GCRY_MD_SHA256>  sha256_t;
typedef hash_t<GCRY_MD_SHA384>  sha384_t;
typedef hash_t<GCRY_MD_SHA512>  sha512_t;

typedef hash_t<GCRY_MD_CRC32>           crc32_t;
typedef hash_t<GCRY_MD_CRC32_RFC1510>   crc32_rfc1510_t;
typedef hash_t<GCRY_MD_CRC24_RFC2440>   crc24_rfc2440_t;

typedef hash_t<GCRY_MD_WHIRLPOOL>       whirlpool_t;

} //namespace hash
} //namespace gcrypt

#endif

