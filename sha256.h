#ifndef SHA256_H
#define SHA256_H

#include <string>

typedef unsigned char byte;
typedef unsigned int word32;
typedef unsigned long long word64;

class SHA256 {
protected:
    const static word32 sha256_k[]; 
    static const unsigned int SHA224_256_BLOCK_SIZE = (512 / 8); 

public:
    void init();
    void update(const byte *message, unsigned int len);
    void final(byte *digest); 
    std::string final();     

    static const unsigned int DIGEST_SIZE = (256 / 8); 

protected:
    void transform(const byte *message, unsigned int block_nb);
    word32 m_h[8];    
    word64 m_tot_len; 
    word32 m_len;     
    byte m_block[2 * SHA224_256_BLOCK_SIZE]; 
};


std::string calculateFileSHA256(const std::string& filePath);

#endif 
