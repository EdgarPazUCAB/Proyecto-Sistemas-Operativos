#include "sha256.h"
#include <cstring>    
#include <fstream>    
#include <sstream>    
#include <iomanip>   
#include <stdexcept>  



const word32 SHA256::sha256_k[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


static word32 rotate_right(word32 val, int n) {
    return (val >> n) | (val << (32 - n));
}

static word32 choose(word32 e, word32 f, word32 g) {
    return (e & f) ^ (~e & g);
}

static word32 majority(word32 a, word32 b, word32 c) {
    return (a & b) ^ (a & c) ^ (b & c);
}

static word32 sigma0(word32 x) {
    return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22);
}

static word32 sigma1(word32 x) {
    return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25);
}

static word32 gamma0(word32 x) {
    return rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3);
}

static word32 gamma1(word32 x) {
    return rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10);
}


static word32 sha256_endian_swap(word32 val) {
    return ( (val & 0xFF000000) >> 24 ) |
           ( (val & 0x00FF0000) >> 8  ) |
           ( (val & 0x0000FF00) << 8  ) |
           ( (val & 0x000000FF) << 24 );
}

void SHA256::init() {
    m_h[0] = 0x6a09e667;
    m_h[1] = 0xbb67ae85;
    m_h[2] = 0x3c6ef372;
    m_h[3] = 0xa54ff53a;
    m_h[4] = 0x510e527f;
    m_h[5] = 0x9b05688c;
    m_h[6] = 0x1f83d9ab;
    m_h[7] = 0x5be0cd19;

    m_len = 0;
    m_tot_len = 0;
   
}

void SHA256::transform(const byte *message, unsigned int block_nb) {
  
    word32 a, b, c, d, e, f, g, h;
    word32 w[64];

    for (unsigned int i = 0; i < block_nb; i++) {
       
        a = m_h[0];
        b = m_h[1];
        c = m_h[2];
        d = m_h[3];
        e = m_h[4];
        f = m_h[5];
        g = m_h[6];
        h = m_h[7];

      
        for (unsigned int j = 0; j < 64; j++) {
            if (j < 16) {
                
                w[j] = sha256_endian_swap(
                    ((word32)message[i * SHA224_256_BLOCK_SIZE + j * 4 + 0] << 24) |
                    ((word32)message[i * SHA224_256_BLOCK_SIZE + j * 4 + 1] << 16) |
                    ((word32)message[i * SHA224_256_BLOCK_SIZE + j * 4 + 2] << 8)  |
                    ((word32)message[i * SHA224_256_BLOCK_SIZE + j * 4 + 3])
                );
            } else {
                w[j] = gamma1(w[j - 2]) + w[j - 7] + gamma0(w[j - 15]) + w[j - 16];
            }

            
            word32 T1 = h + sigma1(e) + choose(e, f, g) + sha256_k[j] + w[j];
            word32 T2 = sigma0(a) + majority(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

       
        m_h[0] += a;
        m_h[1] += b;
        m_h[2] += c;
        m_h[3] += d;
        m_h[4] += e;
        m_h[5] += f;
        m_h[6] += g;
        m_h[7] += h;
    }
    
}

void SHA256::update(const byte *message, unsigned int len) {
   
    m_tot_len += len;
    
    
    if (m_len > 0) {
        unsigned int remain_len = SHA224_256_BLOCK_SIZE - m_len;
        if (len < remain_len) {
            memcpy(m_block + m_len, message, len);
            m_len += len;
            return;
        } else {
            memcpy(m_block + m_len, message, remain_len);
            transform(m_block, 1);
            message += remain_len;
            len -= remain_len;
            m_len = 0; 
        }
    }

    
    unsigned int block_nb = len / SHA224_256_BLOCK_SIZE;
    if (block_nb > 0) {
        transform(message, block_nb);
        message += block_nb * SHA224_256_BLOCK_SIZE;
        len -= block_nb * SHA224_256_BLOCK_SIZE;
    }

    
    if (len > 0) {
        memcpy(m_block, message, len);
        m_len = len;
    }
 
}


void SHA256::final(byte *digest) {
    
    word64 len_b = m_tot_len * 8; 
    unsigned int pm_len = m_len; 

    
    m_block[pm_len++] = 0x80; 
    if (pm_len > SHA224_256_BLOCK_SIZE - 8) {
        
        memset(m_block + pm_len, 0, SHA224_256_BLOCK_SIZE - pm_len);
        transform(m_block, 1);
        pm_len = 0;
    }
    
    memset(m_block + pm_len, 0, SHA224_256_BLOCK_SIZE - pm_len - 8);

    
    m_block[SHA224_256_BLOCK_SIZE - 8] = (byte)((len_b >> 56) & 0xFF);
    m_block[SHA224_256_BLOCK_SIZE - 7] = (byte)((len_b >> 48) & 0xFF);
    m_block[SHA224_256_BLOCK_SIZE - 6] = (byte)((len_b >> 40) & 0xFF);
    m_block[SHA224_256_BLOCK_SIZE - 5] = (byte)((len_b >> 32) & 0xFF);
    m_block[SHA224_256_BLOCK_SIZE - 4] = (byte)((len_b >> 24) & 0xFF);
    m_block[SHA224_256_BLOCK_SIZE - 3] = (byte)((len_b >> 16) & 0xFF);
    m_block[SHA224_256_BLOCK_SIZE - 2] = (byte)((len_b >> 8) & 0xFF);
    m_block[SHA224_256_BLOCK_SIZE - 1] = (byte)((len_b) & 0xFF);

    transform(m_block, 1);

  
    for (int i = 0; i < 8; i++) {
        digest[i * 4 + 0] = (byte)((m_h[i] >> 24) & 0xFF);
        digest[i * 4 + 1] = (byte)((m_h[i] >> 16) & 0xFF);
        digest[i * 4 + 2] = (byte)((m_h[i] >> 8) & 0xFF);
        digest[i * 4 + 3] = (byte)((m_h[i]) & 0xFF);
    }
   
}

std::string SHA256::final() {
    
    byte digest[DIGEST_SIZE];
    final(digest); 

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < DIGEST_SIZE; i++) {
        ss << std::setw(2) << static_cast<unsigned int>(digest[i]);
    }
  
    return ss.str();
}

std::string calculateFileSHA256(const std::string& filePath) {
    
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("No se pudo abrir el archivo para calcular SHA256: " + filePath);
    }
  

    SHA256 sha256;
    sha256.init();

    const int bufferSize = 4096;
    unsigned char buffer[bufferSize];

    long long totalBytesRead = 0;

    while (file.read(reinterpret_cast<char*>(buffer), bufferSize)) {
       
        sha256.update(buffer, bufferSize);
        totalBytesRead += bufferSize;
        
    }
    if (file.gcount() > 0) { 
        sha256.update(buffer, file.gcount());
        totalBytesRead += file.gcount();
        
    }
   

    std::string hashResult = sha256.final();
    
    return hashResult;
}
