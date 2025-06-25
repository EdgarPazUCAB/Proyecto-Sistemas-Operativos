#include "encryption.h"
#include <fstream>
#include <vector>


void encryptFile(const std::string& sourcePath, const std::string& destinationPath) {
    std::ifstream source(sourcePath, std::ios::binary);
    std::ofstream destination(destinationPath, std::ios::binary);

    if (!source.is_open()) {
        throw std::runtime_error("Error: No se pudo abrir el archivo de origen para encriptar: " + sourcePath);
    }
    if (!destination.is_open()) {
        throw std::runtime_error("Error: No se pudo crear/abrir el archivo de destino para encriptar: " + destinationPath);
    }

    char ch;
    while (source.get(ch)) {
        
        if (ch >= 32 && ch <= 126) { 
            ch = 32 + ((ch - 32 + 3) % 95);
        }
        destination.put(ch);
    }

    if (source.bad() || destination.bad()) {
        throw std::runtime_error("Error de lectura/escritura durante la encriptacion de " + sourcePath + " a " + destinationPath);
    }
}


void decryptFile(const std::string& sourcePath, const std::string& destinationPath) {
    std::ifstream source(sourcePath, std::ios::binary);
    std::ofstream destination(destinationPath, std::ios::binary);

    if (!source.is_open()) {
        throw std::runtime_error("Error: No se pudo abrir el archivo de origen para desencriptar: " + sourcePath);
    }
    if (!destination.is_open()) {
        throw std::runtime_error("Error: No se pudo crear/abrir el archivo de destino para desencriptar: " + destinationPath);
    }

    char ch;
    while (source.get(ch)) {
        
        if (ch >= 32 && ch <= 126) {
            ch = 32 + ((ch - 32 - 3 + 95) % 95); 
        }
        destination.put(ch);
    }

    if (source.bad() || destination.bad()) {
        throw std::runtime_error("Error de lectura/escritura durante la desencriptacion de " + sourcePath + " a " + destinationPath);
    }
}
