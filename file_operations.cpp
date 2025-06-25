#include "file_operations.h"
#include <fstream>
#include <sstream>
#include <vector>
#include <iterator> 


void copyFile(const std::string& sourcePath, const std::string& destinationPath) {
    std::ifstream source(sourcePath, std::ios::binary);
    std::ofstream destination(destinationPath, std::ios::binary);

    if (!source.is_open()) {
        throw std::runtime_error("Error: No se pudo abrir el archivo de origen: " + sourcePath);
    }
    if (!destination.is_open()) {
        throw std::runtime_error("Error: No se pudo crear/abrir el archivo de destino: " + destinationPath);
    }

    
    destination << source.rdbuf();

    if (source.bad() || destination.bad()) {
        throw std::runtime_error("Error de lectura/escritura durante la copia de " + sourcePath + " a " + destinationPath);
    }
}


void writeHashToFile(const std::string& filePath, const std::string& hash) {
    std::ofstream outFile(filePath);
    if (!outFile.is_open()) {
        throw std::runtime_error("Error: No se pudo crear/abrir el archivo de hash para escritura: " + filePath);
    }
    outFile << hash;
    outFile.flush(); 
    outFile.close(); 
}


std::string readHashFromFile(const std::string& filePath) {
    std::ifstream inFile(filePath);
    if (!inFile.is_open()) {
        throw std::runtime_error("Error: No se pudo abrir el archivo de hash para lectura: " + filePath);
    }
    std::stringstream buffer;
    buffer << inFile.rdbuf();
    if (inFile.bad()) {
        throw std::runtime_error("Error de lectura en el archivo de hash: " + filePath);
    }
    return buffer.str();
}


bool compareFiles(const std::string& filePath1, const std::string& filePath2) {
    std::ifstream f1(filePath1, std::ios::binary | std::ios::ate);
    std::ifstream f2(filePath2, std::ios::binary | std::ios::ate);

    if (!f1.is_open() || !f2.is_open()) {
        return false; 
    }

  
    if (f1.tellg() != f2.tellg()) {
        return false;
    }

    
    f1.seekg(0, std::ios::beg);
    f2.seekg(0, std::ios::beg);

    
    return std::equal(std::istreambuf_iterator<char>(f1.rdbuf()),
                      std::istreambuf_iterator<char>(),
                      std::istreambuf_iterator<char>(f2.rdbuf()));
}
