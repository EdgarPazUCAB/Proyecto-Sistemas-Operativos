#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>
#include <stdexcept> 


void encryptFile(const std::string& sourcePath, const std::string& destinationPath);
void decryptFile(const std::string& sourcePath, const std::string& destinationPath);

#endif 
