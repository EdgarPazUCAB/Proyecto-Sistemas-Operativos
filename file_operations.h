#ifndef FILE_OPERATIONS_H
#define FILE_OPERATIONS_H

#include <string>
#include <vector>
#include <stdexcept> 


void copyFile(const std::string& sourcePath, const std::string& destinationPath);
void writeHashToFile(const std::string& filePath, const std::string& hash);
std::string readHashFromFile(const std::string& filePath);
bool compareFiles(const std::string& filePath1, const std::string& filePath2);

#endif 
