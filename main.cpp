// Elaborado por Edgar Paz. C.I. 30843445

#include <iostream>
#include <string>
#include <vector>
#include <chrono> 
#include <iomanip> 
#include <fstream> 
#include <sstream> 
#include <ctime>   
#include <windows.h> 

#include "file_operations.h"
#include "encryption.h"
#include "sha256.h"


std::string getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    
    std::tm* local_tm = std::localtime(&in_time_t);

    char buffer[80];
    std::strftime(buffer, sizeof(buffer), "%H:%M:%S", local_tm);

    return std::string(buffer);
}


std::string formatDuration(std::chrono::nanoseconds duration) {
    auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    
    
    if (total_ms < 1000) {
        std::stringstream ss;
        ss << total_ms << " ms";
        return ss.str();
    }

   
    long long total_seconds = total_ms / 1000;
    long long hours = total_seconds / 3600;
    long long minutes = (total_seconds % 3600) / 60;
    long long seconds = total_seconds % 60;
    
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << hours << ":"
       << std::setfill('0') << std::setw(2) << minutes << ":"
       << std::setfill('0') << std::setw(2) << seconds;
    return ss.str();
}


struct ThreadData {
    std::string originalFilePath;
    int copyIndex;
    std::string originalFileBaseHash;
    bool* validationErrorFlag; 
    CRITICAL_SECTION* cs;     
};


DWORD WINAPI processSingleCopyOptimized(LPVOID param) {
    ThreadData* data = static_cast<ThreadData*>(param);

  
    std::string originalFilePath = data->originalFilePath;
    int copyIndex = data->copyIndex;
    std::string originalFileBaseHash = data->originalFileBaseHash;
    bool* validationErrorFlag = data->validationErrorFlag;
    CRITICAL_SECTION* cs = data->cs;
        
    
    std::string tempCopyPath = "temp_copia_opt_" + std::to_string(copyIndex) + ".txt";
    std::string encryptedCopyPath = "copia_opt_" + std::to_string(copyIndex) + "_enc.txt";
    std::string decryptedCopyPath = "copia_opt_" + std::to_string(copyIndex) + "_dec.txt";
    std::string encryptedHashPath = "copia_opt_" + std::to_string(copyIndex) + "_enc.hash";
    
    bool currentCopyError = false; 

    try {
        
        copyFile(originalFilePath, tempCopyPath);

       
        if (!compareFiles(originalFilePath, tempCopyPath)) {
            std::cerr << "ERROR (Opt): Copia temporal '" << tempCopyPath << "' no es idéntica al original.txt" << std::endl;
            currentCopyError = true;
        }

        
        encryptFile(tempCopyPath, encryptedCopyPath);
        
      
        std::string calculatedEncryptedHash = calculateFileSHA256(encryptedCopyPath);
        writeHashToFile(encryptedHashPath, calculatedEncryptedHash);

       
        std::string storedEncryptedHash;
        std::string currentCalculatedEncryptedHash;

        try {
            storedEncryptedHash = readHashFromFile(encryptedHashPath);
            currentCalculatedEncryptedHash = calculateFileSHA256(encryptedCopyPath);
        } catch (const std::runtime_error& e) {
            std::cerr << "Error (Opt) al preparar hashes para comparación (archivo opt " << copyIndex << "): " << e.what() << std::endl;
            currentCopyError = true;
        }

        
        if (storedEncryptedHash != currentCalculatedEncryptedHash) {
            std::cerr << "Error (Opt) en el procesamiento del archivo " << copyIndex << ": Fallo de validacion de hash para el archivo ENCRIPTADO (Opt)" << std::endl;
            currentCopyError = true;
        } else {
           
            decryptFile(encryptedCopyPath, decryptedCopyPath);
            
          
            std::string calculatedDecryptedHash = calculateFileSHA256(decryptedCopyPath);

            if (calculatedDecryptedHash != originalFileBaseHash) {
                std::cerr << "Error (Opt) en el procesamiento del archivo " << copyIndex << ": Fallo de validacion de hash para el archivo DESENCRIPTADO (Opt)" << std::endl;
                currentCopyError = true;
            }
        }

    } catch (const std::runtime_error& e) {
      
        std::cerr << "Error general (Opt) en el procesamiento del archivo " << copyIndex << ": " << e.what() << std::endl;
        currentCopyError = true;
    }


    std::remove(tempCopyPath.c_str());
    std::remove(encryptedCopyPath.c_str());
    std::remove(decryptedCopyPath.c_str());
    std::remove(encryptedHashPath.c_str());

    
    if (currentCopyError) {
        EnterCriticalSection(cs); 
        *validationErrorFlag = true;
        LeaveCriticalSection(cs); 
    }
    
    return 0; 
}


int main() {
    std::string originalFilePath = "original.txt";
    int numCopies;

    std::cout << "Introduce el numero de copias a generar (N): ";
    std::cin >> numCopies;

    if (numCopies <= 0) {
        std::cout << "El numero de copias debe ser mayor que 0." << std::endl;
        return 1;
    }

    
    std::string originalFileBaseHash;
    try {
        originalFileBaseHash = calculateFileSHA256(originalFilePath);
    } catch (const std::runtime_error& e) {
        std::cerr << "Error al calcular el hash del archivo original: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "--------------------------------------------------" << std::endl;
    std::cout << "\"PROCESO BASE\"" << std::endl;
    std::cout << "TI: " << getCurrentTime() << std::endl;

    auto base_start_time = std::chrono::high_resolution_clock::now();
    bool baseValidationError = false; 

    for (int i = 0; i < numCopies; ++i) {
        std::string tempCopyPath = "temp_copia_" + std::to_string(i + 1) + ".txt";
        std::string encryptedCopyPath = "copia_" + std::to_string(i + 1) + "_enc.txt";
        std::string decryptedCopyPath = "copia_" + std::to_string(i + 1) + "_dec.txt";
        std::string encryptedHashPath = "copia_" + std::to_string(i + 1) + "_enc.hash";

        try {
            copyFile(originalFilePath, tempCopyPath);
            
            if (!compareFiles(originalFilePath, tempCopyPath)) {
                std::cout << "ERROR: Copia temporal '" << tempCopyPath << "' no es idéntica al original.txt" << std::endl;
                baseValidationError = true;
            }

            encryptFile(tempCopyPath, encryptedCopyPath);
            std::string calculatedEncryptedHash = calculateFileSHA256(encryptedCopyPath);
            writeHashToFile(encryptedHashPath, calculatedEncryptedHash);

            std::string storedEncryptedHash;
            std::string currentCalculatedEncryptedHash; 

            try {
                storedEncryptedHash = readHashFromFile(encryptedHashPath);
                currentCalculatedEncryptedHash = calculateFileSHA256(encryptedCopyPath);
            } catch (const std::runtime_error& e) {
                std::cerr << "Error al preparar hashes para comparación (archivo " << i + 1 << "): " << e.what() << std::endl;
                baseValidationError = true;
            }

            if (storedEncryptedHash != currentCalculatedEncryptedHash) {
                std::cout << "Error en el procesamiento del archivo " << i + 1 << ": Fallo de validacion de hash para el archivo ENCRIPTADO " << i + 1 << std::endl;
                baseValidationError = true;
            } else {
                decryptFile(encryptedCopyPath, decryptedCopyPath);
                std::string calculatedDecryptedHash = calculateFileSHA256(decryptedCopyPath);

                if (calculatedDecryptedHash != originalFileBaseHash) {
                    std::cout << "Error en el procesamiento del archivo " << i + 1 << ": Fallo de validacion de hash para el archivo DESENCRIPTADO " << i + 1 << std::endl;
                    baseValidationError = true;
                }
            }

        } catch (const std::runtime_error& e) {
            std::cerr << "Error general en el procesamiento del archivo " << i + 1 << ": " << e.what() << std::endl;
            baseValidationError = true;
        }

        std::remove(tempCopyPath.c_str());
        std::remove(encryptedCopyPath.c_str());
        std::remove(decryptedCopyPath.c_str());
        std::remove(encryptedHashPath.c_str());
    }

    auto base_end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> base_total_duration = base_end_time - base_start_time;
    std::chrono::nanoseconds base_total_nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(base_total_duration);
    
    std::cout << "TFIN : " << getCurrentTime() << std::endl;
    std::chrono::nanoseconds base_tppa_nanos = (numCopies > 0) ? base_total_nanos / numCopies : std::chrono::nanoseconds(0);

    std::cout << "TPPA : " << formatDuration(base_tppa_nanos) << std::endl;
    std::cout << "TT   : " << formatDuration(base_total_nanos) << std::endl;
    std::cout << "--------------------------------------------------" << std::endl;
    std::cout << "Habra errores en la verificacion final (Proceso Base)?: " << (baseValidationError ? "SI" : "NO") << std::endl;

    std::cout << std::endl;

    
    std::cout << "--------------------------------------------------" << std::endl;
    std::cout << "\"PROCESO OPTIMIZADO\"" << std::endl;
    std::cout << "TI: " << getCurrentTime() << std::endl;

    auto optimized_start_time = std::chrono::high_resolution_clock::now();
    
    bool optimizedValidationError = false; 
    CRITICAL_SECTION globalCs;         
    InitializeCriticalSection(&globalCs);
    std::vector<HANDLE> threads;
    
    std::vector<ThreadData> threadData(numCopies); 

    
    for (int i = 0; i < numCopies; ++i) {
        threadData[i].originalFilePath = originalFilePath; 
        threadData[i].copyIndex = i + 1;
        threadData[i].originalFileBaseHash = originalFileBaseHash;
        threadData[i].validationErrorFlag = &optimizedValidationError; 
        threadData[i].cs = &globalCs; 

        HANDLE hThread = CreateThread(
            NULL,               
            0,                  
            processSingleCopyOptimized, 
            &threadData[i],     
            0,                 
            NULL                
        );

        if (hThread == NULL) {
            std::cerr << "Error al crear el hilo para la copia " << i + 1 << ". Error Code: " << GetLastError() << std::endl;
            
            EnterCriticalSection(&globalCs);
            optimizedValidationError = true;
            LeaveCriticalSection(&globalCs);
          
        } else {
            threads.push_back(hThread); 
        }
    }

 
    if (!threads.empty()) {
        
        WaitForMultipleObjects(threads.size(), threads.data(), TRUE, INFINITE);
    }

   
    for (HANDLE hThread : threads) {
        CloseHandle(hThread);
    }

  
    DeleteCriticalSection(&globalCs);

    auto optimized_end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> optimized_total_duration = optimized_end_time - optimized_start_time;
    std::chrono::nanoseconds optimized_total_nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(optimized_total_duration);
    
    std::cout << "TFIN : " << getCurrentTime() << std::endl;
    std::chrono::nanoseconds optimized_tppa_nanos = (numCopies > 0) ? optimized_total_nanos / numCopies : std::chrono::nanoseconds(0);

    std::cout << "TPPA : " << formatDuration(optimized_tppa_nanos) << std::endl;
    std::cout << "TT   : " << formatDuration(optimized_total_nanos) << std::endl;


    double pm_value = 0.0;
    if (base_total_nanos.count() > 0) {
        pm_value = (static_cast<double>(base_total_nanos.count() - optimized_total_nanos.count()) / base_total_nanos.count()) * 100.0;
    }
    std::cout << "PM   : " << std::fixed << std::setprecision(2) << pm_value << "%" << std::endl;

    
    auto df_milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(optimized_total_nanos);
    std::cout << "DF   : " << df_milliseconds.count() << " ms" << std::endl;

    std::cout << "--------------------------------------------------" << std::endl;
  
    std::cout << "¿Habra errores en la verificacion final (Proceso Optimizado)?: " << (optimizedValidationError ? "SI" : "NO") << std::endl;

    return 0;
}
