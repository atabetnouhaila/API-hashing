#include <iostream>
#include <Windows.h>

// Function to compute hash from a string following the observed logic in PowerShell
DWORD calculateHashPowerShellStyle(char* inputString)
{
    DWORD hash = 0x35;  // Initial hash value based on the PowerShell script output
    size_t length = strnlen_s(inputString, 50);  // Get the length of the input string

    // Iterate through each character of the string
    for (size_t i = 0; i < length; ++i)
    {
        char currentChar = inputString[i];  // Current character
        int charValue = static_cast<int>(currentChar);  // ASCII value of the character

        // Update the hash value as observed in the PowerShell output
        hash += (hash * 0xab10f29f + charValue) & 0xffffff;

        // Display each iteration as in the PowerShell script for reference
        std::cout << "Iteration " << i + 1 << " : " << currentChar
            << " : 0x" << std::hex << charValue
            << " : 0x" << std::hex << hash << std::endl;
    }

    return hash;  // Return the computed hash
}

// Function to find a function's address using its hash
PDWORD findFunctionByHash(char* moduleName, DWORD targetHash)
{
    PDWORD functionAddress = nullptr;

    // Load the specified module (e.g., kernel32 for CreateThread)
    HMODULE moduleBase = LoadLibraryA(moduleName);

    // Get DOS and NT headers for the module
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)moduleBase + dosHeader->e_lfanew);

    // Locate the export directory
    DWORD_PTR exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)moduleBase + exportDirRVA);

    // Get pointers to functions, names, and ordinals
    PDWORD funcRVAList = (PDWORD)((DWORD_PTR)moduleBase + exportDirectory->AddressOfFunctions);
    PDWORD nameRVAList = (PDWORD)((DWORD_PTR)moduleBase + exportDirectory->AddressOfNames);
    PWORD ordinalRVAList = (PWORD)((DWORD_PTR)moduleBase + exportDirectory->AddressOfNameOrdinals);

    // Iterate through the exported functions and calculate hashes
    for (DWORD i = 0; i < exportDirectory->NumberOfFunctions; ++i)
    {
        DWORD nameRVA = nameRVAList[i];
        char* functionName = (char*)((DWORD_PTR)moduleBase + nameRVA);

        // Calculate the hash for each exported function name
        DWORD calculatedHash = calculateHashPowerShellStyle(functionName);

        // Compare the calculated hash to the target hash (e.g., for CreateThread)
        if (calculatedHash == targetHash)
        {
            DWORD_PTR functionRVA = funcRVAList[ordinalRVAList[i]];
            functionAddress = (PDWORD)((DWORD_PTR)moduleBase + functionRVA);
            std::cout << functionName << " : 0x" << std::hex << calculatedHash << " : " << functionAddress << std::endl;
            return functionAddress;
        }
    }

    return nullptr;
}

// Typedef for the CreateThread function signature
typedef HANDLE(NTAPI* ThreadCreationFunc)(
    LPSECURITY_ATTRIBUTES   threadAttributes,
    SIZE_T                  stackSize,
    LPTHREAD_START_ROUTINE  startRoutine,
    LPVOID                  parameter,
    DWORD                   creationFlags,
    LPDWORD                 threadId
    );

int main()
{
    // Use the PowerShell-calculated hash for CreateThread: 0x544e304
    PDWORD createThreadAddress = findFunctionByHash((char*)"kernel32", 0x544e304);

    // Cast the resolved address to the CreateThread function type
    ThreadCreationFunc CreateThread = (ThreadCreationFunc)createThreadAddress;
    DWORD threadId = 0;

    // Call CreateThread with default parameters
    HANDLE threadHandle = CreateThread(NULL, 0, NULL, NULL, 0, &threadId);

    return 0;
}
