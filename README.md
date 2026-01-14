# API Hashing Project

## Description

This project demonstrates **API hashing**, a technique used to resolve Windows API functions by their hash values instead of their function names. The implementation includes both a PowerShell script for calculating function name hashes and a C++ program that parses PE (Portable Executable) headers to dynamically resolve and call Windows APIs using these hashes.

The project specifically demonstrates resolving the `CreateThread` function from `kernel32.dll` (loaded as `"kernel32"`) by calculating its hash value and then searching through the module's export directory to find the matching function address.

## Purpose

The purpose of this project is to:

- **Understand API hashing techniques**: Learn how malware and security tools use hash-based API resolution to obfuscate function calls and evade static analysis detection
- **Explore PE file structure**: Gain hands-on experience with Windows PE headers, including DOS headers, NT headers, and export directories
- **Implement dynamic API resolution**: Build a system that can resolve Windows API functions at runtime without hardcoding function names
- **Educational security research**: Study common obfuscation techniques used in cybersecurity, malware analysis, and reverse engineering contexts

## What Built

The project consists of two main components:

### 1. PowerShell Hash Calculator (`HashingAPI.ps1`)
- Calculates hash values for Windows API function names
- Uses a custom hashing algorithm with:
  - Initial hash value: `0x35`
  - Multiplier: `0xab10f29f`
  - Bitwise mask: `0xffffff`
- Iterates through each character in the function name and updates the hash
- Outputs detailed iteration information showing the hash calculation process
- Example: Calculates hash `0x544e304` for `CreateThread`

### 2. C++ API Resolver (`API_Hashing.cpp`)
- **Hash Calculation Function** (`calculateHashPowerShellStyle`):
  - Implements the same hashing algorithm as the PowerShell script
  - Processes input strings character by character
  - Returns the computed hash value

- **Function Resolution** (`findFunctionByHash`):
  - Loads a specified Windows module using `LoadLibraryA()` (e.g., `"kernel32"` which loads `kernel32.dll`)
  - Parses PE headers to locate the export directory
  - Iterates through all exported functions
  - Calculates hash for each exported function name
  - Matches the calculated hash against the target hash
  - Returns the function address when a match is found

- **Main Function**:
  - Resolves `CreateThread` from `kernel32.dll` (loaded as `"kernel32"`) using hash `0x544e304`
  - Casts the resolved address to the appropriate function pointer type
  - Demonstrates calling the resolved function

## How to Run/Test

### Prerequisites
- **Windows Operating System** (required for Windows API calls)
- **Visual Studio 2019 or later** with C++ development tools
- **PowerShell** (included with Windows)

### Building the Project

1. **Open the Solution**:
   - Open `API_Hashing.sln` in Visual Studio

2. **Select Configuration**:
   - Choose either `Debug` or `Release` configuration
   - Select `x64` or `Win32` platform (x64 is recommended for modern systems)

3. **Build the Project**:
   - Press `Ctrl+Shift+B` or go to `Build` → `Build Solution`
   - The executable will be generated in `x64/Debug/` or `x64/Release/` directory

### Testing the PowerShell Script

1. **Run the Hash Calculator**:
   ```powershell
   .\HashingAPI.ps1
   ```

2. **Expected Output**:
   - You should see iteration-by-iteration hash calculations
   - Final output showing `CreateThread` with its hash value `0x544e304`

### Testing the C++ Program

1. **Run the Executable**:
   - Navigate to the output directory (e.g., `x64/Debug/`)
   - Run `API_Hashing.exe` from Command Prompt or PowerShell

2. **Expected Output**:
   - Console output showing hash calculation iterations for each exported function
   - When `CreateThread` is found: `CreateThread : 0x544e304 : <memory_address>`
   - The program will successfully resolve and call `CreateThread`

3. **Debugging**:
   - You can set breakpoints in Visual Studio to inspect:
     - Hash values during calculation
     - PE header structures
     - Function addresses being resolved
     - Export directory contents

### Testing Different Functions

To test with different Windows APIs:

1. **Modify the PowerShell script**:
   - Change `$FunctionsToHash = @("CreateThread")` to include other functions
   - Run the script to get the new hash value

2. **Update the C++ code**:
   - Replace `0x544e304` in `main()` with the new hash value
   - Update the function signature typedef if needed
   - Rebuild and run

## What I Learned

Through this project, I gained valuable insights into:

### 1. **PE File Format Structure**
- Understanding DOS headers (`IMAGE_DOS_HEADER`) and the `e_lfanew` field
- Navigating NT headers (`IMAGE_NT_HEADERS`) and optional headers
- Locating and parsing export directories (`IMAGE_EXPORT_DIRECTORY`)
- Working with RVAs (Relative Virtual Addresses) and converting them to actual memory addresses

### 2. **Windows API Resolution**
- How Windows modules export functions and how the loader resolves them
- The relationship between function names, ordinals, and addresses
- Dynamic loading using `LoadLibraryA()` and manual PE parsing

### 3. **Hashing Algorithms**
- Custom hash function design and implementation
- Character-by-character hash calculation
- Bitwise operations for hash manipulation (`& 0xffffff` for masking)
- Ensuring consistency between different implementations (PowerShell vs C++)

### 4. **Security and Obfuscation Techniques**
- How API hashing is used to evade static analysis
- Why malware authors use hash-based resolution instead of direct API calls
- The trade-offs between obfuscation and performance

### 5. **C++ and Windows Programming**
- Working with Windows data types (`DWORD`, `PDWORD`, `HMODULE`)
- Function pointer typedefs and type casting
- Memory address manipulation and pointer arithmetic
- Safe string operations (`strnlen_s`)

### 6. **Cross-Language Implementation**
- Implementing the same algorithm in PowerShell and C++
- Ensuring algorithmic consistency across different languages
- Understanding how different languages handle integer operations and bitwise math

### 7. **Debugging and Analysis**
- Using Visual Studio debugger to inspect PE structures
- Understanding memory layouts and address spaces
- Tracing execution flow through complex data structures

This project provided hands-on experience with low-level Windows internals and security research techniques that are essential for malware analysis, reverse engineering, and defensive security development.

