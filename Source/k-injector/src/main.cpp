#include <Windows.h>
#include <Psapi.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <mutex>
#pragma warning(disable:4996)

// Enum for process architecture
enum class ProcessArch {
    Unknown,
    x86,    // 32-bit
    x64     // 64-bit
};

// Process information structure
struct ProcessInfo {
    DWORD processId;
    std::string processName;
    std::string processPath;
    ProcessArch architecture;

    ProcessInfo(DWORD id, const std::string& name, const std::string& path, ProcessArch arch = ProcessArch::Unknown)
        : processId(id), processName(name), processPath(path), architecture(arch) {}
};

// Status struct with thread safety
struct AppStatus {
    // Process selection
    std::vector<ProcessInfo> processList;
    DWORD targetProcessId = 0;
    std::string targetProcessName = "";
    std::string targetProcessPath = "";
    bool processSelected = false;
    ProcessArch targetProcessArch = ProcessArch::Unknown;

    // DLL selection
    std::string dllPath;
    bool dllSelected = false;
    ProcessArch dllArch = ProcessArch::Unknown;

    // Injection status
    std::string injectionStatus = "Select a process and DLL to inject";
    float injectionProgress = 0.0f;

    // Mutex for thread synchronization
    std::mutex statusMutex;

    // Thread-safe methods to update injection status
    void updateInjectionStatus(const std::string& newStatus, float newProgress = -1.0f) {
        std::lock_guard<std::mutex> lock(statusMutex);
        injectionStatus = newStatus;
        if (newProgress >= 0.0f) {
            injectionProgress = newProgress;
        }
    }

    std::string getInjectionStatus() {
        std::lock_guard<std::mutex> lock(statusMutex);
        return injectionStatus;
    }

    float getInjectionProgress() {
        std::lock_guard<std::mutex> lock(statusMutex);
        return injectionProgress;
    }
};

// Global AppStatus instance
AppStatus g_Status;

// Vector to store recent DLLs
std::vector<std::string> g_RecentDLLs;

// Function prototypes
void RefreshProcessList(AppStatus& status);
ProcessArch GetProcessArchitecture(DWORD processId);
ProcessArch GetDLLArchitecture(const std::string& dllPath);
bool InjectDLL(AppStatus& status);
void DisplayProcessList(const AppStatus& status);
bool FileExists(const std::string& path);
std::string GetParentPath(const std::string& path);
std::string GetFileName(const std::string& path);
void SaveRecentDLLs();
void LoadRecentDLLs();
void AddRecentDLL(const std::string& dllPath);
void PrintUsage();
void ListRecentDLLs();

// Function to check if file exists
bool FileExists(const std::string& path) {
    DWORD fileAttributes = GetFileAttributesA(path.c_str());
    return (fileAttributes != INVALID_FILE_ATTRIBUTES &&
        !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY));
}

// Function to get parent path
std::string GetParentPath(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    if (pos != std::string::npos) {
        return path.substr(0, pos);
    }
    return "";
}

// Function to get file name from path
std::string GetFileName(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    if (pos != std::string::npos) {
        return path.substr(pos + 1);
    }
    return path;
}

// Functions for handling recent DLLs
void SaveRecentDLLs() {
    std::ofstream file("recent_dlls.txt");
    if (file.is_open()) {
        for (const auto& dll : g_RecentDLLs) {
            file << dll << std::endl;
        }
        file.close();
    }
}

void LoadRecentDLLs() {
    g_RecentDLLs.clear();
    std::ifstream file("recent_dlls.txt");
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty() && FileExists(line)) {
                g_RecentDLLs.push_back(line);
            }
        }
        file.close();
    }
}

void AddRecentDLL(const std::string& dllPath) {
    // Remove if already exists
    auto it = std::find(g_RecentDLLs.begin(), g_RecentDLLs.end(), dllPath);
    if (it != g_RecentDLLs.end()) {
        g_RecentDLLs.erase(it);
    }

    // Add to the beginning of the list
    g_RecentDLLs.insert(g_RecentDLLs.begin(), dllPath);

    // Limit number of entries
    if (g_RecentDLLs.size() > 10) {
        g_RecentDLLs.resize(10);
    }

    // Save the updated list
    SaveRecentDLLs();
}

// Function to determine if a process is 32-bit or 64-bit
ProcessArch GetProcessArchitecture(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        return ProcessArch::Unknown;
    }

    BOOL isWow64 = FALSE;
    ProcessArch result = ProcessArch::Unknown;

    // IsWow64Process returns TRUE if the process is a 32-bit process running on a 64-bit system
    if (IsWow64Process(hProcess, &isWow64)) {
#ifdef _WIN64
        // If we're running as a 64-bit process
        if (isWow64) {
            // Target is 32-bit
            result = ProcessArch::x86;
        }
        else {
            // Target is 64-bit
            result = ProcessArch::x64;
        }
#else
        // If we're running as a 32-bit process
        if (isWow64) {
            // We're running on a 64-bit OS
            result = ProcessArch::x86;
        }
        else {
            // We're on a 32-bit OS, so the process must be 32-bit
            result = ProcessArch::x86;
        }
#endif
    }

    CloseHandle(hProcess);
    return result;
}

// Function to determine if a DLL is 32-bit or 64-bit
ProcessArch GetDLLArchitecture(const std::string& dllPath) {
    if (dllPath.empty() || !FileExists(dllPath)) {
        return ProcessArch::Unknown;
    }

    // Open the DLL file
    HANDLE hFile = CreateFileA(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return ProcessArch::Unknown;
    }

    // Read the DOS header
    IMAGE_DOS_HEADER dosHeader;
    DWORD bytesRead;
    if (!ReadFile(hFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead, NULL) || bytesRead != sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(hFile);
        return ProcessArch::Unknown;
    }

    // Check the DOS signature
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        return ProcessArch::Unknown;
    }

    // Seek to the PE header
    if (SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        CloseHandle(hFile);
        return ProcessArch::Unknown;
    }

    // Read the NT header signature
    DWORD ntSignature;
    if (!ReadFile(hFile, &ntSignature, sizeof(DWORD), &bytesRead, NULL) || bytesRead != sizeof(DWORD)) {
        CloseHandle(hFile);
        return ProcessArch::Unknown;
    }

    // Check the NT signature
    if (ntSignature != IMAGE_NT_SIGNATURE) {
        CloseHandle(hFile);
        return ProcessArch::Unknown;
    }

    // Read the file header
    IMAGE_FILE_HEADER fileHeader;
    if (!ReadFile(hFile, &fileHeader, sizeof(IMAGE_FILE_HEADER), &bytesRead, NULL) || bytesRead != sizeof(IMAGE_FILE_HEADER)) {
        CloseHandle(hFile);
        return ProcessArch::Unknown;
    }

    CloseHandle(hFile);

    // Check the machine type
    if (fileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        return ProcessArch::x86;
    }
    else if (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        return ProcessArch::x64;
    }

    return ProcessArch::Unknown;
}

// Function to refresh list of running processes
void RefreshProcessList(AppStatus& status) {
    status.processList.clear();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return;
    }

    do {
        std::wstring wProcessName(pe32.szExeFile);
        std::string processName(wProcessName.begin(), wProcessName.end());

        // Skip system processes
        if (pe32.th32ProcessID == 0 || pe32.th32ProcessID == 4) {
            continue;
        }

        // Get process path
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
        std::string processPath = "";

        if (hProcess != NULL) {
            char path[MAX_PATH] = "";
            if (GetModuleFileNameExA(hProcess, NULL, path, MAX_PATH) > 0) {
                processPath = path;
            }
            CloseHandle(hProcess);
        }

        // Get process architecture
        ProcessArch arch = GetProcessArchitecture(pe32.th32ProcessID);

        // Add to the list
        status.processList.push_back(ProcessInfo(pe32.th32ProcessID, processName, processPath, arch));

    } while (Process32Next(snapshot, &pe32));

    CloseHandle(snapshot);

    // Sort the process list alphabetically by name
    std::sort(status.processList.begin(), status.processList.end(),
        [](const ProcessInfo& a, const ProcessInfo& b) {
            return a.processName < b.processName;
        });
}

// Function to display the process list
void DisplayProcessList(const AppStatus& status) {
    std::cout << "Available processes:" << std::endl;
    std::cout << "-------------------" << std::endl;
    
    for (size_t i = 0; i < status.processList.size(); i++) {
        const auto& process = status.processList[i];
        
        std::string archStr;
        switch (process.architecture) {
        case ProcessArch::x86: archStr = "(32-bit)"; break;
        case ProcessArch::x64: archStr = "(64-bit)"; break;
        default: archStr = "(Unknown)"; break;
        }
        
        std::cout << i << ": " << process.processName << " " << archStr << " - PID: " << process.processId;
        if (!process.processPath.empty()) {
            std::cout << " - Path: " << process.processPath;
        }
        std::cout << std::endl;
    }
    std::cout << "-------------------" << std::endl;
}

// Function to list recent DLLs
void ListRecentDLLs() {
    if (g_RecentDLLs.empty()) {
        std::cout << "No recent DLLs found." << std::endl;
        return;
    }

    std::cout << "Recent DLLs:" << std::endl;
    std::cout << "------------" << std::endl;
    
    for (size_t i = 0; i < g_RecentDLLs.size(); i++) {
        std::cout << i << ": " << g_RecentDLLs[i] << std::endl;
    }
    std::cout << "------------" << std::endl;
}

bool InjectDLL(AppStatus& status) {
    if (!status.processSelected || status.targetProcessId == 0) {
        std::cout << "ERROR: No process selected" << std::endl;
        return false;
    }

    if (status.dllPath.empty() || !status.dllSelected) {
        std::cout << "ERROR: No DLL selected" << std::endl;
        return false;
    }

    // Check architecture compatibility
    if (status.dllArch != ProcessArch::Unknown && status.targetProcessArch != ProcessArch::Unknown) {
        if (status.dllArch != status.targetProcessArch) {
            std::cout << "ERROR: Architecture mismatch! Cannot inject a " 
                      << (status.dllArch == ProcessArch::x86 ? "32-bit" : "64-bit")
                      << " DLL into a " 
                      << (status.targetProcessArch == ProcessArch::x86 ? "32-bit" : "64-bit")
                      << " process" << std::endl;
            return false;
        }
    }

    try {
        // Get full path of the DLL
        char lpFullDLLPath[MAX_PATH];
        const DWORD dwFullPathResult = GetFullPathNameA(status.dllPath.c_str(), MAX_PATH, lpFullDLLPath, nullptr);
        if (dwFullPathResult == 0) {
            std::cout << "ERROR: Could not get full path of DLL" << std::endl;
            return false;
        }

        // Open the target process
        const HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, status.targetProcessId);
        if (hTargetProcess == INVALID_HANDLE_VALUE || hTargetProcess == NULL) {
            std::cout << "ERROR: Could not open target process" << std::endl;
            return false;
        }

        std::cout << "Injecting DLL: Allocating memory..." << std::endl;

        // Allocate memory in the target process
        const LPVOID lpPathAddress = VirtualAllocEx(hTargetProcess, nullptr, lstrlenA(lpFullDLLPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (lpPathAddress == nullptr) {
            CloseHandle(hTargetProcess);
            std::cout << "ERROR: Could not allocate memory in target process" << std::endl;
            return false;
        }

        std::cout << "Injecting DLL: Writing path..." << std::endl;

        // Write the DLL path to the allocated memory
        const DWORD dwWriteResult = WriteProcessMemory(hTargetProcess, lpPathAddress, lpFullDLLPath, lstrlenA(lpFullDLLPath) + 1, nullptr);
        if (dwWriteResult == 0) {
            VirtualFreeEx(hTargetProcess, lpPathAddress, 0, MEM_RELEASE);
            CloseHandle(hTargetProcess);
            std::cout << "ERROR: Could not write DLL path to target process" << std::endl;
            return false;
        }

        std::cout << "Injecting DLL: Getting LoadLibraryA address..." << std::endl;

        // Get the address of LoadLibraryA
        const HMODULE hModule = GetModuleHandleA("kernel32.dll");
        if (hModule == INVALID_HANDLE_VALUE || hModule == nullptr) {
            VirtualFreeEx(hTargetProcess, lpPathAddress, 0, MEM_RELEASE);
            CloseHandle(hTargetProcess);
            std::cout << "ERROR: Could not get kernel32.dll handle" << std::endl;
            return false;
        }

        const FARPROC lpFunctionAddress = GetProcAddress(hModule, "LoadLibraryA");
        if (lpFunctionAddress == nullptr) {
            VirtualFreeEx(hTargetProcess, lpPathAddress, 0, MEM_RELEASE);
            CloseHandle(hTargetProcess);
            std::cout << "ERROR: Could not get LoadLibraryA address" << std::endl;
            return false;
        }

        std::cout << "Injecting DLL: Creating remote thread..." << std::endl;

        // Create a remote thread to load the DLL
        const HANDLE hThreadCreationResult = CreateRemoteThread(hTargetProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)lpFunctionAddress, lpPathAddress, 0, nullptr);
        if (hThreadCreationResult == INVALID_HANDLE_VALUE || hThreadCreationResult == NULL) {
            VirtualFreeEx(hTargetProcess, lpPathAddress, 0, MEM_RELEASE);
            CloseHandle(hTargetProcess);
            std::cout << "ERROR: Could not create thread in target process" << std::endl;
            return false;
        }

        // Wait for the thread to finish
        std::cout << "Waiting for injection to complete..." << std::endl;
        WaitForSingleObject(hThreadCreationResult, 5000); // 5 second timeout

        // Cleanup
        CloseHandle(hThreadCreationResult);
        VirtualFreeEx(hTargetProcess, lpPathAddress, 0, MEM_RELEASE);
        CloseHandle(hTargetProcess);

        std::cout << "DLL successfully injected into " << status.targetProcessName << "!" << std::endl;
        return true;
    }
    catch (std::exception& e) {
        std::cout << "ERROR: " << e.what() << std::endl;
        return false;
    }
    catch (...) {
        std::cout << "ERROR: Unknown error during DLL injection" << std::endl;
        return false;
    }
}

void PrintUsage() {
    std::cout << "Command-Line DLL Injector" << std::endl;
    std::cout << "------------------------" << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << "  inject [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help                 Show this help message" << std::endl;
    std::cout << "  -l, --list                 List all running processes" << std::endl;
    std::cout << "  -r, --recent               List recent DLLs" << std::endl;
    std::cout << "  -p, --process <pid/name>   Select process by PID or name" << std::endl;
    std::cout << "  -d, --dll <path>           Select DLL by path" << std::endl;
    std::cout << "  -i, --index <idx>          Select process by index from list" << std::endl;
    std::cout << "  -rd, --recent-dll <idx>    Select DLL by index from recent list" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  inject -l                       List all running processes" << std::endl;
    std::cout << "  inject -r                       List recent DLLs" << std::endl;
    std::cout << "  inject -p notepad.exe -d C:\\path\\to\\mydll.dll" << std::endl;
    std::cout << "  inject -p 1234 -d C:\\path\\to\\mydll.dll" << std::endl;
    std::cout << "  inject -i 5 -d C:\\path\\to\\mydll.dll" << std::endl;
    std::cout << "  inject -p chrome.exe -rd 0" << std::endl;
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    // Set console title
    SetConsoleTitleA("Command-Line DLL Injector");
    
    // Load recent DLLs
    LoadRecentDLLs();
    
    // No arguments provided - show usage
    if (argc <= 1) {
        PrintUsage();
        return 0;
    }

    // Parse command line arguments
    bool listProcesses = false;
    bool listRecentDLLsFlag = false;
    std::string processArg;
    std::string dllArg;
    int processIndex = -1;
    int recentDllIndex = -1;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            PrintUsage();
            return 0;
        }
        else if (arg == "-l" || arg == "--list") {
            listProcesses = true;
        }
        else if (arg == "-r" || arg == "--recent") {
            listRecentDLLsFlag = true;
        }
        else if ((arg == "-p" || arg == "--process") && i + 1 < argc) {
            processArg = argv[++i];
        }
        else if ((arg == "-d" || arg == "--dll") && i + 1 < argc) {
            dllArg = argv[++i];
        }
        else if ((arg == "-i" || arg == "--index") && i + 1 < argc) {
            processIndex = atoi(argv[++i]);
        }
        else if ((arg == "-rd" || arg == "--recent-dll") && i + 1 < argc) {
            recentDllIndex = atoi(argv[++i]);
        }
    }

    // Refresh process list
    RefreshProcessList(g_Status);

    // List processes if requested
    if (listProcesses) {
        DisplayProcessList(g_Status);
        return 0;
    }

    // List recent DLLs if requested
    if (listRecentDLLsFlag) {
        ListRecentDLLs();
        return 0;
    }

    // Process selection logic
    if (!processArg.empty()) {
        // Try to parse as PID first
        DWORD pid = 0;
        try {
            pid = std::stoul(processArg);
        }
        catch (...) {
            pid = 0;
        }

        bool found = false;
        
        if (pid > 0) {
            // Search by PID
            for (const auto& process : g_Status.processList) {
                if (process.processId == pid) {
                    g_Status.targetProcessId = process.processId;
                    g_Status.targetProcessName = process.processName;
                    g_Status.targetProcessPath = process.processPath;
                    g_Status.targetProcessArch = process.architecture;
                    g_Status.processSelected = true;
                    found = true;
                    break;
                }
            }
        }
        else {
            // Search by name
            for (const auto& process : g_Status.processList) {
                if (_stricmp(process.processName.c_str(), processArg.c_str()) == 0) {
                    g_Status.targetProcessId = process.processId;
                    g_Status.targetProcessName = process.processName;
                    g_Status.targetProcessPath = process.processPath;
                    g_Status.targetProcessArch = process.architecture;
                    g_Status.processSelected = true;
                    found = true;
                    break;
                }
            }
        }

        if (!found) {
            std::cout << "Process not found: " << processArg << std::endl;
            return 1;
        }
    }
    else if (processIndex >= 0 && processIndex < static_cast<int>(g_Status.processList.size())) {
        // Select by index
        const auto& process = g_Status.processList[processIndex];
        g_Status.targetProcessId = process.processId;
        g_Status.targetProcessName = process.processName;
        g_Status.targetProcessPath = process.processPath;
        g_Status.targetProcessArch = process.architecture;
        g_Status.processSelected = true;
    }
    else if (processArg.empty() && processIndex == -1) {
        std::cout << "No process specified. Use -p, --process or -i, --index to specify a process." << std::endl;
        return 1;
    }

    // DLL selection logic
    if (!dllArg.empty()) {
        if (!FileExists(dllArg)) {
            std::cout << "DLL file not found: " << dllArg << std::endl;
            return 1;
        }

        g_Status.dllPath = dllArg;
        g_Status.dllSelected = true;
        g_Status.dllArch = GetDLLArchitecture(g_Status.dllPath);
        
        // Add to recent DLLs
        AddRecentDLL(g_Status.dllPath);
    }
    else if (recentDllIndex >= 0 && recentDllIndex < static_cast<int>(g_RecentDLLs.size())) {
        // Select from recent DLLs
        g_Status.dllPath = g_RecentDLLs[recentDllIndex];
        g_Status.dllSelected = true;
        g_Status.dllArch = GetDLLArchitecture(g_Status.dllPath);
    }
    else if (dllArg.empty() && recentDllIndex == -1) {
        std::cout << "No DLL specified. Use -d, --dll or -rd, --recent-dll to specify a DLL." << std::endl;
        return 1;
    }

    // Print selected process and DLL
    if (g_Status.processSelected) {
        std::string archStr;
        switch (g_Status.targetProcessArch) {
        case ProcessArch::x86: archStr = "(32-bit)"; break;
        case ProcessArch::x64: archStr = "(64-bit)"; break;
        default: archStr = "(Unknown)"; break;
        }
        
        std::cout << "Selected process: " << g_Status.targetProcessName << " " << archStr 
                  << " - PID: " << g_Status.targetProcessId << std::endl;
    }

    if (g_Status.dllSelected) {
        std::string archStr;
        switch (g_Status.dllArch) {
        case ProcessArch::x86: archStr = "(32-bit)"; break;
        case ProcessArch::x64: archStr = "(64-bit)"; break;
        default: archStr = "(Unknown)"; break;
        }
        
        std::cout << "Selected DLL: " << g_Status.dllPath << " " << archStr << std::endl;
    }

    // If both process and DLL are selected, perform injection
    if (g_Status.processSelected && g_Status.dllSelected) {
        return InjectDLL(g_Status) ? 0 : 1;
    }

    return 0;
}