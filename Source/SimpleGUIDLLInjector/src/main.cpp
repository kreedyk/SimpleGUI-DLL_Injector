#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <d3d11.h>
#include <tchar.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <Windows.h>
#include <Shlobj.h>
#include <algorithm>
#include <mutex>
#include <tlhelp32.h>
#include <Psapi.h>
#include "resource.h"
#pragma warning(disable:4996)

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Global variables
static ID3D11Device* g_pd3dDevice = NULL;
static ID3D11DeviceContext* g_pd3dDeviceContext = NULL;
static IDXGISwapChain* g_pSwapChain = NULL;
static ID3D11RenderTargetView* g_mainRenderTargetView = NULL;

// Colors matching the original application
ImVec4 COLOR_MAINBACKGROUND = ImVec4(1.0f, 0.94f, 0.97f, 1.0f); // #FFF0F5 LavenderBlush
ImVec4 COLOR_FRAME_BG = ImVec4(1.0f, 0.92f, 0.95f, 1.0f); // #FFEBF3 Light pink
ImVec4 COLOR_BUTTON_BG = ImVec4(1.0f, 0.41f, 0.71f, 1.0f); // #FF69B4 HotPink
ImVec4 COLOR_BUTTON_HOVER = ImVec4(1.0f, 0.08f, 0.58f, 1.0f); // #FF1493 DeepPink
ImVec4 COLOR_TEXT = ImVec4(0.43f, 0.13f, 0.31f, 1.0f); // #6D214F Dark pink text
ImVec4 COLOR_TITLE = ImVec4(0.43f, 0.13f, 0.31f, 1.0f); // #6D214F Dark pink title
ImVec4 COLOR_PROGRESS = ImVec4(1.0f, 0.41f, 0.71f, 1.0f); // #FF69B4 Pink progress bar
ImVec4 COLOR_SEPARATOR = ImVec4(1.0f, 0.41f, 0.71f, 1.0f); // #FF69B4 Pink separator
ImVec4 COLOR_BUTTON_TEXT = ImVec4(1.0f, 1.0f, 1.0f, 1.0f); // White text for buttons
ImVec4 COLOR_2BACKGROUND = ImVec4(1.0f, 0.94f, 0.97f, 1.0f); // Same as MAINBACKGROUND
ImVec4 COLOR_CLOSE_BUTTON = ImVec4(0.7f, 0.2f, 0.3f, 1.0f); // Softer red for Close button
ImVec4 COLOR_COPYRIGHT = ImVec4(0.7f, 0.3f, 0.5f, 1.0f); // Pink for copyright text
ImVec4 COLOR_DROP_ZONE = ImVec4(0.95f, 0.85f, 0.9f, 1.0f); // Light pink for drop zone
ImVec4 COLOR_DROP_TEXT = ImVec4(0.6f, 0.2f, 0.4f, 1.0f); // Darker pink for drop text

float WINDOW_WIDTH = 500.0f;
float WINDOW_HEIGHT = 710.0f;

float FONT_SIZE_TITLE = 34.0f;
float FONT_SIZE_SUBTITLE = 20.0f;
float FONT_SIZE_NORMAL = 17.0f;
float FONT_SIZE_SECTION = 20.0f;
float FONT_SIZE_BUTTON = 20.0f;

// Vector to store recent DLLs
std::vector<std::string> g_RecentDLLs;
static int selectedDLLIndex = -1;

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

// Global AppStatus instance that can be accessed from process selector window
AppStatus g_Status;

// ImGui Process Selector variables
bool g_ShowProcessSelector = false;
char g_ProcessFilterBuffer[256] = "";
std::vector<size_t> g_FilteredProcessIndices;

// Helper function to create the main window
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Process and DLL functions
void RefreshProcessList(AppStatus& status);
ProcessArch GetProcessArchitecture(DWORD processId);
ProcessArch GetDLLArchitecture(const std::string& dllPath);
bool InjectDLL(AppStatus& status);
void OpenProcessSelector();
void FilterProcessList(const char* filter);
void RenderProcessSelector();
void EnableDragDrop(HWND hwnd);
void SaveRecentDLLs();
void LoadRecentDLLs();
void AddRecentDLL(const std::string& dllPath);

// Section frame with title and separator (from reference code)
void BeginSection(const char* title, float* yPos, float height = 100.0f) {
    // Set the cursor position
    ImGui::SetCursorPosY(*yPos);

    // Draw section title
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[1]); // Use the section font
    ImGui::Text("%s", title);
    ImGui::PopFont();

    // Draw pink separator
    ImGui::PushStyleColor(ImGuiCol_Separator, COLOR_SEPARATOR);
    ImGui::Separator();
    ImGui::PopStyleColor();

    // Start child frame
    ImGui::PushStyleColor(ImGuiCol_ChildBg, COLOR_FRAME_BG);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 5.0f);

    ImGui::BeginChild(title, ImVec2(WINDOW_WIDTH - 40, height), true);
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[0]); // Use normal font

    // Update cursor position for next section
    *yPos += height + 40;
}

void EndSection() {
    ImGui::PopFont(); // Pop normal font
    ImGui::EndChild();
    ImGui::PopStyleVar(); // Pop ChildRounding
    ImGui::PopStyleColor(); // Pop ChildBg
}

// Function to check if file exists
static bool FileExists(const std::string& path) {
    DWORD fileAttributes = GetFileAttributesA(path.c_str());
    return (fileAttributes != INVALID_FILE_ATTRIBUTES &&
        !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY));
}

// Function to get parent path
static std::string GetParentPath(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    if (pos != std::string::npos) {
        return path.substr(0, pos);
    }
    return "";
}

// Function to get file name from path
static std::string GetFileName(const std::string& path) {
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

// Function to enable drag and drop for the window
void EnableDragDrop(HWND hwnd) {
    // Enable accepting dragged files to the window
    DragAcceptFiles(hwnd, TRUE);
}

// Thread function for DLL injection to ensure UI updates
DWORD WINAPI InjectDLLThreadFunc(LPVOID lpParam) {
    AppStatus* status = (AppStatus*)lpParam;
    InjectDLL(*status);
    return 0;
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

// ImGui Process Selector Functions
void OpenProcessSelector() {
    // If selector is already open, do nothing
    if (g_ShowProcessSelector)
        return;

    // Refresh the process list
    RefreshProcessList(g_Status);

    // Initially, all processes are visible
    g_FilteredProcessIndices.clear();
    for (size_t i = 0; i < g_Status.processList.size(); i++) {
        g_FilteredProcessIndices.push_back(i);
    }

    // Clear the filter
    memset(g_ProcessFilterBuffer, 0, sizeof(g_ProcessFilterBuffer));

    // Show the selector window
    g_ShowProcessSelector = true;
}

// Function to filter the process list
void FilterProcessList(const char* filter) {
    g_FilteredProcessIndices.clear();

    std::string filterStr = filter;
    std::transform(filterStr.begin(), filterStr.end(), filterStr.begin(), ::tolower);

    for (size_t i = 0; i < g_Status.processList.size(); i++) {
        std::string processName = g_Status.processList[i].processName;
        std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

        if (filterStr.empty() || processName.find(filterStr) != std::string::npos) {
            g_FilteredProcessIndices.push_back(i);
        }
    }
}

// Function to render the ImGui process selector
void RenderProcessSelector() {
    if (!g_ShowProcessSelector)
        return;

    // Window configuration
    ImGui::SetNextWindowSize(ImVec2(500, 440), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImVec2((ImGui::GetIO().DisplaySize.x - 500) * 0.5f,
        (ImGui::GetIO().DisplaySize.y - 440) * 0.5f),
        ImGuiCond_FirstUseEver);

    // Begin modal window
    bool isOpen = true;
    if (ImGui::Begin("Select Process", &isOpen, ImGuiWindowFlags_NoCollapse)) {
        // Filter bar and refresh button
        ImGui::PushItemWidth(ImGui::GetContentRegionAvail().x - 110);
        if (ImGui::InputTextWithHint("##filter", "Filter processes...", g_ProcessFilterBuffer, sizeof(g_ProcessFilterBuffer))) {
            FilterProcessList(g_ProcessFilterBuffer);
        }
        ImGui::PopItemWidth();

        ImGui::SameLine();

        if (ImGui::Button("Refresh", ImVec2(100, 0))) {
            RefreshProcessList(g_Status);
            FilterProcessList(g_ProcessFilterBuffer);
        }

        // Process listing area with scroll
        if (ImGui::BeginChild("ProcessList", ImVec2(0, ImGui::GetContentRegionAvail().y - 40), true)) {
            for (size_t filteredIdx = 0; filteredIdx < g_FilteredProcessIndices.size(); filteredIdx++) {
                size_t processIdx = g_FilteredProcessIndices[filteredIdx];
                const auto& process = g_Status.processList[processIdx];

                // Build process display name
                std::string archStr;
                switch (process.architecture) {
                case ProcessArch::x86: archStr = " (32-bit)"; break;
                case ProcessArch::x64: archStr = " (64-bit)"; break;
                default: archStr = ""; break;
                }

                std::string displayName = process.processName + archStr + " - PID: " + std::to_string(process.processId);

                // Render list item
                if (ImGui::Selectable(displayName.c_str(), false)) {
                    // Process selected
                    g_Status.targetProcessId = process.processId;
                    g_Status.targetProcessName = process.processName;
                    g_Status.targetProcessPath = process.processPath;
                    g_Status.targetProcessArch = process.architecture;
                    g_Status.processSelected = true;

                    // Update status
                    g_Status.updateInjectionStatus("Process selected: " + process.processName + archStr);

                    // Check compatibility with selected DLL
                    if (g_Status.dllSelected && g_Status.dllArch != ProcessArch::Unknown &&
                        g_Status.targetProcessArch != ProcessArch::Unknown) {
                        if (g_Status.dllArch != g_Status.targetProcessArch) {
                            g_Status.updateInjectionStatus("WARNING: Architecture mismatch! Cannot inject a " +
                                std::string(g_Status.dllArch == ProcessArch::x86 ? "32-bit" : "64-bit") +
                                " DLL into a " +
                                std::string(g_Status.targetProcessArch == ProcessArch::x86 ? "32-bit" : "64-bit") +
                                " process", 0);
                        }
                    }

                    // Close the window
                    g_ShowProcessSelector = false;
                }

                // Tooltips to show full process path on hover
                if (ImGui::IsItemHovered() && !process.processPath.empty()) {
                    ImGui::BeginTooltip();
                    ImGui::TextUnformatted(process.processPath.c_str());
                    ImGui::EndTooltip();
                }
            }
        }
        ImGui::EndChild();

        // Cancel button
        ImGui::SetCursorPosX((ImGui::GetWindowSize().x - 100) * 0.5f);
        if (ImGui::Button("Cancel", ImVec2(100, 30)) || !isOpen) {
            g_ShowProcessSelector = false;
        }
    }
    ImGui::End();

    // If window was closed by X button
    if (!isOpen) {
        g_ShowProcessSelector = false;
    }
}

bool InjectDLL(AppStatus& status) {
    if (!status.processSelected || status.targetProcessId == 0) {
        status.updateInjectionStatus("ERROR: No process selected", 0);
        return false;
    }

    if (status.dllPath.empty() || !status.dllSelected) {
        status.updateInjectionStatus("ERROR: No DLL selected", 0);
        return false;
    }

    // Check architecture compatibility
    if (status.dllArch != ProcessArch::Unknown && status.targetProcessArch != ProcessArch::Unknown) {
        if (status.dllArch != status.targetProcessArch) {
            status.updateInjectionStatus("ERROR: Architecture mismatch! Cannot inject a " +
                std::string(status.dllArch == ProcessArch::x86 ? "32-bit" : "64-bit") +
                " DLL into a " +
                std::string(status.targetProcessArch == ProcessArch::x86 ? "32-bit" : "64-bit") +
                " process", 0);
            return false;
        }
    }

    try {
        // Get full path of the DLL
        char lpFullDLLPath[MAX_PATH];
        const DWORD dwFullPathResult = GetFullPathNameA(status.dllPath.c_str(), MAX_PATH, lpFullDLLPath, nullptr);
        if (dwFullPathResult == 0) {
            status.updateInjectionStatus("ERROR: Could not get full path of DLL", 0);
            return false;
        }

        // Open the target process
        const HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, status.targetProcessId);
        if (hTargetProcess == INVALID_HANDLE_VALUE || hTargetProcess == NULL) {
            status.updateInjectionStatus("ERROR: Could not open target process", 0);
            return false;
        }

        status.updateInjectionStatus("Injecting DLL: Allocating memory...", 25);
        Sleep(100); // Small delay to ensure UI updates

        // Allocate memory in the target process
        const LPVOID lpPathAddress = VirtualAllocEx(hTargetProcess, nullptr, lstrlenA(lpFullDLLPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (lpPathAddress == nullptr) {
            CloseHandle(hTargetProcess);
            status.updateInjectionStatus("ERROR: Could not allocate memory in target process", 0);
            return false;
        }

        status.updateInjectionStatus("Injecting DLL: Writing path...", 50);
        Sleep(100); // Small delay to ensure UI updates

        // Write the DLL path to the allocated memory
        const DWORD dwWriteResult = WriteProcessMemory(hTargetProcess, lpPathAddress, lpFullDLLPath, lstrlenA(lpFullDLLPath) + 1, nullptr);
        if (dwWriteResult == 0) {
            VirtualFreeEx(hTargetProcess, lpPathAddress, 0, MEM_RELEASE);
            CloseHandle(hTargetProcess);
            status.updateInjectionStatus("ERROR: Could not write DLL path to target process", 0);
            return false;
        }

        status.updateInjectionStatus("Injecting DLL: Getting LoadLibraryA address...", 75);
        Sleep(100); // Small delay to ensure UI updates

        // Get the address of LoadLibraryA
        const HMODULE hModule = GetModuleHandleA("kernel32.dll");
        if (hModule == INVALID_HANDLE_VALUE || hModule == nullptr) {
            VirtualFreeEx(hTargetProcess, lpPathAddress, 0, MEM_RELEASE);
            CloseHandle(hTargetProcess);
            status.updateInjectionStatus("ERROR: Could not get kernel32.dll handle", 0);
            return false;
        }

        const FARPROC lpFunctionAddress = GetProcAddress(hModule, "LoadLibraryA");
        if (lpFunctionAddress == nullptr) {
            VirtualFreeEx(hTargetProcess, lpPathAddress, 0, MEM_RELEASE);
            CloseHandle(hTargetProcess);
            status.updateInjectionStatus("ERROR: Could not get LoadLibraryA address", 0);
            return false;
        }

        status.updateInjectionStatus("Injecting DLL: Creating remote thread...", 90);
        Sleep(100); // Small delay to ensure UI updates

        // Create a remote thread to load the DLL
        const HANDLE hThreadCreationResult = CreateRemoteThread(hTargetProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)lpFunctionAddress, lpPathAddress, 0, nullptr);
        if (hThreadCreationResult == INVALID_HANDLE_VALUE || hThreadCreationResult == NULL) {
            VirtualFreeEx(hTargetProcess, lpPathAddress, 0, MEM_RELEASE);
            CloseHandle(hTargetProcess);
            status.updateInjectionStatus("ERROR: Could not create thread in target process", 0);
            return false;
        }

        // Wait for the thread to finish
        WaitForSingleObject(hThreadCreationResult, 5000); // 5 second timeout

        // Cleanup
        CloseHandle(hThreadCreationResult);
        VirtualFreeEx(hTargetProcess, lpPathAddress, 0, MEM_RELEASE);
        CloseHandle(hTargetProcess);

        status.updateInjectionStatus("DLL successfully injected into " + status.targetProcessName + "!", 100);
        Sleep(100); // Ensure UI updates
        return true;
    }
    catch (std::exception& e) {
        status.updateInjectionStatus(std::string("ERROR: ") + e.what(), 0);
        return false;
    }
    catch (...) {
        status.updateInjectionStatus("ERROR: Unknown error during DLL injection", 0);
        return false;
    }
}

// Styling function
static void SetImGuiStyle() {
    ImGuiStyle& style = ImGui::GetStyle();

    // Colors
    ImVec4* colors = style.Colors;
    colors[ImGuiCol_WindowBg] = COLOR_MAINBACKGROUND;
    colors[ImGuiCol_FrameBg] = COLOR_FRAME_BG;
    colors[ImGuiCol_Button] = COLOR_BUTTON_BG;
    colors[ImGuiCol_ButtonHovered] = COLOR_BUTTON_HOVER;
    colors[ImGuiCol_ButtonActive] = ImVec4(COLOR_BUTTON_HOVER.x * 0.8f, COLOR_BUTTON_HOVER.y * 0.8f, COLOR_BUTTON_HOVER.z * 0.8f, 1.0f);
    colors[ImGuiCol_Text] = COLOR_TEXT;
    colors[ImGuiCol_PlotHistogram] = COLOR_PROGRESS;
    colors[ImGuiCol_Border] = COLOR_BUTTON_BG;
    colors[ImGuiCol_Separator] = COLOR_SEPARATOR;
    colors[ImGuiCol_Header] = COLOR_BUTTON_BG;
    colors[ImGuiCol_HeaderHovered] = COLOR_BUTTON_HOVER;
    colors[ImGuiCol_HeaderActive] = ImVec4(COLOR_BUTTON_HOVER.x * 0.8f, COLOR_BUTTON_HOVER.y * 0.8f, COLOR_BUTTON_HOVER.z * 0.8f, 1.0f);
    colors[ImGuiCol_TitleBg] = COLOR_FRAME_BG;
    colors[ImGuiCol_TitleBgActive] = COLOR_BUTTON_BG;
    colors[ImGuiCol_ScrollbarBg] = COLOR_FRAME_BG;
    colors[ImGuiCol_ScrollbarGrab] = COLOR_BUTTON_BG;
    colors[ImGuiCol_ScrollbarGrabHovered] = COLOR_BUTTON_HOVER;
    colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(COLOR_BUTTON_HOVER.x * 0.8f, COLOR_BUTTON_HOVER.y * 0.8f, COLOR_BUTTON_HOVER.z * 0.8f, 1.0f);
    colors[ImGuiCol_ChildBg] = COLOR_FRAME_BG;

    // Styling
    style.WindowRounding = 10.0f;
    style.FrameRounding = 5.0f;
    style.ChildRounding = 5.0f;
    style.GrabRounding = 5.0f;
    style.PopupRounding = 5.0f;
    style.ScrollbarRounding = 5.0f;
    style.TabRounding = 5.0f;

    style.FramePadding = ImVec2(10, 8);
    style.ItemSpacing = ImVec2(10, 10);
    style.ItemInnerSpacing = ImVec2(10, 6);
    style.ButtonTextAlign = ImVec2(0.5f, 0.5f);
    style.WindowTitleAlign = ImVec2(0.5f, 0.5f);

    // Button padding
    style.FramePadding = ImVec2(15, 10);

    // Increase sizes for better visibility
    style.ScrollbarSize = 16.0f;
    style.FrameBorderSize = 1.0f;
    style.ChildBorderSize = 1.0f;

    // No window resize option
    style.WindowMinSize = ImVec2(WINDOW_WIDTH, WINDOW_HEIGHT);
}

// Helper functions for DirectX setup
bool CreateDeviceD3D(HWND hWnd)
{
    // Setup swap chain
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
    if (D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK)
        return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = NULL; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = NULL; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = NULL; }
}

void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = NULL; }
}

// Win32 window procedure
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_DROPFILES:
    {
        HDROP hDrop = (HDROP)wParam;
        char szFileName[MAX_PATH];

        // Get the first dropped file (ignore multiple files)
        if (DragQueryFileA(hDrop, 0, szFileName, MAX_PATH) > 0) {
            // Check if it's a .dll file
            std::string filePath = szFileName;
            std::string extension = filePath.substr(filePath.find_last_of(".") + 1);
            std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

            if (extension == "dll") {
                // Update status with the selected file
                g_Status.dllPath = filePath;
                g_Status.dllSelected = true;
                g_Status.dllArch = GetDLLArchitecture(g_Status.dllPath);

                std::string archString;
                switch (g_Status.dllArch) {
                case ProcessArch::x86: archString = " (32-bit)"; break;
                case ProcessArch::x64: archString = " (64-bit)"; break;
                default: archString = " (Unknown architecture)"; break;
                }

                g_Status.updateInjectionStatus("DLL dropped: " + GetFileName(g_Status.dllPath) + archString);

                // Add to recent DLLs
                AddRecentDLL(g_Status.dllPath);
            }
            else {
                g_Status.updateInjectionStatus("ERROR: Dropped file is not a DLL");
            }
        }

        DragFinish(hDrop);
        return 0;
    }
    case WM_SIZE:
        if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
        {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProc(hWnd, msg, wParam, lParam);
}

// Main code
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Create application window
    WNDCLASSEX wc = {
    sizeof(WNDCLASSEX),
    CS_CLASSDC,
    WndProc,
    0L,
    0L,
    GetModuleHandle(NULL),
    LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_ICON1)),
    NULL,
    NULL,
    NULL,
    _T("Simple GUI DLL Injector"),
    NULL
    };

    ::RegisterClassEx(&wc);

    // Create window with no maximize button
    HWND hwnd = ::CreateWindow(wc.lpszClassName, _T("Simple GUI DLL Injector"),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        100, 100, (int)WINDOW_WIDTH, (int)WINDOW_HEIGHT, NULL, NULL, wc.hInstance, NULL);

    // Initialize Direct3D
    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    // Show the window
    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    // Enable drag and drop for the window
    EnableDragDrop(hwnd);

    // Load recent DLLs
    LoadRecentDLLs();

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;  // Enable Keyboard Controls
    io.ConfigWindowsMoveFromTitleBarOnly = true;           // Only move from title bar

    // Fonts setup
    // We'll add 5 fonts: Normal, Section, Title, Subtitle, Button
    float fontSizes[] = { FONT_SIZE_NORMAL, FONT_SIZE_SECTION, FONT_SIZE_TITLE, FONT_SIZE_SUBTITLE, FONT_SIZE_BUTTON };

    // Try to load Segoe UI Bold for all sizes
    for (int i = 0; i < 5; i++) {
        ImFontConfig config;
        config.SizePixels = fontSizes[i];
        config.OversampleH = 3;
        config.OversampleV = 1;
        config.PixelSnapH = true;
        config.GlyphExtraSpacing = ImVec2(1.0f, 1.0f);

        // Try to load fonts in this order: Segoe UI Bold, Segoe UI, Arial Bold, Arial, Default
        ImFont* font = NULL;

        // Try Segoe UI Bold
        font = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeuib.ttf", fontSizes[i], &config);

        // If failed, try Segoe UI
        if (font == NULL) {
            font = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", fontSizes[i], &config);
        }

        // If failed, try Arial Bold
        if (font == NULL) {
            font = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\arialbd.ttf", fontSizes[i], &config);
        }

        // If failed, try Arial
        if (font == NULL) {
            font = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\arial.ttf", fontSizes[i], &config);
        }

        // If all failed, add default scaled font
        if (font == NULL) {
            config.SizePixels = fontSizes[i];
            io.Fonts->AddFontDefault(&config);
        }
    }

    // Setup Platform/Renderer backends
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    // Setup style
    SetImGuiStyle();

    // Initial process list refresh
    RefreshProcessList(g_Status);

    // Buffer for manual DLL path entry
    static char dllPathBuffer[256] = "";

    // Main loop
    bool done = false;
    while (!done)
    {
        // Poll and handle messages
        MSG msg;
        while (::PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done)
            break;

        // Start the Dear ImGui frame
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // Create main window
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2(WINDOW_WIDTH, WINDOW_HEIGHT));

        // Start main window with flags for no resizing, no scrollbar
        ImGui::PushStyleColor(ImGuiCol_WindowBg, COLOR_2BACKGROUND);
        ImGui::Begin("Simple GUI DLL Injector", NULL,
            ImGuiWindowFlags_NoTitleBar |
            ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoScrollbar);

        // Title - Using large font (index 2)
        ImGui::SetCursorPosY(15);
        ImGui::PushFont(io.Fonts->Fonts[2]);
        ImVec2 titleSize = ImGui::CalcTextSize("Simple GUI DLL Injector");
        ImGui::SetCursorPosX((WINDOW_WIDTH - titleSize.x) * 0.5f);
        ImGui::TextColored(COLOR_TITLE, "Simple GUI DLL Injector");
        ImGui::PopFont();

        // Subtitle - Using subtitle font (index 3)
        ImGui::PushFont(io.Fonts->Fonts[3]);
        ImVec2 subtitleSize = ImGui::CalcTextSize("Developed by kreed");
        ImGui::SetCursorPosX((WINDOW_WIDTH - subtitleSize.x) * 0.5f);
        ImGui::TextColored(COLOR_TEXT, "Developed by kreed");
        ImGui::PopFont();

        // Add copyright as small text under subtitle
        ImGui::PushFont(io.Fonts->Fonts[0]); // Use smaller normal font
        char yearBuffer[5];
        time_t t = time(NULL);
        struct tm* timeinfo = localtime(&t);
        strftime(yearBuffer, sizeof(yearBuffer), "%Y", timeinfo);

        std::string copyrightText = "Copyright " + std::string(yearBuffer) + " All Rights Reserved";
        ImVec2 copyrightSize = ImGui::CalcTextSize(copyrightText.c_str());
        ImGui::SetCursorPosX((WINDOW_WIDTH - copyrightSize.x) * 0.5f);
        ImGui::TextColored(COLOR_COPYRIGHT, "%s", copyrightText.c_str());
        ImGui::PopFont();

        // Main Layout using sections
        float yPos = 100.0f;

        // Process Selection Section
        BeginSection("Process", &yPos, 60);

        // Process selection display
        const char* processText = g_Status.processSelected ?
            (g_Status.targetProcessName + " (PID: " + std::to_string(g_Status.targetProcessId) + ")").c_str() :
            "No process selected";

        ImGui::PushItemWidth(ImGui::GetContentRegionAvail().x - 120);
        char processBuf[256];
        strcpy_s(processBuf, processText);
        ImGui::PushStyleColor(ImGuiCol_Text, COLOR_TEXT);
        ImGui::InputText("##process", processBuf, sizeof(processBuf), ImGuiInputTextFlags_ReadOnly);
        ImGui::PopStyleColor();
        ImGui::PopItemWidth();

        // Browse process button
        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Text, COLOR_BUTTON_TEXT);
        if (ImGui::Button("Select", ImVec2(110, 0))) {
            OpenProcessSelector();
        }
        ImGui::PopStyleColor();

        EndSection();

        // DLL Selection Section
        BeginSection("DLL File", &yPos, 60);

        // DLL path display with manual editing
        ImGui::PushItemWidth(ImGui::GetContentRegionAvail().x - 120);
        ImGui::PushStyleColor(ImGuiCol_Text, COLOR_TEXT);

        // Copy the current path to buffer if DLL is selected
        if (g_Status.dllSelected && strlen(dllPathBuffer) == 0) {
            strcpy_s(dllPathBuffer, g_Status.dllPath.c_str());
        }

        // Allow direct editing of the path
        if (ImGui::InputText("##dllpath", dllPathBuffer, sizeof(dllPathBuffer))) {
            // Check if the path exists when user finishes editing
            if (FileExists(dllPathBuffer)) {
                g_Status.dllPath = dllPathBuffer;
                g_Status.dllSelected = true;

                // Determine DLL architecture
                g_Status.dllArch = GetDLLArchitecture(g_Status.dllPath);

                std::string archString;
                switch (g_Status.dllArch) {
                case ProcessArch::x86: archString = " (32-bit)"; break;
                case ProcessArch::x64: archString = " (64-bit)"; break;
                default: archString = " (Unknown architecture)"; break;
                }

                g_Status.updateInjectionStatus("DLL selected: " + GetFileName(g_Status.dllPath) + archString);

                // Add to recent DLLs
                AddRecentDLL(g_Status.dllPath);

                // Check compatibility
                if (g_Status.processSelected && g_Status.dllArch != ProcessArch::Unknown &&
                    g_Status.targetProcessArch != ProcessArch::Unknown) {
                    if (g_Status.dllArch != g_Status.targetProcessArch) {
                        g_Status.updateInjectionStatus("WARNING: Architecture mismatch! " +
                            GetFileName(g_Status.dllPath) + archString + " cannot be injected into " +
                            g_Status.targetProcessName + (g_Status.targetProcessArch == ProcessArch::x86 ? " (32-bit)" : " (64-bit)"), 0);
                    }
                }
            }
        }

        ImGui::PopStyleColor();
        ImGui::PopItemWidth();

        // Browse button
        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Text, COLOR_BUTTON_TEXT);
        if (ImGui::Button("Browse", ImVec2(110, 0))) {
            char filename[MAX_PATH] = "";

            OPENFILENAMEA ofn = { 0 };
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = NULL;
            ofn.lpstrFilter = "DLL Files\0*.dll\0All Files\0*.*\0";
            ofn.lpstrFile = filename;
            ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
            ofn.lpstrTitle = "Select DLL to inject";

            if (GetOpenFileNameA(&ofn)) {
                g_Status.dllPath = filename;
                g_Status.dllSelected = true;
                g_Status.dllArch = GetDLLArchitecture(g_Status.dllPath);

                // Copy to the buffer for display
                strcpy_s(dllPathBuffer, g_Status.dllPath.c_str());

                std::string archString;
                switch (g_Status.dllArch) {
                case ProcessArch::x86: archString = " (32-bit)"; break;
                case ProcessArch::x64: archString = " (64-bit)"; break;
                default: archString = " (Unknown architecture)"; break;
                }

                g_Status.updateInjectionStatus("DLL selected: " + GetFileName(g_Status.dllPath) + archString);

                // Add to recent DLLs
                AddRecentDLL(g_Status.dllPath);
            }
        }
        ImGui::PopStyleColor();

        EndSection();

        // Add spacing to move the drop zone down
        yPos += 15.0f;

        // Drop zone indicator without section title
        ImGui::SetCursorPosY(yPos);

        // Create a drop zone container without a title
        ImGui::PushStyleColor(ImGuiCol_ChildBg, COLOR_FRAME_BG);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 5.0f);
        ImGui::BeginChild("DropZone", ImVec2(WINDOW_WIDTH - 30, 65), true);

        // Center the text in the drop zone
        ImGui::PushStyleColor(ImGuiCol_Text, COLOR_DROP_TEXT);
        ImVec2 dropTextSize = ImGui::CalcTextSize("Drag and drop your DLL file here");
        ImGui::SetCursorPos(ImVec2((ImGui::GetContentRegionAvail().x - dropTextSize.x) * 0.5f,
            (ImGui::GetContentRegionAvail().y - dropTextSize.y) * 0.5f));
        ImGui::Text("Drag and drop your DLL file here");
        ImGui::PopStyleColor();

        ImGui::EndChild();
        ImGui::PopStyleVar();
        ImGui::PopStyleColor();

        // Update position for next element
        yPos += 70.0f;

        // Recent DLLs section
        BeginSection("Recent DLLs", &yPos, 60);

        // If the list is empty, add a placeholder
        if (g_RecentDLLs.empty()) {
            static const char* noRecentDlls = "No recent DLLs";
            ImGui::PushItemWidth(ImGui::GetContentRegionAvail().x);
            ImGui::Combo("##recentdlls", &selectedDLLIndex, &noRecentDlls, 1);
            ImGui::PopItemWidth();
        }
        else {
            // Create an array of const char* for the combo box
            std::vector<const char*> dllItems;
            for (const auto& dll : g_RecentDLLs) {
                dllItems.push_back(dll.c_str());
            }

            ImGui::PushItemWidth(ImGui::GetContentRegionAvail().x);
            if (ImGui::Combo("##recentdlls", &selectedDLLIndex, dllItems.data(), dllItems.size())) {
                if (selectedDLLIndex >= 0 && selectedDLLIndex < g_RecentDLLs.size()) {
                    g_Status.dllPath = g_RecentDLLs[selectedDLLIndex];
                    g_Status.dllSelected = true;
                    g_Status.dllArch = GetDLLArchitecture(g_Status.dllPath);

                    // Update the manual path buffer
                    strcpy_s(dllPathBuffer, g_Status.dllPath.c_str());

                    std::string archString;
                    switch (g_Status.dllArch) {
                    case ProcessArch::x86: archString = " (32-bit)"; break;
                    case ProcessArch::x64: archString = " (64-bit)"; break;
                    default: archString = " (Unknown architecture)"; break;
                    }

                    g_Status.updateInjectionStatus("DLL selected: " + GetFileName(g_Status.dllPath) + archString);
                }
            }
            ImGui::PopItemWidth();
        }

        EndSection();

        // Status Section
        BeginSection("Status", &yPos, 90);

        // Status text
        ImGui::PushStyleColor(ImGuiCol_Text, COLOR_TEXT);
        ImGui::TextWrapped("%s", g_Status.getInjectionStatus().c_str());
        ImGui::PopStyleColor();

        ImGui::Spacing();
        ImGui::Spacing();

        // Progress bar
        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, COLOR_PROGRESS);
        ImGui::ProgressBar(g_Status.getInjectionProgress() / 100.0f, ImVec2(-1, 25));
        ImGui::PopStyleColor();

        EndSection();

        // Buttons - Subir mais para cima 
        ImGui::SetCursorPosY(WINDOW_HEIGHT - 90);
        ImGui::SetCursorPosX((WINDOW_WIDTH - 320) * 0.5f);
        ImGui::PushFont(io.Fonts->Fonts[4]); // Button font
        ImGui::PushStyleColor(ImGuiCol_Text, COLOR_BUTTON_TEXT);

        if (g_Status.processSelected && g_Status.dllSelected) {
            if (ImGui::Button("Inject DLL", ImVec2(200, 50))) {
                // Reset injection status first
                g_Status.updateInjectionStatus("Starting DLL injection...", 10);

                // Launch in a separate thread to keep UI responsive
                CreateThread(NULL, 0, InjectDLLThreadFunc, &g_Status, 0, NULL);
            }
        }
        else {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.5f, 0.5f, 0.5f, 1.0f));
            ImGui::Button("Inject DLL", ImVec2(200, 50));
            ImGui::PopStyleColor();
        }

        ImGui::SameLine();

        // Exit button
        if (ImGui::Button("Exit", ImVec2(100, 50))) {
            done = true;
        }

        ImGui::PopStyleColor(); // Pop button text color
        ImGui::PopFont(); // Pop button font

        // Render the ImGui process selector
        RenderProcessSelector();

        ImGui::End();
        ImGui::PopStyleColor(); // Pop COLOR_BACKGROUND

        // Rendering
        ImGui::Render();
        const float clear_color_with_alpha[4] = { COLOR_MAINBACKGROUND.x, COLOR_MAINBACKGROUND.y, COLOR_MAINBACKGROUND.z, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0); // Present with vsync
    }

    // Save recent DLLs before exiting
    SaveRecentDLLs();

    // Cleanup
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClass(wc.lpszClassName, wc.hInstance);

    return 0;
}