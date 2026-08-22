#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <mutex>
#include <fstream>
#include <ctime>

class Logger {
public:
    static Logger& GetInstance();

    // Initialize UI handle for log edit control
    void SetLogEditWindow(HWND hLogEdit);

    // Primary logging function
    void Log(const std::string& msg);

    // Retrieve full in-memory log history
    std::string GetLogHistory();

    // Clear logs from memory and clear file
    void ClearLogs();

private:
    Logger() = default;
    ~Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    HWND m_hLogEdit = NULL;
    std::vector<std::string> m_logMemory;
    std::mutex m_logMutex;
    const std::string m_logFileName = "FastSystemSecurity.log";
};