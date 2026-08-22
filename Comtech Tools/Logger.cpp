#include "Logger.h"

Logger& Logger::GetInstance() {
    static Logger instance;
    return instance;
}

void Logger::SetLogEditWindow(HWND hLogEdit) {
    std::lock_guard<std::mutex> lock(m_logMutex);
    m_hLogEdit = hLogEdit;
}

void Logger::Log(const std::string& msg) {
    std::lock_guard<std::mutex> lock(m_logMutex);

    // Generate formatted timestamp: [YYYY-MM-DD HH:MM:SS]
    time_t rawtime;
    struct tm timeinfo;
    char timeBuffer[64];

    time(&rawtime);
    localtime_s(&timeinfo, &rawtime);
    strftime(timeBuffer, sizeof(timeBuffer), "[%Y-%m-%d %H:%M:%S] ", &timeinfo);

    std::string formattedLog = std::string(timeBuffer) + msg;

    // 1. Store in memory buffer
    m_logMemory.push_back(formattedLog);

    // 2. Append to disk log file
    std::ofstream logFile(m_logFileName, std::ios::app);
    if (logFile.is_open()) {
        logFile << formattedLog << std::endl;
        logFile.close();
    }

    // 3. Update GUI Edit Control if attached
    if (m_hLogEdit && IsWindow(m_hLogEdit)) {
        std::string fullLogText = "";
        for (const auto& line : m_logMemory) {
            fullLogText += line + "\r\n";
        }
        SetWindowTextA(m_hLogEdit, fullLogText.c_str());
        SendMessageA(m_hLogEdit, EM_SETSEL, (WPARAM)fullLogText.length(), (LPARAM)fullLogText.length());
        SendMessageA(m_hLogEdit, EM_SCROLLCARET, 0, 0);
    }
}

std::string Logger::GetLogHistory() {
    std::lock_guard<std::mutex> lock(m_logMutex);
    std::string fullLog = "";
    for (const auto& line : m_logMemory) {
        fullLog += line + "\n";
    }
    return fullLog;
}

void Logger::ClearLogs() {
    std::lock_guard<std::mutex> lock(m_logMutex);
    m_logMemory.clear();

    // Truncate the file
    std::ofstream logFile(m_logFileName, std::ios::trunc);
    if (logFile.is_open()) {
        logFile.close();
    }

    if (m_hLogEdit && IsWindow(m_hLogEdit)) {
        SetWindowTextA(m_hLogEdit, "");
    }
}