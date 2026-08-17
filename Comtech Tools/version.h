#pragma once
#include <string>

extern std::string g_appProductName;
extern std::string g_appVersion;

// 1. Define your version numbers here
#define CSC_VERSION_MAJOR 4
#define CSC_VERSION_MINOR 6

// 2. Helper macros to convert the numeric values into a string
#define STRINGIZE_NX(A) #A
#define STRINGIZE(A) STRINGIZE_NX(A)

#define MAKE_VERSION_STRING(a, b) STRINGIZE(a) "." STRINGIZE(b)

#define CSC_VERSION_STRING MAKE_VERSION_STRING(CSC_VERSION_MAJOR, CSC_VERSION_MINOR)


