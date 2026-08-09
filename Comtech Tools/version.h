#pragma once
#include <string>

extern std::string g_appProductName;
extern std::string g_appVersion;


// 1. Define your version numbers here. Update ONLY these four values.
#define CSC_VERSION_MAJOR 4
#define CSC_VERSION_MINOR 2
#define CSC_VERSION_BUILD 0
#define CSC_VERSION_REVISION 0

// 2. Helper macros to convert the numeric values into a string
#define STRINGIZE_NX(A) #A
#define STRINGIZE(A) STRINGIZE_NX(A)
#define MAKE_VERSION_STRING(a, b, c, d) STRINGIZE(a) "." STRINGIZE(b) "." STRINGIZE(c) "." STRINGIZE(d)

#define CSC_VERSION_STRING MAKE_VERSION_STRING(CSC_VERSION_MAJOR, CSC_VERSION_MINOR, CSC_VERSION_BUILD, CSC_VERSION_REVISION)

