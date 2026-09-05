#pragma once

#include <windows.h>
#include <string>
#include <functional>
#include "Resource.h"




struct SecurityControl {
    std::string name;
    std::string liveInfo;
    std::string statusLabel;
    std::string actionLabel;
    wchar_t iconGlyph;
    HWND hBtnAction;
    HWND hChkBox;
    bool isChecked;
    int state;
    bool isHovered = false;

    std::function<void(SecurityControl&)> auditFunc;
    std::function<void(bool)> enforceFunc;
};