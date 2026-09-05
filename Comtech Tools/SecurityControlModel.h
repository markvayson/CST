#pragma once
#include <string>

enum class ControlState {
    Warning = 1,
    Secured = 2,
    Applying = 3
};

struct SecurityControlData {
    int id;
    std::string name;
    std::string liveInfo;
    std::string actionLabel;
    wchar_t iconGlyph;
    ControlState state;
    bool isChecked;
};