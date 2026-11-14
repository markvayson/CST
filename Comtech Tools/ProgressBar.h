#pragma once
#include <windows.h>

void RenderProgressBar(HDC hdc, int totalControls, float animatedSecureCount, int percentMet, int trackLeft, int trackRight, int trackTop = 23);