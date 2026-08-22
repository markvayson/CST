#pragma once

#include <d2d1.h>

#pragma comment(lib, "d2d1.lib")

// Direct2D Global Resource Declarations
extern ID2D1Factory* pD2DFactory;
extern ID2D1HwndRenderTarget* pRenderTarget;
extern ID2D1SolidColorBrush* pActiveBrush;
extern ID2D1SolidColorBrush* pInactiveBrush;

// Function Declarations
void InitD2D(HWND hwnd);
void CleanupD2D();
void DrawChevronProgressBar(int totalSegments, int completedSegments, D2D1_RECT_F rect);