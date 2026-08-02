#include "Theme.h"

// Define the variables here (without extern)
HBRUSH g_hBrushBg = NULL;
HBRUSH g_hBrushPanel = NULL;
HFONT  g_hFontTitle = NULL;
HFONT  g_hFontSub = NULL;
HFONT  g_hFontBold = NULL;
HFONT  g_hFontIcon = NULL;

void InitTheme() {
    if (g_hBrushBg == NULL) {
        g_hBrushBg = CreateSolidBrush(COLOR_BG);
        g_hBrushPanel = CreateSolidBrush(COLOR_PANEL);

        g_hFontTitle = CreateFontA(22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
        
        // Bumping list text to 16 to match the 16x16 system icons
        g_hFontSub = CreateFontA(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
        g_hFontBold = CreateFontA(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");

        // UI element icons
        g_hFontIcon = CreateFontA(20, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe MDL2 Assets");
    }
}

void CleanupTheme() {
    if (g_hBrushBg) {
        DeleteObject(g_hBrushBg);
        DeleteObject(g_hBrushPanel);
        DeleteObject(g_hFontTitle);
        DeleteObject(g_hFontSub);
        DeleteObject(g_hFontBold);
        DeleteObject(g_hFontIcon);

        g_hBrushBg = NULL; // Reset to prevent double deletion
    }
}