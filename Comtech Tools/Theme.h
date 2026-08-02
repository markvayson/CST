#pragma once
#include <windows.h>

// Dark Theme Color Palette
#define COLOR_BG          RGB(11, 19, 43)
#define COLOR_PANEL       RGB(15, 23, 42)
#define COLOR_CARD_BG     RGB(15, 26, 48)
#define COLOR_BORDER      RGB(30, 41, 59)
#define COLOR_TEXT_WHITE  RGB(241, 245, 249)
#define COLOR_TEXT_MUTED  RGB(148, 163, 184)
#define COLOR_ACCENT_TEAL RGB(56, 157, 237)
#define COLOR_WARN_AMBER  RGB(245, 158, 11)
#define COLOR_DANGER_RED  RGB(239, 68, 68)

// Global Brushes & Fonts (Declared as extern)
extern HBRUSH g_hBrushBg;
extern HBRUSH g_hBrushPanel;
extern HFONT  g_hFontTitle;
extern HFONT  g_hFontSub;
extern HFONT  g_hFontBold;
extern HFONT  g_hFontIcon;

// Theme Management Functions
void InitTheme();

void CleanupTheme();