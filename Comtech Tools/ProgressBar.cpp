#include "ProgressBar.h"
#include <windows.h>
#include <gdiplus.h>
#include <algorithm>
#include <cmath>

#pragma comment(lib, "gdiplus.lib")

using namespace Gdiplus;

static ULONG_PTR g_gdiplusToken = 0;

void InitGdiplusIfNeeded() {
    if (g_gdiplusToken == 0) {
        GdiplusStartupInput input;
        GdiplusStartup(&g_gdiplusToken, &input, NULL);
    }
}

void RenderProgressBar(HDC hdc, int totalControls, float animatedSecureCount, int percentMet) {
    if (totalControls <= 0) return;

    InitGdiplusIfNeeded();

    Graphics graphics(hdc);
    // AntiAlias for clean diagonal edges + Half pixel offset for sharp subpixel alignment
    graphics.SetSmoothingMode(SmoothingModeAntiAlias);
    graphics.SetPixelOffsetMode(PixelOffsetModeHalf);

    // Track bounds
    RectF rcTrack(150.0f, 23.0f, 245.0f, 16.0f);

    SolidBrush trackBgBrush(Color(255, 15, 23, 42));
    graphics.FillRectangle(&trackBgBrush, rcTrack);

    Color activeColor;
    if (percentMet >= 100)      activeColor = Color(255, 13, 148, 136);
    else if (percentMet >= 50) activeColor = Color(255, 59, 130, 246);
    else                       activeColor = Color(255, 248, 113, 113);

    Color bgSegColor(255, 30, 41, 59);

    float arrowDepth = 8.0f;
    float gap = 2.0f;
    float radius = 3.0f;
    float diameter = radius * 2.0f;

    float totalGaps = (totalControls - 1) * gap;
    float segWidth = (rcTrack.Width - totalGaps - arrowDepth) / static_cast<float>(totalControls);

    for (int i = 0; i < totalControls; i++) {
        float x = rcTrack.X + (i * (segWidth + gap));
        float top = rcTrack.Y;
        float bottom = rcTrack.Y + rcTrack.Height;
        float centerY = top + (rcTrack.Height / 2.0f);

        GraphicsPath path;
        bool isFirst = (i == 0);
        bool isLast = (i == totalControls - 1);

        if (isFirst && isLast) {
            path.AddArc(x, top, diameter, diameter, 180, 90);
            path.AddArc(x + segWidth + arrowDepth - diameter, top, diameter, diameter, 270, 90);
            path.AddArc(x + segWidth + arrowDepth - diameter, bottom - diameter, diameter, diameter, 0, 90);
            path.AddArc(x, bottom - diameter, diameter, diameter, 90, 90);
            path.CloseFigure();
        }
        else if (isFirst) {
            path.AddArc(x, top, diameter, diameter, 180, 90);
            path.AddLine(x + radius, top, x + segWidth, top);
            path.AddLine(x + segWidth, top, x + segWidth + arrowDepth, centerY);
            path.AddLine(x + segWidth + arrowDepth, centerY, x + segWidth, bottom);
            path.AddLine(x + segWidth, bottom, x + radius, bottom);
            path.AddArc(x, bottom - diameter, diameter, diameter, 90, 90);
            path.CloseFigure();
        }
        else if (isLast) {
            float rightX = x + segWidth + arrowDepth;
            path.AddLine(x, top, rightX - radius, top);
            path.AddArc(rightX - diameter, top, diameter, diameter, 270, 90);
            path.AddArc(rightX - diameter, bottom - diameter, diameter, diameter, 0, 90);
            path.AddLine(rightX - radius, bottom, x, bottom);
            path.AddLine(x, bottom, x + arrowDepth, centerY);
            path.CloseFigure();
        }
        else {
            path.AddLine(x, top, x + segWidth, top);
            path.AddLine(x + segWidth, top, x + segWidth + arrowDepth, centerY);
            path.AddLine(x + segWidth + arrowDepth, centerY, x + segWidth, bottom);
            path.AddLine(x + segWidth, bottom, x, bottom);
            path.AddLine(x, bottom, x + arrowDepth, centerY);
            path.CloseFigure();
        }

        // Determine segment active state
        float segmentFill = animatedSecureCount - static_cast<float>(i);
        segmentFill = (std::max)(0.0f, (std::min)(1.0f, segmentFill));

        // Draw segment directly in solid active color or inactive background color (no clip masking blur)
        if (segmentFill >= 1.0f) {
            SolidBrush activeBrush(activeColor);
            graphics.FillPath(&activeBrush, &path);
        }
        else if (segmentFill > 0.0f) {
            // Partial animation state: draw background path first, then clip fill
            SolidBrush segBgBrush(bgSegColor);
            graphics.FillPath(&segBgBrush, &path);

            float maxRightExtent = x + segWidth + arrowDepth;
            float fillRight = x + ((maxRightExtent - x) * segmentFill);

            graphics.SetClip(&path);
            SolidBrush activeBrush(activeColor);
            RectF fillRect(x, top, fillRight - x, rcTrack.Height);
            graphics.FillRectangle(&activeBrush, fillRect);
            graphics.ResetClip();
        }
        else {
            SolidBrush segBgBrush(bgSegColor);
            graphics.FillPath(&segBgBrush, &path);
        }
    }
}