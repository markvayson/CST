#include "ProgressBar.h"

// Define Global Direct2D Resources
ID2D1Factory* pD2DFactory = nullptr;
ID2D1HwndRenderTarget* pRenderTarget = nullptr;
ID2D1SolidColorBrush* pActiveBrush = nullptr;
ID2D1SolidColorBrush* pInactiveBrush = nullptr;

// Initialize Direct2D Resources
void InitD2D(HWND hwnd) {
    D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &pD2DFactory);

    RECT rc;
    GetClientRect(hwnd, &rc);

    pD2DFactory->CreateHwndRenderTarget(
        D2D1::RenderTargetProperties(),
        D2D1::HwndRenderTargetProperties(hwnd, D2D1::SizeU(rc.right - rc.left, rc.bottom - rc.top)),
        &pRenderTarget
    );

    // Active Chevron Accent (Electric Blue)
    pRenderTarget->CreateSolidColorBrush(D2D1::ColorF(0x00, 0x66, 0xFF), &pActiveBrush);
    // Track Background Chevron
    pRenderTarget->CreateSolidColorBrush(D2D1::ColorF(0x1E, 0x29, 0x3B), &pInactiveBrush);
}

// Release Direct2D Resources
void CleanupD2D() {
    if (pActiveBrush) { pActiveBrush->Release(); pActiveBrush = nullptr; }
    if (pInactiveBrush) { pInactiveBrush->Release(); pInactiveBrush = nullptr; }
    if (pRenderTarget) { pRenderTarget->Release(); pRenderTarget = nullptr; }
    if (pD2DFactory) { pD2DFactory->Release(); pD2DFactory = nullptr; }
}

void DrawChevronProgressBar(int totalSegments, int completedSegments, D2D1_RECT_F rect) {
    if (!pRenderTarget) return;

    pRenderTarget->BeginDraw();

    // REMOVE THIS LINE: pRenderTarget->Clear(D2D1::ColorF(0, 0.0f));

    float totalWidth = rect.right - rect.left;
    float height = rect.bottom - rect.top;
    float segmentGap = 4.0f;
    float segmentWidth = (totalWidth - (segmentGap * (totalSegments - 1))) / totalSegments;
    float arrowOffset = height * 0.35f;

    for (int i = 0; i < totalSegments; ++i) {
        float xLeft = rect.left + i * (segmentWidth + segmentGap);
        float xRight = xLeft + segmentWidth;

        ID2D1PathGeometry* pPathGeometry = nullptr;
        ID2D1GeometrySink* pSink = nullptr;

        pD2DFactory->CreatePathGeometry(&pPathGeometry);
        pPathGeometry->Open(&pSink);

        // Define Chevron Polygon Points
        pSink->BeginFigure(D2D1::Point2F(xLeft, rect.top), D2D1_FIGURE_BEGIN_FILLED);
        pSink->AddLine(D2D1::Point2F(xRight - arrowOffset, rect.top));
        pSink->AddLine(D2D1::Point2F(xRight, rect.top + (height / 2.0f)));
        pSink->AddLine(D2D1::Point2F(xRight - arrowOffset, rect.bottom));
        pSink->AddLine(D2D1::Point2F(xLeft, rect.bottom));
        if (i > 0) {
            pSink->AddLine(D2D1::Point2F(xLeft + arrowOffset, rect.top + (height / 2.0f)));
        }
        pSink->EndFigure(D2D1_FIGURE_END_CLOSED);
        pSink->Close();

        ID2D1SolidColorBrush* currentBrush = (i < completedSegments) ? pActiveBrush : pInactiveBrush;
        pRenderTarget->FillGeometry(pPathGeometry, currentBrush);

        pSink->Release();
        pPathGeometry->Release();
    }

    pRenderTarget->EndDraw();
}


