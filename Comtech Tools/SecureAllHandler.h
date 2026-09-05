#ifndef SECURE_ALL_HANDLER_H
#define SECURE_ALL_HANDLER_H

#include <windows.h>
#include <vector>
#include <string>

struct SecurityControl;

struct ConfirmDialogData {
    std::string title;
    std::string message;
    std::vector<std::string> items;
    std::vector<bool> selectedItems;
    bool confirmed = false;
};

bool ShowCustomConfirmDialog(HWND hParent, ConfirmDialogData* pData);
void HandleSecureAllAction(HWND hwnd, std::vector<SecurityControl>& controls, bool& isExecuting);

#endif // SECURE_ALL_HANDLER_H