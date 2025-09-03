#include "message_window.h"

void MessageWindow::Init() {}

void MessageWindow::Draw() {}

bool MessageWindow::Open(std::string, int* result, std::span<std::string>, int, int)
{
    if (result) *result = 0;
    s_isVisible = true;
    return MSG_OPEN;
}

void MessageWindow::Close()
{
    s_isVisible = false;
}

