#include "options_menu.h"

void OptionsMenu::Init() {}

void OptionsMenu::Draw() {}

void OptionsMenu::Open(bool isPause, SWA::EMenuType pauseMenuType)
{
    s_isPause = isPause;
    s_pauseMenuType = pauseMenuType;
    s_isVisible = true;
}

void OptionsMenu::Close()
{
    s_isVisible = false;
}

bool OptionsMenu::CanClose()
{
    return true;
}

