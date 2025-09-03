#pragma once

#ifdef MW05_ENABLE_SWA
#include <api/SWA.h>
#else
namespace SWA { enum EMenuType { eMenuType_WorldMap = 0 }; }
#endif

class OptionsMenu
{
public:
    static inline bool s_isVisible = false;
    static inline bool s_isPause = false;
    static inline bool s_isRestartRequired = false;

    static inline SWA::EMenuType s_pauseMenuType;

    static void Init();
    static void Draw();
    static void Open(bool isPause = false, SWA::EMenuType pauseMenuType = SWA::eMenuType_WorldMap);
    static void Close();

    static bool CanClose();
};
