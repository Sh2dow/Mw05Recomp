#include <ui/debug_console.h>
#include <sdl_listener.h>
#include <SDL3/SDL.h>

// SDL event listener for debug console keyboard input
static class DebugConsoleListener : public SDLEventListener
{
    bool m_isBacktickDown = false;
    bool m_isF1Down = false;

public:
    bool OnSDLEvent(SDL_Event* event) override
    {
        switch (event->type)
        {
        case SDL_KEYDOWN:
        {
            // Toggle console with backtick (`) or F1
            if (event->key.key == SDLK_GRAVE && !m_isBacktickDown)
            {
                DebugConsole::Toggle();
                m_isBacktickDown = true;
                return true; // Consume event
            }
            else if (event->key.key == SDLK_F1 && !m_isF1Down)
            {
                DebugConsole::Toggle();
                m_isF1Down = true;
                return true; // Consume event
            }
            break;
        }

        case SDL_KEYUP:
        {
            if (event->key.key == SDLK_GRAVE)
                m_isBacktickDown = false;
            else if (event->key.key == SDLK_F1)
                m_isF1Down = false;
            break;
        }
        }

        return false;
    }
}
g_debugConsoleListener;

