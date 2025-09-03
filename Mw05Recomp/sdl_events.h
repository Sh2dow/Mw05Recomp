#pragma once

#include <SDL3/SDL.h>
#include <ui/game_window.h>

#define SDL_USER_EVILSONIC (SDL_EVENT_USER + 1)

inline void SDL_ResizeEvent(SDL_Window* pWindow, int width, int height)
{
    SDL_Event event{};
    event.type = SDL_EVENT_WINDOW_RESIZED;
    event.window.windowID = SDL_GetWindowID(pWindow);
    event.window.data1 = width;
    event.window.data2 = height;

    SDL_PushEvent(&event);
}

inline void SDL_MoveEvent(SDL_Window* pWindow, int x, int y)
{
    SDL_Event event{};
    event.type = SDL_EVENT_WINDOW_MOVED;
    event.window.windowID = SDL_GetWindowID(pWindow);
    event.window.data1 = x;
    event.window.data2 = y;

    SDL_PushEvent(&event);
}

inline void SDL_User_EvilSonic(bool isEvil)
{
    SDL_Event event{};
    event.type = SDL_USER_EVILSONIC;
    event.user.code = isEvil;

    SDL_PushEvent(&event);
}
