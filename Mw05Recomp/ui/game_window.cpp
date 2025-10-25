#include "game_window.h"
#include <gpu/video.h>
#include <os/logger.h>
#include <os/user.h>
#include <os/version.h>
#include <app.h>
#include <sdl_listener.h>
#include <SDL3/SDL_iostream.h> // SDL_IOFromMem (SDL3)

#if _WIN32
#include <dwmapi.h>
#include <shellscalingapi.h>
#endif

#include <res/images/game_icon.bmp.h>
#include <res/images/game_icon_night.bmp.h>

bool m_isFullscreenKeyReleased = true;
bool m_isResizing = false;

// SDL3: event watch callback must return bool
bool Window_OnSDLEvent(void*, SDL_Event* event)
{
    // ImGui context may not be created yet during early SDL events.
    if (ImGui::GetCurrentContext() && ImGui::GetIO().BackendPlatformUserData != nullptr)
        ImGui_ImplSDL3_ProcessEvent(event);

    for (auto listener : GetEventListeners())
    {
        if (listener->OnSDLEvent(event))
        {
            // In SDL3, returning false would drop the event from the queue.
            // We handled it in listeners but still keep it in the queue.
            return true;
        }
    }

    switch (event->type)
    {
        case SDL_EVENT_QUIT:
        {
            fprintf(stderr, "[GAME-WINDOW] SDL_EVENT_QUIT received! s_isSaving=%d\n", App::s_isSaving ? 1 : 0);
            fflush(stderr);

            if (App::s_isSaving)
                break;

            fprintf(stderr, "[GAME-WINDOW] Calling App::Exit()...\n");
            fflush(stderr);
            App::Exit();

            break;
        }

        case SDL_EVENT_KEY_DOWN:
        {
            switch (event->key.key)
            {
                // Toggle fullscreen on ALT+ENTER.
                case SDLK_RETURN:
                {
                    if (!(event->key.mod & SDL_KMOD_ALT) || !m_isFullscreenKeyReleased)
                        break;

                    Config::Fullscreen = GameWindow::SetFullscreen(!GameWindow::IsFullscreen());

                    if (Config::Fullscreen)
                    {
                        Config::Monitor = GameWindow::GetDisplay();
                    }
                    else
                    {
                        Config::WindowState = GameWindow::SetMaximised(Config::WindowState == EWindowState::Maximised);
                    }

                    // Block holding ALT+ENTER spamming window changes.
                    m_isFullscreenKeyReleased = false;

                    break;
                }

                // Restore original window dimensions on F2.
                case SDLK_F2:
                    Config::Fullscreen = GameWindow::SetFullscreen(false);
                    GameWindow::ResetDimensions();
                    break;

                // Recentre window on F3.
                case SDLK_F3:
                {
                    if (GameWindow::IsFullscreen())
                        break;

                    GameWindow::SetDimensions(GameWindow::s_width, GameWindow::s_height);

                    break;
                }
            }

            break;
        }

        case SDL_EVENT_KEY_UP:
        {
            switch (event->key.key)
            {
                // Allow user to input ALT+ENTER again.
                case SDLK_RETURN:
                    m_isFullscreenKeyReleased = true;
                    break;
            }
        }

        case SDL_EVENT_WINDOW_RESIZED:
        case SDL_EVENT_WINDOW_MOVED:
        case SDL_EVENT_WINDOW_RESTORED:
        case SDL_EVENT_WINDOW_MAXIMIZED:
        case SDL_EVENT_WINDOW_FOCUS_LOST:
        case SDL_EVENT_WINDOW_FOCUS_GAINED:
        {
            if (event->type == SDL_EVENT_WINDOW_FOCUS_LOST) {
                GameWindow::s_isFocused = false;
                SDL_ShowCursor(); // SDL3: parameterless
            } else if (event->type == SDL_EVENT_WINDOW_FOCUS_GAINED) {
                GameWindow::s_isFocused = true;
                if (GameWindow::IsFullscreen()) {
                    if (GameWindow::s_isFullscreenCursorVisible) SDL_ShowCursor(); else SDL_HideCursor();
                }
            } else if (event->type == SDL_EVENT_WINDOW_RESTORED) {
                Config::WindowState = EWindowState::Normal;
            } else if (event->type == SDL_EVENT_WINDOW_MAXIMIZED) {
                Config::WindowState = EWindowState::Maximised;
            } else if (event->type == SDL_EVENT_WINDOW_RESIZED) {
                m_isResizing = true;
                Config::WindowSize = -1;
                GameWindow::s_width = event->window.data1;
                GameWindow::s_height = event->window.data2;
                GameWindow::SetTitle(fmt::format("{} - [{}x{}]", GameWindow::GetTitle(), GameWindow::s_width, GameWindow::s_height).c_str());
            } else if (event->type == SDL_EVENT_WINDOW_MOVED) {
                GameWindow::s_x = event->window.data1;
                GameWindow::s_y = event->window.data2;
            }

            break;
        }

        case SDL_USER_EVILSONIC:
            GameWindow::s_isIconNight = event->user.code;
            GameWindow::SetIcon(GameWindow::s_isIconNight);
            break;
    }

    return true; // keep event
}

void GameWindow::Init(const char* sdlVideoDriver)
{
    fprintf(stderr, "[GAMEWINDOW] Init ENTER\n"); fflush(stderr);

#ifdef __linux__
    SDL_SetHint("SDL_APP_ID", "io.github.hedge_dev.unleashedrecomp");
#endif

    fprintf(stderr, "[GAMEWINDOW] Before SDL_InitSubSystem(SDL_INIT_VIDEO)\n"); fflush(stderr);
    // SDL3: SDL_VideoInit removed. Use hint + SDL_InitSubSystem.
    if (sdlVideoDriver && *sdlVideoDriver)
        SDL_SetHint(SDL_HINT_VIDEO_DRIVER, sdlVideoDriver);
    SDL_InitSubSystem(SDL_INIT_VIDEO);
    fprintf(stderr, "[GAMEWINDOW] After SDL_InitSubSystem(SDL_INIT_VIDEO)\n"); fflush(stderr);
    // Verbose boot marker
    if (SDL_GetHintBoolean("MW_VERBOSE", SDL_FALSE)) {
        printf("[boot] SDL video subsystem initialized\n"); fflush(stdout);
    }

    fprintf(stderr, "[GAMEWINDOW] Before SDL_GetCurrentVideoDriver\n"); fflush(stderr);
    auto videoDriverName = SDL_GetCurrentVideoDriver();
    fprintf(stderr, "[GAMEWINDOW] After SDL_GetCurrentVideoDriver videoDriverName=%s\n", videoDriverName ? videoDriverName : "NULL"); fflush(stderr);

    fprintf(stderr, "[GAMEWINDOW] Before LOGFN\n"); fflush(stderr);
    // CRITICAL FIX: LOGFN hangs in natural path (mutex deadlock)! Use fprintf instead.
    if (videoDriverName) {
        fprintf(stderr, "[GAMEWINDOW] SDL video driver: \"%s\"\n", videoDriverName);
        fflush(stderr);
    }
    fprintf(stderr, "[GAMEWINDOW] After LOGFN\n"); fflush(stderr);

    fprintf(stderr, "[GAMEWINDOW] Before SDL_AddEventWatch\n"); fflush(stderr);
    SDL_AddEventWatch(Window_OnSDLEvent, s_pWindow);
    fprintf(stderr, "[GAMEWINDOW] After SDL_AddEventWatch\n"); fflush(stderr);
    if (SDL_GetHintBoolean("MW_VERBOSE", SDL_FALSE)) {
        printf("[boot] SDL event watch registered\n"); fflush(stdout);
    }

#ifdef _WIN32
    SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE);
#endif

    s_x = Config::WindowX;
    s_y = Config::WindowY;
    s_width = Config::WindowWidth;
    s_height = Config::WindowHeight;

    if (s_x == -1 && s_y == -1)
        s_x = s_y = SDL_WINDOWPOS_CENTERED;

    if (!IsPositionValid())
        GameWindow::ResetDimensions();

    fprintf(stderr, "[GAMEWINDOW] Before SDL_CreateWindow\n"); fflush(stderr);
    // SDL3: CreateWindow no longer takes x/y. Set position afterwards.
    s_pWindow = SDL_CreateWindow("Most Wanted Recompiled", s_width, s_height, GetWindowFlags());
    fprintf(stderr, "[GAMEWINDOW] After SDL_CreateWindow s_pWindow=%p\n", s_pWindow); fflush(stderr);
    if (SDL_GetHintBoolean("MW_VERBOSE", SDL_FALSE)) {
        int w=0,h=0; SDL_GetWindowSize(s_pWindow,&w,&h);
        printf("[boot] Window created %dx%d\n", w, h); fflush(stdout);
    }

    if (!s_pWindow) {
        printf("[boot][error] SDL_CreateWindow failed: %s\n", SDL_GetError());
        fflush(stdout);
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, GameWindow::GetTitle(), SDL_GetError(), nullptr);
        std::_Exit(1);
    }

#if defined(_WIN32)
    fprintf(stderr, "[GAMEWINDOW] Before SDL_GetWindowProperties\n"); fflush(stderr);
    // SDL3: fetch Win32 HWND from window properties for D3D12 backend
    SDL_PropertiesID props = SDL_GetWindowProperties(s_pWindow);
    void* hwndPtr = SDL_GetPointerProperty(props, SDL_PROP_WINDOW_WIN32_HWND_POINTER, nullptr);
    HWND hwnd = (HWND)hwndPtr;
    s_renderWindow = hwnd;
    fprintf(stderr, "[GAMEWINDOW] After SDL_GetWindowProperties hwnd=%p\n", hwnd); fflush(stderr);
    if (SDL_GetHintBoolean("MW_VERBOSE", SDL_FALSE)) {
        printf("[boot] Win32 HWND=%p\n", hwnd); fflush(stdout);
    }
#endif
    fprintf(stderr, "[GAMEWINDOW] Before SDL_SetWindowPosition\n"); fflush(stderr);
    if (s_pWindow) SDL_SetWindowPosition(s_pWindow, s_x, s_y);
    fprintf(stderr, "[GAMEWINDOW] After SDL_SetWindowPosition\n"); fflush(stderr);

    if (IsFullscreen())
        SDL_HideCursor();

    fprintf(stderr, "[GAMEWINDOW] Before SetDisplay\n"); fflush(stderr);
    SetDisplay(Config::Monitor);
    fprintf(stderr, "[GAMEWINDOW] After SetDisplay\n"); fflush(stderr);
    fprintf(stderr, "[GAMEWINDOW] Before SetIcon\n"); fflush(stderr);
    SetIcon();
    fprintf(stderr, "[GAMEWINDOW] After SetIcon\n"); fflush(stderr);
    fprintf(stderr, "[GAMEWINDOW] Before SetTitle\n"); fflush(stderr);
    SetTitle();
    fprintf(stderr, "[GAMEWINDOW] After SetTitle\n"); fflush(stderr);

    fprintf(stderr, "[GAMEWINDOW] Before SDL_SetWindowMinimumSize\n"); fflush(stderr);
    SDL_SetWindowMinimumSize(s_pWindow, MIN_WIDTH, MIN_HEIGHT);
    fprintf(stderr, "[GAMEWINDOW] After SDL_SetWindowMinimumSize\n"); fflush(stderr);

    // SDL3: use window properties instead of SDL_syswm.h (done elsewhere in your file)
    fprintf(stderr, "[GAMEWINDOW] Before SetTitleBarColour\n"); fflush(stderr);
    SetTitleBarColour();
    fprintf(stderr, "[GAMEWINDOW] After SetTitleBarColour\n"); fflush(stderr);

    fprintf(stderr, "[GAMEWINDOW] Before SDL_ShowWindow\n"); fflush(stderr);
    SDL_ShowWindow(s_pWindow);
    fprintf(stderr, "[GAMEWINDOW] After SDL_ShowWindow - Init COMPLETE\n"); fflush(stderr);
}

void GameWindow::Update()
{
    if (!GameWindow::IsFullscreen() && !GameWindow::IsMaximised() && !s_isChangingDisplay)
    {
        Config::WindowX = GameWindow::s_x;
        Config::WindowY = GameWindow::s_y;
        Config::WindowWidth = GameWindow::s_width;
        Config::WindowHeight = GameWindow::s_height;
    }

    if (m_isResizing)
    {
        SetTitle();
        m_isResizing = false;
    }

    if (g_needsResize)
        s_isChangingDisplay = false;
}

SDL_Surface* GameWindow::GetIconSurface(void* pIconBmp, size_t iconSize)
{
    // SDL3: SDL_RWFromMem -> SDL_IOFromMem
    auto rw = SDL_IOFromMem(pIconBmp, iconSize);
    auto surface = SDL_LoadBMP_IO(rw, true);

    if (!surface)
        LOGF_ERROR("Failed to load icon: {}", SDL_GetError());

    return surface;
}

void GameWindow::SetIcon(void* pIconBmp, size_t iconSize)
{
    if (auto icon = GetIconSurface(pIconBmp, iconSize))
    {
        SDL_SetWindowIcon(s_pWindow, icon);
        // SDL3: SDL_FreeSurface -> SDL_DestroySurface
        SDL_DestroySurface(icon);
    }
}

void GameWindow::SetIcon(bool isNight)
{
    if (isNight)
    {
        SetIcon(g_game_icon_night, sizeof(g_game_icon_night));
    }
    else
    {
        SetIcon(g_game_icon, sizeof(g_game_icon));
    }
}

const char* GameWindow::GetTitle()
{
    if (Config::UseOfficialTitleOnTitleBar)
    {
        auto isSWA = Config::Language == ELanguage::Japanese;

        if (Config::UseAlternateTitle)
            isSWA = !isSWA;

        return isSWA
            ? "SONIC WORLD ADVENTURE"
            : "SONIC UNLEASHED";
    }

    return "Most Wanted Recompiled";
}

void GameWindow::SetTitle(const char* title)
{
    SDL_SetWindowTitle(s_pWindow, title ? title : GetTitle());
}

void GameWindow::SetTitleBarColour()
{
#if _WIN32
    if (os::user::IsDarkTheme())
    {
        auto version = os::version::GetOSVersion();

        if (version.Major < 10 || version.Build <= 17763)
            return;

        auto flag = version.Build >= 18985
            ? DWMWA_USE_IMMERSIVE_DARK_MODE
            : 19; // DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1

        const DWORD useImmersiveDarkMode = 1;
        DwmSetWindowAttribute(s_renderWindow, flag, &useImmersiveDarkMode, sizeof(useImmersiveDarkMode));
    }
#endif
}

bool GameWindow::IsFullscreen()
{
    // SDL3: use SDL_WINDOW_FULLSCREEN
    return (SDL_GetWindowFlags(s_pWindow) & SDL_WINDOW_FULLSCREEN) != 0;
}

bool GameWindow::SetFullscreen(bool isEnabled)
{
    if (isEnabled)
    {
        // Borderless fullscreen by default
        SDL_SetWindowFullscreen(s_pWindow, true);
        if (s_isFullscreenCursorVisible) SDL_ShowCursor(); else SDL_HideCursor();
    }
    else
    {
        SDL_SetWindowFullscreen(s_pWindow, false);
        SDL_ShowCursor();

        SetIcon(GameWindow::s_isIconNight);
        SetDimensions(Config::WindowWidth, Config::WindowHeight, Config::WindowX, Config::WindowY);
    }

    return isEnabled;
}
    
void GameWindow::SetFullscreenCursorVisibility(bool isVisible)
{
    s_isFullscreenCursorVisible = isVisible;

    if (IsFullscreen())
    {
        if (s_isFullscreenCursorVisible) SDL_ShowCursor(); else SDL_HideCursor();
    }
    else
    {
        SDL_ShowCursor();
    }
}

bool GameWindow::IsMaximised()
{
    return (SDL_GetWindowFlags(s_pWindow) & SDL_WINDOW_MAXIMIZED) != 0;
}

EWindowState GameWindow::SetMaximised(bool isEnabled)
{
    if (isEnabled)
    {
        SDL_MaximizeWindow(s_pWindow);
    }
    else
    {
        SDL_RestoreWindow(s_pWindow);
    }

    return isEnabled
        ? EWindowState::Maximised
        : EWindowState::Normal;
}

SDL_Rect GameWindow::GetDimensions()
{
    SDL_Rect rect{};

    SDL_GetWindowPosition(s_pWindow, &rect.x, &rect.y);
    SDL_GetWindowSize(s_pWindow, &rect.w, &rect.h);

    return rect;
}

void GameWindow::GetSizeInPixels(int *w, int *h)
{
    SDL_GetWindowSizeInPixels(s_pWindow, w, h);
}

void GameWindow::SetDimensions(int w, int h, int x, int y)
{
    s_width = w;
    s_height = h;
    s_x = x;
    s_y = y;

    SDL_SetWindowSize(s_pWindow, w, h);
    SDL_ResizeEvent(s_pWindow, w, h);

    SDL_SetWindowPosition(s_pWindow, x, y);
    SDL_MoveEvent(s_pWindow, x, y);
}

void GameWindow::ResetDimensions()
{
    s_x = SDL_WINDOWPOS_CENTERED;
    s_y = SDL_WINDOWPOS_CENTERED;
    s_width = DEFAULT_WIDTH;
    s_height = DEFAULT_HEIGHT;

    Config::WindowX = s_x;
    Config::WindowY = s_y;
    Config::WindowWidth = s_width;
    Config::WindowHeight = s_height;
}

uint32_t GameWindow::GetWindowFlags()
{
    // SDL3: SDL_WINDOW_ALLOW_HIGHDPI -> SDL_WINDOW_HIGH_PIXEL_DENSITY
    uint32_t flags = SDL_WINDOW_HIDDEN | SDL_WINDOW_RESIZABLE | SDL_WINDOW_HIGH_PIXEL_DENSITY;

    if (Config::WindowState == EWindowState::Maximised)
        flags |= SDL_WINDOW_MAXIMIZED;

    if (Config::Fullscreen)
        flags |= SDL_WINDOW_FULLSCREEN;

#ifdef SDL_VULKAN_ENABLED
    flags |= SDL_WINDOW_VULKAN;
#endif

    return flags;
}

int GameWindow::GetDisplayCount()
{
    int count = 0;
    SDL_DisplayID* displays = SDL_GetDisplays(&count);
    if (!displays) {
            LOGF_ERROR("Failed to get display list: {}", SDL_GetError());
            return 1;
        }
    SDL_free(displays);
    return count;
}

int GameWindow::GetDisplay()
{
    SDL_DisplayID did = SDL_GetDisplayForWindow(s_pWindow);
    int n = 0;
    SDL_DisplayID* displays = SDL_GetDisplays(&n);
    if (!displays || n <= 0) {
        if (displays) SDL_free(displays);
        return 0;
    }
    int idx = 0;
    for (int i = 0; i < n; ++i) {
        if (displays[i] == did) {
            idx = i;
            break;
        }
    }
    SDL_free(displays);
    return idx;
}

void GameWindow::SetDisplay(int displayIndex)
{
    if (!IsFullscreen())
        return;
 
            if (GetDisplay() == displayIndex)
            return;
 
    s_isChangingDisplay = true;
 
    SDL_Rect bounds;
            int n = 0;
        SDL_DisplayID* displays = SDL_GetDisplays(&n);
        if (displays && displayIndex >= 0 && displayIndex < n &&
            SDL_GetDisplayBounds(displays[displayIndex], &bounds))
    {
        SetFullscreen(false);
        SetDimensions(bounds.w, bounds.h, bounds.x, bounds.y);
        SetFullscreen(true);
    }
    else
    {
        ResetDimensions();
    }
        if (displays) SDL_free(displays);
}


std::vector<SDL_DisplayMode> GameWindow::GetDisplayModes(bool ignoreInvalidModes, bool ignoreRefreshRates)
{
    auto result = std::vector<SDL_DisplayMode>();
    auto uniqueResolutions = std::set<std::pair<int, int>>();
    int count = 0;
    SDL_DisplayID* displays = SDL_GetDisplays(&count);
    if (!displays || count <= 0) return result;

    int displayIndex = std::clamp(GetDisplay(), 0, count - 1);
    SDL_DisplayID did = displays[displayIndex];
    SDL_free(displays);

    int modeCount = 0;
    SDL_DisplayMode** modes = SDL_GetFullscreenDisplayModes(did, &modeCount);
    if (!modes || modeCount <= 0) return result;

    for (int i = modeCount - 1; i >= 0; --i) // reverse order
    {
        const SDL_DisplayMode& mode = *modes[i];
        if (ignoreInvalidModes) {
            if (mode.w < MIN_WIDTH || mode.h < MIN_HEIGHT)
                continue;

            if (const SDL_DisplayMode* desktopMode = SDL_GetDesktopDisplayMode(did)) {
                if (mode.w >= desktopMode->w || mode.h >= desktopMode->h)
                    continue;
            }
        }

        if (ignoreRefreshRates) {
            auto res = std::make_pair(mode.w, mode.h);
            if (uniqueResolutions.find(res) == uniqueResolutions.end()) {
                uniqueResolutions.insert(res);
                result.push_back(mode);
            }
        } else {
            result.push_back(mode);
        }
    }

    SDL_free(modes);
    return result;
}

int GameWindow::FindNearestDisplayMode()
{
    auto result = -1;
    auto displayModes = GetDisplayModes();
    auto currentDiff = std::numeric_limits<int>::max();

    for (int i = 0; i < (int)displayModes.size(); i++)
    {
        auto& mode = displayModes[i];

        auto widthDiff = abs(mode.w - s_width);
        auto heightDiff = abs(mode.h - s_height);
        auto totalDiff = widthDiff + heightDiff;

        if (totalDiff < currentDiff)
        {
            currentDiff = totalDiff;
            result = i;
        }
    }

    return result;
}

bool GameWindow::IsPositionValid()
{
    auto displayCount = GetDisplayCount();

    int n = 0;
    SDL_DisplayID* displays = SDL_GetDisplays(&n);
    for (int i = 0; i < displayCount; i++)
    {
        SDL_Rect bounds;

        if (displays && i < n && SDL_GetDisplayBounds(displays[i], &bounds))
        {
            auto x = s_x;
            auto y = s_y;

            // Window spans across the entire display in windowed mode, which is invalid.
            if (!Config::Fullscreen && s_width == bounds.w && s_height == bounds.h)
                return false;

            if (x == SDL_WINDOWPOS_CENTERED_DISPLAY(displays[i]))
                x = bounds.w / 2 - s_width / 2;

            if (y == SDL_WINDOWPOS_CENTERED_DISPLAY(displays[i]))
                y = bounds.h / 2 - s_height / 2;

            if (x >= bounds.x && x < bounds.x + bounds.w &&
                y >= bounds.y && y < bounds.y + bounds.h)
            {
                if (displays) SDL_free(displays);
                return true;
            }
        }
    }
    if (displays) SDL_free(displays);
    return false;
}
