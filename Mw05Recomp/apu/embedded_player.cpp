#include <apu/audio.h>
#include <apu/embedded_player.h>
#include <user/config.h>

#include <res/music/installer.ogg.h>
#include <res/sounds/sys_worldmap_cursor.ogg.h>
#include <res/sounds/sys_worldmap_finaldecide.ogg.h>
#include <res/sounds/sys_actstg_pausecansel.ogg.h>
#include <res/sounds/sys_actstg_pausecursor.ogg.h>
#include <res/sounds/sys_actstg_pausedecide.ogg.h>
#include <res/sounds/sys_actstg_pausewinclose.ogg.h>
#include <res/sounds/sys_actstg_pausewinopen.ogg.h>

enum class EmbeddedSound
{
    SysWorldMapCursor,
    SysWorldMapFinalDecide,
    SysActStgPauseCansel,
    SysActStgPauseCursor,
    SysActStgPauseDecide,
    SysActStgPauseWinClose,
    SysActStgPauseWinOpen,
    Count,
};

struct EmbeddedSoundData
{
    MIX_Audio* audio{};
};

static std::array<EmbeddedSoundData, size_t(EmbeddedSound::Count)> g_embeddedSoundData = {};
static const std::unordered_map<std::string_view, EmbeddedSound> g_embeddedSoundMap =
{
    { "sys_worldmap_cursor", EmbeddedSound::SysWorldMapCursor },
    { "sys_worldmap_finaldecide", EmbeddedSound::SysWorldMapFinalDecide },
    { "sys_actstg_pausecansel", EmbeddedSound::SysActStgPauseCansel },
    { "sys_actstg_pausecursor", EmbeddedSound::SysActStgPauseCursor },
    { "sys_actstg_pausedecide", EmbeddedSound::SysActStgPauseDecide },
    { "sys_actstg_pausewinclose", EmbeddedSound::SysActStgPauseWinClose },
    { "sys_actstg_pausewinopen", EmbeddedSound::SysActStgPauseWinOpen },
};

static MIX_Mixer* g_mixer = nullptr;
static MIX_Track* g_musicTrack = nullptr;

static void OnSfxStopped(void* userdata, MIX_Track* track)
{
    (void)userdata;
    MIX_DestroyTrack(track);
}

static void PlayEmbeddedSound(EmbeddedSound s)
{
    EmbeddedSoundData &data = g_embeddedSoundData[size_t(s)];
    if (data.audio == nullptr)
    {
        // The sound hasn't been created yet, create it and pick it.
        const void *soundData = nullptr;
        size_t soundDataSize = 0;
        switch (s)
        {
        case EmbeddedSound::SysWorldMapCursor:
            soundData = g_sys_worldmap_cursor;
            soundDataSize = sizeof(g_sys_worldmap_cursor);
            break;
        case EmbeddedSound::SysWorldMapFinalDecide:
            soundData = g_sys_worldmap_finaldecide;
            soundDataSize = sizeof(g_sys_worldmap_finaldecide);
            break;
        case EmbeddedSound::SysActStgPauseCansel:
            soundData = g_sys_actstg_pausecansel;
            soundDataSize = sizeof(g_sys_actstg_pausecansel);
            break;
        case EmbeddedSound::SysActStgPauseCursor:
            soundData = g_sys_actstg_pausecursor;
            soundDataSize = sizeof(g_sys_actstg_pausecursor);
            break;
        case EmbeddedSound::SysActStgPauseDecide:
            soundData = g_sys_actstg_pausedecide;
            soundDataSize = sizeof(g_sys_actstg_pausedecide);
            break;
        case EmbeddedSound::SysActStgPauseWinClose:
            soundData = g_sys_actstg_pausewinclose;
            soundDataSize = sizeof(g_sys_actstg_pausewinclose);
            break;
        case EmbeddedSound::SysActStgPauseWinOpen:
            soundData = g_sys_actstg_pausewinopen;
            soundDataSize = sizeof(g_sys_actstg_pausewinopen);
            break;
        default:
            assert(false && "Unknown embedded sound.");
            return;
        }

        SDL_IOStream* io = SDL_IOFromConstMem(soundData, soundDataSize);
        data.audio = MIX_LoadAudio_IO(g_mixer, io, true, true);
    }

    MIX_Track* track = MIX_CreateTrack(g_mixer);
    if (!track)
        return;
    MIX_SetTrackAudio(track, data.audio);
    MIX_SetTrackGain(track, Config::MasterVolume * Config::EffectsVolume);
    MIX_SetTrackStoppedCallback(track, OnSfxStopped, nullptr);
    MIX_PlayTrack(track, 0);
}

static MIX_Audio* g_installerMusic;

void EmbeddedPlayer::Init() 
{
    if (!g_mixer)
    {
        g_mixer = MIX_CreateMixerDevice(SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK, nullptr);
    }

    SDL_IOStream* io = SDL_IOFromConstMem(g_installer_music, sizeof(g_installer_music));
    g_installerMusic = MIX_LoadAudio_IO(g_mixer, io, true, true);

    s_isActive = true;
}

void EmbeddedPlayer::Play(const char *name) 
{
    assert(s_isActive && "Playback shouldn't be requested if the Embedded Player isn't active.");

    auto it = g_embeddedSoundMap.find(name);
    if (it == g_embeddedSoundMap.end())
    {
        return;
    }

    PlayEmbeddedSound(it->second);
}

void EmbeddedPlayer::PlayMusic()
{
    if (g_musicTrack && MIX_TrackPlaying(g_musicTrack))
        return;

    if (!g_musicTrack)
        g_musicTrack = MIX_CreateTrack(g_mixer);

    MIX_SetTrackAudio(g_musicTrack, g_installerMusic);
    MIX_SetTrackGain(g_musicTrack, Config::MasterVolume * Config::MusicVolume * MUSIC_VOLUME);

    SDL_PropertiesID props = SDL_CreateProperties();
    SDL_SetNumberProperty(props, MIX_PROP_PLAY_LOOPS_NUMBER, -1);
    MIX_PlayTrack(g_musicTrack, props);
    SDL_DestroyProperties(props);
}

void EmbeddedPlayer::FadeOutMusic()
{
    if (g_musicTrack && MIX_TrackPlaying(g_musicTrack))
    {
        SDL_AudioSpec spec{};
        if (!MIX_GetMixerFormat(g_mixer, &spec))
            return;
        Sint64 frames = MIX_MSToFrames(spec.freq, 1000);
        MIX_StopTrack(g_musicTrack, frames);
    }
}

void EmbeddedPlayer::Shutdown() 
{
    for (EmbeddedSoundData &data : g_embeddedSoundData)
    {
        if (data.audio != nullptr)
        {
            MIX_DestroyAudio(data.audio);
            data.audio = nullptr;
        }
    }

    if (g_musicTrack)
    {
        MIX_DestroyTrack(g_musicTrack);
        g_musicTrack = nullptr;
    }

    if (g_installerMusic)
    {
        MIX_DestroyAudio(g_installerMusic);
        g_installerMusic = nullptr;
    }

    if (g_mixer)
    {
        MIX_DestroyMixer(g_mixer);
        g_mixer = nullptr;
    }
    MIX_Quit();

    s_isActive = false;
}
