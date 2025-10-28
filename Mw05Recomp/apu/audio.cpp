#include <stdafx.h>

#include <bit>

#include "audio.h"
#include <kernel/memory.h>

#define AUDIO_DRIVER_KEY (uint32_t)('DAUD')

// Use to dump raw audio captures to the game folder.
//#define AUDIO_DUMP_SAMPLES_PATH "audio.pcm"

#ifdef AUDIO_DUMP_SAMPLES_PATH
std::ofstream g_audioDumpStream;
#endif

uint32_t XAudioRegisterRenderDriverClient(be<uint32_t>* callback, be<uint32_t>* driver)
{
    fprintf(stderr, "[MW05_AUDIO] XAudioRegisterRenderDriverClient called: callback=%08X param=%08X\n",
            (uint32_t)*callback, (uint32_t)callback[1]);
    fflush(stderr);

#ifdef AUDIO_DUMP_SAMPLES_PATH
    g_audioDumpStream.open(AUDIO_DUMP_SAMPLES_PATH, std::ios::binary);
#endif

    *driver = AUDIO_DRIVER_KEY;
    if (auto cb = g_memory.FindFunction(*callback))
    {
        fprintf(stderr, "[MW05_AUDIO] Audio callback found at 0x%08X, registering client...\n", (uint32_t)*callback);
        fflush(stderr);

        XAudioRegisterClient(cb, callback[1]);

        fprintf(stderr, "[MW05_AUDIO] Audio client registered successfully\n");
        fflush(stderr);
    }
    else
    {
        fprintf(stderr, "[boot][warn] Audio callback 0x%08X not found; audio disabled until valid.\n", (uint32_t)*callback);
        fflush(stderr);
    }

    fprintf(stderr, "[MW05_AUDIO] XAudioRegisterRenderDriverClient returning 0, driver=%08X\n", AUDIO_DRIVER_KEY);
    fflush(stderr);

    return 0;
}

uint32_t XAudioUnregisterRenderDriverClient(uint32_t driver)
{
    return 0;
}

uint32_t XAudioSubmitRenderDriverFrame(uint32_t driver, void* samples)
{
#ifdef AUDIO_DUMP_SAMPLES_PATH
    static uint32_t xaudioSamplesBuffer[XAUDIO_NUM_SAMPLES * XAUDIO_NUM_CHANNELS];
    for (size_t i = 0; i < XAUDIO_NUM_SAMPLES; i++)
    {
        for (size_t j = 0; j < XAUDIO_NUM_CHANNELS; j++)
        {
            xaudioSamplesBuffer[i * XAUDIO_NUM_CHANNELS + j] = ByteSwap(((uint32_t *)samples)[j * XAUDIO_NUM_SAMPLES + i]);
        }
    }

    g_audioDumpStream.write((const char *)(xaudioSamplesBuffer), sizeof(xaudioSamplesBuffer));
#endif

    XAudioSubmitFrame(samples);
    return 0;
}
