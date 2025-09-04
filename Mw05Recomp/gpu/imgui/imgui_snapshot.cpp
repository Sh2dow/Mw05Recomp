#include "imgui_snapshot.h"

#include <locale/locale.h>
#include <user/config.h>
#include <kernel/xdbf.h>
#include <app.h>

#ifdef ENABLE_IM_FONT_ATLAS_SNAPSHOT
#include <res/font/im_font_atlas.bin.h>
#include <decompressor.h>

template<typename T1, typename T2>
void ImFontAtlasSnapshot::SnapPointer(size_t offset, const T1& value, const T2& ptr, size_t count)
{
    if (ptr != nullptr && count != 0)
    {
        if (!objects.contains(ptr))
        {
            constexpr size_t ALIGN = alignof(std::remove_pointer_t<T2>);
            constexpr size_t SIZE = sizeof(std::remove_pointer_t<T2>);

            size_t ptrOffset = (data.size() + ALIGN - 1) & ~(ALIGN - 1);
            data.resize(ptrOffset + SIZE * count);
            memcpy(&data[ptrOffset], ptr, SIZE * count);

            for (size_t i = 0; i < count; i++)
            {
                size_t curPtrOffset = ptrOffset + SIZE * i;
                objects[&ptr[i]] = curPtrOffset;
                Traverse(curPtrOffset, ptr[i]);
            }
        }

        size_t fieldOffset = offset + (reinterpret_cast<ptrdiff_t>(&ptr) - reinterpret_cast<ptrdiff_t>(&value));
        *reinterpret_cast<size_t*>(&data[fieldOffset]) = objects[ptr];
        offsets.push_back(fieldOffset);
    }
}

template<typename T>
void ImFontAtlasSnapshot::Traverse(size_t offset, const T& value)
{
    if constexpr (std::is_pointer_v<T>)
    {
        SnapPointer(offset, value, value, 1);
    }
    else
    {
        // Unsupported when snapshotting is disabled
    }
}

template<typename T>
size_t ImFontAtlasSnapshot::Snap(const T& value)
{
    size_t offset = (data.size() + alignof(T) - 1) & ~(alignof(T) - 1);
    data.resize(offset + sizeof(T));
    memcpy(&data[offset], &value, sizeof(T));
    objects[&value] = offset;
    Traverse(offset, value);
    return offset;
}

struct ImFontAtlasSnapshotHeader
{
    uint32_t imguiVersion;
    uint32_t dataOffset;
    uint32_t offsetCount;
    uint32_t offsetsOffset;
};

void ImFontAtlasSnapshot::Snap()
{
#ifdef ENABLE_IM_FONT_ATLAS_SNAPSHOT
    data.resize(sizeof(ImFontAtlasSnapshotHeader));
    size_t dataOffset = Snap(*ImGui::GetIO().Fonts);

    size_t offsetsOffset = data.size();
    std::sort(offsets.begin(), offsets.end());

    data.insert(data.end(), 
        reinterpret_cast<uint8_t*>(offsets.data()),
        reinterpret_cast<uint8_t*>(offsets.data() + offsets.size()));

    auto header = reinterpret_cast<ImFontAtlasSnapshotHeader*>(data.data());
    header->imguiVersion = IMGUI_VERSION_NUM;
    header->dataOffset = dataOffset;
    header->offsetCount = offsets.size();
    header->offsetsOffset = offsetsOffset;
#else
    // Snapshot disabled; provide a no-op with a consistent symbol.
    data.clear();
    offsets.clear();
    objects.clear();
#endif
}

static std::unique_ptr<uint8_t[]> g_imFontAtlas;

ImFontAtlas* ImFontAtlasSnapshot::Load()
{
    g_imFontAtlas = decompressZstd(g_im_font_atlas, g_im_font_atlas_uncompressed_size);

    auto header = reinterpret_cast<ImFontAtlasSnapshotHeader*>(g_imFontAtlas.get());
    assert(header->imguiVersion == IMGUI_VERSION_NUM && "ImGui version mismatch, the font atlas needs to be regenerated!");

    auto offsetTable = reinterpret_cast<uint32_t*>(g_imFontAtlas.get() + header->offsetsOffset);
    for (size_t i = 0; i < header->offsetCount; i++)
    {
        *reinterpret_cast<size_t*>(g_imFontAtlas.get() + (*offsetTable)) += reinterpret_cast<size_t>(g_imFontAtlas.get());
        ++offsetTable;
    }

    return reinterpret_cast<ImFontAtlas*>(g_imFontAtlas.get() + header->dataOffset);
}
#endif // ENABLE_IM_FONT_ATLAS_SNAPSHOT


static int Utf8CharFromBytes(unsigned int* out_char, const char* in_text, const char* in_text_end)
{
    if (in_text >= in_text_end || !in_text)
        return 0;
    const unsigned char c = (unsigned char)*in_text;
    if (c < 0x80) { *out_char = c; return 1; }
    if ((c >> 5) == 0x6) {
        if (in_text + 1 >= in_text_end) { *out_char = 0xFFFD; return 1; }
        *out_char = ((c & 0x1F) << 6) | ((unsigned char)in_text[1] & 0x3F);
        return 2;
    }
    if ((c >> 4) == 0xE) {
        if (in_text + 2 >= in_text_end) { *out_char = 0xFFFD; return 1; }
        *out_char = ((c & 0x0F) << 12) | (((unsigned char)in_text[1] & 0x3F) << 6) | ((unsigned char)in_text[2] & 0x3F);
        return 3;
    }
    if ((c >> 3) == 0x1E) {
        if (in_text + 3 >= in_text_end) { *out_char = 0xFFFD; return 1; }
        *out_char = ((c & 0x07) << 18) | (((unsigned char)in_text[1] & 0x3F) << 12) | (((unsigned char)in_text[2] & 0x3F) << 6) | ((unsigned char)in_text[3] & 0x3F);
        return 4;
    }
    *out_char = 0xFFFD;
    return 1;
}

static void GetGlyphs(std::set<ImWchar>& glyphs, const std::string_view& value)
{
    const char* cur = value.data();
    const char* end = value.data() + value.size();
    while (cur < end)
    {
        unsigned int c;
        int consumed = Utf8CharFromBytes(&c, cur, end);
        if (consumed <= 0) break;
        cur += consumed;
        glyphs.emplace((ImWchar)c);
    }
}

static std::vector<ImWchar> g_glyphRanges;

void ImFontAtlasSnapshot::GenerateGlyphRanges()
{
    std::vector<std::string_view> localeStrings;

    for (auto& config : g_configDefinitions)
        config->GetLocaleStrings(localeStrings);

    std::set<ImWchar> glyphs;

    for (size_t i = 0x20; i <= 0xFF; i++)
        glyphs.emplace(i);

    for (auto& localeString : localeStrings)
        GetGlyphs(glyphs, localeString);

    for (auto& [name, locale] : g_locale)
    {
        for (auto& [language, value] : locale)
            GetGlyphs(glyphs, value);
    }

    for (size_t i = XDBF_LANGUAGE_ENGLISH; i <= XDBF_LANGUAGE_ITALIAN; i++)
    {
        auto achievements = g_xdbfWrapper.GetAchievements(static_cast<EXDBFLanguage>(i));
        for (auto& achievement : achievements)
        {
            GetGlyphs(glyphs, achievement.Name);
            GetGlyphs(glyphs, achievement.UnlockedDesc);
            GetGlyphs(glyphs, achievement.LockedDesc);
        }
    }

    for (auto glyph : glyphs)
    {
        if (g_glyphRanges.empty() || (g_glyphRanges.back() + 1) != glyph)
        {
            g_glyphRanges.push_back(glyph);
            g_glyphRanges.push_back(glyph);
        }
        else
        {
            g_glyphRanges.back() = glyph;
        }
    }

    g_glyphRanges.push_back(0);
}

ImFont* ImFontAtlasSnapshot::GetFont(const char* name)
{
    // Prefer default font when the requested file is missing to avoid startup failure
    auto& io = ImGui::GetIO();
    auto fontAtlas = io.Fonts;
    if (name && std::filesystem::exists(name))
        return fontAtlas->AddFontFromFileTTF(name, 24.0f, nullptr, g_glyphRanges.data());

    return fontAtlas->AddFontDefault();
}
