#include "ui.h"
#include "../libs/stb/stb_image.h"
#define kIMAGE_SIZE    (64)
#define kIMAGE_PADDING (8)
#define kITEM_SIZE     (kIMAGE_SIZE + kIMAGE_PADDING + kIMAGE_PADDING)

#define FileMapItem std::pair<std::string, File_ptr>

#define SHOWED_FILE  std::pair<FileMapItem, int>


namespace ImGui  // Widgets
{

void Clock(float t1, float t2, float t3)
{
    static ImGui::WIcon clock_icon {0, 0, 0};
    if (!clock_icon.texture) ImGui::LoadTextureFromFile("./res/images/Clock.png", &clock_icon);
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (!window->SkipItems && clock_icon.texture && clock_icon.width && clock_icon.height)
    {
        ImVec2 pos = window->DC.CursorPos;

        ImVec2 imsize = ImVec2(49, 49);
        ImVec2 offset = pos + ImVec2(25, 25);

        const ImRect imbb(
            ImVec2(pos.x, pos.y),
            ImVec2(pos.x + imsize.x, pos.y + imsize.y));

        window->DrawList->AddImage(reinterpret_cast<ImTextureID>(clock_icon.texture), imbb.Min, imbb.Max,
            ImVec2(0, 0), ImVec2(1, 1), IM_COL32(255, 255, 255, 255));
        float c1 = std::cos(3.141693 * t1 / 6.0);
        float c2 = std::cos(3.141693 * t2 / 30.0);
        float c3 = std::cos(3.141693 * t3 / 30.0);
        float s1 = std::sin(3.141693 * t1 / 6.0);
        float s2 = std::sin(3.141693 * t2 / 30.0);
        float s3 = std::sin(3.141693 * t3 / 30.0);
        static auto col1 = GetColorU32(Hex2ImVec4("#979797"));
        static auto col2 = GetColorU32(Hex2ImVec4("#72AFD3"));
        static auto col3 = GetColorU32(Hex2ImVec4("#60DFCD"));
        window->DrawList->AddLine(offset - ImVec2(s1 * 2, -c1 * 2), offset + ImVec2(s1 * 15, -c1 * 15), col1, 4);
        window->DrawList->AddLine(offset - ImVec2(s2 * 2, -c2 * 2), offset + ImVec2(s2 * 18, -c2 * 18), col2, 3);
        window->DrawList->AddLine(offset - ImVec2(s3 * 2, -c3 * 2), offset + ImVec2(s3 * 21, -c3 * 21), col3, 2);
        Dummy({ imsize.x, imsize.y });
    }
}

void Overrided_BeginTooltip()
{
    ImGuiTooltipFlags tooltip_flags = ImGuiTooltipFlags_None;
    ImGuiWindowFlags  extra_window_flags = ImGuiWindowFlags_None;
    ImGuiContext& g = *GImGui;

    if (g.DragDropWithinSource || g.DragDropWithinTarget)
    {
        // The default tooltip position is a little offset to give space to see the context menu
        // (it's also clamped within the current viewport/monitor) In the context of a dragging
        // tooltip we try to reduce that offset and we enforce following the cursor. Whatever we do
        // we want to call SetNextWindowPos() to enforce a tooltip position and disable clipping the
        // tooltip without our display area, like regular tooltip do.
        // ImVec2 tooltip_pos = g.IO.MousePos - g.ActiveIdClickOffset - g.Style.WindowPadding;
        ImVec2 tooltip_pos =
            g.IO.MousePos + ImVec2(16 * g.Style.MouseCursorScale, 8 * g.Style.MouseCursorScale);
        SetNextWindowPos(tooltip_pos);
        // SetNextWindowBgAlpha(g.Style.Colors[ImGuiCol_PopupBg].w * 0.60f);
        // PushStyleVar(ImGuiStyleVar_Alpha, g.Style.Alpha * 0.60f); // This would be nice but e.g
        // ColorButton with checkboard has issue with transparent colors :(
        tooltip_flags |= ImGuiTooltipFlags_OverridePreviousTooltip;
    }

    char window_name[16];
    ImFormatString(window_name, IM_ARRAYSIZE(window_name), "##Tooltip_%02d",
        g.TooltipOverrideCount);
    if (tooltip_flags & ImGuiTooltipFlags_OverridePreviousTooltip)
        if (ImGuiWindow* window = FindWindowByName(window_name))
            if (window->Active)
            {
                // Hide previous tooltip from being displayed. We can't easily "reset" the content
                // of a window so we create a new one.
                window->Hidden = true;
                window->HiddenFramesCanSkipItems = 1;  // FIXME: This may not be necessary?
                ImFormatString(window_name, IM_ARRAYSIZE(window_name), "##Tooltip_%02d",
                    ++g.TooltipOverrideCount);
            }
    ImGuiWindowFlags flags = ImGuiWindowFlags_Tooltip | ImGuiWindowFlags_NoInputs |
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_AlwaysAutoResize;
    Begin(window_name, NULL, flags | extra_window_flags);
}

// Simple helper function to load an image into a OpenGL texture with common settings
bool LoadTextureFromFile(const char* filename, WIcon* out_icon)
{
    // Load from file
    int            image_width = 0;
    int            image_height = 0;
    unsigned char* image_data = stbi_load(filename, &image_width, &image_height, NULL, 4);
    if (image_data == NULL)
        return false;

    // Create a OpenGL texture identifier
    GLuint image_texture;
    glGenTextures(1, &image_texture);
    glBindTexture(GL_TEXTURE_2D, image_texture);

    // Setup filtering parameters for display
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S,
        GL_CLAMP_TO_EDGE);  // This is required on WebGL for non power-of-two textures
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);  // Same

    // Upload pixels into texture
#if defined(GL_UNPACK_ROW_LENGTH) && !defined(__EMSCRIPTEN__)
    glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
#endif
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, image_width, image_height, 0, GL_RGBA, GL_UNSIGNED_BYTE,
        image_data);
    stbi_image_free(image_data);
    glBindTexture(GL_TEXTURE_2D, 0);

    out_icon->texture = image_texture;
    out_icon->width = image_width;
    out_icon->height = image_height;

    return true;
}

bool RenderShadow_v1(const ImVec2& p1, const ImVec2& p2, int32_t color, const int32_t& dx, const int32_t& dy, const int32_t& blur, const int32_t& spread, const int32_t& round, const bool& inner)
{
    struct shadow_t
    {
        std::vector<uint32_t> data;
        int32_t width, height;
        int32_t dx, dy, blur, spread, round;
        bool inner;
        int32_t real_width, real_height;
        int32_t offset_x, offset_y;

        GLuint image_texture;
    };

    int32_t width  = std::abs(floor(p1.x - p2.x));
    int32_t height = std::abs(floor(p1.y - p2.y));
    int32_t x = std::min(p1.x, p2.x);
    int32_t y = std::min(p1.y, p2.y);

    static std::vector<shadow_t*> stored_shadows = std::vector<shadow_t*>();

    shadow_t* select = nullptr; 

    for(auto& el : stored_shadows)
    {
        if(
            width == el->width &&
            height == el->height &&
            dx == el->dx &&
            dy == el->dy &&
            blur == el->blur &&
            spread == el->spread &&
            round == el->round &&
            inner == el->inner
            )
            {
                select = el;
                break;
            }
    }

    if(select == nullptr)
    {
        select = new shadow_t();
        stored_shadows.push_back(select);
        int32_t x1 = 0;
        int32_t x2 = width;
        int32_t y1 = 0;
        int32_t y2 = height;
        int32_t real_width = width;
        int32_t real_height = height;

        if(inner)
        {
            select->offset_x = x1;
            select->offset_y = y1;
            select->real_width = real_width;
            select->real_height = real_height;

            x1 = dx - blur;
            y1 = dy - blur;

            x2 = dx + real_width  + blur;
            y2 = dy + real_height + blur;
        }
        else
        {
            x1 = y1 = blur + spread;
            x2 += x1;
            y2 += y1;
            real_width += x1 * 2 + 4;
            real_height += y1 * 2 + 4;
            select->offset_x = dx + x1 - 2;
            select->offset_y = dy + y1 - 2;
            select->real_width = real_width;
            select->real_height = real_height;

            x1 = blur * 2 + 2;
            y1 = blur * 2 + 2;

            x2 = real_width  - blur * 2 - 2;
            y2 = real_height - blur * 2 - 2;
        }
        
        select->width = width;
        select->height = height;
        select->dx = dx;
        select->dy = dy;
        select->blur = blur;
        select->spread = spread;
        select->round = round;
        select->inner = inner;

        select->data.resize(select->real_width * select->real_height);

        static auto getDistToPointSqr = [](const float& x1, const float& y1, const float& x2, const float& y2) -> float
        {
            return (x1 - x2) * (x1 - x2) + (y1 - y2) * (y1 - y2);
        };

        static auto Q_rsqrt = [](const float& number) -> float
        {
            long i;
            float x2, y;
            const float threehalfs = 1.5F;

            x2 = number * 0.5F;
            y  = number;
            i  = * ( long * ) &y;
            i  = 0x5f3759df - ( i >> 1 );
            y  = * ( float * ) &i;
            y  = y * ( threehalfs - ( x2 * y * y ) );

            return y;
        };

        static auto getDistToSection = [](const float& x1, const float& y1, const float& x2, const float& y2, const float& cx, const float& cy) -> float
        {
            float dx = (x1 - x2);
            float dy = (y1 - y2);

            if((dx * (x1 - cx) + dy * (y1 - cy)) * (dx * (x2 - cx) + dy * (y2 - cy)) <= 0)
            {
                float q_r = Q_rsqrt(dx * dx + dy * dy);
                dx *= q_r;
                dy *= q_r;
                float c = dy * x1 - dx * y2;

                return abs(dy * cx - dx * cy - c);
            }
            else
            {
                float r1 = getDistToPointSqr(x1, y1, cx, cy);
                float r2 = getDistToPointSqr(x2, y2, cx, cy);
                return sqrtf(r1 > r2 ? r2 : r1);
            }
        };
        
        static auto getDistToRoundRect_outer = [](const float& x1, const float& y1, const float& x2, const float& y2, const float& r, const float& cx, const float& cy) -> float
        {
            if(
                (x1 + r - cx) * (x2 - r - cx) < 0 && (y1 - cy) * (y2 - cy) < 0 ||
                (x1 - cx) * (x2 - cx) < 0 && (y1 + r - cy) * (y2 - r - cy) < 0)
                return 0;
            
            float rs[8];
            rs[0] = getDistToPointSqr(x1 + r, y1 + r, cx, cy);
            rs[1] = getDistToPointSqr(x2 - r, y2 - r, cx, cy);
            rs[2] = getDistToPointSqr(x1 + r, y2 - r, cx, cy);
            rs[3] = getDistToPointSqr(x2 - r, y1 + r, cx, cy);

            float br = rs[0];
            for (int i = 1; i < 4; i++) {
                if (rs[i] < br) {
                    br = rs[i];
                }
            }
            br = sqrtf(br);
            
            if(br < r)
                return 0;
            br -= r; 
            
            rs[4] = getDistToSection(x1 + r, y1, x2 - r, y1, cx, cy); // top
            rs[5] = getDistToSection(x1 + r, y2, x2 - r, y2, cx, cy); // bottom

            rs[6] = getDistToSection(x1, y1 + r, x1, y2 - r, cx, cy); // left
            rs[7] = getDistToSection(x2, y1 + r, x2, y2 - r, cx, cy); // right
            //float br = rs[4];
            for (int i = 4; i < 8; i++) {
                if (rs[i] < br) {
                    br = rs[i];
                }
            }
            
            return br;
        };

        static auto getDistToRoundRect_inner = [](const float& x1, const float& y1, const float& x2, const float& y2, const float& r, const float& cx, const float& cy) -> float
        {
            if((x1 - cx) * (x2 - cx) > 0 || (y1 - cy) * (y2 - cy) > 0)
                return 0;
            float vs[4];
            vs[0] = (x1 - cx) * (x1 - cx);
            vs[1] = (y1 - cy) * (y1 - cy);
            vs[2] = (x2 - cx) * (x2 - cx);
            vs[3] = (y2 - cy) * (y2 - cy);
            float r1, r2;
            int n = 0;
            float min = vs[0];
            for(int i = 1; i < 4; i++) if(min > vs[i])
            {
                min = vs[i];
                n = i;
            }

            int m = (n == 0 ? 1 : 0);
            float min2 = vs[m];
            for(int i = 1; i < 4; i++) if(min2 > vs[i] && min < vs[i])
            {
                min2 = vs[i];
                m = i;
            }

            if(!(
                (x1 + r - cx)   * (x2 - r - cx)   < 0 && 
                (y1 - cy)       * (y2 - cy)       < 0 ||
                (x1 - cx)       * (x2 - cx)       < 0 && 
                (y1 + r - cy)   * (y2 - r - cy)   < 0))
            {
                float rs[4];
                rs[0] = getDistToPointSqr(x1 + r, y1 + r, cx, cy);
                rs[1] = getDistToPointSqr(x2 - r, y2 - r, cx, cy);
                rs[2] = getDistToPointSqr(x1 + r, y2 - r, cx, cy);
                rs[3] = getDistToPointSqr(x2 - r, y1 + r, cx, cy);

                float br = rs[0];
                for (int i = 1; i < 4; i++) {
                    if (rs[i] < br) {
                        br = rs[i];
                    }
                }
                br = sqrtf(br);
                
                if(br > r)
                    return 0;
                return r - br;
            }

            {
                if((x1 - cx) * (x2 - cx) > 0 && (y1 - cy) * (y2 - cy) > 0)
                    return 0;
                return sqrtf(min);
            }
        };



        uint8_t* col = (uint8_t*)(&color);

        int32_t base_round = inner ? round + blur : round - blur;
        if(base_round < 0)
            base_round = 0;

        for(int32_t x = 0; x < real_width; ++x) for(int32_t y = 0; y < real_height; ++y)
        {
            int i = x + y * real_width;
            uint8_t* px = (uint8_t*)(&(select->data.data()[i]));
            float r = 0;
            if(inner)
                r = getDistToRoundRect_inner(x1, y1, x2, y2, base_round, x, y);
            else
                r = getDistToRoundRect_outer(x1, y1, x2, y2, base_round, x, y);

                                    
            float k = (blur * 2 - r) / (blur * 2.0);
            if(k < 0)
                k = 0;
            if(k > 1)
                k = 1;

            if(inner)
            {
                if(
                    (round - x) * (width - round  - x) < 0 && 
                    (0     - y) * (height         - y) < 0 ||
                    (0     - x) * (width          - x) < 0 && 
                    (round - y) * (height - round - y) < 0
                );
                else
                {
                    float rs[4];
                    rs[0] = getDistToPointSqr(0 + round, 0 + round, x, y);
                    rs[1] = getDistToPointSqr(width - round, height - round, x, y);
                    rs[2] = getDistToPointSqr(0 + round, height - round, x, y);
                    rs[3] = getDistToPointSqr(width - round, 0 + round, x, y);

                    float br = rs[0];
                    for (int i = 1; i < 4; i++) {
                        if (rs[i] < br) {
                            br = rs[i];
                        }
                    }
                    
                    if(br >= round * round)
                        k = 0;
                }
            }


            px[0] = col[0];
            px[1] = col[1];
            px[2] = col[2];
            px[3] = col[3] * k;
        }

        GLuint image_texture;
        glGenTextures(1, &image_texture);
        glBindTexture(GL_TEXTURE_2D, image_texture);

        // Setup filtering parameters for display
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S,
            GL_CLAMP_TO_EDGE);  // This is required on WebGL for non power-of-two textures
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);  // Same

        // Upload pixels into texture
#if defined(GL_UNPACK_ROW_LENGTH) && !defined(__EMSCRIPTEN__)
        glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
#endif
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, real_width, real_height, 0, GL_RGBA, GL_UNSIGNED_BYTE,
            select->data.data());
        glBindTexture(GL_TEXTURE_2D, 0);
        select->data.clear();
        select->image_texture = image_texture;


    }

    if(select != nullptr)
    {
        if(select->image_texture == 0)
            return false;

        ImGuiWindow* window = ImGui::GetCurrentWindow();

        const ImRect imbb(
            ImVec2(
                x - select->offset_x, 
                y - select->offset_y),
            ImVec2(
                x - select->offset_x + select->real_width, 
                y - select->offset_y + select->real_height));

        window->DrawList->AddImage(reinterpret_cast<ImTextureID>(select->image_texture), imbb.Min, imbb.Max);
    }
    else
        return false;
    return true;
}

FileMapItem MyTreeWiew(std::string label, FileMap* map, const ImVec2& size_arg, bool use_ch)
{
    ImGuiContext& g = *GImGui;
    const ImGuiStyle& style = g.Style;
    ImGuiWindow* window = GetCurrentWindow();
    ImVec2 shadow_pos = window->DC.CursorPos + style.WindowPadding;
    BeginChild(std::string(label).append("BeginChild").c_str(), {0, 0}, true);
    window = GetCurrentWindow();
    

    
    FileMapItem ret = {"", File_ptr()};

    int tab_deep = 1;

    const int tab_size = 10;

    auto map_to_sotred_vector = [](FileMap* map) -> std::vector<FileMapItem>
    {
        std::vector<FileMapItem> out;
        for(auto el : (*map))
        {
            out.push_back(el);
        }
        std::sort(out.begin(), out.end(), 
            [] (FileMapItem const& a, FileMapItem const& b) 
            {
                return a.first < b.first; 
            });
        return out;
    };

    std::function<bool(const std::string&, const File_ptr&)> DrawFile = [&](const std::string& fullname, const File_ptr& file)->bool
    {
        ImVec2 pos = window->DC.CursorPos;
        
        bool isFolder = !file->map.empty();

        bool iOpen = isFolder && ((file->status & FILE_TREE_OPEN) != 0);

        const ImGuiID id = window->GetID(label.append("_").append(file->hash).c_str());
        const ImGuiID id_ch = window->GetID(label.append("_").append(file->hash).append("_ch").c_str());


        std::string name = "";
        
        for(int i = 0; i < fullname.size(); i++)
        {
            char c = fullname[i];
            if(c == '\\' || c == '/')
            {
                name.clear();
            }
            else
            {
                name += c;
            }
        }
        if(isFolder)
            name = std::string(">") + name;
        const ImVec2 label_size = CalcTextSize(name.c_str(), NULL, true);

        const ImVec2 corr_size = {size_arg.x - 48 * use_ch, size_arg.y};

        const ImVec2 size = CalcItemSize(corr_size, label_size.x + style.FramePadding.x * 2.0f, label_size.y + style.FramePadding.y * 2.0f);

        const ImRect bb(
            {pos.x + tab_deep * tab_size, pos.y}, 
            {pos.x + size.x             , pos.y + size.y});

        ItemSize(size, style.FramePadding.y);
        if (ItemAdd(bb, id))
        {
            const ImRect bb1(
                bb.Min,
                bb.Max - ImVec2(size_arg.x * 0.50, 0) - ImVec2(2,0)
                );
            const ImRect bb2(
                {bb1.Max.x, bb.Min.y},
                bb.Max - ImVec2(size_arg.x * 0.15, 0) - ImVec2(2,0)
                );
            const ImRect bb3(
                {bb2.Max.x, bb.Min.y},
                bb.Max - ImVec2(2,0)
                );
            const ImRect bb3_1(
                (bb3.Min + bb.Max) / 2 - ImVec2(12, 12),
                (bb3.Min + bb.Max) / 2 + ImVec2(12, 12)
                );

            bool hovered, held;
            bool pressed = ButtonBehavior(bb, id, &hovered, &held, ImGuiButtonFlags_None);

            if(pressed)
            {
                ret = {fullname, file};
            }

            // Render
            const ImU32 col = hovered ? GetColorU32(ImGuiCol_ButtonActive) : GetColorU32(Hex2ImVec4("#E8F9FF"));
            RenderFrame(bb.Min, bb.Max, col, true, 10);

            RenderTextClipped(bb1.Min + style.FramePadding, bb1.Max - style.FramePadding, name.c_str(), NULL, &label_size, {0, 0.5f}, &bb1);

            RenderTextClipped(bb2.Min + style.FramePadding, bb2.Max - style.FramePadding, file->formatTime.c_str(), NULL, &label_size, {0.0f, 0.5f}, &bb2);

            const ImGuiID id_ch = window->GetID(label.append("_").append(file->hash).append("_casdasdh").c_str());


        }
        if(use_ch)
        {
            SameLine();
            static ImGui::WIcon checkboxes_on_icon {0, 0, 0};
            static ImGui::WIcon checkboxe_off_icon {0, 0, 0};
            static ImGui::WIcon checkboxe_on_off_icon {0, 0, 0}; 
            if (!checkboxes_on_icon.texture)
            {
                ImGui::LoadTextureFromFile("./res/images/checkboxe_on.png", &checkboxes_on_icon);
            }
            if (!checkboxe_off_icon.texture)
            {
                ImGui::LoadTextureFromFile("./res/images/checkboxe_off.png", &checkboxe_off_icon);
            }
            if (!checkboxe_on_off_icon.texture)
            {
                ImGui::LoadTextureFromFile("./res/images/checkboxe_on_off.png", &checkboxe_on_off_icon);
            }
            auto used = file->GetUsed();
            if(MyCheckBox(
                id_ch, 
                //reinterpret_cast<ImTextureID>(used == 2 ? checkboxes_on_icon.texture : (used == 1 ? checkboxe_on_off_icon.texture : checkboxe_off_icon.texture)),
                reinterpret_cast<ImTextureID>(used == 2 ? checkboxe_on_off_icon.texture : (used == 1 ? checkboxe_on_off_icon.texture : checkboxe_off_icon.texture)),
                {24, 24},
                ImVec2(0, 0),
                ImVec2(1, 1), 
                ImVec4(255, 255, 255, 255),
                ImVec4(255, 255, 255, 255)))
                file->SetUsed(!file->used);
        }
        if(isFolder)
        {
            tab_deep += 1;
            auto sort_map = map_to_sotred_vector(&file->map);

            for(auto el : sort_map)
            {
                DrawFile(el.first, el.second);
            }
            tab_deep -= 1;
        }
        return true;
    };
    
    auto sort_map = map_to_sotred_vector(map);

    for(auto el : sort_map)
    {
        DrawFile(el.first, el.second);
    }
    auto win_size = window->Size;
    ImRect bb = ImRect(
                shadow_pos - style.WindowPadding,
                shadow_pos + win_size - style.WindowPadding
                );
    EndChild();
    RenderShadow_v1(bb.Min, bb.Max, IM_COL32(0, 0, 0, 20), 8, 8, 10, 0, 12, true);
    RenderShadow_v1(bb.Min, bb.Max, IM_COL32(255, 255, 255, 150), -8, -8, 10, 0, 12, true);
    return ret;
}

void ShowImage(ImGui::WIcon* icon)
{
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (!window->SkipItems && icon->texture && icon->width && icon->height)
    {
        ImVec2 pos = window->DC.CursorPos;

        ImVec2 imsize = ImVec2(icon->width, icon->height);

        const ImRect imbb(
            ImVec2(pos.x, pos.y),
            ImVec2(pos.x + imsize.x, pos.y + imsize.y));

        window->DrawList->AddImage(reinterpret_cast<ImTextureID>(icon->texture), imbb.Min, imbb.Max,
            ImVec2(0, 0), ImVec2(1, 1), IM_COL32(255, 255, 255, 255));
        Dummy({ imsize.x, imsize.y });
    }
}

bool MyButton(const char* label, const ImVec2& size_arg)
{
    
    ImGuiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    ImGuiContext& g = *GImGui;
    const ImGuiStyle& style = g.Style;
    const ImGuiID id = window->GetID(label);
    const ImVec2 label_size = CalcTextSize(label, NULL, true);

    ImVec2 pos = window->DC.CursorPos;

    ImVec2 size = CalcItemSize(size_arg, label_size.x + style.FramePadding.x * 2.0f, label_size.y + style.FramePadding.y * 2.0f);

    const ImRect bb(pos, pos + size);
    ItemSize(size, style.FramePadding.y);
    if (!ItemAdd(bb, id))
        return false;

    bool hovered, held;
    bool pressed = ButtonBehavior(bb, id, &hovered, &held, ImGuiButtonFlags_None);

    // Render
    const ImU32 col = GetColorU32((held && hovered) ? ImGuiCol_ButtonActive : hovered ? ImGuiCol_ButtonHovered : ImGuiCol_Button);

    RenderNavHighlight(bb, id);
    
    if (held)
    {
        RenderFrame(bb.Min, bb.Max, col, true, 12);
        RenderShadow_v1(bb.Min, bb.Max, IM_COL32(0, 0, 0, 20), 8, 8, 10, 0, 12, true);
        RenderShadow_v1(bb.Min, bb.Max, IM_COL32(255, 255, 255, 100), -8, -8, 10, 0, 12, true);

    }
    else if (hovered)
    {
        RenderShadow_v1(bb.Min, bb.Max, IM_COL32(0, 0, 0, 20), -8, -8, 10, 0, 12, false);
        RenderShadow_v1(bb.Min, bb.Max, IM_COL32(255, 255, 255, 255), 8, 8, 10, 0, 12, false);
        RenderFrame(bb.Min, bb.Max, col, true, 12);

    }
    else
    {
        //RenderFrame(bb.Min, bb.Max, col, true, 12);
    }

    RenderTextClipped(bb.Min + style.FramePadding, bb.Max - style.FramePadding, label, NULL, &label_size, style.ButtonTextAlign, &bb);

    // Automatically close popups
    //if (pressed && !(flags & ImGuiButtonFlags_DontClosePopups) && (window->Flags & ImGuiWindowFlags_Popup))
    //    CloseCurrentPopup();

    IMGUI_TEST_ENGINE_ITEM_INFO(id, label, g.LastItemData.StatusFlags);
    
    return pressed;
}

bool MyMenuButton(const char* label, const ImVec2& size_arg)
{
    ImGuiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    ImGuiContext& g = *GImGui;
    const ImGuiStyle& style = g.Style;
    const ImGuiID id = window->GetID(label);
    const ImVec2 label_size = CalcTextSize(label, NULL, true);

    ImVec2 pos = window->DC.CursorPos;

    ImVec2 size = CalcItemSize(size_arg, label_size.x + style.FramePadding.x * 2.0f, label_size.y + style.FramePadding.y * 2.0f);

    const ImRect bb(pos, pos + size);
    ItemSize(size, style.FramePadding.y);
    if (!ItemAdd(bb, id))
        return false;

    bool hovered, held;
    bool pressed = ButtonBehavior(bb, id, &hovered, &held, ImGuiButtonFlags_None);

    // Render
//    const ImU32 col = GetColorU32(ImGuiCol_Button);
    const ImU32 col = GetColorU32(Hex2ImVec4("#E8F9FF"));

    RenderNavHighlight(bb, id);
    RenderFrame(bb.Min, bb.Max, col, true, 12);

    static auto hover_text_color = Hex2ImVec4("#1E9AFE");
    static auto held_text_color = Hex2ImVec4("#37ECBA");
    static auto base_text_color = style.Colors[ImGuiCol_Text];

    auto text_color = base_text_color;

    if (held)
    {
        text_color = held_text_color;
    }
    else if (hovered)
    {
        text_color = hover_text_color;
    }

    PushStyleColor(ImGuiCol_Text, text_color);
    
    RenderTextClipped(bb.Min + style.FramePadding, bb.Max - style.FramePadding, label, NULL, &label_size, style.ButtonTextAlign, &bb);

    PopStyleColor();

    return pressed;
}

bool MyCheckBox(ImGuiID id, ImTextureID texture_id, const ImVec2 &size, const ImVec2 &uv0,
                const ImVec2 &uv1, const ImVec4 &bg_col, const ImVec4 &tint_col)
{
    ImGuiContext& g = *GImGui;
    ImGuiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    const ImVec2 padding = g.Style.FramePadding;
    const ImRect bb(window->DC.CursorPos, window->DC.CursorPos + size + padding * 2.0f);
    ItemSize(bb);
    if (!ItemAdd(bb, id))
        return false;

    bool hovered, held;
    bool pressed = ButtonBehavior(bb, id, &hovered, &held);

    // Render
//    const ImU32 col = GetColorU32((held && hovered) ? ImGuiCol_ButtonActive : hovered ? ImGuiCol_ButtonHovered : ImGuiCol_Button);
    const ImU32 col = GetColorU32(Hex2ImVec4("#E8F9FF"));
    RenderNavHighlight(bb, id);
    RenderFrame(bb.Min, bb.Max, col, true, ImClamp((float)ImMin(padding.x, padding.y), 0.0f, g.Style.FrameRounding));
    if (bg_col.w > 0.0f)
        window->DrawList->AddRectFilled(bb.Min + padding, bb.Max - padding, GetColorU32(bg_col));
    window->DrawList->AddImage(texture_id, bb.Min + padding, bb.Max - padding, uv0, uv1, GetColorU32(tint_col));

    return pressed;
}

void TextCentered(std::string text) 
{
    auto windowWidth = ImGui::GetWindowSize().x;
    auto textWidth   = ImGui::CalcTextSize(text.c_str()).x;

    ImGui::SetCursorPosX((windowWidth - textWidth) * 0.5f);
    ImGui::Text(text.c_str());
}

}  // namespace ImGui

