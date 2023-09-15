#include "uploader.h"

#include "common/WLoger/Include/WLoger.h"

// imgui
#include <imgui.h>
#ifndef IMGUI_DEFINE_MATH_OPERATORS
# define IMGUI_DEFINE_MATH_OPERATORS
#endif
#include <imgui_internal.h>

#include "ui.h"

// std
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <list>
#include <memory>
#include <set>
#include <string>

// curl
#include <curl/curl.h>

// nfd
#include <nfd.hpp>

// local
#include "ws/WebsocketClient.h"
#include "mac_address.h"

#include <thread>

#include <chrono>
using namespace std::chrono_literals;

extern bool GlobalRunning;

static char password[256];
static char password_locals[256];
static std::string __message__ = "place to client mesage";;

extern const uint8_t __char2int[256];

size_t FileUploader::files_to_upload_amount = 0;
size_t FileUploader::uploaded_files_amount = 0;

// UI

FileUploader::FileUploader(): settings_(), _archivedFilesInfo(), _localFilesInfo(),
    _server_status("server offline"), _stop_ping(false), _login_status(LoginStatus::NO_LOGIN)
{
    _localFilesInfo.clear();
    client = 0;
    std::string backup_path = settings_.Get("backup_path");
    if (backup_path != "") {
        _backup_path = backup_path;
    } else {
        _backup_path = "backup/";
    }
    if(settings_.Get("url") == "")
    {
        settings_.Set("url", "ws://65.108.13.158:8081\0");
        settings_.Set("appname", "test\0");
        settings_.Set("res_dirs", "\0");
        settings_.Set("backup_path", "backup/\0");
        settings_.Save();
    }
    int i = 0;
    while(settings_[std::string("res_dir") + std::to_string(i)][0] != '\0')
    {
        AddFileToFileMap(&_localFilesInfo, settings_[std::string("res_dir") + std::to_string(i)]);
        i++;
    }

    _login_manager = std::make_shared<SettingsManager>(SettingsManager(std::string("credentials.json")));
    if (_login_manager->IsThereSavedCredentials()) {
        SetLoginStatus(LoginStatus::FILE_LOGIN);
        RunClient();
    }

//    _register_window = std::make_unique<RegisterWindow>(RegisterWindow(client));
}

void FileUploader::SetStyles()
{
    //
    // Style updates
    //
    // ImGui::Spectrum::StyleColorsSpectrum();
    ImGuiStyle* style = &ImGui::GetStyle();
    style->GrabRounding = 12.0f;
    style->WindowRounding = 12.0f;
    style->FrameRounding = 12.0f;
    style->TabRounding = 12.0f;
    style->ChildRounding = 12.0f;
    style->TabMinWidthForCloseButton = FLT_MAX;
    style->TabBorderSize = 1.0f;
    style->WindowMenuButtonPosition = ImGuiDir_Right;
    style->TabBorderSize = 1.5f;
    style->ItemInnerSpacing = { 8, 8 };
    style->WindowPadding = { 15, 15 };
    style->FrameBorderSize = 0.0f;
    style->WindowBorderSize = 0.0f;


    ImVec4* colors = style->Colors;
    colors[ImGuiCol_Button] = Hex2ImVec4("#3B80C6");
    colors[ImGuiCol_ButtonHovered] = Hex2ImVec4("#35C3F5");
    colors[ImGuiCol_Text] = Hex2ImVec4("#2f2f2f");
    colors[ImGuiCol_WindowBg] = Hex2ImVec4("#E8F9FF");
    colors[ImGuiCol_Tab] = Hex2ImVec4("#E8F9FF");
    colors[ImGuiCol_TitleBgActive] = Hex2ImVec4("#E8F9FF");
    colors[ImGuiCol_TitleBg] = Hex2ImVec4("#E8F9FF");
    colors[ImGuiCol_TabActive] = Hex2ImVec4("#E8F9FF");
    colors[ImGuiCol_Separator] = Hex2ImVec4("#E8F9FF");
    colors[ImGuiCol_TabHovered] = Hex2ImVec4("#E8F9FF");
    colors[ImGuiCol_FrameBg] = Hex2ImVec4("#E8F9FF");
    colors[ImGuiCol_Border] = Hex2ImVec4("#E8F6F9");
//    colors[ImGuiCol_Button] = Hex2ImVec4("#E8F9FF");
    colors[ImGuiCol_PopupBg] = Hex2ImVec4("#E8F9FF");
    colors[ImGuiCol_ButtonActive] = Hex2ImVec4("#CCE7E8");

    colors[ImGuiCol_PlotHistogram] = colors[ImGuiCol_ButtonHovered];

    colors[ImGuiCol_ChildBg] = Hex2ImVec4("#E8F9FF");
}

void UpdateAndRender(int posx, int posy, int width, int height)
{
    static bool          not_inited = true;
    static FileUploader* darwinics_uploader;
    if (not_inited)
    {
        not_inited = false;

        darwinics_uploader = new FileUploader();
        darwinics_uploader->StartPingServer();
        darwinics_uploader->SetStyles();

        curl_global_init(CURL_GLOBAL_ALL);

        NFD_Init();
    }
    darwinics_uploader->Update();
    darwinics_uploader->ShowWindow(posx, posy, width, height);

    std::cout << std::flush;

    // TODO(Sedenkov): cleanup
}

#define FileMapItem std::pair<std::string, File>

#define SHOWED_FILE  std::pair<FileMapItem, int>

static ImGui::WIcon Governor {0, 0, 0};
static ImGui::WIcon archive_steps[3][8]{
{
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0}
},
{
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0}
},
{
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0}
}
};

static ImGui::WIcon restore_steps[3][5]{
{
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0}
},
{
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0}
},
{
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0},
    {0, 0, 0}
}
};

enum ETabIndex : uint32_t
{
    ETab_NONE = 0,
    ETab_LOCAL,
    ETab_BACKUP,
    ETab_GOV,
    ETab_Archive,
    ETab_Restore

};

#if defined(_WIN32)
using CallBase_t = void (FileUploader::*)();
#else
typedef void (FileUploader::*CallBase_t)();
#endif


void FileUploader::None_Head()
{

}

void FileUploader::None_Left()
{

}

void FileUploader::None_Right()
{

}

void FileUploader::Gov_Head()
{
    ImGui::ShowImage(&Governor);
    ImGui::SameLine();
    ImGui::TextCentered("Storage");
    ImGui::TextCentered("The system can be autonatically be restore in another computer by a backup o fthe archiving disks,");
    ImGui::TextCentered("governor storage and import the exported keys");
}

void FileUploader::Gov_Left()
{
    ImGuiContext &g = *GImGui;
    const ImGuiStyle &style = g.Style;
    ImGui::TextCentered("Archiving Server");

    ImGui::Text("Update URL: ");
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, {20, 20});
    ImGui::SetNextItemWidth(600);
    if (ImGui::InputText("##Update URL", settings_["url"], 256)) {
        settings_.Save();
    }
    auto rect = g.LastItemData.Rect;
    ImGui::RenderShadow_v1(rect.Min, rect.Max, IM_COL32(0, 0, 0, 20), 8, 8, 10, 0, 12, true);
    ImGui::RenderShadow_v1(rect.Min, rect.Max, IM_COL32(255, 255, 255, 150), -8, -8, 10, 0, 12,
                           true);

    ImGui::Text("Name: ");
    ImGui::SetNextItemWidth(600);
    if (ImGui::InputText("##Name", settings_["appname"], 256)) {
        settings_.Save();
    }
    rect = g.LastItemData.Rect;
    ImGui::RenderShadow_v1(rect.Min, rect.Max, IM_COL32(0, 0, 0, 20), 8, 8, 10, 0, 12, true);
    ImGui::RenderShadow_v1(rect.Min, rect.Max, IM_COL32(255, 255, 255, 150), -8, -8, 10, 0, 12,
                           true);

    ImGui::Text("Password: ");
    ImGui::SetNextItemWidth(600);
    if (ImGui::InputText("##Password", password, 256)) {
    }
    rect = g.LastItemData.Rect;
    ImGui::RenderShadow_v1(rect.Min, rect.Max, IM_COL32(0, 0, 0, 20), 8, 8, 10, 0, 12, true);
    ImGui::RenderShadow_v1(rect.Min, rect.Max, IM_COL32(255, 255, 255, 150), -8, -8, 10, 0, 12,
                           true);

    ImGui::PopStyleVar(1);

    if (ImGui::Button("Connect to server", ImVec2 {150, 40})) {
        if (password[0] != '\0') {
            Login();
            SetLoginStatus(FileUploader::LoginStatus::INPUT_TEXT_LOGIN);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Register new user", ImVec2 {150, 40})) {
        ImGui::OpenPopup("Register new user...");
    }
    ImGui::SameLine();
    if (ImGui::Button("Chose backup path", ImVec2 {150, 40})) {
        nfdchar_t *outPath = nullptr;
        // show the dialog
        nfdresult_t           result = NFD_PickFolderU8(&outPath, "");
        bool                  new_path = false;
        std::filesystem::path res;
        if (result == NFD_OKAY) {
            res = std::filesystem::u8path(outPath);
            bool exists = std::filesystem::exists(res);
            if (exists) {
                new_path = true;
            } else {
            }
        } else if (result == NFD_CANCEL) {
        } else {
        }

        if (new_path) {
            auto str_path = res.string();
            str_path.push_back('\0');
            settings_.Set("backup_path", str_path);
            _backup_path = res;
            settings_.Save();
        }
    }

    // Always center this window when appearing
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("Register new user...", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
        static float input_text_width = 250, padding = 10;

        ImGui::TextCentered("Register new user");

        ImGui::Text("Login: ");
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, {20, 20});
        ImGui::SetNextItemWidth(input_text_width - padding);
        ImGui::InputText("##register_login", _register_login_buf, _buf_size);
        rect = g.LastItemData.Rect;
        ImGui::RenderShadow_v1(rect.Min, rect.Max, IM_COL32(0, 0, 0, 20), 8, 8, 10, 0, 12, true);
        ImGui::RenderShadow_v1(rect.Min, rect.Max, IM_COL32(255, 255, 255, 150), -8, -8, 10, 0, 12,
                               true);

        ImGui::Text("Password: ");
        ImGui::SetNextItemWidth(input_text_width - padding);
        ImGui::InputText("##register_password", _register_password_buf, _buf_size);
        rect = g.LastItemData.Rect;
        ImGui::RenderShadow_v1(rect.Min, rect.Max, IM_COL32(0, 0, 0, 20), 8, 8, 10, 0, 12, true);
        ImGui::RenderShadow_v1(rect.Min, rect.Max, IM_COL32(255, 255, 255, 150), -8, -8, 10, 0, 12,
                               true);

        ImGui::Text("Confirm password: ");
        ImGui::SetNextItemWidth(input_text_width - padding);
        ImGui::InputText("##register_confirm_password", _register_confirm_password_buf, _buf_size);
        rect = g.LastItemData.Rect;
        ImGui::RenderShadow_v1(rect.Min, rect.Max, IM_COL32(0, 0, 0, 20), 8, 8, 10, 0, 12, true);
        ImGui::RenderShadow_v1(rect.Min, rect.Max, IM_COL32(255, 255, 255, 150), -8, -8, 10, 0, 12,
                               true);
        ImGui::PopStyleVar(1);

        ImGui::Separator();

        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
        ImGui::PushStyleColor(ImGuiCol_FrameBg, Hex2ImVec4("#35C3F5"));
        ImGui::Checkbox("Remember credentials and login", &login_after_reg);
        ImGui::PopStyleColor();
        ImGui::PopStyleVar();

        static std::string register_message;
        if (ImGui::Button("Register", ImVec2(120, 0))) {
            if (client) {
                if (_register_password_buf[0] != '\0') {
                    if (strcmp(_register_password_buf, _register_confirm_password_buf) == 0) {
                        Json newJson = JsonWorker::CreateJsonObject();
                        JsonWorker::AddToJsonVal(newJson, "user_name", _register_login_buf);
                        JsonWorker::AddToJsonVal(newJson, "password", _register_password_buf);
                        WebsocketClient::command(client, (int)ECommandType::REGISTER_NEW_USER,
                                                 newJson);
                        ImGui::CloseCurrentPopup();
                    } else {
                        register_message = "Passwords don't match!";
                    }
                } else {
                    register_message = "Password can't be empty";
                }
            } else {
                register_message = "Client is down";
            }
        }
        ImGui::SetItemDefaultFocus();
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
            ImGui::CloseCurrentPopup();
        }

        ImGui::Text("%s", register_message.c_str());

        ImGui::EndPopup();
    }

    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 10);
    std::string backup_path_text = "Backup path is " + _backup_path.string();
    ImGui::Text("%s", backup_path_text.c_str());
}

void FileUploader::Gov_Right()
{
    ImGuiContext& g = *GImGui;
    const ImGuiStyle& style = g.Style;
    ImGui::TextCentered("Governor");
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, {20, 20});
    ImGui::Text("Password: ");
    ImGui::SetNextItemWidth(600);
    if (ImGui::InputText("##Password", password_locals, 256))
    {

    }
    auto rect = g.LastItemData.Rect;
    ImGui::RenderShadow_v1(rect.Min, rect.Max, IM_COL32(0, 0, 0, 20), 8, 8, 10, 0, 12, true);
    ImGui::RenderShadow_v1(rect.Min, rect.Max, IM_COL32(255, 255, 255, 150), -8, -8, 10, 0, 12, true);

    ImGui::PopStyleVar(1);
}

void FileUploader::Backup_Head()
{
    ImGui::ShowImage(&Governor);
    ImGui::SameLine();
    ImGui::TextCentered("Backup Storage");
}

void FileUploader::Backup_Left()
{
    ImGui::TextCentered("Select folders");

    if (ImGui::Button("Update server file list", ImVec2{ 150, 40 }))
    {
        if (client)
        {
            Json newJson = JsonWorker::CreateJsonObject();
            JsonWorker::AddToJsonVal(newJson, "dummy", ":");
            JsonWorker::AddToJsonVal(newJson, "machine_id", _availableMachines[_selected_machine]);
            WebsocketClient::command(client, (int)ECommandType::GET_FILE_LIST, newJson);
        }
        else
        {
            __message__ = "client not started";
        }
    }
    auto ret = ImGui::MyTreeWiew("ContentTrree" ,&_archivedFilesInfo, {400, 30}, true);
}

void FileUploader::Backup_Right()
{

}

void FileUploader::Local_Head()
{
    ImGui::ShowImage(&Governor);
    ImGui::SameLine();
    ImGui::TextCentered("Monitored folder");
}

void FileUploader::Local_Left()
{
    ImGui::TextCentered("Select folders");
    if (ImGui::Button("Add folder to select", ImVec2{ 150, 40 }))
    {
        nfdchar_t* outPath = nullptr;
        // show the dialog
        nfdresult_t result = NFD_PickFolderU8(&outPath, "");
        bool        new_path = false;
        std::filesystem::path res;
        if (result == NFD_OKAY)
        {
            res = std::filesystem::u8path(outPath);
            bool                  exists = std::filesystem::exists(res);
            if (exists)
            {
                new_path = true;
            }
            else
            {
            }
        }
        else if (result == NFD_CANCEL)
        {
        }
        else
        {
        }

        if (new_path)
        {
            AddFileToFileMap(&_localFilesInfo, res);
            int i = 0;
            while(settings_[std::string("res_dir") + std::to_string(i)][0] != '\0')
            {
                i++;
            }
            settings_.Set(std::string("res_dir") + std::to_string(i), res.string());
            settings_.Save();
        }
    }

    ImGui::SameLine();

    if (ImGui::Button("Add files to select", ImVec2{ 150, 40 }))
    {
        NFD::UniquePathSet constoutPath = nullptr;
        nfdresult_t        result = NFD::OpenDialogMultiple(constoutPath, 0, 0, "");

        if (result == NFD_OKAY)
        {
            nfdpathsetsize_t numPaths;
            NFD::PathSet::Count(constoutPath, numPaths);
            nfdpathsetsize_t i;

            for (i = 0; i < numPaths; ++i)
            {
                NFD::UniquePathSetPath cpath;
                NFD::PathSet::GetPath(constoutPath, i, cpath);
                std::filesystem::path res = std::filesystem::u8path(cpath.get());
                AddFileToFileMap(&_localFilesInfo, res);
            }
        }
    }
    auto ret = ImGui::MyTreeWiew("ContentTrree" ,&_localFilesInfo, {400, 30}, true);
}

void FileUploader::Local_Right()
{
    if (client) {
        std::string caption = _availableMachines.empty() ? "machine_id" : _availableMachines[_selected_machine];
        if (ImGui::BeginCombo("##selected_machine", caption.c_str())) {
            for (size_t i = 0; i < _availableMachines.size(); i++) {
                if (_availableMachines[i].empty()) {
                    continue;
                }
                const bool is_selected = (i == _selected_machine);
                if (ImGui::Selectable(_availableMachines[i].c_str(), is_selected)) {
                    _selected_machine = i;
                }

                if (is_selected) {
                    ImGui::SetItemDefaultFocus();
                }
            }
            ImGui::EndCombo();
        }

        if (ImGui::Button("Apply")) {
            Json newJson = JsonWorker::CreateJsonObject();
            JsonWorker::AddToJsonVal(newJson, "machine_id", _availableMachines[_selected_machine]);
            WebsocketClient::command(client, (int)ECommandType::SET_MACHINE_ID, newJson);

            client->m_macAddress = _availableMachines[_selected_machine];
        }
    }

    //auto ret = ImGui::MyTreeWiew("ContentTrree" ,&_archivedFilesInfo, {400, 30}, true);
}

static int archive_step = 0;
static std::thread* archive_thread = 0;
static int restore_step = 0;
static std::thread* restore_thread = 0;
static char localpass[32] = "";

void FileUploader::Archive_Head()
{
    if(archive_thread == 0)
    {
        archive_thread = new std::thread([this]()
        {
            archive_step = 0;
#if defined(_WIN32)
            Sleep(500);
#else
            std::this_thread::sleep_for(500ms);
#endif
            archive_step = 1;

#if defined(_WIN32)
            Sleep(500);
#else
            std::this_thread::sleep_for(500ms);
#endif

            archive_step = 2;
#if defined(_WIN32)
            Sleep(500);
#else
            std::this_thread::sleep_for(500ms);
#endif

            if (settings_.Get("url").size() > 0)
            {
                if (settings_.Get("url").find("ws://") != std::string::npos)
                {
                    if (client)
                    {
                        auto        old_client = client;
                        std::thread th([old_client]()
                            {
                                old_client->close();
                                delete old_client;
                            });
                        th.detach();
                        client = 0;
                    }
                    RunClient();

                    if (!_availableMachines.empty()) {
                        client->m_macAddress = _availableMachines[_selected_machine];
                    }
                }
            }

            #if defined(_WIN32)
                        Sleep(500);
            #else
                        std::this_thread::sleep_for(500ms);
            #endif

            archive_step = 3;

            #if defined(_WIN32)
                        Sleep(500);
            #else
                        std::this_thread::sleep_for(500ms);
            #endif
            archive_step = 4;
            if (client)
            {
                Json newJson = JsonWorker::CreateJsonObject();
                JsonWorker::AddToJsonVal(newJson, "dummy", ":");
                JsonWorker::AddToJsonVal(newJson, "machine_id", _availableMachines[_selected_machine]);
                WebsocketClient::command(client, (int)ECommandType::GET_FILE_LIST, newJson);

                int iters = 0;
                while(_update_file_list_status == 0)
                {
                    iters++;
                    if(iters > 100)
                    {
                        archive_step = 5;
                        __message__ = "GET_FILE_LIST timeout error";
                        return 1;
                    }
                    #if defined(_WIN32)
                        Sleep(100);
                    #else
                        std::this_thread::sleep_for(100ms);
                    #endif
                }
                _update_file_list_status = 0;

                std::string str_pass = password_locals;

                int send_count = 0;
                int need_send_count = 0;

                FileClaback *error_callback =
                    new FileClaback([&](const File &file, std::string meta) {
                        send_count++;
                    });

                FileClaback *sended_callback = new FileClaback([&](const File &file,
                                                                   std::string meta) {
                    send_count++;
                    if(file.type == FileType::FILE_TYPE_FILE && file.used)
                    {
                        try
                        {
                            std::filesystem::remove(file.path);
                        }
                        catch(const std::exception& e)
                        {
                            WLE << e.what();
                            __message__ = e.what();
                        }
                    }
                    File_ptr f_ptr_loc = FindFileInFileMap(&_localFilesInfo, file);
                    File_ptr f_ptr_arc = FindFileInFileMap(&_archivedFilesInfo, file);

                    std::function<File_ptr(File_ptr)> add_if_need = [&](File_ptr file) -> File_ptr {
                        File_ptr f = FindFileInFileMap(&_archivedFilesInfo, *file);
                        if(f != nullptr)
                        {
                            return f;
                        }
                        if(file->parent != nullptr)
                        {
                            File_ptr parent = add_if_need(file->parent);
                            f = File_ptr(new File(*file));
                            f->map.clear();
                            parent->map[f->path] = f;
                        }
                        else
                        {
                            f = File_ptr(new File(*file));
                            f->map.clear();
                            _archivedFilesInfo[f->path] = f;
                        }
                        return f;
                    };

                    if(f_ptr_arc == nullptr)
                        add_if_need(f_ptr_loc);
                    else
                        *f_ptr_arc = *f_ptr_loc;

                    DeleteFileInFileMap(&_localFilesInfo, file);
                });

                FileClaback *uploaded_callback =
                    new FileClaback([&](const File &file, std::string meta) {
                        need_send_count++;
                    });

                _error_callbacks[error_callback] = error_callback;
                _sended_calbacks[sended_callback] = sended_callback;
                _uploaded_callbacks[uploaded_callback] = uploaded_callback;

                UploadRequest(_localFilesInfo, str_pass);

                iters = 0;

                /*
                ** todo(Sedenkov):
                ** while (std::atomic<int> status == STATUS_OK {}
                */
                while(send_count < need_send_count)
                {
                    iters++;
                    if(iters > 15 * 60 * 2)
                    {
                        restore_step = 5;
                        __message__ = "Receive file timeout error";
                        return 1;
                    }
            #if defined(_WIN32)
                    Sleep(500);
            #else
                    std::this_thread::sleep_for(500ms);
            #endif
                }

                _error_callbacks.erase(error_callback);
                _sended_calbacks.erase(sended_callback);
                _uploaded_callbacks.erase(uploaded_callback);
                delete error_callback;
                delete sended_callback;
                delete uploaded_callback;
            }

            archive_step = 5;
            #if defined(_WIN32)
                    Sleep(500);
            #else
                    std::this_thread::sleep_for(500ms);
            #endif
            if(client)
            {
                Json newJson = JsonWorker::CreateJsonObject();
                JsonWorker::AddToJsonVal(newJson, "dummy", ":");
                JsonWorker::AddToJsonVal(newJson, "machine_id", _availableMachines[_selected_machine]);
                WebsocketClient::command(client, (int)ECommandType::GET_FILE_LIST, newJson);

                int iters = 0;
                while(_update_file_list_status == 0)
                {
                    iters++;
                    if(iters > 100)
                    {
                        archive_step = 5;
                        __message__ = "GET_FILE_LIST timeout error";
                        return 1;
                    }
            #if defined(_WIN32)
                    Sleep(100);
            #else
                    std::this_thread::sleep_for(100ms);
            #endif                
                }
                _update_file_list_status = 0;
            }

            archive_step = 6;

            #if defined(_WIN32)
                    Sleep(500);
            #else
                    std::this_thread::sleep_for(500ms);
            #endif

            archive_step = 7;

            auto files = FileMapToVector(&_localFilesInfo);
            for(auto el : files)
            {
                if(el.second->type == FileType::FILE_TYPE_FILE && el.second->used)
                {
                    try
                    {
                        std::filesystem::remove(el.first);
                    }
                    catch(const std::exception& e)
                    {
                        WLE << e.what();
                        __message__ = e.what();
                    }
                }
            }
            #if defined(_WIN32)
                    Sleep(1000);
            #else
                    std::this_thread::sleep_for(1000ms);
            #endif

            archive_step = 8;

            auto ths = archive_thread;
            *((size_t*)(&archive_thread)) = 1;
            return 0;
        });
    }
    ImGui::ShowImage(&Governor);
    ImGui::SameLine();
    std::string text = "";
    switch (archive_step)
    {
    case 0:
        text = "Identification of new files";
        break;
    case 1:
        text = "Local System Ciphering";
        break;
    case 2:
        text = "Launching Connection";
        break;
    case 3:
        text = "Archiving Mounting Disk";
        break;
    case 4:
        text = "Transferring to Archiving System";
        break;
    case 5:
        text = "Archiving System Ciphering";
        break;
    case 6:
        text = "Dismount Disk";
        break;
    case 7:
        text = "Deleting Files on Local System";
        break;
    case 8:
        text = "Archiving Process is finished";
        break;
    default:
        break;
    }
    ImGui::TextCentered(text.c_str());
    std::time_t t = std::time(0);   // get time now
    std::tm* now = std::localtime(&t);
    ImGui::Clock(now->tm_hour + now->tm_min / 60.0 + now->tm_sec / 3600.0, now->tm_min + now->tm_sec / 60.0, now->tm_sec);
    ImGui::SameLine();
    auto window = ImGui::GetCurrentWindow();
    auto oldpos = window->DC.CursorPos;
    ImGui::Text("Estimated time remaining:");
    ImGui::SameLine();
    auto pos = window->DC.CursorPos;
    pos.y = oldpos.y;
    for(int i = 0; i < 8; i++)
    {
        ImRect bb{
            pos + ImVec2(60, 0) + ImVec2(120 * i, 0),
            pos + ImVec2(60, 0) + ImVec2(120 * i, 0) + ImVec2(64, 64)
        };
        ImRect bb2{
            pos + ImVec2(90, 29) + ImVec2(120 * i, 0),
            pos + ImVec2(90, 29) + ImVec2(120 * i, 0) + ImVec2(120, 6)
        };
        ImRect bb3{
            pos + ImVec2(90, 22) + ImVec2(120 * i, 0),
            pos + ImVec2(90, 22) + ImVec2(120 * i, 0) + ImVec2(120, 20)
        };
        if(i == 7)
        {
            bb2 = ImRect(
                pos + ImVec2(90, 30) + ImVec2(120 * i, 0),
                pos + ImVec2(90, 30) + ImVec2(120 * i, 0) + ImVec2(0, 0));
            bb3 = bb2;
        }
        ImGui::RenderShadow_v1(bb3.Min, bb3.Max, IM_COL32(0, 0, 0, 20), 4, 4, 5, 0, 31, true);
        ImGui::RenderShadow_v1(bb3.Min, bb3.Max, IM_COL32(255, 255, 255, 150), -4, -4, 5, 0, 31, true);
        if(i > archive_step)
        {
            window->DrawList->AddRectFilled(bb.Min, bb.Max, ImGui::GetColorU32(ImGuiCol_TitleBg), 31);
            window->DrawList->AddImage(reinterpret_cast<ImTextureID>(archive_steps[0][i].texture), bb.Min, bb.Max,
                ImVec2(0, 0), ImVec2(1, 1), IM_COL32(255, 255, 255, 255));
            ImGui::RenderShadow_v1(bb.Min, bb.Max, IM_COL32(0, 0, 0, 20), 4, 4, 5, 0, 31, true);
            ImGui::RenderShadow_v1(bb.Min, bb.Max, IM_COL32(255, 255, 255, 150), -4, -4, 5, 0, 31, true);
        }
        else if(i == archive_step)
        {
            const auto col = ImGui::GetColorU32(Hex2ImVec4("#1E9AFE"));
            if (archive_step == 4) {
                float  upload_progress = files_to_upload_amount == 0
                                           ? 0
                                           : static_cast<float>(uploaded_files_amount) /
                                                static_cast<float>(files_to_upload_amount + 1);
                ImVec2 progress_mark(bb2.Min.x + ((bb2.Max.x - bb2.Min.x) * upload_progress),
                                     bb2.Max.y);
                window->DrawList->AddRectFilled(bb2.Min, bb2.Max, col);
                progress_mark.y = bb2.Min.y;
                window->DrawList->AddRectFilled(progress_mark, bb2.Max,
                                                ImGui::GetColorU32(ImGuiCol_TitleBg));
            } else {
                window->DrawList->AddRectFilled(bb2.Min, bb2.Max, col);
            }
            ImGui::RenderShadow_v1(bb.Min, bb.Max, IM_COL32(0, 0, 0, 20), -4, -4, 5, 0, 31, false);
            ImGui::RenderShadow_v1(bb.Min, bb.Max, IM_COL32(255, 255, 255, 150), 4, 4, 5, 0, 31, false);
            window->DrawList->AddRectFilled(bb.Min, bb.Max, ImGui::GetColorU32(ImGuiCol_TitleBg), 31);
            window->DrawList->AddImage(reinterpret_cast<ImTextureID>(archive_steps[1][i].texture), bb.Min, bb.Max,
                ImVec2(0, 0), ImVec2(1, 1), IM_COL32(255, 255, 255, 255));
        }
        else
        {
            const auto col = ImGui::GetColorU32(Hex2ImVec4("#60DFCD"));
            window->DrawList->AddRectFilled(bb2.Min, bb2.Max, col);
            ImGui::RenderShadow_v1(bb.Min, bb.Max, IM_COL32(0, 0, 0, 20), -4, -4, 5, 0, 31, false);
            ImGui::RenderShadow_v1(bb.Min, bb.Max, IM_COL32(255, 255, 255, 150), 4, 4, 5, 0, 31, false);
            window->DrawList->AddRectFilled(bb.Min, bb.Max, ImGui::GetColorU32(ImGuiCol_TitleBg), 31);
            window->DrawList->AddImage(reinterpret_cast<ImTextureID>(archive_steps[2][i].texture), bb.Min, bb.Max,
                ImVec2(0, 0), ImVec2(1, 1), IM_COL32(255, 255, 255, 255));
        }
    }
    if (archive_step == 4) {
        ImGui::NewLine();
        ImGui::Text("%s %.1f %s ", WebsocketClient::uploading_filename.c_str(),
                    100.f * static_cast<float>(WebsocketClient::uploaded_size) /
                        static_cast<float>(WebsocketClient::uploading_file_size + 1),
                    "%");
    }
}

void FileUploader::Archive_Left()
{
    ImGui::TextCentered("Local system");
    auto ret = ImGui::MyTreeWiew("ContentTrree" ,&_localFilesInfo, {400, 30});
}

void FileUploader::Archive_Right()
{
    ImGui::TextCentered("Archiving system");
    auto ret = ImGui::MyTreeWiew("ContentTrree" ,&_archivedFilesInfo, {400, 30});

}

void FileUploader::Restore_Head()
{
    if(restore_thread == 0)
    {
        restore_thread = new std::thread([this]()
        {
            restore_step = 0;

            if (settings_.Get("url").size() > 0)
            {
                if (settings_.Get("url").find("ws://") != std::string::npos)
                {
                    if (client)
                    {
                        auto        old_client = client;
                        std::thread th([old_client]()
                            {
                                old_client->close();
                                delete old_client;
                            });
                        th.detach();
                        client = 0;
                    }
                    RunClient();

                    if (!_availableMachines.empty()) {
                        client->m_macAddress = _availableMachines[_selected_machine];
                    }
                }
            }

            #if defined(_WIN32)
                    Sleep(500);
            #else
                    std::this_thread::sleep_for(500ms);
            #endif

            restore_step = 1;

            #if defined(_WIN32)
                    Sleep(500);
            #else
                    std::this_thread::sleep_for(500ms);
            #endif

            restore_step = 2;

            #if defined(_WIN32)
                    Sleep(500);
            #else
                    std::this_thread::sleep_for(500ms);
            #endif

            restore_step = 2;

            if (client)
            {
                int iters = 0;

                if(_archivedFilesInfo.empty())
                {
                    Json newJson = JsonWorker::CreateJsonObject();
                    JsonWorker::AddToJsonVal(newJson, "dummy", ":");
                    JsonWorker::AddToJsonVal(newJson, "machine_id", _availableMachines[_selected_machine]);
                    WebsocketClient::command(client, (int)ECommandType::GET_FILE_LIST, newJson);

                    while(_update_file_list_status == 0)
                    {
                        WLI << "while on iter " << iters << std::endl;
                        iters++;
                        if(iters > 100)
                        {
                            WLI << "GET_FILE_LIST timeout error" << std::endl;
                            restore_step = 5;
                            __message__ = "GET_FILE_LIST timeout error";
                            return 1;
                        }
            #if defined(_WIN32)
                    Sleep(100);
            #else
                    std::this_thread::sleep_for(100ms);
            #endif
                    }
                }

                std::string str_pass = password_locals;
                _update_file_list_status = 0;

                int receive_count = 0;
                int need_receive_count = 0;
                {
                    auto files = FileMapToVector(&_archivedFilesInfo);
                    for (const auto& file : files)
                    {
                        if(!file.second->used)
                            continue;
                        if(!(file.second->formatTime != ""))
                            continue;
                        if(!(file.second->type == FileType::FILE_TYPE_FILE))
                            continue;
                        if (!file.second->map.empty())
                            continue;
                        need_receive_count++;
                    }
                }

                std::vector<File> received_files;

                FileClaback* error_callback = new FileClaback([&](const File& file, std::string meta)
                {
                    receive_count++;
                    WLI << "receive error " << file.path << " : " << receive_count << " | " << need_receive_count;
                });
                FileClaback* receivecallback = new FileClaback([&](const File& file, std::string meta)
                {
                    receive_count++;
                    WLI << "receive " << file.path << " : " << receive_count << " | " << need_receive_count;
                    if(!(file.formatTime != ""))
                        return;
                    File_ptr f_ptr_loc = FindFileInFileMap(&_localFilesInfo, file);
                    File_ptr f_ptr_arc = FindFileInFileMap(&_archivedFilesInfo, file);
                    std::function<File_ptr(File_ptr)> add_if_need = [&](File_ptr file) -> File_ptr
                    {
                        File_ptr f = FindFileInFileMap(&_localFilesInfo, *file);
                        if(f != nullptr)
                        {
                            return f;
                        }
                        if(file->parent != nullptr)
                        {
                            File_ptr parent = add_if_need(file->parent);
                            f = File_ptr(new File(*file));
                            f->map.clear();
                            parent->map[f->path] = f;
                        }
                        else
                        {
                            f = File_ptr(new File(*file));
                            f->map.clear();
                            _localFilesInfo[f->path] = f;
                        }
                        return f;
                    };
                    if(f_ptr_loc == nullptr)
                        add_if_need(f_ptr_arc);
                    else
                        *f_ptr_loc = *f_ptr_arc;
                });

                _error_callbacks[error_callback] = error_callback;
                _reseive_callbacks[receivecallback] = receivecallback;

                DownloadRequest(_archivedFilesInfo, str_pass);

                iters = 0;
                while(receive_count < need_receive_count)
                {
                    iters++;
                    if(iters > 100) // 30 * 60 * 2)
                    {
                        restore_step = 5;
                        __message__ = "Receive file timeout error";
                        WLI << "Receive file timeout error" << std::endl;
                        //return 1;
                    }
            #if defined(_WIN32)
                    Sleep(500);
            #else
                    std::this_thread::sleep_for(500ms);
            #endif
                }

                _error_callbacks.erase(error_callback);
                _reseive_callbacks.erase(receivecallback);
                delete error_callback;
                delete receivecallback;
            }

            restore_step = 3;

            #if defined(_WIN32)
                    Sleep(500);
            #else
                    std::this_thread::sleep_for(500ms);
            #endif
            restore_step = 4;

            #if defined(_WIN32)
                    Sleep(500);
            #else
                    std::this_thread::sleep_for(500ms);
            #endif
            restore_step = 5;

            auto ths = restore_thread;
            *((size_t*)(&restore_thread)) = 1;
            return 0;
        }
        );
    }
    ImGui::ShowImage(&Governor);
    ImGui::SameLine();
    std::string text = "";
    switch (restore_step)
    {
    case 0:
        text = "Selecting Files or Folders to Restore";
        break;
    case 1:
        text = "Deciphering Files or Folders in Archiving Disk";
        break;
    case 2:
        text = "Transferring Files or Folders from Archiving to Local System";
        break;
    case 3:
        text = "Dismounting Archiving Disk";
        break;
    case 4:
        text = "Decipherring Files & Folders in Local System";
        break;
    case 5:
        text = "Ending Restoring Process";
        break;
    default:
        break;
    }
    ImGui::TextCentered(text.c_str());
    std::time_t t = std::time(0);   // get time now
    std::tm* now = std::localtime(&t);
    ImGui::Clock(now->tm_hour + now->tm_min / 60.0 + now->tm_sec / 3600.0, now->tm_min + now->tm_sec / 60.0, now->tm_sec);
    ImGui::SameLine();
    auto window = ImGui::GetCurrentWindow();
    auto oldpos = window->DC.CursorPos;
    ImGui::Text("Estimated time remaining:");
    ImGui::SameLine();
    auto pos = window->DC.CursorPos;
    pos.y = oldpos.y;
    for(int i = 0; i < 5; i++)
    {
        ImRect bb{
            pos + ImVec2(60, 0) + ImVec2(120 * i, 0),
            pos + ImVec2(60, 0) + ImVec2(120 * i, 0) + ImVec2(64, 64)
        };
        ImRect bb2{
            pos + ImVec2(90, 29) + ImVec2(120 * i, 0),
            pos + ImVec2(90, 29) + ImVec2(120 * i, 0) + ImVec2(120, 6)
        };
        ImRect bb3{
            pos + ImVec2(90, 22) + ImVec2(120 * i, 0),
            pos + ImVec2(90, 22) + ImVec2(120 * i, 0) + ImVec2(120, 20)
        };
        if(i == 4)
        {
            bb2 = ImRect(
                pos + ImVec2(90, 30) + ImVec2(120 * i, 0),
                pos + ImVec2(90, 30) + ImVec2(120 * i, 0) + ImVec2(0, 0));
            bb3 = bb2;
        }
        ImGui::RenderShadow_v1(bb3.Min, bb3.Max, IM_COL32(0, 0, 0, 20), 4, 4, 5, 0, 31, true);
        ImGui::RenderShadow_v1(bb3.Min, bb3.Max, IM_COL32(255, 255, 255, 150), -4, -4, 5, 0, 31, true);
        if(i > restore_step)
        {
            window->DrawList->AddRectFilled(bb.Min, bb.Max, ImGui::GetColorU32(ImGuiCol_TitleBg), 31);
            window->DrawList->AddImage(reinterpret_cast<ImTextureID>(restore_steps[0][i].texture), bb.Min, bb.Max,
                ImVec2(0, 0), ImVec2(1, 1), IM_COL32(255, 255, 255, 255));
            ImGui::RenderShadow_v1(bb.Min, bb.Max, IM_COL32(0, 0, 0, 20), 4, 4, 5, 0, 31, true);
            ImGui::RenderShadow_v1(bb.Min, bb.Max, IM_COL32(255, 255, 255, 150), -4, -4, 5, 0, 31, true);
        }
        else if(i == restore_step)
        {
            const auto col = ImGui::GetColorU32(Hex2ImVec4("#1E9AFE"));
            window->DrawList->AddRectFilled(bb2.Min, bb2.Max, col);
            ImGui::RenderShadow_v1(bb.Min, bb.Max, IM_COL32(0, 0, 0, 20), -4, -4, 5, 0, 31, false);
            ImGui::RenderShadow_v1(bb.Min, bb.Max, IM_COL32(255, 255, 255, 150), 4, 4, 5, 0, 31, false);
            window->DrawList->AddRectFilled(bb.Min, bb.Max, ImGui::GetColorU32(ImGuiCol_TitleBg), 31);
            window->DrawList->AddImage(reinterpret_cast<ImTextureID>(restore_steps[1][i].texture), bb.Min, bb.Max,
                ImVec2(0, 0), ImVec2(1, 1), IM_COL32(255, 255, 255, 255));
        }
        else
        {
            const auto col = ImGui::GetColorU32(Hex2ImVec4("#60DFCD"));
            window->DrawList->AddRectFilled(bb2.Min, bb2.Max, col);
            ImGui::RenderShadow_v1(bb.Min, bb.Max, IM_COL32(0, 0, 0, 20), -4, -4, 5, 0, 31, false);
            ImGui::RenderShadow_v1(bb.Min, bb.Max, IM_COL32(255, 255, 255, 150), 4, 4, 5, 0, 31, false);
            window->DrawList->AddRectFilled(bb.Min, bb.Max, ImGui::GetColorU32(ImGuiCol_TitleBg), 31);
            window->DrawList->AddImage(reinterpret_cast<ImTextureID>(restore_steps[2][i].texture), bb.Min, bb.Max,
                ImVec2(0, 0), ImVec2(1, 1), IM_COL32(255, 255, 255, 255));
        }
    }
}

void FileUploader::Restore_Left()
{
    ImGui::TextCentered("Local system");
    auto ret = ImGui::MyTreeWiew("ContentTrree" ,&_localFilesInfo, {400, 30});
}

void FileUploader::Restore_Right()
{
    ImGui::TextCentered("Archiving system");
    auto ret = ImGui::MyTreeWiew("ContentTrree" ,&_archivedFilesInfo, {400, 30});

}

void FileUploader::ShowWindow([[maybe_unused]] int posx, [[maybe_unused]] int posy,
    [[maybe_unused]] int width, [[maybe_unused]] int height)
{
    if (!Governor.texture)
    {
        ImGui::LoadTextureFromFile("./res/images/Governor.png", &Governor);
    }
    for(int i = 0; i < 8; i++)
    {
        if (!archive_steps[0][i].texture)
        {
            ImGui::LoadTextureFromFile((std::string("./res/images/archive_step_") + std::to_string(i + 1) + ".png").c_str(), &archive_steps[0][i]);
        }
        if (!archive_steps[1][i].texture)
        {
            ImGui::LoadTextureFromFile((std::string("./res/images/archive_step_") + std::to_string(i + 1) + "-1.png").c_str(), &archive_steps[1][i]);
        }
        if (!archive_steps[2][i].texture)
        {
            ImGui::LoadTextureFromFile((std::string("./res/images/archive_step_") + std::to_string(i + 1) + "-2.png").c_str(), &archive_steps[2][i]);
        }
    }
    for(int i = 0; i < 5; i++)
    {
        if (!restore_steps[0][i].texture)
        {
            ImGui::LoadTextureFromFile((std::string("./res/images/archive_step_") + std::to_string(i + 1) + ".png").c_str(), &restore_steps[0][i]);
        }
        if (!restore_steps[1][i].texture)
        {
            ImGui::LoadTextureFromFile((std::string("./res/images/archive_step_") + std::to_string(i + 1) + "-1.png").c_str(), &restore_steps[1][i]);
        }
        if (!restore_steps[2][i].texture)
        {
            ImGui::LoadTextureFromFile((std::string("./res/images/archive_step_") + std::to_string(i + 1) + "-2.png").c_str(), &restore_steps[2][i]);
        }
    }
    static ETabIndex tabIndex = ETabIndex::ETab_GOV;
    ImGuiContext& g = *GImGui;
    const ImGuiStyle& style = g.Style;
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    bool open = true;
    ImGui::SetNextWindowSize(ImVec2{ (float)width, (float)height });

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoCollapse;

    if (ImGui::Begin("Darwinics", &open, flags)) {
        static ImGui::WIcon logo {0, 0, 0};
        if (!logo.texture)
        {
            ImGui::LoadTextureFromFile("./res/images/Logo.png", &logo);
        }
        ImGui::BeginChild("Toolbar", { 0, 80 });
        {
            static std::function<void()> menu_content = [](){};
            ImGuiWindow* window = ImGui::GetCurrentWindow();
            static ImVec2 popup_pos;
            static ImVec2 pos;
            ImGuiWindowFlags window_flags = ImGuiWindowFlags_ChildMenu | ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoNavFocus;
            if (window->Flags & ImGuiWindowFlags_ChildMenu)
                window_flags |= ImGuiWindowFlags_ChildWindow;
            ImGui::ShowImage(&logo);

            bool need_open_enc_dow = 0;

            ImGui::SameLine(0, 20);
            pos = window->DC.CursorPos;
            if (ImGui::MyButton("Selection####Selection menubtn", { 150, 60 }))
            {
                need_open_enc_dow = 1;
                popup_pos = pos + ImVec2(0, 60);

                menu_content = [&](){
                    if(ImGui::MyMenuButton("Monitored folders", { 150, 30 }))
                    {
                        tabIndex = ETabIndex::ETab_LOCAL;
                        ImGui::CloseCurrentPopup();
                    }

                    if(ImGui::MyMenuButton("Key Length", { 150, 30 }))
                    {

                    }

                    if(ImGui::MyMenuButton("Governor Storage", { 150, 30 }))
                    {
                        tabIndex = ETabIndex::ETab_GOV;
                        ImGui::CloseCurrentPopup();
                    }

                    if(ImGui::MyMenuButton("Backup Storage", { 150, 30 }))
                    {
                        tabIndex = ETabIndex::ETab_BACKUP;
                        ImGui::CloseCurrentPopup();
                    }

                    if(ImGui::MyMenuButton("Setting", { 150, 30 }))
                    {

                    }
                };
            }

            ImGui::SameLine(0, 20);
            pos = window->DC.CursorPos;
            if (ImGui::MyButton("Actions####Actions menubtn", { 150, 60 }))
            {
                need_open_enc_dow = 1;
                popup_pos = pos + ImVec2(0, 60);

                menu_content = [this](){
                    if(ImGui::MyMenuButton("Archive", { 150, 30 }))
                    {
                        if (!_logged_in) {
                            ImGui::CloseCurrentPopup();
                            OpenCustomPopupWithMessage("Log in to use Archive function!");
                            _open_custom_popup = true;
                        } else {
                            tabIndex = ETabIndex::ETab_Archive;
                            ImGui::CloseCurrentPopup();

                            if ((size_t)archive_thread == 1)
                                archive_thread = 0;
                        }
                    }

                    if(ImGui::MyMenuButton("Restore", { 150, 30 }))
                    {
                        if (!_logged_in) {
                            ImGui::CloseCurrentPopup();
                            OpenCustomPopupWithMessage("Log in to use Restore function!");
                            _open_custom_popup = true;
                        } else {
                            tabIndex = ETabIndex::ETab_Restore;
                            ImGui::CloseCurrentPopup();
                            if (_logged_in && (size_t)restore_thread == 1)
                                restore_thread = 0;
                        }
                    }

                };
            }

            ImGui::SameLine(0, 20);
            pos = window->DC.CursorPos;
            if (ImGui::MyButton("Keys####Keys menubtn", { 150, 60 }))
            {
                need_open_enc_dow = 1;
                popup_pos = pos + ImVec2(0, 60);

                menu_content = [](){
                    if(ImGui::MyMenuButton("Generate", { 150, 30 }))
                    {

                    }

                    if(ImGui::MyMenuButton("Store", { 150, 30 }))
                    {

                    }

                    if(ImGui::MyMenuButton("Retrieve", { 150, 30 }))
                    {

                    }

                    if(ImGui::MyMenuButton("Import", { 150, 30 }))
                    {

                    }

                    if(ImGui::MyMenuButton("Export", { 150, 30 }))
                    {

                    }
                };
            }

            ImGui::SameLine(0, 20);
            pos = window->DC.CursorPos;
            if (ImGui::MyButton("License####License menubtn", { 150, 60 }))
            {
                need_open_enc_dow = 1;
                popup_pos = pos + ImVec2(0, 60);

                menu_content = [](){
                    if(ImGui::MyMenuButton("Info", { 150, 30 }))
                    {

                    }

                    if(ImGui::MyMenuButton("Renew", { 150, 30 }))
                    {

                    }

                    if(ImGui::MyMenuButton("Scan QR", { 150, 30 }))
                    {

                    }
                };
            }

            ImGui::SameLine(0, 20);
            pos = window->DC.CursorPos;
            if (ImGui::MyButton("About####About menubtn", { 150, 60 }))
            {
                need_open_enc_dow = 1;
                popup_pos = pos + ImVec2(0, 60);

                menu_content = [](){
                    if(ImGui::MyMenuButton("Hermeticsis", { 150, 30 }))
                    {

                    }

                    if(ImGui::MyMenuButton("Cybmentis", { 150, 30 }))
                    {

                    }

                    if(ImGui::MyMenuButton("QRCrypto", { 150, 30 }))
                    {

                    }
                };
            }

            if(need_open_enc_dow)
            {
                ImGui::OpenPopup("_context_menu");
            }

            ImGui::SetNextWindowPos(popup_pos, ImGuiCond_Always);
            ImGui::SetNextWindowBgAlpha(1);
            ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, 12);
            ImGui::PushStyleVar(ImGuiStyleVar_PopupBorderSize, 1);
            ImGui::PushStyleColor(ImGuiCol_Border, Hex2ImVec4("#E0F0F0"));

            if (ImGui::BeginPopup("_context_menu")) {

                menu_content();

                ImGui::EndPopup();
            }

            ImGui::PopStyleVar(2);
            ImGui::PopStyleColor();


        }
        ImGui::EndChild();


        std::string cmessage = "";
        if (client)
            cmessage = client->message();
        if(cmessage.size() > 0)
            __message__ = cmessage;

        ImGui::Text(client ? ( client->isOnline() ? "client online" : "client offline") : "client not create");
        ImGui::SameLine();
        ImGui::Text(__message__.c_str());
        ImGui::SameLine(ImGui::GetWindowWidth() - 150);
        ImGui::Text(_server_status.c_str());

        ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0);
        ImGui::BeginChild("Content", ImVec2{ 0, 0 });
        {
            static CallBase_t head_content = &FileUploader::None_Head;
            static CallBase_t left_content = &FileUploader::None_Head;
            static CallBase_t right_content = &FileUploader::None_Head;
            #define __GEN__CASE__(tag, name) \
            case ETabIndex::ETab_##tag: { \
                head_content = &FileUploader::name##_Head; \
                left_content = &FileUploader::name##_Left; \
                right_content = &FileUploader::name##_Right; \
            } break
            switch (tabIndex)
            {
            __GEN__CASE__(GOV, Gov);
            __GEN__CASE__(LOCAL, Local);
            __GEN__CASE__(BACKUP, Backup);
            __GEN__CASE__(Archive, Archive);
            __GEN__CASE__(Restore, Restore);
            default:
                head_content = &FileUploader::None_Head;
                left_content = &FileUploader::None_Head;
                right_content = &FileUploader::None_Head;
                break;
            #undef __GEN__CASE__
            }

            ImVec2 pos[3];
            ImVec2 win_size[3];
            ImRect bb[3];
            window = ImGui::GetCurrentWindow();

            pos[0] = window->DC.CursorPos + style.WindowPadding * 2;
            win_size[0] = ImVec2{ width - style.WindowPadding.x * 6, 230 };
            bb[0] = ImRect(
                pos[0],
                pos[0] + win_size[0]
                );

            pos[1] =  pos[0] + ImVec2(0, 230 + style.WindowPadding.y * 2);
            win_size[1] = ImVec2{ win_size[0].x / 2 - style.WindowPadding.x, 520 };
            bb[1] = ImRect(
                pos[1],
                pos[1] + win_size[1]
                );

            pos[2] =  pos[1] + ImVec2(win_size[1].x + style.WindowPadding.x * 2, 0);
            win_size[2] = win_size[1];
            bb[2] = ImRect(
                pos[2],
                pos[2] + win_size[2]
                );
            for(int i = 0; i < 3; i++)
            {
                ImGui::RenderShadow_v1(bb[i].Min, bb[i].Max, IM_COL32(0, 0, 0, 20), -8, -8, 10, 0, 12, false);
                ImGui::RenderShadow_v1(bb[i].Min, bb[i].Max, IM_COL32(255, 255, 255, 150), 8, 8, 10, 0, 12, false);
            }

            window->DC.CursorPos = pos[0];
            ImGui::BeginChild("Headr", win_size[0], true);
            {
                (this->*head_content)();
            }
            ImGui::EndChild();
            window->DC.CursorPos = pos[1];
            ImGui::BeginChild("Left Side", win_size[1], true);
            {
                (this->*left_content)();
            }
            ImGui::EndChild();
            window->DC.CursorPos = pos[2];
            ImGui::BeginChild("Right Side", win_size[2], true);
            {
                (this->*right_content)();
            }
            ImGui::EndChild();



        }
        ImGui::EndChild();

        ImGui::PopStyleVar();

        if (_open_custom_popup) {
            ImGui::OpenPopup("Message##popup");
            _open_custom_popup = false;
        }
        if (ImGui::BeginPopupModal("Message##popup", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::Text("%s", _custom_popup_message.c_str());
            if (ImGui::Button("OK", ImVec2(50, 25))) {
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }

        ImGui::End();
    }

    if (!open)
    {
        GlobalRunning = false;
    }
}

// NETWORK

void FileUploader::RunClient()
{
    auto trepl = [](std::string inp) -> std::string
    {
        std::string temp = "";
        int         index = -1;
        for (int i = 0; i < inp.size(); i++)
        {
            if (inp[i] == ':')
                index = i;
        }
        if (index > 2)
        {
            for (int i = 0; i < index; i++)
            {
                temp += inp[i];
            }
        }
        else
            temp = inp;
        return temp;
    };

    auto get_port = [](std::string inp) -> uint16_t
    {
        uint16_t    ret = 8081;
        std::string temp = "";
        int         index = -1;
        for (int i = 0; i < inp.size(); i++)
        {
            if (inp[i] == ':')
                index = i;
        }
        if (index > 2)
        {
            for (int i = index + 1; i < inp.size(); i++)
            {
                temp += inp[i];
            }
        }
        else
            temp = "";
        try
        {
            if (temp.size() > 0)
                ret = std::stoi(temp);
        }
        catch (const std::exception& e)
        {
        }

        return ret;
    };

    std::string uri_info = settings_["url"];
    std::string uri_data = settings_["url"];

    uint16_t port = get_port(settings_["url"]);

    uri_info = trepl(uri_info).append(":").append(std::to_string(port));
    uri_data = trepl(uri_data).append(":").append(std::to_string(port + 1));

    // create info websocket
    client = new WebsocketClient(uri_info, uri_data);
    client->SetPassword(password);
    client->SetUsername(settings_["appname"]);
    client->SetRegistrationPassword(_register_password_buf);
    client->SetRegistrationUsername(_register_login_buf);
    client->SetFileUploader(this);
    {
        try
        {
            client->run();
        }
        catch (const std::exception& e)
        {
            std::cout << e.what() << std::endl;
        }
        catch (websocketpp::lib::error_code e)
        {
            std::cout << e.message() << std::endl;
        }
        catch (...)
        {
            std::cout << "other exception" << std::endl;
        }
    };
}

void FileUploader::UpdateUploadedFilesInfo(std::string str)
{
    _archivedFilesInfo.clear();

    FileMapFromString(&_archivedFilesInfo, str);


    _update_file_list_status = 1;
}

void FileUploader::UpdateAvailableMachines(std::string data)
{
    _availableMachines.clear();
    WLI << "FileUploader::UpdateAvailableMachines data" << data << std::endl;
    AvailableMachinesVectorFromString(_availableMachines, data);

    std::string mac_address;
    for (char c : getMacAddress()) {
        if (c != ':') {
            mac_address.push_back(c);
        }
    }
    _selected_machine =
        std::find(_availableMachines.begin(), _availableMachines.end(), mac_address) -
        _availableMachines.begin();
}

void FileUploader::FileSaved(const File& file, std::string meta)
{
    for (auto el : this->_loaded_calbacks)
    {
        if(el.second != nullptr)
            el.second->operator()(file, meta);
    }
}

void FileUploader::FileRemoved(const File& file, std::string meta)
{
    _localFilesInfo.erase(file.path);
    _archivedFilesInfo.erase(file.path);
    for (auto el : this->_removed_calbacks)
    {
        if(el.second != nullptr)
            el.second->operator()(file, meta);
    }
}

void FileUploader::FileSent(const File& file, std::string meta)
{
    for (auto el : _sended_calbacks)
    {
        if(el.second != nullptr)
            el.second->operator()(file, meta);
    }
}

void FileUploader::FileUploaded(const File& file, std::string meta)
{
    for (auto el : _uploaded_callbacks)
    {
        if(el.second != nullptr)
            el.second->operator()(file, meta);
    }
}

void FileUploader::FileError(const File& file, std::string meta)
{
    for (auto el : _error_callbacks)
    {
        if(el.second != nullptr)
            el.second ->operator()(file, meta);
    }
}

void FileUploader::FileReseive(const File& file, std::string meta)
{
    for (auto el : _reseive_callbacks)
    {
        if(el.second != nullptr)
            el.second->operator()(file, meta);
    }
}

FunctionResult FileUploader::DownloadRequest(FileMap _list, const std::string& pass)
{
    FunctionResult result;
    if (_list.empty())
    {
        auto all_files = _localFilesInfo;
        auto list = _archivedFilesInfo;

        FileMapDiff(&_list, &all_files, &list);
    }
    if (!_list.empty())
    {
        auto files = FileMapToVector(&_list);
        for (const auto& file : files)
        {
            if(!file.second->used)
                continue;
            if(!(file.second->formatTime != ""))
                continue;
            if(!(file.second->type == FileType::FILE_TYPE_FILE))
                continue;
            Json newJson = JsonWorker::CreateJsonObject();
            JsonWorker::AddToJsonVal(newJson, "hash", file.second->hash);
            JsonWorker::AddToJsonVal(newJson, "path", file.first);
            WebsocketClient::command(client, (int)ECommandType::RECEIVE_FILE, newJson, pass);
        }
    }
    else
    {
    }

    return result;
}

FunctionResult FileUploader::DeleteRequest(FileMap _list, const std::string& pass)
{
    FunctionResult result;
    if (_list.empty())
    {
        return result;
    }

    auto files = FileMapToVector(&_list);
    for (const auto& file : files)
    {
        Json newJson = JsonWorker::CreateJsonObject();
        JsonWorker::AddToJsonVal(newJson, "hash", file.second->hash);
        JsonWorker::AddToJsonVal(newJson, "path", file.first);
        WebsocketClient::command(client, (int)ECommandType::REMOVE_FILE, newJson, pass);
    }

    return result;
}

FunctionResult FileUploader::RenameRequest(std::pair<std::string, File> old,
    std::pair<std::string, File> file, const std::string& pass)
{
    FunctionResult result;

    Json newJson = JsonWorker::CreateJsonObject();
    JsonWorker::AddToJsonVal(newJson, "old_path", old.first);
    JsonWorker::AddToJsonVal(newJson, "old_hash", old.second.hash);
    JsonWorker::AddToJsonVal(newJson, "new_path", file.first);
    JsonWorker::AddToJsonVal(newJson, "new_hash", file.second.hash);
    WebsocketClient::command(client, (int)ECommandType::RENAME_FILE, newJson, pass);

    return result;
}

void PrepareFiles(const std::vector<std::pair<std::string, File_ptr>> &files)
{
    for (const auto &file: files) {

    }
}

/**
** @brief upload files to the server
**
** @param _list files to upload
** @param pass
** @return ** FunctionResult
*/
FunctionResult FileUploader::UploadRequest(FileMap _list, const std::string& pass)
{
    FunctionResult result;
    if (_list.empty())
    {
        auto all_files = _localFilesInfo;
        auto list = _archivedFilesInfo;

        FileMapDiff(&_list, &list, &all_files);
    }
    if (!_list.empty())
    {
        auto files = FileMapToVector(&_list);
        files_to_upload_amount = files.size();
        for (const auto& file : files)
        {
            if(!file.second->used)
                continue;
            Json newJson = JsonWorker::CreateJsonObject();
            JsonWorker::AddToJsonVal(newJson, "file", file.second->ToStringNoMap());
            WebsocketClient::command(client, (int)ECommandType::SEND_FILE_INFO, newJson, pass);
            FileUploaded(*file.second.get(), "");
            uploaded_files_amount++;
        }
    }
    else
    {
    }

    return result;
}

void FileUploader::SetLoadProgress(std::string archive_name, float value)
{

}

void FileUploader::Update()
{
}

void FileUploader::GetServerStatus()
{
    if (client) {
        Json newJson = JsonWorker::CreateJsonObject();
        JsonWorker::AddToJsonVal(newJson, "dummy", ":");
        WebsocketClient::command(client, (int)ECommandType::GET_SERVER_STATUS, newJson);
    } else {
        RunClient();
    }
}

void FileUploader::SetServerStatus(const std::string &status) {
    _server_status = status;
}

std::filesystem::path FileUploader::GetBackupFolder() {
    return _backup_path;
}

FileUploader::~FileUploader() {
    _stop_ping = true;
    _ping_server_thread.join();
}

bool
FileUploader::StartPingServer()
{
    _ping_server_thread = std::thread([this]() {
        #if defined(_WIN32)
            int wait_time = 1000;
        #else
            auto wait_time = 1000ms;
        #endif
        while (!_stop_ping) {
            ChangeServerStatus(0);
            GetServerStatus();
        #if defined(_WIN32)
            Sleep(wait_time);
        #else
            std::this_thread::sleep_for(wait_time);
        #endif
            if (!_availableMachines.empty()) {
        #if defined(_WIN32)
                wait_time = 5000;
        #else
                wait_time = 5000ms;
        #endif
            }
            int status = CheckServerStatus();
            if (status == 0) {
                SetServerStatus("server offline");
            } else if(status == 1) {
                SetServerStatus("server online");
            }
        }
    });
    return true;
}

void FileUploader::ChangeServerStatus(int status) {
    std::lock_guard<std::mutex> lk(_status_mutex);
    _get_server_status = status;
}

int FileUploader::CheckServerStatus() {
    std::lock_guard<std::mutex> lk(_status_mutex);
    return _get_server_status;
}

std::shared_ptr<SettingsManager> FileUploader::GetLoginManager() const {
    return _login_manager;
}

std::string
FileUploader::GetEncodingPass()
{
    return std::string(password_locals);
}

FileUploader::LoginStatus FileUploader::GetStatus() const {
    return _login_status;
}

void FileUploader::SetLoginStatus(LoginStatus status) {
    _login_status = status;
}

void FileUploader::SomeoneLoggedIn(const std::string &user_name) {
    settings_.Set("appname", user_name);
    _logged_in = true;
}

void FileUploader::OpenCustomPopupWithMessage(const std::string &message)
{
    _open_custom_popup = true;
    _custom_popup_message = message;
}

bool FileUploader::LoginAfterRegistration() const
{
    return login_after_reg;
}

void FileUploader::Login() {
    if (!settings_.Get("appname").empty() &&
        !settings_.Get("url").empty() &&
        settings_.Get("url").find("ws://") != std::string::npos) {
        if (client) {
            auto        old_client = client;
            std::thread th([old_client]() {
                old_client->close();
                delete old_client;
            });
            th.detach();
            client = 0;
        }
        RunClient();
    }
}
