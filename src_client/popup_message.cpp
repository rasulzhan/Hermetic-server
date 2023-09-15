#include "popup_message.h"

#include <imgui.h>

static int id = 0;

PopupMessage::PopupMessage(MessageType type, std::string message):
    isActive_(true), type_(type), message_(message)
{
    const char *t = type_ == InfoMessage ? "Attention" : "Error";
    title_ = t;
    title_ += "###ppid" + std::to_string(id++);
}

bool
PopupMessage::IsActive() const
{
    return isActive_;
}

void
PopupMessage::Show()
{
    if (isActive_) {
        ImGui::SetNextWindowSize(ImVec2 {150, 150});
        ImGui::Begin(title_.c_str(), 0,
                     ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoResize |
                         ImGuiWindowFlags_NoCollapse);
        {
            ImGui::PushTextWrapPos(140);
            ImGui::TextWrapped("%s", message_.c_str());
            ImGui::PopTextWrapPos();

            if (ImGui::Button("Ok")) {
                isActive_ = false;
                ImGui::CloseCurrentPopup();
            }
        }
        ImGui::End();
    }
}
