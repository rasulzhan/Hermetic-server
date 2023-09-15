#include "SettingsManager.h"

SettingsManager::SettingsManager(const std::string &filename): _filename(filename)
{}

bool
SettingsManager::IsThereSavedCredentials() const
{
    return std::filesystem::exists(_filename);
}

void
SettingsManager::GetSavedCredentials(std::string &login, std::string &user_password,
                                     std::string &public_password)
{
    if (!IsThereSavedCredentials()) {
        return;
    }

    Json doc = JsonWorker::ReadFromFile(_filename.string());

    if (doc->HasMember("login")) {
        login = doc->operator[]("login").GetString();
    }
    if (doc->HasMember("user_password")) {
        user_password = doc->operator[]("user_password").GetString();
    }
    if (doc->HasMember("public_password")) {
        public_password = doc->operator[]("public_password").GetString();
    }
}

void
SettingsManager::SaveCredentials(const std::string &login, const std::string &user_password,
                                 const std::string &public_password)
{
    Json doc;
    if (false && IsThereSavedCredentials()) {
        doc = JsonWorker::ReadFromFile(_filename.string());
    } else {
        doc = JsonWorker::CreateJsonObject();
    }

    JsonWorker::AddToJsonVal(doc, "login", login);
    JsonWorker::AddToJsonVal(doc, "user_password", user_password);
    JsonWorker::AddToJsonVal(doc, "public_password", public_password);

    JsonWorker::SaveToFile(_filename.string(), doc);
}
