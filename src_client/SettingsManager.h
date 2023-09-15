#ifndef DRWINUPLOADER_SETTINGSMANAGER_H
#define DRWINUPLOADER_SETTINGSMANAGER_H

#include "../common/json_worker.h"

#include <filesystem>
#include <fstream>
#include <string>

class SettingsManager
{
public:
    explicit SettingsManager(const std::string &filename);

    bool IsThereSavedCredentials() const;

    void GetSavedCredentials(std::string &login, std::string &user_password,
                             std::string &public_password);

    void SaveCredentials(const std::string &login, const std::string &user_password,
                         const std::string &public_password);

private:
    std::filesystem::path _filename;
};

#endif  // DRWINUPLOADER_SETTINGSMANAGER_H
