#include "settings.h"

#include <fstream>
#include <filesystem>
#include <cstring>

Settings::Settings(): filename("upload.cfg")
{
    Load();
}

void
Settings::Save()
{
    std::fstream fs(filename, std::ios::out);

    for(auto el : map)
    {
        fs << el.first << "=" << el.second << "\n";
    }
}

void
Settings::Load()
{
    bool exists = std::filesystem::exists(filename);
    if (exists) {
        std::fstream fs(filename, std::ios::in);

        std::string config_line;
        while (std::getline(fs, config_line)) {
            auto s = config_line.find('=');
            if (s != config_line.npos) {
                std::string name = config_line.substr(0, s);
                std::string value = config_line.substr(s + 1);
                Set(name, value);
            }
        }
    } else {
    }
}
