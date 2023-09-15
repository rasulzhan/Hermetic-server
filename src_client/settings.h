#ifndef SETTINGS_H
#define SETTINGS_H

#include <cstring>
#include <string>
#include <unordered_map>

class Settings
{
public:
    std::unordered_map<std::string, char[256]> map;

    Settings();
    void Save();
    void Load();

    char *operator[](std::string key)
    {
        if (map.find(key) == map.end())
            map[key][0] = '\0';
        return map[key];
    }
    std::string Get(std::string key)
    {
        return std::string(this->operator[](key));
    }
    void Set(std::string key, std::string value)
    {
        std::strncpy(map[key], value.data(), (value.size() < 256) ? value.size() : 256);
    }

private:
    const std::string filename;
};

#endif /* SETTINGS_H */
