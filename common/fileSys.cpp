#include "fileSys.h"

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include <cstring>
#include <fstream>
#include <memory>
#include <openssl/evp.h>

#include "json_worker.h"

std::string GenMD5(std::filesystem::path file)
{

    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX       md5;
    MD5_Init(&md5);

    std::string str = file.string();

    MD5_Update(&md5, str.data(), str.size());
    MD5_Final(hash, &md5);

    char outputBuffer[MD5_DIGEST_LENGTH * 2 + 1];
    int  i = 0;
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }

    outputBuffer[MD5_DIGEST_LENGTH * 2] = 0;

    return outputBuffer;
}

void File::genFormatTime()
{
    std::time_t tt = to_time_t(time);
    std::tm *gmt = std::gmtime(&tt);
    std::stringstream buffer;
    buffer << std::put_time(gmt, "%d.%m.%Y %H:%M");
    formatTime = buffer.str();
}

File::File(
        std::string _path,
        std::string _hash,
        int _status,
        int _type ,
        std::filesystem::file_time_type _time,
        std::unordered_map<std::string ,File_ptr> _map,
        File_ptr _parent
    ) :
    path(_path),
    hash(_hash),
    status(_status),
    type(_type),
    map(_map),
    time(_time),
    parent(_parent)
{
    genFormatTime();
}

std::string FileMapToString(const FileMap* map)
{
    std::string str = "[";
    if(map != 0)
        if(map->size() > 0)
            for (const auto& el : *(map))
            {
                str += el.second->ToString();
            }
    return str + "]";
}

std::string File::ToString() const
{
    std::string str = "";
    std::string tstr = FileMapToString(&map);
    str = str + "{" + "path:" + path + ",hash:" + hash + ",time:" + formatTime + ",map:" + tstr + "}";
    return str;
}

std::string File::GetParentsHashs() const
{
    std::string tstr = "";
    auto pr = parent;
    while(pr != nullptr)
    {
        tstr = pr->hash + "/" + tstr;
        pr = pr->parent;
    }
    return tstr;
}

std::string File::GetPath() const
{
    return path;
}

std::string File::ToStringNoMap() const
{
    std::string str = "";
    str = str + "{" + "path:" + path + ",hash:" + hash + ",time:" + formatTime + ",parents_hashs:" + GetParentsHashs() + "}";
    return str;
}

void FileMapFromString(FileMap* map, std::string str, uint32_t* i, File_ptr parent)
{
    uint32_t __loc_i = 0;
    if(i == 0)
        i = &__loc_i;
    while(str[*i] != '[')
        *i = *i + 1;
    *i = *i + 1;
    while(str[*i] != ']')
    {
        File_ptr file = File_ptr(new File());
        file->FromString(str, i, file);
        *i = *i + 1;
        file->parent = parent;
        (*map)[file->path] = file;
    }

}

void AvailableMachinesVectorFromString(std::vector<std::string> &available_machines, const std::string &str)
{
    int last_end = 0;
    for (int i = 0; i < str.size(); i++) {
        if (str[i] == ',') {
            available_machines.push_back(str.substr(last_end, i - last_end));
            last_end = i + 1;
        }
    }
}

void File::FromString(std::string str, uint32_t* i, File_ptr self)
{
    uint32_t __loc_i = 0;
    if(i == 0)
        i = &__loc_i;
    while(str[*i] != '{')
        *i = *i + 1;

    auto readIn = [&](std::string* out) -> void
    {
        while(str[*i] != ':')
            *i = *i + 1;
        *i = *i + 1;
        *out = "";
        while(str[*i] != ',')
        {
            *out += str[*i];
            *i = *i + 1;
        }
    };

    readIn(&path);
    readIn(&hash);
    readIn(&formatTime);
    while(str[*i] != ':')
        *i = *i + 1;

    FileMapFromString(&map, str, i, self);
    *i = *i + 1;
}

void File::FromStringNoMap(std::string str, std::string& parents_hashs)
{
    uint32_t __i = 0;
    uint32_t* i = &__i;

    auto readIn = [&](std::string* out) -> void
    {
        while(str[*i] != ':')
            *i = *i + 1;
        *i = *i + 1;
        *out = "";
        while(str[*i] != ',' && str[*i] != '}')
        {
            *out += str[*i];
            *i = *i + 1;
        }
    };

    readIn(&path);
    readIn(&hash);
    readIn(&formatTime);
    readIn(&parents_hashs);

}

void AddFileToFileMap(FileMap* map, std::filesystem::path file, bool only_filename, bool ignore_data)
{
    WLI << "enter AddFileToFileMap" << std::endl;
    try {
        if (std::filesystem::exists(file))
        {
            WLI << "file exists and is " << file.string() << std::endl;
            std::filesystem::directory_entry file_entry = std::filesystem::directory_entry(file);
            std::error_code err_code;
            auto file_entry_tyme = file_entry.last_write_time(err_code);
            std::function<void(std::filesystem::path, File_ptr)> DirectoryWalker = [&](std::filesystem::path current, File_ptr parent) -> void
            {
                for (auto entry : std::filesystem::directory_iterator(current))
                {
                    auto entry_tyme = entry.last_write_time(err_code);
                    std::string hash = GenMD5(entry);
                    std::string str = entry.path().string();
                    if(only_filename)
                        str = entry.path().filename().string();
                    if (!entry.is_directory())
                    {
                        if(ignore_data && entry.path().extension() == ".data")
                            continue;

                        auto filedata = File_ptr(new File(
                            str,
                            hash,
                            FILE_OK | FILE_LOCALE,
                            FILE_TYPE_FILE,
                            entry_tyme,
                            std::unordered_map<std::string ,File_ptr>(),
                            parent
                        ));
                        parent->map[str] = filedata;
                        if(ignore_data)
                        {
                            std::string path_from_file = entry.path().string();
                            path_from_file.append(".data");

                            if(std::filesystem::exists(path_from_file)) {
                                std::ifstream reader(path_from_file, std::ios::in);
                                std::ostringstream sstr;
                                sstr << reader.rdbuf();
                                Json newJson = JsonWorker::Deserialize(sstr.str());
                                reader.close();
                                /*
                                JsonWorker::AddToJsonVal(newJson, "link", file.path);
                                JsonWorker::AddToJsonVal(newJson, "hash", file.hash);
                                JsonWorker::AddToJsonVal(newJson, "datatime", file.formatTime);
                                JsonWorker::AddToJsonVal(newJson, "status", file.status);
                                JsonWorker::AddToJsonVal(newJson, "type", file.type);
                                JsonWorker::AddToJsonVal(newJson, "secret", secret);
                                */
                                filedata->path = JsonWorker::FindStringVal(newJson, "link");
                                filedata->hash = JsonWorker::FindStringVal(newJson, "hash");
                                filedata->type = std::stoi(JsonWorker::FindStringVal(newJson, "type"));
                                filedata->status = std::stoi(JsonWorker::FindStringVal(newJson, "status"));
                                filedata->formatTime = JsonWorker::FindStringVal(newJson, "datatime");

                                std::string current_secret = JsonWorker::FindStringVal(newJson, "secret");
                                if(current_secret.size() > 0)
                                    filedata->status |= FILE_ENCRYPTED;
                            }
                        }
                    }
                    else
                    {
                        auto filedata = File_ptr(new File(
                            str,
                            hash,
                            FILE_OK | FILE_LOCALE,
                            FILE_TYPE_DIR,
                            entry_tyme,
                            std::unordered_map<std::string ,File_ptr>(),
                            parent
                        ));
                        DirectoryWalker(entry, filedata);
                        parent->map[str] = filedata;
                        if(ignore_data)
                        {
                            std::string path_from_file = entry.path().string();
                            path_from_file.append(".data");

                            if(std::filesystem::exists(path_from_file)) {
                                std::ifstream reader(path_from_file, std::ios::in);
                                std::ostringstream sstr;
                                sstr << reader.rdbuf();
                                Json newJson = JsonWorker::Deserialize(sstr.str());
                                reader.close();
                                /*
                                JsonWorker::AddToJsonVal(newJson, "link", file.path);
                                JsonWorker::AddToJsonVal(newJson, "hash", file.hash);
                                JsonWorker::AddToJsonVal(newJson, "datatime", file.formatTime);
                                JsonWorker::AddToJsonVal(newJson, "status", file.status);
                                JsonWorker::AddToJsonVal(newJson, "type", file.type);
                                JsonWorker::AddToJsonVal(newJson, "secret", secret);
                                */
                                filedata->path = JsonWorker::FindStringVal(newJson, "link");
                                filedata->hash = JsonWorker::FindStringVal(newJson, "hash");
                                filedata->type = std::stoi(JsonWorker::FindStringVal(newJson, "type"));
                                filedata->status = std::stoi(JsonWorker::FindStringVal(newJson, "status"));
                                filedata->formatTime = JsonWorker::FindStringVal(newJson, "formatTime");

                                std::string current_secret = JsonWorker::FindStringVal(newJson, "secret");
                                if(current_secret.size() > 0)
                                    filedata->status |= FILE_ENCRYPTED;
                            }
                        }
                    }
                }
            };
            std::string str = file.string();
            WLI << "str before filename strip " << str << std::endl;
            if(only_filename)
                str = file.filename().string();
            WLI << "some str idk " << str << std::endl;
            std::string hash = GenMD5(file);
            WLI << "some hash " << hash << std::endl;
            if (!std::filesystem::is_directory(file))
            {
                WLI << "it is indeed a file" << std::endl;
                map->operator[](str) = File_ptr(new File(
                        str,
                        hash,
                        FILE_OK | FILE_LOCALE,
                        FILE_TYPE_FILE,
                        file_entry_tyme,
                        std::unordered_map<std::string ,File_ptr>(),
                        nullptr
                    ));
            }
            else
            {
                WLI << "oh no it is a directory" << std::endl;
                auto filedata = File_ptr(new File(
                        str,
                        hash,
                        FILE_OK | FILE_LOCALE,
                        FILE_TYPE_DIR,
                        file_entry_tyme,
                        std::unordered_map<std::string ,File_ptr>(),
                        nullptr
                    ));
                DirectoryWalker(file, filedata);
                map->operator[](str) = filedata;

            }

        }
    } catch(std::filesystem::filesystem_error& ex)
    {
        printf("mounting exception\n");
    }
}

void AddFileToFileMap(FileMap* map, std::string path, const File& file)
{
    map->operator[](path) = File_ptr(new File(file));
}

void AddFileToFileMap(FileMap* map, std::string path, std::string hash, int status, FileType ft)
{
    map->operator[](path) = File_ptr(new File(path, hash, status, ft));
}

void FileMapDiff(FileMap* map, std::unordered_map<std::string ,File_ptr>* left, std::unordered_map<std::string ,File_ptr>* right)
{
    for (auto entry : *right)
    {
        auto exists = left->find(entry.first);

        if (exists == left->end())
        {
            AddFileToFileMap(map, entry.first, entry.second->hash, FILE_NEW);
        }
        else
        {
            if (exists->second->hash != entry.second->hash)
            {
                AddFileToFileMap(map, entry.first, entry.second->hash, FILE_MODIFIED);
            }
        }
    }
}

std::vector<std::pair<std::string, File_ptr>> FileMapToVector(FileMap* map)
{
    std::vector<std::pair<std::string, File_ptr>> ret;

    std::function<void(std::pair<std::string, File_ptr>)> rec = [&](std::pair<std::string, File_ptr> cur)
    {
        if(cur.second->type != FILE_TYPE_DIR)
            ret.push_back(cur);
        for (auto info : cur.second->map)
            rec(info);
    };
    for (auto info : *map)
    {
        rec(info);

    }

    return ret;
}

File_ptr FindFileInFileMap(FileMap* map, const File& file)
{
    std::function<File_ptr(FileMap*)> __r = [&](FileMap* map) -> File_ptr
    {

        for(auto el : *map)
        {
            if(el.second->hash == file.hash || el.second->path == file.path || el.first == file.path)
            {
                return el.second;
            }
            File_ptr rem = __r(&el.second->map);
            if(rem != nullptr)
                return rem;
        }
        return nullptr;
    };

    return __r(map);

}

void DeleteFileInFileMap(FileMap* map, const File& file)
{
    std::function<bool(FileMap*)> __r = [&](FileMap* map) -> bool
    {
        File_ptr rem = nullptr;
        for(auto el : *map)
        {
            if(el.second->hash == file.hash || el.second->path == file.path || el.first == file.path)
            {
                map->erase(el.first);
                return true;
            }
            if(__r(&el.second->map))
                return true;
        }
        return false;
    };

    __r(map);

}
