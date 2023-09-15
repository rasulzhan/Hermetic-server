#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <list>
#include <functional>
#include <filesystem>

template <typename TP>
static std::time_t to_time_t(TP tp)
{
    using namespace std::chrono;
    auto sctp = time_point_cast<system_clock::duration>(tp - TP::clock::now()
              + system_clock::now());
    return system_clock::to_time_t(sctp);
}

enum FileStatus
{
    FILE_ERROR = 0,
    FILE_OK = 1 << 0,
    FILE_NEW = 1 << 1,
    FILE_MODIFIED = 1 << 2,
    FILE_LOCALE = 1 << 3,
    FILE_UPLOADED = 1 << 4,
    FILE_ENCRYPTED = 1 << 5,

    FILE_TREE_OPEN = 1 << 31,
};

enum FileType
{
    FILE_TYPE_FILE,
    FILE_TYPE_DIR,
    FILE_TYPE_ERROR
};
struct File;
typedef std::shared_ptr<File> File_ptr;


struct File
{
    std::string path;
    std::string hash;
    std::filesystem::file_time_type time;
    std::string formatTime;
    int status;
    int type = FILE_TYPE_FILE;
    std::unordered_map<std::string ,File_ptr> map;
    File_ptr parent;
    bool used = true;

    void genFormatTime();

    File(
            std::string _path = "",
            std::string _hash = "",
            int _status = FILE_OK | FILE_LOCALE,
            int _type =  FILE_TYPE_FILE,
            std::filesystem::file_time_type _time = std::filesystem::file_time_type(),
            std::unordered_map<std::string ,File_ptr> _map = std::unordered_map<std::string ,File_ptr>(),
            File_ptr _parent = nullptr
        );

    std::string ToString() const;

    std::string ToStringNoMap() const;

    std::string GetPath() const;

    std::string GetParentsHashs() const;

    void FromString(std::string, uint32_t* end_i = 0, File_ptr self = nullptr);

    void FromStringNoMap(std::string str, std::string& parents_hashs);

    void SetUsed(bool _used)
    {
        used = _used;
        for(auto el : map)
        {
            el.second->SetUsed(used);
        }
    }

    uint8_t GetUsed()
    {
        uint8_t _used = 69;
        for(auto el : map)
        {
            auto t = el.second->GetUsed();

            if(t == 0)
            {
                if(_used == 2)
                {
                    used = false;
                    return 1;
                }
                _used = 0;
            }
            else if(t == 2)
            {
                if(_used == 0)
                {
                    used = false;
                    return 1;
                }
                _used = 2;
            }


            else if(t == 1)
            {
                used = false;
                return 1;
            }
        }
        if(_used == 69)
        {
            _used = used ? 2 : 0;
        }
        if(_used == 0)
        {
            used = false;
        }
        else
        {
            used = true;
        }
        return _used;
    }
};

typedef std::unordered_map<std::string ,File_ptr> FileMap;


std::string FileMapToString(const FileMap*);

void FileMapFromString(FileMap*, std::string, uint32_t* end_i = 0, File_ptr parent = nullptr);

void AvailableMachinesVectorFromString(std::vector<std::string> &available_machines, const std::string &str);

void AddFileToFileMap(FileMap* map, std::filesystem::path file, bool only_filename = false, bool ignore_data = false);

void AddFileToFileMap(FileMap* map, std::string path, const File& file);

void AddFileToFileMap(FileMap* map, std::string path, std::string hash, int status, FileType ft = FILE_TYPE_FILE);

void FileMapDiff(FileMap* map, FileMap* left, FileMap* right);

std::vector<std::pair<std::string, File_ptr>> FileMapToVector(FileMap* map);

void DeleteFileInFileMap(FileMap* map, const File& file);

File_ptr FindFileInFileMap(FileMap* map, const File& file);
