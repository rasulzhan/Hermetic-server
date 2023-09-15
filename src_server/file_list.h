#ifndef FILE_LIST_H
#define FILE_LIST_H

#include <filesystem>
#include <string>
#include <unordered_map>

using file_hash = std::string;
using file_name = std::string;

// TODO(Sedenkov): overload arithmetic operators

class FileList
{
public:
    enum FileStatus
    {
        FILE_OK,
        FILE_DELETED,
        FILE_NEW,
        FILE_MODIFIED,

        FILE_ERROR
    };

    struct File
    {
        file_hash  hash;
        FileStatus status;
    };

    FileList();

    /**
    ** @brief form list from stringstream
    ** stream must have the following structure:
    ** hash file_path
    ** hash file_path
    **
    */
    explicit FileList(std::stringstream &s);

    /**
    ** @brief read information from file.
    **
    ** file must have the following structure
    ** hash file_path
    ** hash file_path
    **
    ** @note removes enc extension from file names
    **
    */
    explicit FileList(std::filesystem::path file_with_info);

    int AddFile(std::filesystem::path file, std::string hash);
    int AddFile(std::filesystem::path file, std::string hash, FileStatus status);
    int AddFile(std::filesystem::path file, File f);

    /**
    ** @brief find different entries using another list
    ** returns another list that contains files that not in this list
    **
    ** @param new_list
    ** @param detect_deleted
    ** @return ** FileList
    */
    FileList Diff(FileList new_list, bool detect_deleted = false);

    FileList Section(std::string section);

    // NOTE(Sedenkov): we save filenames with .enc extension to file!
    int SaveToFile(std::filesystem::path file);

    void Clear()
    {
        files_.clear();
    }

    bool Empty()
    {
        // return filesInfo_.empty();
        return files_.empty();
    }

    std::string ToString(bool output_status = false);

    auto begin()
    {
        return files_.begin();
        // return filesInfo_.begin();
    }
    auto end()
    {
        return files_.end();
        // return filesInfo_.end();
    }

    // std::unordered_map<file_name, file_hash> filesInfo_;


private:
    std::unordered_map<file_name, File> files_;
};

#endif /* FILE_LIST_H */
