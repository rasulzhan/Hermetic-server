#include "file_list.h"

#include <fstream>
#include <iostream>
#include <algorithm>

// trim from start (in place)
static inline void
ltrim(std::string &s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
                return !std::isspace(ch);
            }));
}

// trim from end (in place)
static inline void
rtrim(std::string &s)
{
    s.erase(std::find_if(s.rbegin(), s.rend(),
                         [](unsigned char ch) {
                             return !std::isspace(ch);
                         })
                .base(),
            s.end());
}

// trim from both ends (in place)
static inline void
trim(std::string &s)
{
    rtrim(s);
    ltrim(s);
}

FileList::FileList()
{}

FileList::FileList(std::filesystem::path file_with_info)
{
    if (std::filesystem::exists(file_with_info)) {
        std::ifstream f;
        f.open(file_with_info, std::ios::in);

        if (f.is_open()) {
            std::string line;
            while (std::getline(f, line)) {
                auto split_pos = line.find(' ');
                if (split_pos != line.npos) {
                    std::string hash = line.substr(0, split_pos);
                    std::string file = line.substr(split_pos + 1);

                    if (file.ends_with(".enc")) {
                        file = file.substr(0, file.size() - 4);
                    }
                    this->AddFile(file, hash);
                } else {
                    std::cerr << "Error parsing hash file\n";
                }
            }
        }
    }
}

#define HASH_LEN 32

FileList::FileList(std::stringstream &s)
{
    std::string line;
    while (std::getline(s, line)) {
        auto split_pos = line.find(' ');
        if (split_pos != line.npos) {
            std::string hash = line.substr(0, split_pos);
            std::string file = line.substr(split_pos + 1);

            auto status_pos = file.find('\t');
            if (status_pos == file.npos) {
                this->AddFile(file, hash);
            } else {
                FileStatus status = static_cast<FileStatus>(std::stoi(file.substr(status_pos + 1)));
                this->AddFile(file, hash, status);
            }
        } else {
            std::cerr << "Error parsing hash file\n";
        }
    }
}

int
FileList::AddFile(std::filesystem::path file, std::string hash)
{
    std::string file_name = file.string();
    trim(file_name);
    std::replace(file_name.begin(), file_name.end(), '\\', '/');
    std::cout << "File added: " << hash << " " << file_name << "\n";
    // filesInfo_[file_name] = hash;
    files_[file_name] = File {.hash = hash, .status = FILE_OK};

    return 1;
}

int
FileList::AddFile(std::filesystem::path file, std::string hash, FileStatus status)
{
    std::string file_name = file.string();
    trim(file_name);
    // NOTE(Sedenkov): replace \ on / if we on windows
    std::replace(file_name.begin(), file_name.end(), '\\', '/');
    std::cout << "File added: " << hash << " " << file_name << "\t" << status << "\n";
    // filesInfo_[file_name] = hash;
    files_[file_name] = File {.hash = hash, .status = status};

    return 1;
}

int
FileList::AddFile(std::filesystem::path file, File f)
{
    std::string file_name = file.string();
    trim(file_name);
    std::replace(file_name.begin(), file_name.end(), '\\', '/');
    std::cout << "File added: " << f.hash << " " << file << file_name << "\t" << f.status << "\n";
    files_[file_name] = f;

    return 1;
}

FileList
FileList::Diff(FileList new_list, bool detect_deleted)
{
    FileList result;
    for (auto entry: new_list) {
        auto exists = files_.find(entry.first);

        // files only in second list
        if (exists == files_.end()) {
            result.AddFile(entry.first, entry.second.hash, FILE_NEW);
        } else {
            // new list has different file
            if (exists->second.hash != entry.second.hash) {
                std::cout << "Hashes: " << exists->second.hash << "------" << entry.second.hash;
                result.AddFile(entry.first, entry.second.hash, FILE_MODIFIED);
            }
        }
    }

    return result;
}

inline bool
caseInsCharCompSingle(char a, char b)
{
    return (toupper(a) == b);
}

std::string::const_iterator
caseInsFind(std::string &s, const std::string &p)
{
    std::string tmp;

    std::transform(p.begin(), p.end(),       // Make the pattern
                   std::back_inserter(tmp),  // upper-case
                   toupper);

    return (std::search(s.begin(), s.end(),       // Return the iter-
                        tmp.begin(), tmp.end(),   // ator returned by
                        caseInsCharCompSingle));  // search
}

FileList
FileList::Section(std::string section)
{
    FileList result;

    // for (auto info: filesInfo_) {
    for (auto info: files_) {
        std::string name = info.first;
        auto        it = caseInsFind(name, section);
        // auto found = info.first.find(section);
        // NOTE(Sedenkov): section can be only at the start
        if (it - name.begin() == 0) {
            result.AddFile(info.first, info.second);
        }
    }

    return result;
}

int
FileList::SaveToFile(std::filesystem::path file)
{
    std::ofstream f;
    f.open(file, std::ios_base::out);

    // for (auto info: filesInfo_) {
    for (auto info: files_) {
        bool has_enc = info.first.ends_with(".enc");
        f << info.second.hash << " " << info.first << (has_enc ? "" : ".enc") << "\n";
    }

    f.close();

    return 0;
}

std::string
FileList::ToString(bool output_status)
{
    std::stringstream result;

    // for (auto entry: filesInfo_) {
    for (auto info: files_) {
        result << info.second.hash << " " << info.first;
        if (output_status) {
            result << "\t" << info.second.status;
        }
        result << "\n";
    }

    return result.str();
}
