#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#include <set>
#include <string>
#include <string.h>
#include <iostream>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <functional>
#include <iterator>

#define FS_SHOW_ALL                 true
#define FS_SHOW_INFO                true

typedef std::set<std::string, std::greater<std::string>> DirTree;
typedef std::set<std::string, std::greater<std::string>>& DirTreeRef;
typedef const std::set<std::string, std::greater<std::string>>& DirTreeConstRef;

enum class FileType {
    REG,    // regular file
    DIR,    // directory
    CHR,    // character device
    BLK,    // block device
    FIFO,   // FIFO
    LNK,    // link
    SOCK,   // socket
    UNDEF   // undefined
};


class FileSystem
{
public:
    FileSystem();

    void List(const char* path, bool showAll = true, bool showInfo = false);
    void List(const std::string& path,  bool showAll = true, bool showInfo = false);

    FileType GetFileType(const char* path);
    FileType GetFileType(const std::string& path);

    int Remove(const char* path);
    int Remove(const std::string& path);

    int RemoveAll(const char* path);
    int RemoveAll(const std::string& path);

private:
    void _List(const char* path, bool showAll = true, bool showInfo = false);
    FileType _GetFileType(const char* path);
    std::string _FileTypeToString(const FileType& fileType);
    int _RemoveAllFiles(const char* path);
    int _RemoveAllDirs(const char* path);
    void _BuildDirTree(const char* path, DirTreeRef dirTree);
};


#endif // FILESYSTEM_H
