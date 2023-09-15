#include "filesystem.h"

FileSystem::FileSystem()
{

}

void FileSystem::List(const char *path, bool showAll, bool showInfo)
{
    _List(path, showAll, showInfo);
}

void FileSystem::List(const std::string &path, bool showAll, bool showInfo)
{
    _List(path.c_str(), showAll, showInfo);
}

FileType FileSystem::GetFileType(const char *path)
{
    return _GetFileType(path);
}

FileType FileSystem::GetFileType(const std::string &path)
{
    return _GetFileType(path.c_str());
}

int FileSystem::Remove(const char *path)
{
    return rmdir(path);
}

int FileSystem::Remove(const std::string &path)
{
    return rmdir(path.c_str());
}

int FileSystem::RemoveAll(const char *path)
{
    int result = _RemoveAllFiles(path);
    return (result == 0) ? _RemoveAllDirs(path) : result;
}

int FileSystem::RemoveAll(const std::string &path)
{
    return RemoveAll(path.c_str());
}

void FileSystem::_List(const char *path, bool showAll, bool showInfo)
{
    DIR* dir = opendir(path);

    if (dir != nullptr) {
        dirent* entry;
        while ((entry = readdir(dir)) != nullptr)
        {
            bool currentDir = (strcmp(entry->d_name, ".") == 0) ? true : false;
            bool parentDir = (strcmp(entry->d_name, "..") == 0) ? true : false;
            std::string fullPath = std::string(path) + "/" + std::string(entry->d_name);

            FileType fileType = _GetFileType(fullPath.c_str());

            if ((!currentDir && !parentDir) || showAll) {
                if (showInfo) {
                    std::cout << "[ " << _FileTypeToString(fileType) << " ] " << fullPath << std::endl;
                }
                else {
                    std::cout << fullPath << std::endl;
                }
            }

            if (!currentDir && !parentDir && (fileType == FileType::DIR)) {
                _List(fullPath.c_str(), showAll, showInfo);
            }
        }
    }
    closedir(dir);
}

FileType FileSystem::_GetFileType(const char *path)
{
    struct stat _stat;
    lstat(path, &_stat);

    if (S_ISREG(_stat.st_mode))
        return FileType::REG;
    else if (S_ISDIR(_stat.st_mode))
        return FileType::DIR;
    else if (S_ISCHR(_stat.st_mode))
        return FileType::CHR;
    else if (S_ISBLK(_stat.st_mode))
        return FileType::BLK;
    else if (S_ISFIFO(_stat.st_mode))
        return FileType::FIFO;
    else if (S_ISLNK(_stat.st_mode))
        return FileType::LNK;
    else if (S_ISSOCK(_stat.st_mode))
        return FileType::SOCK;

    return FileType::UNDEF;
}

std::string FileSystem::_FileTypeToString(const FileType &fileType)
{
    switch (fileType) {
    case FileType::REG:
        return "REG";
    case FileType::DIR:
        return "DIR";
    case FileType::CHR:
        return "CHR";
    case FileType::BLK:
        return "BLK";
    case FileType::FIFO:
        return "FIFO";
    case FileType::LNK:
        return "LNK";
    case FileType::SOCK:
        return "SOCK";
    case FileType::UNDEF:
        return "UNDEF";
    default:
        return "UNDEF";
    }
}

int FileSystem::_RemoveAllFiles(const char *path)
{
    DIR* dir = opendir(path);

    if (dir != nullptr)
    {
        dirent* entry;
        while ((entry = readdir(dir)) != nullptr)
        {
            bool currentDir = (strcmp(entry->d_name, ".") == 0) ? true : false;
            bool parentDir = (strcmp(entry->d_name, "..") == 0) ? true : false;
            std::string fullPath = std::string(path) + "/" + std::string(entry->d_name);

            FileType fileType = _GetFileType(fullPath.c_str());
            if (fileType == FileType::REG) {
                int result = unlink(fullPath.c_str());
                if (result != 0) {
                    closedir(dir);
                    return result;
                }
            }

            if (!currentDir && !parentDir && (fileType == FileType::DIR)) {
                int result = _RemoveAllFiles(fullPath.c_str());
                if (result != 0) {
                    closedir(dir);
                    return result;
                }
            }
        }
    }

    closedir(dir);
    return 0;
}

int FileSystem::_RemoveAllDirs(const char *path)
{
    DirTree _dirTree;
    _BuildDirTree(path, _dirTree);

    for(auto& path : _dirTree) {
        int result = rmdir(path.c_str());
        if (result != 0) {
            return result;
        }
    }

    //deprecated coding
//    for(std::set<std::string>::iterator path = _dirTree.begin(); path != _dirTree.end(); ++path) {
//        int result = rmdir(path->c_str());
//        if (result != 0) {
//            return result;
//        }
//    }

    return 0;
}

void FileSystem::_BuildDirTree(const char *path, DirTreeRef dirTree)
{
    DIR* dir = opendir(path);

    if (dir != nullptr) {
        dirent* entry;
        while ((entry = readdir(dir)) != nullptr)
        {
            bool currentDir = (strcmp(entry->d_name, ".") == 0) ? true : false;
            bool parentDir = (strcmp(entry->d_name, "..") == 0) ? true : false;
            std::string fullPath = std::string(path) + "/" + std::string(entry->d_name);

            FileType fileType = _GetFileType(fullPath.c_str());
            if (!currentDir && !parentDir && (fileType == FileType::DIR)) {
                dirTree.insert(fullPath);
                _BuildDirTree(fullPath.c_str(), dirTree);
            }
        }
    }
    closedir(dir);
}
