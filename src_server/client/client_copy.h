//
// Created by viktor on 26.02.23.
//

#ifndef SERVER_CLIENT_COPY_H
#define SERVER_CLIENT_COPY_H
#include "common/fileSys.h"
#include "common/json_worker.h"

#define ___key "FnK0b6VH1htWjMZ41Feg2i2VwwteUuum"

#include "src_server/additional/common_server.h"

class OneClient
{
public:
    explicit OneClient(string& _uuid);
    // ~OneClient();

    Json GetFileJson(const File& file);

    void Init();

    void StartUploadFile(const File &file, const string &secret, const string &parents_hash, size_t file_size = 0);
    void WriteChunkToUploadFile(uint8_t *data, size_t offset, size_t size = 0);
    bool EndUploadFile(const File &file, const std::string &secret, const std::string &parents_hash,
                     size_t file_size);

    void StartDownloadFile(std::filesystem::path file_path);
    void WriteChunkToDownloadFile(ClientConnection &conn, int offset, int size);
    void EndDownloadFile();

    void SaveFile(const File& file, const string& secret, const string& parents_hash);

    void RemoveFile(const File& file);

    void RenameFile(const File& file_old, const File& file_new);

    bool CheckPermision(const File& file, const string& secret);

    std::string GetPathToFile(const File& file);

    void LoadUserFileSystem(std::string machine_id);
    void UnloadUserFileSystem() const;

    void SetMachineId(const std::string &machine_id);

    vector<string> GetCurrentUserAvailableMachineIDs();

    ClientConnection m_connInfo;
    ClientConnection m_connData;

    std::vector<ClientConnection> m_allDataConnections;

    vector<uint8_t> m_binData;
    FileMap m_files;

    string m_userName;
    string m_userPass;
    string m_userPath;
    string m_uuid;
    string m_aesKey;
    string m_machineId;

    std::filesystem::path m_vfs_file;
    std::filesystem::path m_vfs_mount_point;

    std::mutex m_mutex;

    std::mutex m_fileDownloadMutex;
    FILE *m_currentDownloadFile = nullptr;
private:
    std::mutex m_fileUploadMutex;
    FILE *m_currentUploadFile = nullptr;
    int m_fileSize;
    std::atomic_int32_t m_fileWritten;

    File_ptr m_currentParent;
    std::filesystem::path m_currentPath;
};

#endif //SERVER_CLIENT_COPY_H
