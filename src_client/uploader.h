#ifndef UPLOADER_H
#define UPLOADER_H
#include "common/fileSys.h"
#include "settings.h"
#include "SettingsManager.h"

#include <any>
#include <atomic>
#include <filesystem>
#include <future>
#include <list>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

void UpdateAndRender(int posx, int posy, int width, int height);

class WebsocketClient;

struct FunctionResult
{
    enum OperationType
    {
        HttpDownload,
        SftpDownload,

        HttpUpload,
        // EncryptFiles,
        SftpUpload,

        DecrypeFiles,
    } operation;
    bool              success;
    std::stringstream result;
};


class FileUploader
{
public:
    FileUploader();
    ~FileUploader();

    void RunClient();

    FunctionResult DownloadRequest(FileMap _list = FileMap(), const std::string& pass = "");
    FunctionResult UploadRequest(FileMap _list = FileMap(), const std::string& pass = "");
    FunctionResult DeleteRequest(FileMap _list = FileMap(), const std::string& pass = "");
    FunctionResult RenameRequest(std::pair<std::string, File> old, std::pair<std::string, File> file, const std::string& pass = "");

    void SetStyles();

    void ShowWindow(int posx, int posy, int width, int height);

    void Update();

    void UpdateUploadedFilesInfo(std::string data);
    void UpdateAvailableMachines(std::string data);

    typedef std::function<void (const File& file, std::string)> FileClaback;

    void FileSaved(const File& file, std::string meta);
    void FileRemoved(const File& file, std::string meta);
    void FileSent(const File& file, std::string meta);
    void FileUploaded(const File& file, std::string meta);
    void FileReseive(const File& file, std::string meta);
    void FileError(const File& file, std::string meta);

    static size_t files_to_upload_amount;
    static size_t uploaded_files_amount;

    bool StartPingServer();

    void GetServerStatus();

    void SetServerStatus(const std::string &status);

    std::filesystem::path GetBackupFolder();

    // TODO Change _get_server_status for atomic
    void ChangeServerStatus(int status);
    int CheckServerStatus();

    std::shared_ptr<SettingsManager> GetLoginManager() const;

    std::string GetEncodingPass();

    enum LoginStatus {
        NO_LOGIN = 0,
        INPUT_TEXT_LOGIN,
        REGISTRATION_LOGIN,
        FILE_LOGIN
    };
    LoginStatus GetStatus() const;
    void SetLoginStatus(LoginStatus status);

    void SomeoneLoggedIn(const std::string &user_name);

    void OpenCustomPopupWithMessage(const std::string &message);

    bool LoginAfterRegistration() const;
    void Login();
private:

    std::unordered_map<void*, FileClaback*>
        _loaded_calbacks,
        _removed_calbacks,
        _sended_calbacks,
        _uploaded_callbacks,
        _reseive_callbacks,
        _error_callbacks;


#define __GEN__CONTENT__(name)\
void name##_Head();\
void name##_Left();\
void name##_Right()

    __GEN__CONTENT__(None);
    __GEN__CONTENT__(Gov);
    __GEN__CONTENT__(Backup);
    __GEN__CONTENT__(Local);
    __GEN__CONTENT__(Archive);
    __GEN__CONTENT__(Restore);

#undef __GEN__CONTENT__

    void SetLoadProgress(std::string archive_name, float);

    // config

    Settings settings_;


    FileMap _archivedFilesInfo;
    FileMap _localFilesInfo;
    std::vector<std::string> _availableMachines;
    size_t _selected_machine = 0;

    WebsocketClient* client;

    int _update_file_list_status = 0, _get_server_status = 0;
    std::mutex _status_mutex;

    std::string _server_status;
    bool _stop_ping;
    std::thread _ping_server_thread;

    std::filesystem::path _backup_path;
    std::shared_ptr<SettingsManager> _login_manager;
    LoginStatus _login_status;

    bool _logged_in = false;

    static constexpr int _buf_size = 256;
    char _register_login_buf[_buf_size]{};
    char _register_password_buf[_buf_size]{};
    char _register_confirm_password_buf[_buf_size]{};
    bool login_after_reg = false;

    bool _open_custom_popup = false;
    std::string _custom_popup_message;
};

#endif /* UPLOADER_H */
