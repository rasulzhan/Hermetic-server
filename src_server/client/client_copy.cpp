//
// Created by viktor on 26.02.23.
//
#include "client_copy.h"
#include <algorithm>
#include <sstream>
#include <filesystem>
#include <cassert>

OneClient::OneClient(string& _uuid){
    m_uuid = _uuid;
    m_userName = "";
}

std::string OneClient::GetPathToFile(const File& file)
{
    auto f_ptr = FindFileInFileMap(&m_files, file);
    if(f_ptr == nullptr)
        return "";
    std::string path_from_file = std::filesystem::current_path().string();
    path_from_file.append("/");
    path_from_file.append(m_userPath);
    if (path_from_file.back() != '/') {
        path_from_file.push_back('/');
    }
    WLI << "GetPathToFile " << f_ptr->path << std::endl;
    WLI << "f_ptr->GetParentsHashs() " << f_ptr->GetParentsHashs() << std::endl;
    if (std::filesystem::exists(path_from_file + f_ptr->GetParentsHashs())) {
	path_from_file.append(f_ptr->GetParentsHashs());
        if (path_from_file.back() != '/') {
            path_from_file.push_back('/');
        }
    }
    //path_from_file.append(f_ptr->GetParentsHashs());
    path_from_file.append(f_ptr->hash);
    return path_from_file;
}

Json OneClient::GetFileJson(const File& file)
{
    std::string path_from_file = GetPathToFile(file) + ".data";

    if(std::filesystem::exists(path_from_file)) {

        std::string current_secret;
        std::ifstream reader(path_from_file, std::ios::in);
        std::ostringstream sstr;
        sstr << reader.rdbuf();
        Json newJson = JsonWorker::Deserialize(sstr.str());
        reader.close();
        return newJson;
    }
    else
        return JsonWorker::CreateJsonObject();
}

void
OneClient::Init()
{
    std::cout << "Init : " << m_userName << std::endl;
    FileMap     temp;
    std::string tmp = "mount/" + m_machineId + "/";
    WLI << "Init() mounting path is " << tmp << std::endl;
    AddFileToFileMap(&temp, std::filesystem::path(tmp), false, true);  // true, true);
    WLI << "tetmp after addfiletofilemap" << std::endl;
    if (!temp.empty()) {
        for (auto el: temp.begin()->second->map) {
            WLI << "name " << el.first << std::endl;
            for (const auto &[k, v]: el.second->map) {
                WLI << "subname " << k << std::endl;
            }
            m_files[el.first] = el.second;
        }
    }
    for (auto el: m_files) {
        el.second->parent = nullptr;
    }
}

void
OneClient::StartUploadFile(const File &file, const std::string &secret, const std::string &parents_hash,
                     size_t file_size)
{
    std::cout << "enter StartUploadFile m_userName is " << m_userName << std::endl;
    if(m_userName.size() == 0)
        return;

    char key[] = ___key;

    std::filesystem::path file_path = file.path;
    std::filesystem::path file_parent_path = file.path; // example path: c:\\users\\username\\documents\\files\\1\\2\\file.txt
    file_parent_path = file_parent_path.parent_path(); // c:\\users\\username\\documents\\files\\1\\2

    std::filesystem::path t_userPath = m_userPath;
                                                            //             files/ 1 /2
    std::filesystem::path parents_hash_path{parents_hash}; // example hash: 123/456/789/
    // NOTE(Sedenkov): hash is ending with extra directory delimeter
    parents_hash_path = parents_hash_path.parent_path();
    // std::filesystem::path parents_and_file_hash{parents_hash};
    // parents_and_file_hash /= file.hash; // 123/456/789/abc
    const int depth = std::distance(parents_hash_path.begin(), parents_hash_path.end()); // 3 for example hash
    File_ptr parent = nullptr;

    auto create_directory_if_not_exists = [](std::filesystem::path &path, File_ptr parent) {
        if (!std::filesystem::exists(path)) {
            std::filesystem::create_directory(path);
            std::ofstream datasavestream(path.string() + ".data", std::ios::out);
            Json          newJson = JsonWorker::CreateJsonObject();

            JsonWorker::AddToJsonVal(newJson, "link", parent->path);
            JsonWorker::AddToJsonVal(newJson, "hash", parent->hash);
            JsonWorker::AddToJsonVal(newJson, "datatime", parent->formatTime);
            JsonWorker::AddToJsonVal(newJson, "status", parent->status);
            JsonWorker::AddToJsonVal(newJson, "type", parent->type);
            JsonWorker::AddToJsonVal(newJson, "secret", "");

            auto str = JsonWorker::Serialize(newJson);
            datasavestream.write(reinterpret_cast<const char *>(str.data()), (int)str.size());
            datasavestream.close();
        }
    };

    auto origin_path_it = file_parent_path.end();
    std::advance(origin_path_it, -depth); // c:\\users\\username\\documents\\files
    WLI << "before for loop" << std::endl;
    for (auto hash_it = parents_hash_path.begin(); hash_it != parents_hash_path.end();
         ++hash_it, ++origin_path_it) {
        auto &one = *hash_it;
        WLI << "before if" << std::endl;
        if (one == *parents_hash_path.begin()) {
            WLI << "if true" << std::endl;
            auto iter = m_files.find(one.string());
            if (iter != std::end(m_files)) {
                WLI << "another if true" << std::endl;
                parent = iter->second;
            } else {
                WLI << "another if false" << std::endl;
                File    *t_new_file = new File(origin_path_it->string(), hash_it->string(),
                                               FILE_OK | FILE_LOCALE, FileType::FILE_TYPE_DIR,
                                               std::filesystem::file_time_type(), FileMap(), nullptr);
                File_ptr n_file = File_ptr(t_new_file);
                m_files[one.string()] = parent = n_file;
            }
        } else {
            WLI << "if false" << std::endl;
            auto iter = parent->map.find(one.string());
            if (iter != std::end(m_files)) {
                WLI << "if false true" << std::endl;
                parent = iter->second;
            } else {
                WLI << "if false false" << std::endl;
                File_ptr n_file = File_ptr(new File(
                    origin_path_it->string(), hash_it->string(), FILE_OK | FILE_LOCALE,
                    FileType::FILE_TYPE_DIR, std::filesystem::file_time_type(), FileMap(), parent));
                parent->map[one.string()] = n_file;
                parent = n_file;
            }
        }

        std::filesystem::path new_dir = t_userPath;
        new_dir /= one;
        WLI << "after ifs" << std::endl;
        create_directory_if_not_exists(new_dir, parent);
        WLI << "after create_directory_if_not_exists" << std::endl;
        t_userPath = new_dir;
    }
    m_currentParent = parent;

    auto r = t_userPath / file.hash;
    m_currentPath = r;
    WLI << "before m_currentUploadFile = fopen(r.string().c_str(), \"wb\");" << std::endl;
    m_currentUploadFile = fopen(r.string().c_str(), "wb");
    WLI << "after fopen" << std::endl;
    // TODO(Sedenkov): error handling
    if(m_currentUploadFile != nullptr)
    {
        fseek(m_currentUploadFile, 0, SEEK_END);
        off_t file_length = ftell(m_currentUploadFile);
        if(file_length < file_size)
        {
            m_fileSize = file_length;
            m_fileWritten = 0;
            WLI << "fseek file length is less than requesed filesize" << std::endl;
            std::cout << "Upload file " << file_size << "/" << m_fileSize << std::endl;

            return;
        }
        fseek(m_currentUploadFile, file_size, SEEK_SET);
        WLI << "after fseek" << std::endl;
        std::cout << "Upload file " << file_size << std::endl;
        // fputc('\0', m_currentUploadFile);
    }
    m_fileSize = file_size;
    m_fileWritten = 0;
}

void OneClient::WriteChunkToUploadFile(uint8_t *data, size_t offset, size_t size)
{
    std::lock_guard<std::mutex> client_lock(m_fileUploadMutex);
    std::cout << "enter WriteChunkToUploadFile" << std::endl;
    char key[] = ___key;
    //assert(m_currentUploadFile);
    if (m_currentUploadFile == nullptr) {
        std::cout << "assert(m_currentUploadFile)" << std::endl;
        m_currentUploadFile = fopen(m_currentPath.string().c_str(), "wb");

    }

    const size_t chunk_size = 64 * 1024;
    size_t current_written_size = 0;

    std::vector<uint8_t> enc_data(chunk_size);
    std::vector<uint8_t> dec_data(chunk_size);
    std::cout << "Write to upload file " << offset << "-- " << size << std::endl;
    while (current_written_size < size) {
        size_t bytes_to_copy = std::min(chunk_size, size - current_written_size);
        std::memcpy(enc_data.data(), data + current_written_size, bytes_to_copy);
        // decrypt
        // TODO(Sedenkov): tag check
        Decryption decrypt {
            reinterpret_cast<unsigned char *>(m_uuid.data()),
            (int)m_uuid.size(),
            (unsigned char *)m_aesKey.data(),
            const_cast<unsigned char *>(example_aes_iv),
            0, 0
        };
        Encryption encrypt {
             reinterpret_cast<unsigned char *>(m_uuid.data()), (int)m_uuid.size(),
                  reinterpret_cast<unsigned char *>(key),
                  const_cast<unsigned char *>(example_aes_iv)
        };

        // TODO(Sedenkov): something wrong with this decryption, fix it
        decrypt.DecryptNextBlock(dec_data.data(), bytes_to_copy, enc_data.data());
        decrypt.FinishDecryption(dec_data.data(), 0);

        encrypt.EncyptNextBlock(dec_data.data(), bytes_to_copy, enc_data.data());

        unsigned char tag2[EVP_GCM_TLS_TAG_LEN];
        encrypt.FinishEncryption(enc_data.data(), tag2);

        // write to file
        {
            std::lock_guard<std::mutex> client_lock(m_fileUploadMutex);
            if(m_currentUploadFile) {
                fseek(m_currentUploadFile, offset + current_written_size, SEEK_SET);
                fwrite(enc_data.data(), 1, bytes_to_copy, m_currentUploadFile);
                fflush(m_currentUploadFile);
            }
        }

        current_written_size += bytes_to_copy;
        m_fileWritten += bytes_to_copy;
    }
}

bool OneClient::EndUploadFile(const File &file, const std::string &secret, const std::string &parents_hash,
                     size_t file_size)
{
    std::cout << "End Upload File" << std::endl;
    if (m_fileWritten < m_fileSize) {
        WLI << "m_fileWritten < m_fileSize" << std::endl;
        return false;
    }
    {
        WLI << "before fclose" << std::endl;
        std::lock_guard<std::mutex> client_lock(m_fileUploadMutex);
        fclose(m_currentUploadFile);
        WLI << "after fclose" << std::endl;
    }

#ifdef __linux__
    chmod(m_currentPath.string().c_str(), 0660);
#endif

    std::ofstream datasavestream(m_currentPath.string() + ".data", std::ios::out);
    Json newJson = JsonWorker::CreateJsonObject();

    JsonWorker::AddToJsonVal(newJson, "link", file.path);
    JsonWorker::AddToJsonVal(newJson, "hash", file.hash);
    JsonWorker::AddToJsonVal(newJson, "datatime", file.formatTime);
    JsonWorker::AddToJsonVal(newJson, "status", file.status);
    JsonWorker::AddToJsonVal(newJson, "type", file.type);
    JsonWorker::AddToJsonVal(newJson, "secret", secret);

    auto nfile = File_ptr(new File(file));

    if(secret.size() > 0)
        nfile->status |= FILE_ENCRYPTED;
    auto str = JsonWorker::Serialize(newJson);
    //std::cout << "sonWorker::Serialize : " << str << std::endl;
    datasavestream.write(reinterpret_cast<const char*>(str.data()), (int)str.size());
    datasavestream.close();

    if(parents_hash.size() == 0)
    {
        m_files[nfile->hash] = nfile;
    }
    else
    {
        m_currentParent->map[nfile->hash] = nfile;
    }

    return true;
}

void OneClient:: StartDownloadFile(std::filesystem::path file_path)
{
    int iter_numb = 0, iter_limit = 1000;
    while (m_fileWritten < m_fileSize && iter_numb < iter_limit) {
        WLI << "wait for some reason" << std::endl;
	iter_numb++;
        // NOTE(Sedenkov): just wait for this.0
    }
    if (m_currentDownloadFile) {
        fclose(m_currentDownloadFile);
    }

    m_currentDownloadFile = fopen(file_path.string().c_str(), "rb");
}

// NOTE(Sedenkov): Maybe we can just send the offset and size of the whole block only once, and then
// for each connection just read on arrival of the binary data
void OneClient::WriteChunkToDownloadFile(ClientConnection &conn, int offset, int size)
{
#if 0
        /* send binary data of file */
        std::ifstream input(path_from_file, std::ios::binary );
        vector<uint8_t> m_data(std::istreambuf_iterator<char>(input), {});

        auto * decryptedtext = new unsigned char [m_data.size()];
        auto * encryptedtext = new unsigned char [m_data.size()];
        std::size_t ciphertext_len;

        Decrypt(client, m_data.data(), decryptedtext, (int)m_data.size(), key);

        /* Buffer for the decrypted text */

        /* encrypt data */
        Encrypt(client, decryptedtext, encryptedtext, (int)m_data.size(), client->m_aesKey.data());
        ciphertext_len = (int)m_data.size();

        /* sending data */
        size_t mess_size = 1024, pointer = 0, curLen;
        while (pointer != ciphertext_len) {
            curLen = std::min(mess_size, ciphertext_len - pointer);
            sendMessageData(client->m_connData, encryptedtext + pointer, curLen);
            pointer += curLen;
            //float ans = (float)pointer/(float)ciphertext_len;
            //setUploadFileProgress(ans*100);
        }

        delete[] encryptedtext;

        /* send info about the end of sending the file */
        sendMessageData(client->m_connData, EServerMessageType::FILE_RECEIVED, options);
#endif
}


void OneClient::SaveFile(const File& file, const string& secret, const string& parents_hash)
{
    char key[] = ___key;
    if(m_userName.size() == 0)
        return;

    string full_path = parents_hash + file.hash;
    //std::cout << "Save start" << std::endl;
    auto * decryptedtext = new unsigned char [m_binData.size()];
    auto * encryptedtext = new unsigned char [m_binData.size()];
    std::size_t ciphertext_len;
    //std::cout << "Save alloc buff" << std::endl;

    ::decrypt(m_binData.data(), (int)m_binData.size(),
              reinterpret_cast<unsigned char *>(m_uuid.data()), (int)m_uuid.size(),
              example_aes_tag,
              reinterpret_cast<unsigned char *>(m_aesKey.data()),
              const_cast<unsigned char *>(example_aes_iv), decryptedtext);

    ::encrypt(decryptedtext, (int)m_binData.size(),
                            reinterpret_cast<unsigned char *>(m_uuid.data()), (int)m_uuid.size(),
                            reinterpret_cast<unsigned char *>(key),
                            const_cast<unsigned char *>(example_aes_iv), encryptedtext, example_aes_tag);
    //std::cout << "Save decrypt encrypt" << std::endl;

    std::filesystem::path path_p(full_path);
    std::filesystem::path link_p(file.path);

    vector<string> split_path;
    split_path.push_back("");
    for(int i = 0; i < full_path.size(); i++)
    {
        if(full_path[i] == '\\' || full_path[i] == '/')
        {
            //std::cout << split_path.back() << std::endl;
            split_path.push_back("");
        }
        else
        {
            split_path.back() += full_path[i];
        }
    }
    vector<string> split_link;
    split_link.push_back("");
    for(int i = 0; i < file.path.size(); i++)
    {
        if(file.path[i] == '\\' || file.path[i] == '/')
        {
            //std::cout << split_link.back() << std::endl;
            split_link.push_back("");
        }
        else
        {
            split_link.back() += file.path[i];
        }
    }
    for(int i = 1; i < split_link.size(); i++)
        split_link[i] = split_link[i - 1] + (split_link[i].back() != '\\' && split_link[i - 1].back() != '\\' ? "\\" : "") + split_link[i];

    string filename = split_path.back();
    split_path.pop_back();
    split_link.pop_back();
    string t_userPath = m_userPath;
    File_ptr parent = nullptr;
    for (int i = 0, p_size = split_path.size(), l_size = split_link.size(); i < p_size; i++) {
        auto &one = split_path[i];
        std::cout << "create folder " << one.c_str() << std::endl;

        if (i == 0) { // folders in root of the user
            auto iter = m_files.find(one);
            std::cout << "Add to m_files" << std::endl;

            if (iter != std::end(m_files)) {
                std::cout << "Add exist" << std::endl;
                parent = iter->second;
            } else {
                std::cout << "Add new" << std::endl;
                File *t_new_file = new File(split_link[i - p_size + l_size], split_path[i], 9,
                                            FileType::FILE_TYPE_DIR,
                                            std::filesystem::file_time_type(), FileMap(), nullptr);
                std::cout << "Add new 2" << std::endl;
                File_ptr n_file = File_ptr(t_new_file);
                std::cout << "End Create new" << std::endl;
                m_files[one] = parent = n_file;
            }
            std::cout << "End add to m_files" << std::endl;

        } else {
            std::cout << "Add to map" << std::endl;
            auto iter = parent->map.find(one);
            if (iter != std::end(m_files))
                parent = iter->second;
            else {
                File_ptr n_file = File_ptr(new File(
                    split_link[i - p_size + l_size], split_path[i], 9, FileType::FILE_TYPE_DIR,
                    std::filesystem::file_time_type(), FileMap(), parent));
                parent->map[one] = n_file;
                parent = n_file;
            }
            std::cout << "End add to map" << std::endl;
        }
        string newDir = t_userPath + "/" + one;
        if (!std::filesystem::exists(newDir)) {
            std::filesystem::create_directory(newDir);
            std::ofstream datasavestream(newDir + ".data", std::ios::out);
            Json          newJson = JsonWorker::CreateJsonObject();

            JsonWorker::AddToJsonVal(newJson, "link", parent->path);
            JsonWorker::AddToJsonVal(newJson, "hash", parent->hash);
            JsonWorker::AddToJsonVal(newJson, "datatime", parent->formatTime);
            JsonWorker::AddToJsonVal(newJson, "status", parent->status);
            JsonWorker::AddToJsonVal(newJson, "type", parent->type);
            JsonWorker::AddToJsonVal(newJson, "secret", "");

            auto str = JsonWorker::Serialize(newJson);
            datasavestream.write(reinterpret_cast<const char *>(str.data()), (int)str.size());
            datasavestream.close();
        }
        t_userPath = newDir;
    }

    std::ofstream savestream(t_userPath + "/" + filename, std::ios::out | std::ios::binary);
    savestream.write(reinterpret_cast<const char*>(encryptedtext), (int)m_binData.size());
    savestream.close();
    m_binData.clear();

#ifdef __linux__
    chmod((t_userPath + "/" + filename).c_str(), 0660);
#endif

    std::ofstream datasavestream(t_userPath + "/" + filename + ".data", std::ios::out);
    Json newJson = JsonWorker::CreateJsonObject();

    JsonWorker::AddToJsonVal(newJson, "link", file.path);
    JsonWorker::AddToJsonVal(newJson, "hash", file.hash);
    JsonWorker::AddToJsonVal(newJson, "datatime", file.formatTime);
    JsonWorker::AddToJsonVal(newJson, "status", file.status);
    JsonWorker::AddToJsonVal(newJson, "type", file.type);
    JsonWorker::AddToJsonVal(newJson, "secret", secret);

    auto nfile = File_ptr(new File(file));

    if(secret.size() > 0)
        nfile->status |= FILE_ENCRYPTED;
    auto str = JsonWorker::Serialize(newJson);
    //std::cout << "sonWorker::Serialize : " << str << std::endl;
    datasavestream.write(reinterpret_cast<const char*>(str.data()), (int)str.size());
    datasavestream.close();

    if(split_path.size() == 0)
    {
        m_files[nfile->hash] = nfile;
    }
    else
    {
        parent->map[nfile->hash] = nfile;
    }

}

bool OneClient::CheckPermision(const File& file, const string& secret)
{
    std::string path_from_file = GetPathToFile(file) + ".data";

    if(std::filesystem::exists(path_from_file)) {

        Json newJson = GetFileJson(file);

        auto current_secret = JsonWorker::FindStringVal(newJson, "secret");

        return current_secret == secret;
    }
    else
        return secret.size() == 0;
}

void OneClient::RemoveFile(const File& file)
{
    std::string path_from_file = GetPathToFile(file);
    if(m_userName.size() == 0)
        return;
    if(std::filesystem::exists(path_from_file))
        std::remove(path_from_file.data());

    if(std::filesystem::exists(path_from_file + ".data"))
        std::remove((path_from_file + ".data").c_str());

    // TODO
    //m_files.erase(std::remove(m_files.begin(), m_files.end(), str_path));
}

void OneClient::RenameFile(const File& file_old, const File& file_new)
{
    /// TODO
    /// rework it
    ///

    return;
}

static std::mutex vfs_mutex;

#include "ffs_operations.h"
#include "disk.h"

// Error logging for THIS MODULE, helps differentiate from logging of other modules
// Prints errors and logging info to STDOUT
// Passes format strings and args to vprintf, basically a wrapper for printf
static void
error_log(char *fmt, ...)
{
#ifdef ERR_FLAG
    va_list args;
    va_start(args, fmt);

    printf("DISK : ");
    vprintf(fmt, args);
    printf("\n");

    va_end(args);
#endif
}

int
mkfs(const char *path_to_storage)
{
    init_fs();                           // Creates root directory

    uint64_t i, size = 1 * 1024 * 1024;  // 1 MB
    int      fd = open(path_to_storage, O_CREAT | O_TRUNC | O_RDWR, 0666);

    uint8_t to_write = 0;
    for (i = 0; i < size; i++) {
        write(fd, &to_write, sizeof(to_write));
    }
    printf("%s\n", "Done creating! Writing superblock and metadata!");

    // Write size of disk to superblock
    lseek(fd, 0, SEEK_SET);
    write(fd, &size, sizeof(size));
    error_log("Wrote size %lu to file\n", size);

    // Calculate size of BITMAP in bits
    uint64_t bsize = size / BLOCK_SIZE;
    // Size of BITMAP in bytes
    bsize /= 8;
    bmap_size = bsize;
    error_log("bsize %lu to file\n", bsize);

    // Write number of blocks taken by bitmap in superblock
    lseek(fd, sizeof(size), SEEK_SET);
    write(fd, &bsize, sizeof(bsize));
    error_log("Wrote bsize %lu to file\n", bsize);

    // Blocks needed by BITMAP, to be marked as 1 in bitmap
    uint64_t bmap_blocks = bsize / BLOCK_SIZE;
    bmap_blocks++;

    // First (bmap_blocks) need to marked with 1 in BITMAP
    error_log("Marking first %lu blocks\n", bmap_blocks + SUPERBLOCKS);

    bitmap = (uint8_t *)calloc(bsize, BLOCK_SIZE);
    if (!bitmap) {
        perror("No memory for bitmap");
        exit(0);
    }
    for (i = 0; i < bmap_blocks + SUPERBLOCKS; i++)
        setBitofMap(i);

    error_log("Done marking!\n");

    void    *buf;
    uint64_t firstFreeBlock = findFirstFreeBlock();
    error_log("First free block = %lu\n", firstFreeBlock);
    error_log("Constructing block for root node!\n");

    fs_tree_node *root = node_exists("/");
    root->inode_no = firstFreeBlock;

    constructBlock(root, &buf);  // Create block for root node
    error_log("Done constructing block for root node!\n");
    output_node(*root);

    writeBlock(firstFreeBlock, buf);
    error_log("Done writing block for root node!\n");

    setBitofMap(firstFreeBlock);
    error_log("Writing bitmap to file\n");
    for (i = 0; i < bmap_blocks; i++) {
        writeBlock(SUPERBLOCKS + i, bitmap + (i * BLOCK_SIZE));
    }

    error_log("Freeing, closing, end!\n");
    free(buf);
    free(bitmap);
    bitmap = nullptr;
    buf = nullptr;
    close(fd);
    printf("Done!\n");
    return 0;
}

static struct fuse_operations ffs_operations = {
    .getattr = ffs_getattr,
    .mknod = ffs_mknod,
    .mkdir = ffs_mkdir,
    .unlink = ffs_unlink,
    .rmdir = ffs_rmdir,
    .rename = ffs_rename,
    .chmod = ffs_chmod,
    .chown = ffs_chown,
    .truncate = ffs_truncate,
    .utime = ffs_utimens,
    .open = ffs_open,
    .read = ffs_read,
    .write = ffs_write,
    .flush = ffs_flush,
    .readdir = ffs_readdir,
};

std::filesystem::path mount_dir = "./mount";

// NOTE(Sedenkov): it global variable for ffs library
int diskfd;
// NOTE(Sedenkov): there is possible case when one machine is used by different users
// will be conflict
void
OneClient::LoadUserFileSystem(std::string machine_id)
{
    // std::lock_guard<std::mutex> l(vfs_mutex);
    std::filesystem::path machine_vfs_file = m_userPath + machine_id;
    // int                   diskfd = 0;
    {
        std::lock_guard<std::mutex> l(vfs_mutex);
        try {
        if (!std::filesystem::exists(machine_vfs_file)) {
            mkfs(machine_vfs_file.string().c_str());
            diskfd = openDisk((char *)machine_vfs_file.string().c_str(), 0);

            init_fs();
        } else {
            diskfd = openDisk((char *)machine_vfs_file.string().c_str(), 0);
            {
                //std::lock_guard<std::mutex> l(vfs_mutex);
                load_fs(diskfd);
            }
        }

        std::filesystem::path mount_point(mount_dir);
        mount_point /= machine_id;
        m_userPath = mount_point.string();
        std::filesystem::create_directory(mount_point);
    std::thread t([=]{
        char program_name[] = "";
        char foreground_option[] = "-f";
        char mount_point_optoin[256];
        std::strncpy(mount_point_optoin, mount_point.string().c_str(), 255);

        char *argv[] = {&program_name[0], &foreground_option[0], &mount_point_optoin[0], NULL};
        int   argc = (int)(sizeof(argv) / sizeof(argv[0])) - 1;

        return fuse_main(argc, argv, &ffs_operations);
        // return fuse_main(argc, argv, &hello_oper, NULL);
    });
    t.detach();

    close(diskfd);
        }catch(std::filesystem::filesystem_error &ex)
        {
            std::cerr << "Filesystem error!!!" << std::endl;
        }
    }
}

void OneClient::UnloadUserFileSystem() const
{
    if(!m_userPath.empty())
        fuse_unmount(m_userPath.c_str());
}

void OneClient::SetMachineId(const std::string &machine_id) {
    UnloadUserFileSystem();
    m_machineId = machine_id;
    LoadUserFileSystem(machine_id);
}

vector<string>
OneClient::GetCurrentUserAvailableMachineIDs()
{
    vector<string> result;
    if (!m_userName.empty()) {
        std::string users_volumes = "files/" + m_userName;
        for (auto const &dir_entry: std::filesystem::directory_iterator{users_volumes}) {
            result.push_back(dir_entry.path().filename().string());
        }
    }
    return result;
}
