TODO:
[] Осталось часть старого кода, надо немного почистить
[] Загрузить файлы с сервера можно только после перезапуска. Проблема скорее всего со списком файлов m_files в client_copy
Проблема с restore с ключом шифрования файлов  

## Archive and restore
Each section in ImGui is displayed in FileUploader::ShowWindow. Archive and restore are implemented in functions
Archive_Head and Restore_Head. They are called from FileUploader::ShowWindow using macros.

## Usage of application:
0. Register new user or Login
1. Login
2. In menu button "Selection" chose "Monitored folders"
3. Select some files to upload with "Add folder to select" or "Add files to select"
4. In menu button "Actions" chose "Archive". And client will upload files to server and DELETE them from your computer
5. After archiving is finished, you can restore uploaded files
6. To restore in "Actions" tap "Restore"

## Status update
Launches in separate thread in FileUploader::StartPingServer() and pings server

## Login 
client                                                                             server
1 close existing WebsocketClient if opened FileUploader::Login()
2 create new WebsocketClient and connect to server FileUploader::RunClient() --->  3. open connection WebsocketServer::onOpenInfo
5 Get password hash and username from input texts                             <--- 4. EServerMessageType::USER_REG_STEP_1
6 EClientMessageType::MERGE_SOCKETS_STEP_1 --->                                    7. Check credentials and load user filesystem client->LoadUserFileSystem
9 Display that client is online                                               <--- 8. EServerMessageType::USER_REG_STEP_2
10 EClientMessageType::MERGE_SOCKETS_STEP_2 --->                                   11. add new connection to list

## Registration
client                                              server
1 EClientMessageType::REGISTER_NEW_USER --->        2. check new user
4 Display message box if registration failed    <---3. EServerMessageType::USER_CREATED_FAILED or EServerMessageType::USER_CREATED_SUCCEED

## Change machine
client                                                  server
1 chose mac address of machine from combobox, hit Apply 
2 EClientMessageType::SET_MACHINE_ID --->               3 reload user filesystem with new machine

## Download file from the server message diagram
client                                              server

1. EClientMessageType::START_RECEIVE_FILE --->          2. open file
4. open file, divide by block,                    <---  3. EServerMessageType::START_RECEIVE_FILE
5. EClientMessageType::DOWNLOAD_FILE_BLOCK --->         6. decrypt, encrypt chunks
8. decrypt and write to the file                   <----7. EServerMessageType::FILE_CHUNK_INFO
9. EClientMessageType::END_FILE_DOWNLOAD --->          10. close file
12. Save info about file                          <--- 11.EServerMessageType::FILE_RECEIVED

На шаге 8 запоминается сколько байтов от файла было обработанно: g_DownloadedFileSize == g_FileFullSize

## Upload file from the server message diagram

client                                              server
1 EClientMessageType::START_SEND_BIG_FILE --->         2. open file (method OneClient::StartUploadFile)
4 Open File, divide it on blocks                  <--- 3. EServerMessageType::FILE_INFO_RECEIVED send back to client confirmation that file info received
5 Encrypt file chunks and send them
6 EClientMessageType::FILE_CHUNK_INFO --->             7. accept chunk, decrypt, encrypt and write to file on server (method OneClient::WriteChunkToUploadFile)
7.5 update uploading progress                           7.5 TODO add here step as message back to the client that chunk is received and written
8 EClientMessageType::END_SEND_BIG_FILE --->           9. wait until all chunks at step 7 are processed
10 Sleep for 1 second                             <--- 11. If not ready EServerMessageType::FILE_UPLOADING
12 Send again EClientMessageType::END_SEND_BIG_FILE    13. Check if file is done
14 Postprocess and moving to the next file        <--- 15. EServerMessageType::FILE_SENT
