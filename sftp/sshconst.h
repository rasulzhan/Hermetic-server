#ifndef __SSH_CONST_H__
#define __SSH_CONST_H__

#if defined(_WIN64)
#define PRIsize_t "%llu"
#else
#define PRIsize_t "%u"
#endif

#define MAX_SSH_PACKET_LEN 32768

/* SSH Packet Types -- Defined by internet draft */
/* Transport Layer */
#define SSH_MSG_DISCONNECT                          1
#define SSH_MSG_IGNORE                              2
#define SSH_MSG_UNIMPLEMENTED                       3
#define SSH_MSG_DEBUG                               4
#define SSH_MSG_SERVICE_REQUEST                     5
#define SSH_MSG_SERVICE_ACCEPT                      6

#define SSH_MSG_KEXINIT                             20
#define SSH_MSG_NEWKEYS                             21

/* diffie-hellman-group1-sha1 */
#define SSH_MSG_KEXDH_INIT                          30
#define SSH_MSG_KEXDH_REPLY                         31

/* diffie-hellman-group-exchange-sha1 */
#define SSH_MSG_KEX_DH_GEX_REQUEST_OLD              30
#define SSH_MSG_KEX_DH_GEX_REQUEST                  34
#define SSH_MSG_KEX_DH_GEX_GROUP                    31
#define SSH_MSG_KEX_DH_GEX_INIT                     32
#define SSH_MSG_KEX_DH_GEX_REPLY                    33

/* User Authentication */
#define SSH_MSG_USERAUTH_REQUEST                    50
#define SSH_MSG_USERAUTH_FAILURE                    51
#define SSH_MSG_USERAUTH_SUCCESS                    52
#define SSH_MSG_USERAUTH_BANNER                     53

/* "public key" method */
#define SSH_MSG_USERAUTH_PK_OK                      60
/* "password" method */
#define SSH_MSG_USERAUTH_PASSWD_CHANGEREQ           60
/* "keyboard-interactive" method */
#define SSH_MSG_USERAUTH_INFO_REQUEST               60
#define SSH_MSG_USERAUTH_INFO_RESPONSE              61

/* Channels */
#define SSH_MSG_GLOBAL_REQUEST                      80
#define SSH_MSG_REQUEST_SUCCESS                     81
#define SSH_MSG_REQUEST_FAILURE                     82

#define SSH_MSG_CHANNEL_OPEN                        90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION           91
#define SSH_MSG_CHANNEL_OPEN_FAILURE                92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST               93
#define SSH_MSG_CHANNEL_DATA                        94
#define SSH_MSG_CHANNEL_EXTENDED_DATA               95
#define SSH_MSG_CHANNEL_EOF                         96
#define SSH_MSG_CHANNEL_CLOSE                       97
#define SSH_MSG_CHANNEL_REQUEST                     98
#define SSH_MSG_CHANNEL_SUCCESS                     99
#define SSH_MSG_CHANNEL_FAILURE                     100

#define SSH_MSG_INVALID_VALUE                       255

#define SSH_CHANNEL_ERROR_TIMEOUT                   -2

/* Error codes returned in SSH_MSG_CHANNEL_OPEN_FAILURE message
   (see RFC4254) */
#define SSH_OPEN_ADMINISTRATIVELY_PROHIBITED 1
#define SSH_OPEN_CONNECT_FAILED              2
#define SSH_OPEN_UNKNOWN_CHANNELTYPE         3
#define SSH_OPEN_RESOURCE_SHORTAGE           4


// Disconnection error codes
#define SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT             1
#define SSH_DISCONNECT_PROTOCOL_ERROR                          2
#define SSH_DISCONNECT_KEY_EXCHANGE_FAILED                     3
#define SSH_DISCONNECT_RESERVED                                4
#define SSH_DISCONNECT_MAC_ERROR                               5
#define SSH_DISCONNECT_COMPRESSION_ERROR                       6
#define SSH_DISCONNECT_SERVICE_NOT_AVAILABLE                   7
#define SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED          8
#define SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE                 9
#define SSH_DISCONNECT_CONNECTION_LOST                        10
#define SSH_DISCONNECT_BY_APPLICATION                         11
#define SSH_DISCONNECT_TOO_MANY_CONNECTIONS                   12
#define SSH_DISCONNECT_AUTH_CANCELLED_BY_USER                 13
#define SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE         14
#define SSH_DISCONNECT_ILLEGAL_USER_NAME                      15

// SFTP

#define SSH_FXP_INIT                1
#define SSH_FXP_VERSION             2
#define SSH_FXP_OPEN                3
#define SSH_FXP_CLOSE               4
#define SSH_FXP_READ                5
#define SSH_FXP_WRITE               6
#define SSH_FXP_LSTAT               7
#define SSH_FXP_FSTAT               8
#define SSH_FXP_SETSTAT             9
#define SSH_FXP_FSETSTAT           10
#define SSH_FXP_OPENDIR            11
#define SSH_FXP_READDIR            12
#define SSH_FXP_REMOVE             13
#define SSH_FXP_MKDIR              14
#define SSH_FXP_RMDIR              15
#define SSH_FXP_REALPATH           16
#define SSH_FXP_STAT               17
#define SSH_FXP_RENAME             18
#define SSH_FXP_READLINK           19
#define SSH_FXP_LINK               21
#define SSH_FXP_BLOCK              22
#define SSH_FXP_UNBLOCK            23

#define SSH_FXP_STATUS            101
#define SSH_FXP_HANDLE            102
#define SSH_FXP_DATA              103
#define SSH_FXP_NAME              104
#define SSH_FXP_ATTRS             105

#define SSH_FXP_EXTENDED          200
#define SSH_FXP_EXTENDED_REPLY    201

// File atrts
#define SSH_FILEXFER_ATTR_SIZE              0x00000001
#define SSH_FILEXFER_ATTR_PERMISSIONS       0x00000004
#define SSH_FILEXFER_ATTR_ACCESSTIME        0x00000008
#define SSH_FILEXFER_ATTR_CREATETIME        0x00000010
#define SSH_FILEXFER_ATTR_MODIFYTIME        0x00000020
#define SSH_FILEXFER_ATTR_ACL               0x00000040
#define SSH_FILEXFER_ATTR_OWNERGROUP        0x00000080
#define SSH_FILEXFER_ATTR_SUBSECOND_TIMES   0x00000100
#define SSH_FILEXFER_ATTR_BITS              0x00000200
#define SSH_FILEXFER_ATTR_ALLOCATION_SIZE   0x00000400
#define SSH_FILEXFER_ATTR_TEXT_HINT         0x00000800
#define SSH_FILEXFER_ATTR_MIME_TYPE         0x00001000
#define SSH_FILEXFER_ATTR_LINK_COUNT        0x00002000
#define SSH_FILEXFER_ATTR_UNTRANSLATED_NAME 0x00004000
#define SSH_FILEXFER_ATTR_CTIME             0x00008000
#define SSH_FILEXFER_ATTR_EXTENDED          0x80000000

// Type field
#define SSH_FILEXFER_TYPE_REGULAR          1
#define SSH_FILEXFER_TYPE_DIRECTORY        2
#define SSH_FILEXFER_TYPE_SYMLINK          3
#define SSH_FILEXFER_TYPE_SPECIAL          4
#define SSH_FILEXFER_TYPE_UNKNOWN          5
#define SSH_FILEXFER_TYPE_SOCKET           6
#define SSH_FILEXFER_TYPE_CHAR_DEVICE      7
#define SSH_FILEXFER_TYPE_BLOCK_DEVICE     8
#define SSH_FILEXFER_TYPE_FIFO             9

// File permissions
#define S_IRUSR  0000400
#define S_IWUSR  0000200
#define S_IXUSR  0000100
#define S_IRGRP  0000040
#define S_IWGRP  0000020
#define S_IXGRP  0000010
#define S_IROTH  0000004
#define S_IWOTH  0000002
#define S_IXOTH  0000001
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

// Status response
#define SSH_FX_OK                            0
#define SSH_FX_EOF                           1
#define SSH_FX_NO_SUCH_FILE                  2
#define SSH_FX_PERMISSION_DENIED             3
#define SSH_FX_FAILURE                       4
#define SSH_FX_BAD_MESSAGE                   5
#define SSH_FX_NO_CONNECTION                 6
#define SSH_FX_CONNECTION_LOST               7
#define SSH_FX_OP_UNSUPPORTED                8
#define SSH_FX_INVALID_HANDLE                9
#define SSH_FX_NO_SUCH_PATH                  10
#define SSH_FX_FILE_ALREADY_EXISTS           11
#define SSH_FX_WRITE_PROTECT                 12
#define SSH_FX_NO_MEDIA                      13
#define SSH_FX_NO_SPACE_ON_FILESYSTEM        14
#define SSH_FX_QUOTA_EXCEEDED                15
#define SSH_FX_UNKNOWN_PRINCIPAL             16
#define SSH_FX_LOCK_CONFLICT                 17
#define SSH_FX_DIR_NOT_EMPTY                 18
#define SSH_FX_NOT_A_DIRECTORY               19
#define SSH_FX_INVALID_FILENAME              20
#define SSH_FX_LINK_LOOP                     21
#define SSH_FX_CANNOT_DELETE                 22
#define SSH_FX_INVALID_PARAMETER             23
#define SSH_FX_FILE_IS_A_DIRECTORY           24
#define SSH_FX_BYTE_RANGE_LOCK_CONFLICT      25
#define SSH_FX_BYTE_RANGE_LOCK_REFUSED       26
#define SSH_FX_DELETE_PENDING                27
#define SSH_FX_FILE_CORRUPT                  28
#define SSH_FX_OWNER_INVALID                 29
#define SSH_FX_GROUP_INVALID                 30
#define SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK   31

#define SSH_FXF_ACCESS_DISPOSITION          0x00000007
#define SSH_FXF_CREATE_NEW                  0x00000000
#define SSH_FXF_CREATE_TRUNCATE             0x00000001
#define SSH_FXF_OPEN_EXISTING               0x00000002
#define SSH_FXF_OPEN_OR_CREATE              0x00000003
#define SSH_FXF_TRUNCATE_EXISTING           0x00000004
#define SSH_FXF_APPEND_DATA                 0x00000008
#define SSH_FXF_APPEND_DATA_ATOMIC          0x00000010
#define SSH_FXF_TEXT_MODE                   0x00000020
#define SSH_FXF_BLOCK_READ                  0x00000040
#define SSH_FXF_BLOCK_WRITE                 0x00000080
#define SSH_FXF_BLOCK_DELETE                0x00000100
#define SSH_FXF_BLOCK_ADVISORY              0x00000200
#define SSH_FXF_NOFOLLOW                    0x00000400
#define SSH_FXF_DELETE_ON_CLOSE             0x00000800
#define SSH_FXF_ACCESS_AUDIT_ALARM_INFO     0x00001000
#define SSH_FXF_ACCESS_BACKUP               0x00002000
#define SSH_FXF_BACKUP_STREAM               0x00004000
#define SSH_FXF_OVERRIDE_OWNER              0x00008000

// ace mask
#define ACE4_READ_DATA         0x00000001
#define ACE4_LIST_DIRECTORY    0x00000001
#define ACE4_WRITE_DATA        0x00000002
#define ACE4_ADD_FILE          0x00000002
#define ACE4_APPEND_DATA       0x00000004
#define ACE4_ADD_SUBDIRECTORY  0x00000004
#define ACE4_READ_NAMED_ATTRS  0x00000008
#define ACE4_WRITE_NAMED_ATTRS 0x00000010
#define ACE4_EXECUTE           0x00000020
#define ACE4_DELETE_CHILD      0x00000040
#define ACE4_READ_ATTRIBUTES   0x00000080
#define ACE4_WRITE_ATTRIBUTES  0x00000100
#define ACE4_DELETE            0x00010000
#define ACE4_READ_ACL          0x00020000
#define ACE4_WRITE_ACL         0x00040000
#define ACE4_WRITE_OWNER       0x00080000
#define ACE4_SYNCHRONIZE       0x00100000


// attrs
#define O_RDONLY                ACE4_READ_DATA | ACE4_READ_ATTRIBUTES
#define O_WRONLY                ACE4_WRITE_DATA | ACE4_WRITE_ATTRIBUTES
#define O_RDWR                  O_RDONLY | O_WRONLY
#define O_APPEND                ACE4_WRITE_DATA | ACE4_WRITE_ATTRIBUTES | ACE4_APPEND_DATA
                                //flags = SSH_FXF_APPEND_DATA and or SSH_FXF_APPEND_DATA_ATOMIC
#define O_CREAT                 SSH_FXF_OPEN_OR_CREATE
#define O_TRUNC                 SSH_FXF_TRUNCATE_EXISTING


#define SSH_FXF_READ                        0x00000001
#define SSH_FXF_WRITE                       0x00000002
#define SSH_FXF_APPEND                      0x00000004
#define SSH_FXF_CREATE                      0x00000008
#define SSH_FXF_TRUNC                       0x00000010
#define SSH_FXF_EXCL                        0x00000020


// EXTENDED DATA TYPES

#define SSH_EXTENDED_DATA_STDERR    1

/* OpenSSH formatted keys */
#define OPENSSH_AUTH_MAGIC      "openssh-key-v1"
#define OPENSSH_HEADER_BEGIN    "-----BEGIN OPENSSH PRIVATE KEY-----"
#define OPENSSH_HEADER_END      "-----END OPENSSH PRIVATE KEY-----"

#endif // __SSH_CONST_H__
