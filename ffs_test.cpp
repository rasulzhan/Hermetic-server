#include "bitmap.h"
#include "disk.h"
#include "ffs_operations.h"
#include "tree.h"

#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

// macros for backward compatibility
#define openDisk(x) openDisk(x, 0)

char *path_to_mount;
int   diskfd;

static struct fuse_operations ffs_operations = {
    .getattr = ffs_getattr,
    //.readlink = ffs_readlink,
    .mknod = ffs_mknod,
    .mkdir = ffs_mkdir,
    .unlink = ffs_unlink,
    .rmdir = ffs_rmdir,
    //.symlink	= ffs_symlink,
    .rename = ffs_rename,
    //.link	    = ffs_link,
    .chmod = ffs_chmod,
    .chown = ffs_chown,
    .truncate = ffs_truncate,
    .utime = ffs_utimens,
    .open = ffs_open,
    .read = ffs_read,
    .write = ffs_write,
    //.statfs	    = ffs_statfs,
    .flush = ffs_flush,
    //.release	= ffs_release,
    //.fsync	    = ffs_fsync,
    //.setxattr	= ffs_setxattr,
    //.getxattr	= ffs_getxattr,
    //.listxattr	= ffs_listxattr,
    //.removexattr = ffs_removexattr,
    //.opendir	= ffs_opendir,
    .readdir = ffs_readdir, /*
//.releasedir	= ffs_releasedir,
//.fsyncdir	= ffs_fsyncdir,
.init	    = ffs_init,
.destroy	= ffs_destroy,
.access	    = ffs_access,
.create	    = ffs_create,
.ftruncate	= ffs_ftruncate,
.fgetattr	= ffs_fgetattr,
//.lock	    = ffs_lock,*/
                            /*.bmap	    = ffs_bmap,
                            //.ioctl	    = ffs_ioctl,
                            //.poll	    = ffs_poll,
                            //.write_buf	= ffs_write_buf,
                            //.read_buf	= ffs_read_buf,
                            //.flock	    = ffs_flock,
                            //.fallocate	= ffs_fallocate,*/
};

int
mkfs(const char *path_to_storage)
{
    init_fs();                           // Creates root directory

    uint64_t i, size = 1 * 1024 * 1024;  // 1 MB
    int      fd = open(path_to_storage, O_CREAT | O_TRUNC | O_RDWR, 0666);
    diskfd = fd;

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
    close(fd);
    printf("Done!\n");
    return 0;
}

#include <string>
#include <thread>
struct user
{
    user(std::string name): name(name)
    {
        mount_point = "~/mount/name";
        mkfs(name.c_str());

        diskfd = openDisk((char *)name.c_str());
    };
    std::string name;
    std::string mount_point;

    int diskfd;
    struct fuse_session *se;
};

int
main(int argc, char **argv)
{
    // user user1("user1");
    // user user2("user2");

    // std::thread t([]() {

    // });

    mkfs(argv[argc - 1]);
    diskfd = openDisk(argv[argc - 1]);
    init_fs();



    
    // load_fs(diskfd);
    return fuse_main(argc - 1, argv, &ffs_operations);

    // fuse_unmount();
}
