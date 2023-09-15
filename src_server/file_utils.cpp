#include <filesystem>

#include <fstream>

void
CatFiles(std::filesystem::path dst, const std::vector<std::filesystem::path> &source_files)
{
    std::ofstream cat_file;

    cat_file.open(dst, std::ios_base::binary);

    for (auto &s: source_files) {
    }
}
