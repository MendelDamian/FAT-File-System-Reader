#include "file_reader.h"
#include "tested_declarations.h"
#include "rdebug.h"

DISK* disk_open_from_file(const char* volume_file_name)
{
    (void)volume_file_name;
    return NULL;
}

int disk_read(DISK* pdisk, int32_t first_sector, void* buffer, int32_t sectors_to_read)
{
    (void)pdisk;
    (void)first_sector;
    (void)buffer;
    (void)sectors_to_read;
    return 0;
}

int disk_close(DISK* pdisk)
{
    (void)pdisk;
    return 0;
}

VOLUME* fat_open(DISK* pdisk, uint32_t first_sector)
{
    (void)pdisk;
    (void)first_sector;
    return NULL;
}

int fat_close(VOLUME* pvolume)
{
    (void)pvolume;
    return 0;
}

FILE2* file_open(VOLUME* pvolume, const char* file_name)
{
    (void)pvolume;
    (void)file_name;
    return NULL;
}

int file_close(FILE2* stream)
{
    (void)stream;
    return 0;
}

size_t file_read(void *ptr, size_t size, size_t nmemb, FILE2* stream)
{
    (void)ptr;
    (void)size;
    (void)nmemb;
    (void)stream;
    return 0;
}

int32_t file_seek(FILE2* stream, int32_t offset, int whence)
{
    (void)stream;
    (void)offset;
    (void)whence;
    return 0;
}

DIR* dir_open(VOLUME* pvolume, const char* dir_path)
{
    (void)pvolume;
    (void)dir_path;
    return NULL;
}

int dir_read(DIR* pdir, DIR_ENTRY* pentry)
{
    (void)pdir;
    (void)pentry;
    return 0;
}

int dir_close(DIR* pdir)
{
    (void)pdir;
    return 0;
}

