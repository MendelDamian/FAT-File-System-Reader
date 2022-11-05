#ifndef FILE_READER_H
#define FILE_READER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

typedef struct disk_t
{
    FILE *f;
    int32_t sectors;  // 1 sector = 512 bytes.
} DISK;

typedef struct volume_t
{
    int x;
} VOLUME;

typedef struct file_t
{
    int x;
} FILE2;

typedef struct dir_t
{
    int x;
} DIR;

typedef struct dir_entry_t
{
    char name[32];
} DIR_ENTRY;

DISK* disk_open_from_file(const char* volume_file_name);
int disk_read(DISK* pdisk, int32_t first_sector, void* buffer, int32_t sectors_to_read);

int disk_close(DISK* pdisk);
VOLUME* fat_open(DISK* pdisk, uint32_t first_sector);
int fat_close(VOLUME* pvolume);

FILE2* file_open(VOLUME* pvolume, const char* file_name);
int file_close(FILE2* stream);

size_t file_read(void *ptr, size_t size, size_t nmemb, FILE2* stream);
int32_t file_seek(FILE2* stream, int32_t offset, int whence);

DIR* dir_open(VOLUME* pvolume, const char* dir_path);
int dir_read(DIR* pdir, DIR_ENTRY* pentry);
int dir_close(DIR* pdir);

#endif //FILE_READER_H
