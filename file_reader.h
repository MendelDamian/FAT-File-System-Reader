#ifndef FILE_READER_H
#define FILE_READER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

typedef struct extended_section_t
{
    uint8_t drive_number;
    uint8_t windows_nt_flags;
    uint8_t signature;
    uint32_t volume_id;
    char volume_label[11];
    char file_system_type[8];
} EXTENDED_SECTION;

typedef struct disk_t
{
    FILE *file;
    char oem_name[8];
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t reserved_sector_count;
    uint8_t table_count;
    uint16_t root_entry_count;
    uint16_t total_sectors_16;
    uint8_t media_type;
    uint16_t table_size_16;
    uint16_t sectors_per_track;
    uint16_t head_side_count;
    uint32_t hidden_sector_count;
    uint32_t large_sectors_32;
    EXTENDED_SECTION extended_section;
} DISK;

typedef struct volume_t
{
    DISK *disk;
    uint32_t root_dir_start;
    uint32_t data_start;
} VOLUME;

typedef struct file_t
{
    VOLUME *volume;
    uint8_t type;
    uint8_t count_secondary_entries;
    uint16_t checksum;
    uint16_t attributes;
    uint16_t reserved1;
    uint32_t creation;
    uint32_t last_write;
    uint32_t last_access;
    uint8_t creation_time_ms;
    uint8_t last_write_time_ms;
    uint8_t offset_creation_time;
    uint8_t offset_last_write_time;
    uint8_t offset_last_access_time;
    uint8_t reserved2[7];
} FILE2;

typedef struct dir_t
{
    VOLUME *volume;
    uint32_t first_cluster;
    uint32_t size;
} DIR;

typedef struct dir_entry_t
{
    char name[11];
    uint8_t attributes;
    uint8_t reserved_windows_nt;
    uint8_t creation_time_tenths;
    uint16_t creation_time;
    uint16_t creation_date;
    uint16_t last_access_date;
    uint16_t first_cluster_high;
    uint16_t last_write_time;
    uint16_t last_write_date;
    uint16_t first_cluster_low;
    uint32_t size;
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
