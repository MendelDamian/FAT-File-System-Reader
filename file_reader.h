#ifndef FILE_READER_H
#define FILE_READER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>

typedef struct time_t time_t;
typedef struct date_t date_t;
typedef struct bootsector_t bootsector_t;
typedef struct clusters_chain_t clusters_chain_t;
typedef struct volume_t volume_t;
typedef struct disk_t disk_t;
typedef struct dir_t dir_t;
typedef struct file_t file_t;
typedef struct dir_entry_t dir_entry_t;
typedef struct dir_entry_data_t dir_entry_data_t;

typedef enum fat_type_t
{
    FAT12, FAT16, FAT32
} fat_type_t;

struct time_t
{
    uint16_t second: 5;
    uint16_t minute: 6;
    uint16_t hour: 5;
} __attribute__((packed));

struct date_t
{
    uint16_t day: 5;
    uint16_t month: 4;
    uint16_t year: 7;
} __attribute__((packed));

struct bootsector_t
{
    // Assembly code instructions to jump to boot code (mandatory in bootable partition)
    uint8_t bootjmp[3];
    // OEM name in ASCII
    char oem_name[8];
    // Bytes per sector (512, 1024, 2048, or 4096)
    uint16_t bytes_per_sector;
    // Sectors per cluster (Must be a power of 2 and cluster size must be <=32 KB)
    uint8_t sectors_per_cluster;
    // Size of reserved area, in sectors
    uint16_t reserved_sector_count;
    // Number of FATs (usually 2)
    uint8_t table_count;
    // Maximum number of files in the root directory (FAT12/16; 0 for FAT32)
    uint16_t root_entry_count;
    // Number of sectors in the file system; if 2 B is not large enough, set to 0 and use 4 B value in bytes 32-35 below
    uint16_t total_sectors_16;
    // Media type (0xf0=removable disk, 0xf8=fixed disk)
    uint8_t media_type;
    // Size of each FAT, in sectors, for FAT12/16; 0 for FAT32
    uint16_t table_size_16;
    // Sectors per track in storage device
    uint16_t sectors_per_track;
    // Number of heads in storage device
    uint16_t head_side_count;
    // Number of sectors before the start partition
    uint32_t hidden_sector_count;
    // Number of sectors in the file system; this field will be 0 if the 2B field above (bytes 19-20) is non-zero
    uint32_t total_sectors_32;
    // BIOS INT 13h (low level disk services) drive number
    uint8_t drive_number;
    // Not used
    uint8_t reserved;
    // Extended boot signature to validate next three fields (0x29)
    uint8_t boot_signature;
    // Volume serial number
    uint32_t volume_id;
    // Volume label, in ASCII
    char volume_label[11];
    // File system type level, in ASCII. (Generally "FAT", "FAT12", or "FAT16")
    char file_system[8];
    // Not used
    uint8_t boot_code[448];
    // Signature value (0xaa55)
    uint16_t signature;
}__attribute__((packed));

struct clusters_chain_t
{
    uint16_t *clusters;
    size_t size;
};

struct volume_t
{
    disk_t *disk;
    bootsector_t bs;
    fat_type_t fat_type;
    void *fat_table;
    uint32_t root_dir_sectors;
    int32_t first_data_sector;
    int32_t first_root_dir_sector;
    uint32_t cluster_size;
};

struct disk_t
{
    FILE *file;
    size_t size;
};

struct dir_entry_t
{
    char name[13];
    size_t size;
    bool is_archived;
    bool is_readonly;
    bool is_volume_label;
    bool is_system;
    bool is_hidden;
    bool is_directory;
    date_t creation_date;
    time_t creation_time;
    int32_t first_cluster;
};

struct dir_t
{
    dir_t *parent_dir;
    volume_t *volume;
    dir_entry_t entry;
    int32_t current_entry;
    int32_t sector_count;
};

struct file_t
{
    dir_t *parent_dir;
    dir_entry_t entry;
    clusters_chain_t *clusters_chain;
    int32_t position;
};

struct dir_entry_data_t
{
    char filename[11];
    uint8_t attributes;
    uint8_t reserved_windows_NT;
    uint8_t creation_time_tenths;
    time_t creation_time;
    date_t creation_date;
    date_t last_access_date;
    uint16_t first_cluster_high;
    time_t last_write_time;
    date_t last_write_date;
    uint16_t first_cluster_low;
    uint32_t file_size;
} __attribute__((packed));

disk_t *disk_open_from_file(const char *volume_file_name);
int disk_read(disk_t *pdisk, int32_t first_sector, void *buffer, int32_t sectors_to_read);
int disk_close(disk_t *pdisk);

volume_t *fat_open(disk_t *pdisk, uint32_t first_sector);
int fat_close(volume_t *pvolume);

file_t *file_open(volume_t *pvolume, const char *file_name);
size_t file_read(void *ptr, size_t size, size_t nmemb, file_t *stream);
int32_t file_seek(file_t *stream, int32_t offset, int whence);
int file_close(file_t *stream);

dir_t *dir_open(volume_t *pvolume, const char *dir_path);
int dir_read(dir_t *pdir, dir_entry_t *pentry);
int dir_close(dir_t *pdir);

clusters_chain_t *get_clusters_chain(volume_t *pvolume, uint16_t first_cluster);
clusters_chain_t *get_clusters_chain_fat16(const void *buffer, size_t size, uint16_t first_cluster);
clusters_chain_t *get_clusters_chain_fat12(const void *buffer, size_t size, uint16_t first_cluster);

#endif //FILE_READER_H
