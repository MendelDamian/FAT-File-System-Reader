#include "fat_reader.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#define FAT12_END_VALUE 0xFF8
#define FAT16_END_VALUE 0xFFF8

CLUSTERS_CHAIN_T *get_clusters_chain(VOLUME_T *pvolume, uint16_t first_cluster);

typedef uint16_t(*get_next_cluster_fn_t)(const void *buffer, size_t size, uint16_t cluster);

size_t min(size_t a, size_t b)
{
    return a < b ? a : b;
}

int32_t get_cluster_first_sector(VOLUME_T *volume, uint16_t cluster)
{
    return ((cluster - 2) * volume->bs.sectors_per_cluster) + volume->first_data_sector;
}

int compare_filenames(const DIR_ENTRY_T *entry, const char *prefix)
{
    return strcasecmp(entry->has_long_name ? entry->long_name : entry->name, prefix);
}

char *get_filename(const char *path)
{
    char *slash = strrchr(path, '/');
    if (slash == NULL)
    {
        slash = strrchr(path, '\\');
    }

    return slash == NULL ? (char *)path : slash + 1;
}

DISK_T *disk_open_from_file(const char *volume_file_name)
{
    if (volume_file_name == NULL)
    {
        errno = EFAULT;
        return NULL;
    }

    FILE *file = fopen(volume_file_name, "rb");
    if (file == NULL)
    {
        errno = ENOENT;
        return NULL;
    }

    DISK_T *disk = calloc(1, sizeof(DISK_T));
    if (disk == NULL)
    {
        errno = ENOMEM;
        fclose(file);
        return NULL;
    }

    disk->file = file;
    fseek(file, 0, SEEK_END);
    disk->size = ftell(file);
    fseek(file, 0, SEEK_SET);

    return disk;
}

int disk_read(DISK_T *pdisk, int32_t first_sector, void *buffer, int32_t sectors_to_read)
{
    if (pdisk == NULL || buffer == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    if (first_sector < 0 || sectors_to_read < 0 || first_sector + sectors_to_read > (int32_t)pdisk->size / 512)
    {
        errno = ERANGE;
        return -1;
    }

    fseek(pdisk->file, first_sector * 512, SEEK_SET);
    if (fread(buffer, 512, sectors_to_read, pdisk->file) != (size_t)sectors_to_read)
    {
        errno = ERANGE;
        return -1;
    }

    return sectors_to_read;
}

int disk_close(DISK_T *pdisk)
{
    if (pdisk == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    fclose(pdisk->file);
    free(pdisk);
    return 0;
}

VOLUME_T *fat_open(DISK_T *pdisk, uint32_t first_sector)
{
    if (pdisk == NULL)
    {
        errno = EFAULT;
        return NULL;
    }

    VOLUME_T *volume = calloc(1, sizeof(VOLUME_T));
    if (volume == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }

    volume->disk = pdisk;
    if (disk_read(pdisk, (int32_t)first_sector, &volume->bs, 1) != 1)
    {
        free(volume);
        errno = EINVAL;
        return NULL;
    }

    BOOTSECTOR_T *bs = &volume->bs;
    if (bs->signature != 0xAA55)
    {
        errno = EINVAL;
        free(volume);
        return NULL;
    }

    // set FAT_TYPE
    if (bs->total_sectors_16 == 0)
    {
        volume->fat_type = FAT32;
    }
    else if (bs->total_sectors_32 == 0)
    {
        volume->fat_type = FAT16;
    }
    else
    {
        volume->fat_type = FAT12;
    }

    // We don't care about FAT32.
    if (volume->fat_type == FAT32)
    {
        free(volume);
        errno = EINVAL;
        return NULL;
    }

    volume->fat_table = calloc(bs->table_size_16, bs->bytes_per_sector);
    if (volume->fat_table == NULL)
    {
        free(volume);
        errno = ENOMEM;
        return NULL;
    }

    int result = disk_read(pdisk, bs->reserved_sector_count, volume->fat_table, bs->table_size_16);
    if (result != bs->table_size_16)
    {
        free(volume->fat_table);
        free(volume);
        errno = EINVAL;
        return NULL;
    }

    volume->root_dir_sectors = ((bs->root_entry_count * 32) + (bs->bytes_per_sector - 1)) / bs->bytes_per_sector;
    volume->first_data_sector = bs->reserved_sector_count + (bs->table_count * bs->table_size_16) + (int32_t)volume->root_dir_sectors;
    volume->first_root_dir_sector = volume->first_data_sector - (int32_t)volume->root_dir_sectors;
    volume->cluster_size = bs->bytes_per_sector * bs->sectors_per_cluster;

    return volume;
}

int fat_close(VOLUME_T *pvolume)
{
    if (pvolume == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    if (pvolume->root_dir)
    {
        dir_close(pvolume->root_dir);
    }

    free(pvolume->fat_table);
    free(pvolume);
    return 0;
}

FILE_T *file_open(VOLUME_T *pvolume, const char *file_name)
{
    if (pvolume == NULL)
    {
        errno = EFAULT;
        return NULL;
    }

    if (file_name == NULL)
    {
        errno = ENOENT;
        return NULL;
    }

    FILE_T *file = calloc(1, sizeof(FILE_T));
    if (file == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }

    char *name = get_filename(file_name);
    strcpy(file->entry.name, name);

    char *dir_path = strndup(file_name, name - file_name);
    if (dir_path == NULL)
    {
        free(file);
        errno = ENOMEM;
        return NULL;
    }

    DIR_T *dir = dir_open(pvolume, dir_path);
    if (dir == NULL)
    {
        free(file);
        return NULL;
    }

    file->dir = dir;

    dir->current_entry = 0;
    while (dir_read(dir, &file->entry) == 0)
    {
        if (compare_filenames(&file->entry, name) == 0)
        {
            if (file->entry.is_directory || file->entry.is_volume_label)
            {
                continue;
            }

            // Load clusters chain.
            file->clusters_chain = get_clusters_chain(pvolume, file->entry.first_cluster);
            if (file->clusters_chain == NULL)
            {
                dir_close(dir);
                free(file);
                return NULL;
            }

            return file;
        }
    }

    if (dir != pvolume->root_dir)
    {
        dir_close(dir);
    }

    errno = ENOENT;
    return NULL;
}

int file_close(FILE_T *stream)
{
    if (stream == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    // Since root directory belongs to the volume, we don't free it.
    if (stream->dir && stream->dir != stream->dir->volume->root_dir)
    {
        dir_close(stream->dir);
    }
    free(stream->clusters_chain);
    free(stream);
    return 0;
}

size_t file_read(void *ptr, size_t size, size_t nmemb, FILE_T *stream)
{
    if (ptr == NULL || stream == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    if (size == 0 || nmemb == 0)
    {
        return 0;
    }

    uint32_t cluster_size = stream->dir->volume->cluster_size;
    int32_t sectors_per_cluster = (int32_t)stream->dir->volume->bs.sectors_per_cluster;

    void *buffer = malloc(cluster_size);
    if (buffer == NULL)
    {
        errno = ENOMEM;
        return 0;
    }

    size_t bytes_read = 0;

    while (bytes_read < size * nmemb && stream->position < (int32_t)stream->entry.size)
    {
        uint16_t current_cluster = stream->clusters_chain->clusters[stream->position /
                                                                    stream->dir->volume->cluster_size];
        if (current_cluster == 0)
        {
            break;
        }

        int32_t sector = get_cluster_first_sector(stream->dir->volume, current_cluster);

        if (disk_read(stream->dir->volume->disk, sector, buffer, sectors_per_cluster) != sectors_per_cluster)
        {
            errno = ERANGE;
            break;
        }

        size_t offset = stream->position % cluster_size;
        size_t remaining_bytes = cluster_size - offset;
        size_t bytes_to_copy = min(remaining_bytes, size * nmemb - bytes_read);
        bytes_to_copy = min(bytes_to_copy, stream->entry.size - stream->position);
        memcpy((uint8_t *)ptr + bytes_read, (uint8_t *)buffer + offset, bytes_to_copy);

        bytes_read += bytes_to_copy;
        file_seek(stream, (int32_t)bytes_to_copy, SEEK_CUR);
    }

    free(buffer);
    return bytes_read / size;
}

int32_t file_seek(FILE_T *stream, int32_t offset, int whence)
{
    if (stream == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    int32_t new_position;

    switch (whence)
    {
        case SEEK_SET:
            new_position = offset;
            break;

        case SEEK_CUR:
            new_position = stream->position + offset;
            break;

        case SEEK_END:
            new_position = (int32_t)stream->entry.size + offset;
            break;

        default:
            errno = EINVAL;
            return -1;
    }

    if (new_position < 0 || new_position > (int32_t)stream->entry.size)
    {
        errno = ENXIO;
        return -1;
    }

    stream->position = new_position;
    return stream->position;
}

void init_root(VOLUME_T *pvolume)
{
    if (pvolume->root_dir)
    {
        return;
    }

    pvolume->root_dir = calloc(1, sizeof(DIR_T));
    if (pvolume->root_dir == NULL)
    {
        errno = ENOMEM;
        return;
    }

    pvolume->root_dir->volume = pvolume;
    pvolume->root_dir->entry.first_cluster = pvolume->first_root_dir_sector;
    pvolume->root_dir->entry.name[0] = '\\';
    pvolume->root_dir->entry.is_directory = true;
}

bool is_root_path(const char *path)
{
    return strcmp(path, "\\") == 0 || strcmp(path, "/") == 0 || strcmp(path, "") == 0;
}

DIR_T *find_sub_directory(DIR_T *parent, const char *name)
{
    DIR_T *dir = calloc(1, sizeof(DIR_T));
    if (dir == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }

    dir->volume = parent->volume;

    parent->current_entry = 0;
    while (dir_read(parent, &dir->entry) == 0)
    {
        if (compare_filenames(&dir->entry, name) == 0)
        {
            if (!dir->entry.is_directory)
            {
                dir_close(dir);
                errno = ENOTDIR;
                return NULL;
            }
            break;
        }
    }
    if (dir->entry.name[0] == '\0')
    {
        dir_close(dir);
        errno = ENOENT;
        return NULL;
    }

    dir->clusters_chain = get_clusters_chain(dir->volume, dir->entry.first_cluster);
    if (dir->clusters_chain == NULL)
    {
        dir_close(dir);
        return NULL;
    }

    // It's a root directory, which has no clusters chain
    if (dir->clusters_chain->clusters[0] == 0)
    {
        dir_close(dir);
        dir = parent->volume->root_dir;
    }

    return dir;
}

int handle_dir_name(const char *name)
{
    if (strcmp(name, ".") == 0)
    {
        return 0;
    }

    if (strcmp(name, "..") == 0)
    {
        return 1;
    }

    return 2;
}

char *extract_dir_name(const char *dir_path, char **end)
{
    while (*dir_path == '\\' || *dir_path == '/')
    {
        dir_path++;
    }

    *end = strchr(dir_path, '\\');
    if (*end == NULL)
    {
        *end = strchr(dir_path, '/');
    }

    if (*end == NULL && *dir_path == '\0')
    {
        return NULL;
    }

    if (*end == NULL)
    {
        *end = strchr(dir_path, '\0');
    }

    char *dir_name = strndup(dir_path, *end - dir_path);
    if (dir_name == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }

    return dir_name;
}

DIR_T *dir_open(VOLUME_T *pvolume, const char *dir_path)
{
    if (pvolume == NULL || dir_path == NULL)
    {
        errno = EFAULT;
        return NULL;
    }

    init_root(pvolume);
    if (pvolume->root_dir == NULL)
    {
        return NULL;
    }

    if (is_root_path(dir_path))
    {
        return pvolume->root_dir;
    }

    DIR_T *current_dir = pvolume->root_dir;

    char *end = NULL;
    char *dir_name = extract_dir_name(dir_path, &end);

    while (dir_name)
    {
        switch (handle_dir_name(dir_name)) {
            case 0: // case "."
                break;

            case 1: // case ".."
                current_dir = find_sub_directory(current_dir, dir_name);
                if (current_dir == NULL)
                {
                    current_dir = pvolume->root_dir;
                }
                break;

            default: // case other
                current_dir = find_sub_directory(current_dir, dir_name);
                if (current_dir == NULL)
                {
                    free(dir_name);
                    return NULL;
                }
        }

        free(dir_name);
        dir_name = extract_dir_name(end, &end);
    }
    return current_dir;
}

int dir_read_entry(DIR_T *pdir, DIR_ENTRY_DATA_T *entry_data)
{
    if (pdir == NULL || entry_data == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    memset(entry_data, 0, sizeof(DIR_ENTRY_DATA_T));
    int32_t sector_size = pdir->volume->bs.bytes_per_sector;

    int32_t sector_to_read;
    if (pdir == pdir->volume->root_dir)
    {
        sector_to_read = pdir->entry.first_cluster + pdir->current_entry * (int32_t)sizeof(DIR_ENTRY_DATA_T) / sector_size;
    }
    else
    {
        size_t cluster_idx = pdir->current_entry * sizeof(DIR_ENTRY_DATA_T) / pdir->volume->cluster_size;
        if (cluster_idx >= pdir->clusters_chain->size)
        {
            return 1;
        }

        uint16_t current_cluster = pdir->clusters_chain->clusters[cluster_idx];
        if (current_cluster == 0)
        {
            return 1;
        }

        int32_t sector_idx = (int32_t)(pdir->current_entry * sizeof(DIR_ENTRY_DATA_T) % pdir->volume->cluster_size) / sector_size;
        sector_to_read = get_cluster_first_sector(pdir->volume, current_cluster) + sector_idx;
    }

    void *buffer = calloc(1, sector_size);
    if (buffer == NULL)
    {
        return -1;
    }

    int result = disk_read(pdir->volume->disk, sector_to_read, buffer, 1);
    if (result != 1)
    {
        free(buffer);
        return -1;
    }

    *entry_data = *((DIR_ENTRY_DATA_T *)buffer + (pdir->current_entry++) % (sector_size / sizeof(DIR_ENTRY_DATA_T)));
    free(buffer);
    return 0;
}

int dir_read(DIR_T *pdir, DIR_ENTRY_T *pentry)
{
    if (pdir == NULL || pentry == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    memset(pentry, 0, sizeof(DIR_ENTRY_T));

    DIR_ENTRY_DATA_T entry_data;
    int result = dir_read_entry(pdir, &entry_data);
    if (result != 0)
    {
        return result;
    }

    if ((uint8_t)entry_data.filename[0] == 0x00)
    {
        return 1;
    }

    if ((uint8_t)entry_data.filename[0] == 0xe5)
    {
        return dir_read(pdir, pentry);
    }

    // Check if 8.3 entry or LFN
    if ((entry_data.attributes & 0x0F) == 0x0F)
    {
        // LFN
        pentry->has_long_name = true;

        do
        {
            LFN_T lfn = *((LFN_T *)&entry_data);

            int seq_num = lfn.sequence_number & 0x3F;  // remove 0x40.

            for (int i = 0; i < 5; i++)
            {
                pentry->long_name[(seq_num - 1) * 13 + i] = (char)lfn.name1[i];
            }

            for (int i = 0; i < 6; i++)
            {
                pentry->long_name[(seq_num - 1) * 13 + i + 5] = (char)lfn.name2[i];
            }

            for (int i = 0; i < 2; i++)
            {
                pentry->long_name[(seq_num - 1) * 13 + i + 11] = (char)lfn.name3[i];
            }

            result = dir_read_entry(pdir, &entry_data);
            if (result != 0)
            {
                return result;
            }

        } while ((entry_data.attributes & 0x0F) == 0x0F);
    }

    // 8.3 entry
    pdir->entry.long_name[0] = '\0';

    int i;
    for (i = 0; i < 8; i++) {
        if (entry_data.filename[i] == ' ') {
            break;
        }
        pentry->name[i] = entry_data.filename[i];
    }
    if (entry_data.filename[8] != ' ')
    {
        pentry->name[i++] = '.';
        for (int j = 8; j < 11; j++)
        {
            if (entry_data.filename[j] == ' ')
            {
                break;
            }
            pentry->name[i++] = entry_data.filename[j];
        }
    }

    pentry->size = entry_data.file_size;
    pentry->is_readonly = entry_data.attributes & 0x01;
    pentry->is_hidden = entry_data.attributes & 0x02;
    pentry->is_system = entry_data.attributes & 0x04;
    pentry->is_volume_label = entry_data.attributes & 0x08;
    pentry->is_directory = entry_data.attributes & 0x10;
    pentry->is_archived = entry_data.attributes & 0x20;
    pentry->creation_date = entry_data.creation_date;
    pentry->creation_time = entry_data.creation_time;
    pentry->last_access_date = entry_data.last_access_date;
    pentry->last_write_date = entry_data.last_write_date;
    pentry->last_write_time = entry_data.last_write_time;
    pentry->first_cluster = entry_data.first_cluster_low;

    if (pentry->is_volume_label)
    {
        memcpy(pdir->volume->label, pentry->name, 11);
        return dir_read(pdir, pentry);
    }
    return 0;
}

int dir_close(DIR_T *pdir)
{
    if (pdir == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    if (pdir->clusters_chain)
    {
        free(pdir->clusters_chain->clusters);
        free(pdir->clusters_chain);
    }

    if (pdir == pdir->volume->root_dir)
    {
        pdir->volume->root_dir = NULL;
    }

    free(pdir);
    return 0;
}

uint16_t get_next_cluster_fat12(const void *buffer, size_t size, uint16_t cluster)
{
    if (buffer == NULL)
    {
        errno = EFAULT;
        return 0;
    }
    uint8_t *FAT_table = (uint8_t *)buffer;
    uint16_t ent_offset = (cluster + (cluster / 2)) % size;
    uint16_t table_value = *(uint16_t *)&FAT_table[ent_offset];
    if (cluster & 1)
    {
        table_value = table_value >> 4;
    }
    else
    {
        table_value = table_value & 0x0FFF;
    }
    return table_value;
}

uint16_t get_next_cluster_fat16(const void *buffer, size_t size, uint16_t cluster)
{
    if (buffer == NULL)
    {
        errno = EFAULT;
        return 0;
    }
    uint8_t *FAT_table = (uint8_t *)buffer;
    uint16_t ent_offset = (cluster * 2) % size;
    return *(uint16_t *)&FAT_table[ent_offset];
}

CLUSTERS_CHAIN_T *get_clusters_chain(VOLUME_T *pvolume, uint16_t first_cluster)
{
    if (pvolume == NULL)
    {
        errno = EFAULT;
        return NULL;
    }

    get_next_cluster_fn_t get_next_cluster_fn;
    uint16_t end_cluster;

    switch(pvolume->fat_type)
    {
        case FAT12:
            get_next_cluster_fn = &get_next_cluster_fat12;
            end_cluster = FAT12_END_VALUE;
            break;

        case FAT16:
            get_next_cluster_fn = &get_next_cluster_fat16;
            end_cluster = FAT16_END_VALUE;
            break;

        default:
            errno = EINVAL;
            return NULL;
    }

    size_t fat_table_size = pvolume->bs.table_size_16 * pvolume->bs.bytes_per_sector;
    CLUSTERS_CHAIN_T *chain = calloc(1, sizeof(CLUSTERS_CHAIN_T));
    if (chain == NULL)
    {
        return NULL;
    }

    chain->clusters = malloc(sizeof(uint16_t));
    if (chain->clusters == NULL)
    {
        free(chain);
        return NULL;
    }

    chain->clusters[0] = first_cluster;
    chain->size = 1;

    uint16_t active_cluster = first_cluster;
    while (1)
    {
        uint16_t table_value = get_next_cluster_fn(pvolume->fat_table, fat_table_size, active_cluster);
        if (table_value >= end_cluster)
        {
            break;
        }

        uint16_t *new_clusters = realloc(chain->clusters, (chain->size + 1) * sizeof(uint16_t));
        if (new_clusters == NULL)
        {
            free(chain->clusters);
            free(chain);
            return NULL;
        }
        chain->clusters = new_clusters;

        chain->clusters[chain->size++] = table_value;
        active_cluster = table_value;
    }

    return chain;
}
