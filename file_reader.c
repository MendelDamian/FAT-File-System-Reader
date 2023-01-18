#include "file_reader.h"
#include "tested_declarations.h"
#include "rdebug.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>

size_t min(size_t a, size_t b)
{
    return a < b ? a : b;
}

int32_t get_cluster_first_sector(VOLUME_T *volume, uint16_t cluster)
{
    return ((cluster - 2) * volume->bs.sectors_per_cluster) + volume->first_data_sector;
}

int compare_filenames(const char *str, const char *prefix)
{
    return strncasecmp(str, prefix, strlen(prefix));
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
    volume->first_data_sector = bs->reserved_sector_count + (bs->table_count * bs->table_size_16) + volume->root_dir_sectors;
    volume->first_root_dir_sector = volume->first_data_sector - volume->root_dir_sectors;
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

    file->parent_dir = dir;
    file->parent_dir->volume = pvolume;

    dir->current_entry = 0;
    while (dir_read(dir, &file->entry) == 0)
    {
        if (compare_filenames(file->entry.name, name) == 0)
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
    if (stream->parent_dir && stream->parent_dir != stream->parent_dir->volume->root_dir)
    {
        dir_close(stream->parent_dir);
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

    uint32_t cluster_size = stream->parent_dir->volume->cluster_size;
    int32_t sectors_per_cluster = (int32_t)stream->parent_dir->volume->bs.sectors_per_cluster;

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
                                                                    stream->parent_dir->volume->cluster_size];
        if (current_cluster == 0)
        {
            break;
        }

        int32_t sector = get_cluster_first_sector(stream->parent_dir->volume, current_cluster);

        if (disk_read(stream->parent_dir->volume->disk, sector, buffer, sectors_per_cluster) != sectors_per_cluster)
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

DIR_T *dir_open(VOLUME_T *pvolume, const char *dir_path)
{
    if (pvolume == NULL || dir_path == NULL)
    {
        errno = EFAULT;
        return NULL;
    }

    if (pvolume->root_dir == NULL)
    {
        pvolume->root_dir = calloc(1, sizeof(DIR_T));
        if (pvolume->root_dir == NULL)
        {
            errno = ENOMEM;
            return NULL;
        }

        pvolume->root_dir->volume = pvolume;
        pvolume->root_dir->entry.first_cluster = pvolume->first_root_dir_sector;
        pvolume->root_dir->entry.name[0] = '\\';
        pvolume->root_dir->entry.is_directory = true;
    }

    if (strcmp(dir_path, "\\") == 0 || strcmp(dir_path, "/") == 0 || strcmp(dir_path, "") == 0)
    {
        return pvolume->root_dir;
    }

    DIR_T *parent_dir = pvolume->root_dir;
    while (true)
    {
        if (dir_path[0] == '\\' || dir_path[0] == '/')
        {
            dir_path++;
        }

        char *slash = strchr(dir_path, '\\');
        if (slash == NULL)
        {
            slash = strchr(dir_path, '/');
        }

        if (slash == NULL && dir_path[0] == '\0')
        {
            break;
        }
        else
        {
            slash = slash == NULL ? strchr(dir_path, '\0') : slash;
        }

        char *dir_name = strndup(dir_path, slash - dir_path);
        if (dir_name == NULL)
        {
            errno = ENOMEM;
            return NULL;
        }

        if (strcmp(dir_name, ".") == 0)
        {
            free(dir_name);
            dir_path = slash + 1;
            continue;
        }

        if (strcmp(dir_name, "..") == 0)
        {
            free(dir_name);
            dir_path = slash + 1;
            DIR_T *parent = parent_dir->parent_dir;
            free(parent_dir);
            parent_dir = parent;
            if (parent_dir == NULL)
            {
                parent_dir = pvolume->root_dir;
            }
            continue;
        }

        DIR_T *dir = calloc(1, sizeof(DIR_T));
        if (dir == NULL)
        {
            free(dir_name);
            errno = ENOMEM;
            return NULL;
        }

        dir->volume = pvolume;
        dir->parent_dir = parent_dir;

        parent_dir->current_entry = 0;
        while (dir_read(parent_dir, &dir->entry) == 0)
        {
            if (strcasecmp(dir_name, dir->entry.name) == 0)
            {
                if (!dir->entry.is_directory)
                {
                    free(dir_name);
                    dir_close(dir);
                    errno = ENOTDIR;
                    return NULL;
                }

                break;
            }
        }

        free(dir_name);
        if (dir->entry.name[0] == '\0')
        {

            dir_close(dir);
            errno = ENOENT;
            return NULL;
        }

        dir->clusters_chain = get_clusters_chain(pvolume, dir->entry.first_cluster);
        if (dir->clusters_chain == NULL)
        {
            dir_close(dir);
            return NULL;
        }

        dir_path = slash;
        parent_dir = dir;
    }

    return parent_dir;
}

int root_dir_read(DIR_T *pdir, DIR_ENTRY_T *pentry)
{
    if (pdir == NULL || pentry == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    int32_t secotr_size = pdir->volume->bs.bytes_per_sector;

    memset(pentry, 0, sizeof(DIR_ENTRY_T));

    void *buffer = calloc(1, secotr_size);
    if (buffer == NULL)
    {
        return -1;
    }

    int32_t secotr_to_read = pdir->entry.first_cluster + pdir->current_entry * sizeof(DIR_ENTRY_DATA_T) / secotr_size;

    int result = disk_read(pdir->volume->disk, secotr_to_read, buffer, 1);
    if (result != 1)
    {
        free(buffer);
        return -1;
    }

    DIR_ENTRY_DATA_T entry_data = *((DIR_ENTRY_DATA_T *)buffer + (pdir->current_entry++) % (secotr_size / sizeof(DIR_ENTRY_DATA_T)));
    free(buffer);

    if ((uint8_t)entry_data.filename[0] == 0x00)
    {
        return 1;
    }

    if ((uint8_t)entry_data.filename[0] == 0xe5)
    {
        return dir_read(pdir, pentry);
    }

    int i;
    for (i = 0; i < 8; i++)
    {
        if (entry_data.filename[i] == ' ')
        {
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
    pentry->first_cluster = entry_data.first_cluster_low;
    return 0;
}

int dir_read(DIR_T *pdir, DIR_ENTRY_T *pentry)
{
    if (pdir == NULL || pentry == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    // Root dir.
    if (pdir->parent_dir == NULL)
    {
        return root_dir_read(pdir, pentry);
    }

    // Check if we are at the end of the directory.
    if (pdir->current_entry * sizeof(DIR_ENTRY_DATA_T) >= pdir->clusters_chain->size * pdir->volume->cluster_size)
    {
        return 1;
    }

    memset(pentry, 0, sizeof(DIR_ENTRY_T));

    int32_t secotr_size = pdir->volume->bs.bytes_per_sector;

    void *buffer = calloc(1, secotr_size);
    if (buffer == NULL)
    {
        return -1;
    }

    uint16_t *clusters = pdir->clusters_chain->clusters;

    uint16_t cluster_to_read = clusters[pdir->current_entry * sizeof(DIR_ENTRY_DATA_T) / pdir->volume->cluster_size];
    uint8_t sector_idx = (pdir->current_entry * sizeof(DIR_ENTRY_DATA_T) % pdir->volume->cluster_size) / secotr_size;
    int32_t sector = get_cluster_first_sector(pdir->volume, cluster_to_read) + sector_idx;

    int result = disk_read(pdir->volume->disk, (int32_t)sector, buffer, 1);
    if (result != 1)
    {
        free(buffer);
        return -1;
    }

    DIR_ENTRY_DATA_T entry_data = *((DIR_ENTRY_DATA_T *)buffer + (pdir->current_entry++) % (secotr_size / sizeof(DIR_ENTRY_DATA_T)));
    free(buffer);

    if ((uint8_t)entry_data.filename[0] == 0x00)
    {
        return 1;
    }

    if ((uint8_t)entry_data.filename[0] == 0xe5)
    {
        return dir_read(pdir, pentry);
    }

    int i;
    for (i = 0; i < 8; i++)
    {
        if (entry_data.filename[i] == ' ')
        {
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
    pentry->first_cluster = entry_data.first_cluster_low;

    return 0;
}

int dir_close(DIR_T *pdir)
{
    if (pdir == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    // Since root directory belongs to the volume, we don't free it.
    if (pdir->parent_dir != pdir->volume->root_dir)
    {
        dir_close(pdir->parent_dir);
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

CLUSTERS_CHAIN_T *get_clusters_chain(VOLUME_T *pvolume, uint16_t first_cluster)
{
    if (pvolume == NULL)
    {
        errno = EFAULT;
        return NULL;
    }

    switch (pvolume->fat_type)
    {
        case FAT12:
            return get_clusters_chain_fat12(pvolume->fat_table,
                                            pvolume->bs.table_size_16 * pvolume->bs.bytes_per_sector, first_cluster);

        case FAT16:
            return get_clusters_chain_fat16(pvolume->fat_table,
                                            pvolume->bs.table_size_16 * pvolume->bs.bytes_per_sector, first_cluster);

        default:
            errno = EINVAL;
            return NULL;
    }
}

CLUSTERS_CHAIN_T *get_clusters_chain_fat16(const void *buffer, size_t size, uint16_t first_cluster)
{
    if (buffer == NULL)
    {
        return NULL;
    }

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

    uint8_t *FAT_table = (uint8_t *)buffer;
    uint16_t ent_offset = (first_cluster * 2) % size;

    while (1)
    {
        uint16_t table_value = *(uint16_t *)&FAT_table[ent_offset];
        if (table_value >= 0xFFF8)
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
        ent_offset = (table_value * 2) % size;
    }

    return chain;
}

CLUSTERS_CHAIN_T *get_clusters_chain_fat12(const void *buffer, size_t size, uint16_t first_cluster)
{
    if (buffer == NULL)
    {
        return NULL;
    }

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
    uint8_t *FAT_table = (uint8_t *)buffer;

    while (1)
    {
        uint16_t ent_offset = (active_cluster + (active_cluster / 2)) % size;
        uint16_t table_value = *(uint16_t *)&FAT_table[ent_offset];
        if (active_cluster & 1)
        {
            table_value = table_value >> 4;
        }
        else
        {
            table_value = table_value & 0x0FFF;
        }

        if (table_value >= 0xFF8)
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
