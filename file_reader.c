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

int32_t get_cluster_first_sector(VOLUME *volume, uint16_t cluster)
{
    return ((cluster - 2) * volume->bs.sectors_per_cluster) + volume->first_data_sector;
}

int compare_filenames(const char *str, const char *prefix)
{
    return strncmp(str, prefix, strlen(prefix));
}

DISK* disk_open_from_file(const char* volume_file_name)
{
    if (volume_file_name == NULL)
    {
        errno = EFAULT;
        return NULL;
    }

    FILE* file = fopen(volume_file_name, "rb");
    if (file == NULL)
    {
        errno = ENOENT;
        return NULL;
    }

    DISK* disk = calloc(1, sizeof(DISK));
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

int disk_read(DISK* pdisk, int32_t first_sector, void* buffer, int32_t sectors_to_read)
{
    if (pdisk == NULL || buffer == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    if (first_sector < 0 || sectors_to_read < 0)
    {
        errno = EINVAL;
        return -1;
    }

    fseek(pdisk->file, first_sector * 512, SEEK_SET);
    size_t read = fread(buffer, 512, sectors_to_read, pdisk->file);
    if (read != (size_t)sectors_to_read)
    {
        errno = EIO;
        return -1;
    }

    return sectors_to_read;
}

int disk_close(DISK* pdisk)
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

VOLUME* fat_open(DISK* pdisk, uint32_t first_sector)
{
    if (pdisk == NULL)
    {
        errno = EFAULT;
        return NULL;
    }

    VOLUME* volume = calloc(1, sizeof(VOLUME));
    if (volume == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }

    volume->disk = pdisk;

    if (disk_read(pdisk, (int32_t)first_sector, &volume->bs, 1) != 1)
    {
        free(volume);
        return NULL;
    }

    BOOTSECTOR *bs = &volume->bs;

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
        errno = EINVAL;
        free(volume);
        return NULL;
    }

    volume->fat_table = calloc(bs->table_size_16,  bs->bytes_per_sector);
    if (volume->fat_table == NULL)
    {
        errno = EINVAL;
        free(volume);
        return NULL;
    }

    int result = disk_read(pdisk, bs->reserved_sector_count, volume->fat_table, bs->table_size_16);
    if (result != bs->table_size_16)
    {
        errno = EINVAL;
        free(volume->fat_table);
        free(volume);
        return NULL;
    }

    volume->root_dir_sectors = ((bs->root_entry_count * 32) + (bs->bytes_per_sector - 1)) / bs->bytes_per_sector;
    volume->first_data_sector = bs->reserved_sector_count + (bs->table_count * bs->table_size_16) + volume->root_dir_sectors;
    volume->first_root_dir_sector = volume->first_data_sector - volume->root_dir_sectors;
    volume->cluster_size = bs->bytes_per_sector * bs->sectors_per_cluster;

    return volume;
}

int fat_close(VOLUME* pvolume)
{
    if (pvolume == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    free(pvolume);
    return 0;
}

FILE_T* file_open(VOLUME* pvolume, const char* file_name)
{
    if (pvolume == NULL || file_name == NULL)
    {
        errno = EFAULT;
        return NULL;
    }

    FILE_T* file = calloc(1, sizeof(FILE_T));
    if (file == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }

    file->volume = pvolume;

    DIR* dir = dir_open(pvolume, "/");
    if (dir == NULL)
    {
        free(file);
        return NULL;
    }

    while (dir_read(dir, &file->entry) == 0)
    {
        if (file->entry.is_directory == false && compare_filenames(file->entry.name, file_name) == 0)
        {
            dir_close(dir);

            // Load cluster chain.
            file->clusters_chain = get_clusters_chain_fat16(pvolume->fat_table,
                                                            pvolume->bs.table_size_16 * pvolume->bs.bytes_per_sector,
                                                            file->entry.first_cluster);
            if (file->clusters_chain == NULL)
            {
                free(file);
                return NULL;
            }

            return file;
        }
    }

    dir_close(dir);
    return NULL;
}

int file_close(FILE_T* stream)
{
    if (stream == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    free(stream->clusters_chain);
    free(stream);
    return 0;
}

size_t file_read(void *ptr, size_t size, size_t nmemb, FILE_T* stream)
{
    if (ptr == NULL || stream == NULL)
    {
        return -1;
    }

    if (size == 0 || nmemb == 0)
    {
        return 0;
    }

    uint32_t cluster_size = stream->volume->cluster_size;
    int32_t sectors_per_cluster = (int32_t)stream->volume->bs.sectors_per_cluster;

    void *buffer = malloc(cluster_size);
    if (buffer == NULL)
    {
        errno = ENOMEM;
        return 0;
    }

    size_t bytes_read = 0;

    while (bytes_read < size * nmemb && stream->position < (int32_t)stream->entry.size)
    {
        uint16_t current_cluster = stream->clusters_chain->clusters[stream->position / stream->volume->cluster_size];
        if (current_cluster == 0)
        {
            break;
        }

        int32_t sector = get_cluster_first_sector(stream->volume, current_cluster);

        if (disk_read(stream->volume->disk, sector, buffer, sectors_per_cluster) != sectors_per_cluster)
        {
            break;
        }

        size_t offset = stream->position % cluster_size;
        size_t remaining_bytes = cluster_size - offset;
        size_t bytes_to_copy = min(remaining_bytes, size * nmemb - bytes_read);
        bytes_to_copy = min(bytes_to_copy, stream->entry.size - stream->position);
        memcpy((uint8_t*)ptr + bytes_read, (uint8_t*)buffer + offset, bytes_to_copy);

        bytes_read += bytes_to_copy;
        file_seek(stream, (int32_t)bytes_to_copy, SEEK_CUR);
    }

    free(buffer);
    return bytes_read / size;
}

int32_t file_seek(FILE_T* stream, int32_t offset, int whence)
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

DIR* dir_open(VOLUME* pvolume, const char* dir_path)
{
    DIR* dir = calloc(1, sizeof(DIR));
    if (dir == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }

    if (strcmp(dir_path, "/") == 0 || strcmp(dir_path, "\\") == 0)
    {
        dir->volume = pvolume;
        dir->entry.first_cluster = (int32_t)pvolume->first_root_dir_sector;
        dir->sector_count = (int32_t)pvolume->root_dir_sectors;
    }
    else
    {
        errno = ENOENT;
        free(dir);
        return NULL;
    }

    return dir;
}

int dir_read(DIR* pdir, DIR_ENTRY* pentry)
{
    if (pdir == NULL || pentry == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    memset(pentry, 0, sizeof(DIR_ENTRY));

    void *buffer = calloc(pdir->sector_count, pdir->volume->bs.bytes_per_sector);
    if (buffer == NULL)
    {
        return -1;
    }

    int result = disk_read(pdir->volume->disk, pdir->entry.first_cluster, buffer, pdir->sector_count);
    if (result != pdir->sector_count)
    {
        free(buffer);
        return -1;
    }

    DIR_ENTRY_DATA entry_data = *((DIR_ENTRY_DATA *)buffer + pdir->current_entry++);
    if ((uint8_t)entry_data.filename[0] == 0x00)
    {
        free(buffer);
        return 1;
    }

    if ((uint8_t)entry_data.filename[0] == 0xe5)
    {
        return dir_read(pdir, pentry);
    }

    free(buffer);

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

int dir_close(DIR* pdir)
{
    if (pdir == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    free(pdir);
    return 0;
}

CLUSTERS_CHAIN *get_clusters_chain(VOLUME *pvolume, const void* buffer, size_t size, uint16_t first_cluster)
{
    if (pvolume == NULL)
    {
        errno = EFAULT;
        return NULL;
    }

    switch (pvolume->fat_type)
    {
        case FAT12:
            return get_clusters_chain_fat12(buffer, size, first_cluster);

        case FAT16:
            return get_clusters_chain_fat16(buffer, size, first_cluster);

        default:
            errno = EINVAL;
            return NULL;
    }
}

CLUSTERS_CHAIN *get_clusters_chain_fat16(const void *buffer, size_t size, uint16_t first_cluster)
{
    if (buffer == NULL)
    {
        return NULL;
    }

    CLUSTERS_CHAIN *chain = calloc(1, sizeof(CLUSTERS_CHAIN));
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

CLUSTERS_CHAIN *get_clusters_chain_fat12(const void *buffer, size_t size, uint16_t first_cluster)
{
    if (buffer == NULL)
    {
        return NULL;
    }

    CLUSTERS_CHAIN *chain = calloc(1, sizeof(CLUSTERS_CHAIN));
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
        if(active_cluster & 1)
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
