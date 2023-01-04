#include "file_reader.h"
#include "tested_declarations.h"
#include "rdebug.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>

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

    if (volume->bs.signature != 0xAA55)
    {
        errno = EINVAL;
        free(volume);
        return NULL;
    }

    // We don't care about FAT32.
    if (volume->bs.table_size_16 == 0)
    {
        errno = EINVAL;
        free(volume);
        return NULL;
    }

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
        if (strcmp(file->entry.name, file_name) == 0)
        {
            dir_close(dir);
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

    free(stream);
    return 0;
}

size_t file_read(void *ptr, size_t size, size_t nmemb, FILE_T* stream)
{
    (void)ptr;
    (void)size;
    (void)nmemb;
    (void)stream;
    return 0;
}

int32_t file_seek(FILE_T* stream, int32_t offset, int whence)
{
    (void)stream;
    (void)offset;
    (void)whence;
    return 0;
}

DIR* dir_open(VOLUME* pvolume, const char* dir_path)
{
    BOOTSECTOR *bs = &pvolume->bs;
    uint32_t root_dir_sectors = ((bs->root_entry_count * 32) + (bs->bytes_per_sector - 1)) / bs->bytes_per_sector;
    uint32_t first_data_sector = bs->reserved_sector_count + (bs->table_count * bs->table_size_16) + root_dir_sectors;
    uint32_t first_root_dir_sector = first_data_sector - root_dir_sectors;

    DIR* dir = calloc(1, sizeof(DIR));
    if (dir == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }

    if (strcmp(dir_path, "/") == 0)
    {
        dir->volume = pvolume;
        dir->first_cluster = (int32_t)first_root_dir_sector;
        dir->sector_count = (int32_t)root_dir_sectors;
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

    void *buffer = calloc(pdir->sector_count, pdir->volume->bs.bytes_per_sector);
    if (buffer == NULL)
    {
        return -1;
    }

    int result = disk_read(pdir->volume->disk, pdir->first_cluster, buffer, pdir->sector_count);
    if (result != pdir->sector_count)
    {
        free(buffer);
        return -1;
    }

    DIR_ENTRY_DATA entry_data = *((DIR_ENTRY_DATA *)buffer + pdir->current_sector++);
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
    pentry->is_directory = entry_data.attributes & 0x10;
    pentry->is_archived = entry_data.attributes & 0x20;
    pentry->creation_date = entry_data.creation_date;
    pentry->creation_time = entry_data.creation_time;
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


CLUSTERS_CHAIN *get_chain_fat16(const void* const buffer, size_t size, uint16_t first_cluster)
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
