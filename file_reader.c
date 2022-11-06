#include "file_reader.h"
#include "tested_declarations.h"
#include "rdebug.h"

#include <stdlib.h>
#include <errno.h>

DISK* disk_open_from_file(const char* volume_file_name)
{
    if (volume_file_name == NULL)
    {
        errno = EFAULT;
        return NULL;
    }

    FILE* file = fopen(volume_file_name, "r");
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
    fseek(file, 0x03, SEEK_SET);  // Skip jmp.
    fread(disk->oem_name, 1, 8, file);
    fread(&disk->bytes_per_sector, 2, 1, file);
    fread(&disk->sectors_per_cluster, 1, 1, file);
    fread(&disk->reserved_sector_count, 2, 1, file);
    fread(&disk->table_count, 1, 1, file);
    fread(&disk->root_entry_count, 2, 1, file);
    fread(&disk->total_sectors_16, 2, 1, file);
    fread(&disk->media_type, 1, 1, file);
    fread(&disk->table_size_16, 2, 1, file);
    fread(&disk->sectors_per_track, 2, 1, file);
    fread(&disk->head_side_count, 2, 1, file);
    fread(&disk->hidden_sector_count, 4, 1, file);
    fread(&disk->large_sectors_32, 4, 1, file);
    fread(&disk->extended_section.drive_number, 1, 1, file);
    fread(&disk->extended_section.windows_nt_flags, 1, 1, file);
    fread(&disk->extended_section.signature, 1, 1, file);
    fread(&disk->extended_section.volume_id, 4, 1, file);
    fread(&disk->extended_section.volume_label, 1, 11, file);
    fread(&disk->extended_section.file_system_type, 1, 8, file);
    return disk;
}

int disk_read(DISK* pdisk, int32_t first_sector, void* buffer, int32_t sectors_to_read)
{
    if (pdisk == NULL || buffer == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    if (first_sector < 0 || sectors_to_read < 0 || (first_sector + sectors_to_read) > pdisk->total_sectors_16)
    {
        errno = ERANGE;
        return -1;
    }

    fseek(pdisk->file, first_sector * pdisk->bytes_per_sector, SEEK_SET);
    fread(buffer, pdisk->bytes_per_sector, sectors_to_read, pdisk->file);
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

