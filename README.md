# File Allocation Table (FAT) File System Reader

A custom FAT file system image reader project developed for the "Operating Systems" classes to consolidate knowledge of file systems and system programming.
The FAT reader supports reading subdirectories and long file name entries. It includes a variety of structures and functions to access the internal information of the file system with ease.


## Author

- [@MendelDamian](https://www.github.com/MendelDamian)

## Features

- Support for reading FAT12 and FAT16 file systems.
- Support for reading long file name entries.
- Support for reading subdirectories.
- Provides structs and functions to access the boot sector, the file allocation table and the volume information.

## To do
- Add support for FAT32 file systems.

## Usage

```c
#include "fat_reader.h"

int main(void)
{
    DISK_T* disk = disk_open_from_file("fat16_volume.img");
    if (disk == NULL)
    {
        puts("You need to provide a valid FAT image file.");
        return 1;
    }

    VOLUME_T* volume = fat_open(disk, 0);
    if (volume == NULL)
    {
        disk_close(disk);
        puts("The provided image file is not a valid FAT volume.");
        return 2;
    }

    FILE_T* file = file_open(volume, "/home/user/notes.txt");
    if (file == NULL)
    {
        fat_close(volume);
        disk_close(disk);
        puts("The provided file does not exist.");
        return 3;
    }

    char buffer[1000] = {0};
    size_t bytes_read = file_read(buffer, 1, 999, file);
    
    printf("Read %zu bytes from the file.\n", bytes_read);
    printf("File contents:\n%s\n", buffer);

    file_close(file);
    fat_close(volume);
    disk_close(disk);
    return 0;
}
```

## Functions
This project provides several functions for memory management, such as:

- `DISK_T *disk_open_from_file(const char *volume_file_name)`: opens a disk image file and returns a pointer to a `DISK_T` structure.
- `int disk_read(DISK_T *pdisk, int32_t first_sector, void *buffer, int32_t sectors_to_read)`: reads `sectors_to_read` sectors from the disk image starting at `first_sector` and stores the data in `buffer`.
- `int disk_close(DISK_T *pdisk)`: closes the disk image file and frees the memory allocated for the `DISK_T` structure.
<br><br>
- `VOLUME_T *fat_open(DISK_T *pdisk, uint32_t first_sector)`: opens a FAT volume and returns a pointer to a `VOLUME_T` structure.
- `int fat_close(VOLUME_T *pvolume)`: closes the FAT volume and frees the memory allocated for the `VOLUME_T` structure.
<br><br>
- `FILE_T *file_open(VOLUME_T *pvolume, const char *file_name)`: opens a file and returns a pointer to a `FILE_T` structure.
- `size_t file_read(void *ptr, size_t size, size_t nmemb, FILE_T *stream);`: reads data from a file into a buffer.
- `int32_t file_seek(FILE_T *stream, int32_t offset, int whence)`: sets the file position indicator for the file stream `stream` to a new position.
- `int file_close(FILE_T *stream)`: closes the file and frees the memory allocated for the `FILE_T` structure.
<br><br>
- `DIR_T *dir_open(VOLUME_T *pvolume, const char *dir_path)`: closes the file and frees the memory allocated for the `FILE_T` structure.
- `int dir_read(DIR_T *pdir, DIR_ENTRY_T *pentry)`: reads the next directory entry from the directory stream `pdir` and stores it in `pentry`.
  * `-1` is returned if invalid arguments are provided.
  * `0` is returned if the next directory entry was successfully read.
  * `1` is returned if the end of the directory stream is reached.
- `int dir_close(DIR_T *pdir)`: closes the directory stream `pdir` and frees the memory allocated for the `DIR_T` structure.

# :warning:NOTE:warning:
Please keep in mind that this project, despite passing automated tests, surely have some bugs and isn't perfect, so don't use it in production. It is for educational purposes only.
