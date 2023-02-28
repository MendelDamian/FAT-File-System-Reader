all: main.c fat_reader.c fat_reader.h
	gcc main.c fat_reader.c -o main
