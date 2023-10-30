#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>

#define BLOCK_SIZE 0x38

int blockCount = 0;
char* blocks[BLOCK_SIZE];

void setup() {
    struct timeval _time;
    gettimeofday(&_time, NULL);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    srand(_time.tv_usec);
}

void header() {
    printf("%s\n", "Datastore for your PON minds");
}

void menu() {
    printf("%s\n", "Choose action:");
    printf("%s\n", "1. Write your PON data");
    printf("%s\n", "2. Read your PON data");
    printf("%s\n", "3. Delete your PON data");
    printf("%s\n", "4. Change your PON data");
    printf("%s", ">>> ");
}

void writeData() {
    if (blockCount + 1 > BLOCK_SIZE) {
        printf("%s\n\n", "You already PONED all your PON blocks");
        return;
    }
    blocks[blockCount] = malloc(BLOCK_SIZE);
    blockCount++;
    unsigned int toRead;
    printf("%s", "How much PONs: ");
    scanf("%d%*c", &toRead);
    if (toRead > BLOCK_SIZE + 2) {
        printf("%s\n", "So PON");
        exit(0);
    }
    printf("%s", "PON it: ");
    read(0, blocks[blockCount - 1], toRead);
    printf("%s\n\n", "PONed.");
}

void readData() {
    unsigned int readBlock;
    printf("%s", "What PON block data you want to see: ");
    scanf("%d%*c", &readBlock);
    if (readBlock >= BLOCK_SIZE || blocks[readBlock] == 0) {
        printf("%s\n\n", "No PON on this block");
        return;
    }
    printf("%s", "Your PON data: ");
    write(1, blocks[readBlock], BLOCK_SIZE);
    printf("\n\n");
}

void deleteData() {
    unsigned int readBlock;
    printf("%s", "What PON block data you want to delete: ");
    scanf("%d%*c", &readBlock);
    if (readBlock >= BLOCK_SIZE || blocks[readBlock] == 0) {
        printf("%s\n\n", "No PON on this block");
        return;
    }
    free(blocks[readBlock]);
    printf("%s\n\n", "PONed.");
}

void changeData() {
    unsigned int changeBlock;
    unsigned int toRead;
    printf("%s", "What PON block data you want to change: ");
    scanf("%d%*c", &changeBlock);
    if (changeBlock >= BLOCK_SIZE || blocks[changeBlock] == 0) {
        printf("%s\n\n", "No PON on this block");
        return;
    }
    printf("%s", "How much PONs: ");
    scanf("%d%*c", &toRead);
    if (toRead > BLOCK_SIZE) {
        printf("%s\n", "So PON");
        exit(0);
    }
    printf("%s", "PON it: ");
    read(0, blocks[changeBlock], toRead);
    printf("%s\n\n", "PONed.");
}

int main() {
    int choice;
    setup();
    header();
    while (1) {
        menu();
        scanf("%d%*c", &choice);
        switch (choice)
        {
        case 1:
            writeData();
            break;

        case 2:
            readData();
            break;

        case 3:
            deleteData();
            break;

        case 4:
            changeData();
            break;
        
        default:
            return 0;
        }
    }
}
