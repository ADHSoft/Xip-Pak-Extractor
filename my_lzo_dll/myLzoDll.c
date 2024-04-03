#include <stdio.h>
#include <stdlib.h>

#include "minilzo.h"


/* DLL export function for decompressing data */
int MyLzoDll_decompressData(unsigned char* compressedData, unsigned int compressedSize, unsigned char* decompressedData, unsigned int decompressedSize)
{
    int r;
    lzo_uint new_len;

    new_len = decompressedSize;
    r = lzo1x_decompress(compressedData, compressedSize, decompressedData, &new_len, NULL);
    if (r != LZO_E_OK && new_len == decompressedSize)
    {
        printf("MyLzoDll - Internal error - decompression failed: %d\n", r);
        return 1;
        
    }
    if (new_len != decompressedSize)
    {
        printf("MyLzoDll - Internal error - decompressed data size mismatch. Expected: %lu Got : %lu\n", (unsigned long) decompressedSize, (unsigned long) new_len);
        return 2;
    } else
    {
        #define VERBOSE_DEBUG 0
        #if VERBOSE_DEBUG
        printf("MyLzoDll - Done!! Decompressed %lu bytes back into %lu bytes\n", (unsigned long) compressedSize, (unsigned long) decompressedSize);
        #endif

        return 0;
    }
}