
#ifndef __MYLZODLL_H__
#define __MYLZODLL_H__

#ifdef __cplusplus
extern "C" {
#endif

__declspec( dllexport ) int MyLzoDll_decompressData(unsigned char* compressedData, unsigned int compressedSize,
unsigned char* decompressedData, unsigned int decompressedSize);

#ifdef __cplusplus
}
#endif

#endif // __MYLZODLL_H__