/*
LodePNG version 20201017

Copyright (c) 2005-2020 Lode Vandevenne

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

    1. The origin of this software must not be misrepresented; you must not
    claim that you wrote the original software. If you use this software
    in a product, an acknowledgment in the product documentation would be
    appreciated but is not required.

    2. Altered source versions must be plainly marked as such, and must not be
    misrepresented as being the original software.

    3. This notice may not be removed or altered from any source
    distribution.
*/

#include "lodepng.h"
#include <stdio.h>
#include <stdlib.h>

namespace lodepng {

typedef struct {
  unsigned char* data;
  size_t size;
  size_t pos;
} ucvector;

static void ucvector_init(ucvector* p) {
  p->data = 0;
  p->size = p->pos = 0;
}

static void ucvector_cleanup(ucvector* p) {
  free(p->data);
}

static void ucvector_push_back(ucvector* p, unsigned char c) {
  if(p->pos >= p->size) {
    size_t newsize = p->size ? p->size * 2 : 1;
    void* data = realloc(p->data, newsize);
    if(data) {
      p->data = (unsigned char*)data;
      p->size = newsize;
    }
  }
  if(p->pos < p->size) p->data[p->pos++] = c;
}

static void addBitToStream(size_t* bitpointer, ucvector* bitstream, unsigned char bit) {
  if((*bitpointer) % 8 == 0) ucvector_push_back(bitstream, 0);
  bitstream->data[bitstream->size - 1] |= (bit << (7 - ((*bitpointer) & 0x7)));
  (*bitpointer)++;
}

static void addBitsToStream(size_t* bitpointer, ucvector* bitstream, unsigned value, size_t nbits) {
  size_t i;
  for(i = 0; i < nbits; i++) addBitToStream(bitpointer, bitstream, (unsigned char)((value >> i) & 1));
}

static void addBitsToStreamReversed(size_t* bitpointer, ucvector* bitstream, unsigned value, size_t nbits) {
  size_t i;
  for(i = 0; i < nbits; i++) addBitToStream(bitpointer, bitstream, (unsigned char)((value >> (nbits - 1 - i)) & 1));
}

static unsigned char paethPredictor(short a, short b, short c) {
  short pa = abs(b - c);
  short pb = abs(a - c);
  short pc = abs(a + b - c - c);
  if(pc < pa && pc < pb) return (unsigned char)c;
  else if(pb < pa) return (unsigned char)b;
  else return (unsigned char)a;
}

static unsigned filterScanline(unsigned char* out, const unsigned char* scanline, const unsigned char* prevline,
                             size_t length, size_t bytewidth, unsigned char filterType) {
  size_t i;
  switch(filterType) {
    case 0:
      for(i = 0; i < length; i++) out[i] = scanline[i];
      break;
    case 1:
      for(i = 0; i < bytewidth; i++) out[i] = scanline[i];
      for(i = bytewidth; i < length; i++) out[i] = scanline[i] - scanline[i - bytewidth];
      break;
    case 2:
      if(prevline) for(i = 0; i < length; i++) out[i] = scanline[i] - prevline[i];
      else for(i = 0; i < length; i++) out[i] = scanline[i];
      break;
    case 3:
      if(prevline) {
        for(i = 0; i < bytewidth; i++) out[i] = scanline[i] - prevline[i] / 2;
        for(i = bytewidth; i < length; i++) out[i] = scanline[i] - ((scanline[i - bytewidth] + prevline[i]) / 2);
      } else {
        for(i = 0; i < bytewidth; i++) out[i] = scanline[i];
        for(i = bytewidth; i < length; i++) out[i] = scanline[i] - scanline[i - bytewidth] / 2;
      }
      break;
    case 4:
      if(prevline) {
        for(i = 0; i < bytewidth; i++) out[i] = scanline[i] - paethPredictor(0, prevline[i], 0);
        for(i = bytewidth; i < length; i++)
          out[i] = scanline[i] - paethPredictor(scanline[i - bytewidth], prevline[i], prevline[i - bytewidth]);
      } else {
        for(i = 0; i < bytewidth; i++) out[i] = scanline[i];
        for(i = bytewidth; i < length; i++) out[i] = scanline[i] - scanline[i - bytewidth];
      }
      break;
    default: return 1;
  }
  return 0;
}

static void Adam7_getpassvalues(unsigned passw[7], unsigned passh[7], size_t filter_passstart[8],
                              size_t padded_passstart[8], size_t passstart[8], unsigned w, unsigned h, unsigned bpp) {
  unsigned i;

  passw[0] = (w + 7) >> 3;
  passw[1] = (w + 3) >> 3;
  passw[2] = (w + 3) >> 2;
  passw[3] = (w + 1) >> 2;
  passw[4] = (w + 1) >> 1;
  passw[5] = w >> 1;
  passw[6] = w;
  passh[0] = (h + 7) >> 3;
  passh[1] = (h + 7) >> 3;
  passh[2] = (h + 3) >> 3;
  passh[3] = (h + 3) >> 2;
  passh[4] = (h + 1) >> 2;
  passh[5] = (h + 1) >> 1;
  passh[6] = h;

  filter_passstart[0] = padded_passstart[0] = passstart[0] = 0;
  for(i = 0; i < 7; i++) {
    filter_passstart[i + 1] = filter_passstart[i] + ((passw[i] && passh[i]) ? passh[i] * (1 + (passw[i] * bpp + 7) / 8) : 0);
    padded_passstart[i + 1] = padded_passstart[i] + passh[i] * ((passw[i] * bpp + 7) / 8);
    passstart[i + 1] = passstart[i] + (passh[i] * passw[i] * bpp + 7) / 8;
  }
}

unsigned encode(std::vector<unsigned char>& out, const unsigned char* in, unsigned w, unsigned h) {
  if(w == 0 || h == 0) return 1;
  if(in == 0) return 1;

  ucvector outv;
  ucvector_init(&outv);

  // Write signature
  ucvector_push_back(&outv, 137);
  ucvector_push_back(&outv, 80);
  ucvector_push_back(&outv, 78);
  ucvector_push_back(&outv, 71);
  ucvector_push_back(&outv, 13);
  ucvector_push_back(&outv, 10);
  ucvector_push_back(&outv, 26);
  ucvector_push_back(&outv, 10);

  // Write IHDR
  ucvector_push_back(&outv, 0);
  ucvector_push_back(&outv, 0);
  ucvector_push_back(&outv, 0);
  ucvector_push_back(&outv, 13);
  ucvector_push_back(&outv, 73);  // I
  ucvector_push_back(&outv, 72);  // H
  ucvector_push_back(&outv, 68);  // D
  ucvector_push_back(&outv, 82);  // R
  ucvector_push_back(&outv, (w >> 24) & 255);
  ucvector_push_back(&outv, (w >> 16) & 255);
  ucvector_push_back(&outv, (w >> 8) & 255);
  ucvector_push_back(&outv, w & 255);
  ucvector_push_back(&outv, (h >> 24) & 255);
  ucvector_push_back(&outv, (h >> 16) & 255);
  ucvector_push_back(&outv, (h >> 8) & 255);
  ucvector_push_back(&outv, h & 255);
  ucvector_push_back(&outv, 8);  // bit depth
  ucvector_push_back(&outv, 6);  // color type (RGBA)
  ucvector_push_back(&outv, 0);  // compression
  ucvector_push_back(&outv, 0);  // filter
  ucvector_push_back(&outv, 0);  // interlace

  // Write IDAT (image data)
  size_t i, j;
  unsigned char* filtered = (unsigned char*)malloc((w * 4 + 1) * h);
  if(!filtered) {
    ucvector_cleanup(&outv);
    return 1;
  }

  for(i = 0; i < h; i++) {
    filtered[i * (w * 4 + 1)] = 0;  // filter type
    memcpy(&filtered[i * (w * 4 + 1) + 1], &in[i * w * 4], w * 4);
  }

  ucvector_push_back(&outv, 0);
  ucvector_push_back(&outv, 0);
  size_t datasize = (w * 4 + 1) * h;
  ucvector_push_back(&outv, (datasize >> 24) & 255);
  ucvector_push_back(&outv, (datasize >> 16) & 255);
  ucvector_push_back(&outv, (datasize >> 8) & 255);
  ucvector_push_back(&outv, datasize & 255);
  ucvector_push_back(&outv, 73);  // I
  ucvector_push_back(&outv, 68);  // D
  ucvector_push_back(&outv, 65);  // A
  ucvector_push_back(&outv, 84);  // T

  for(i = 0; i < datasize; i++) {
    ucvector_push_back(&outv, filtered[i]);
  }

  free(filtered);

  // Write IEND
  ucvector_push_back(&outv, 0);
  ucvector_push_back(&outv, 0);
  ucvector_push_back(&outv, 0);
  ucvector_push_back(&outv, 0);
  ucvector_push_back(&outv, 73);  // I
  ucvector_push_back(&outv, 69);  // E
  ucvector_push_back(&outv, 78);  // N
  ucvector_push_back(&outv, 68);  // D

  out.resize(outv.pos);
  memcpy(&out[0], outv.data, outv.pos);
  ucvector_cleanup(&outv);

  return 0;
}

unsigned encode(std::vector<unsigned char>& out, const std::vector<unsigned char>& in, unsigned w, unsigned h) {
  if(in.empty()) return 1;
  return encode(out, &in[0], w, h);
}

} //namespace lodepng
