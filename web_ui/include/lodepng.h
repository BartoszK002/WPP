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

#ifndef LODEPNG_H
#define LODEPNG_H

#include <string>
#include <vector>
#include <string.h> /*for size_t*/

namespace lodepng {
typedef unsigned char byte;
typedef std::vector<byte> Bytes;

/*
Converts RGBA raw pixel data into a PNG file in memory.
Same as encode, but input is raw pixel data.
out: Output parameter. Pointer to buffer that will contain the PNG file data.
w: width of the raw pixel data in pixels.
h: height of the raw pixel data in pixels.
in: buffer with raw pixel data.
Return value: LodePNG error code (0 means no error).
*/
unsigned encode(std::vector<unsigned char>& out,
               const unsigned char* in, unsigned w, unsigned h);

/*
Same as encode but input is RGBA vector instead of raw pointer.
*/
unsigned encode(std::vector<unsigned char>& out,
               const std::vector<unsigned char>& in,
               unsigned w, unsigned h);

} //namespace lodepng

#endif /*LODEPNG_H*/
