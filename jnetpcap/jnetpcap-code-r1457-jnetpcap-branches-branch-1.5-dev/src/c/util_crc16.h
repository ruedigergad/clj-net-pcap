/* crc16.h
 * Declaration of CRC-16 routines and table
 *
 * 2004 Richard van der Hoff <richardv@mxtelecom.com>
 *
 * $Id: crc16.h 20485 2007-01-18 18:43:30Z guy $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@xxxxxxxxxxxx>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef __CRC16_H_
#define __CRC16_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
	
#include <stdint.h>

/* Calculate the CCITT/ITU/CRC-16 16-bit CRC

   (parameters for this CRC are:
       Polynomial: x^16 + x^12 + x^5 + 1  (0x1021);
       Start value 0xFFFF;
       XOR result with 0xFFFF;
       First bit is LSB)
*/

/** Compute CRC16 CCITT checksum of a buffer of data.
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @return The CRC16 CCITT checksum. */
extern uint16_t crc16_ccitt(const uint8_t *buf, uint32_t len);

/** Compute CRC16 X.25 CCITT checksum of a buffer of data.
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @return The CRC16 X.25 CCITT checksum. */
extern uint16_t crc16_x25_ccitt(const uint8_t *buf, uint32_t len);

/** Compute CRC16 CCITT checksum of a buffer of data.  If computing the
 *  checksum over multiple buffers and you want to feed the partial CRC16
 *  back in, remember to take the 1's complement of the partial CRC16 first.
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC16 CCITT checksum (using the given seed). */
extern uint16_t crc16_ccitt_seed(const uint8_t *buf, uint32_t len, uint16_t seed);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* crc16.h */
