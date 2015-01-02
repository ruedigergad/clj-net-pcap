/*
 *
 * Copyright (C) 2014 Ruediger Gad
 *
 * This file is part of clj-net-pcap.
 *
 * clj-net-pcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License (LGPL) as
 * published by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * clj-net-pcap is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License (LGPL) for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License (LGPL)
 * along with clj-net-pcap.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package clj_net_pcap;

/**
 * Helper class for handling byte arrays.
 * Please note that, by default, the methods do not perform any sanity checks.
 *
 */
public class ByteArrayHelper {

    public static void addToInt(byte[] array, int index, int value) {
        int tmp = array[index+3] & 0xFF |
            (array[index+2] & 0xFF) << 8 |
            (array[index+1] & 0xFF) << 16 |
            (array[index] & 0xFF) << 24;

        tmp += value;

        array[index+3] = (byte) (0xFF & tmp);
        array[index+2] = (byte) ((tmp >> 8) & 0xFF);
        array[index+1] = (byte) ((tmp >> 16) & 0xFF);
        array[index] = (byte) ((tmp >> 24 ) & 0xFF);
    }

    public static int getInt(byte[] array, int index) {
        return   array[index+3] & 0xFF |
            (array[index+2] & 0xFF) << 8 |
            (array[index+1] & 0xFF) << 16 |
            (array[index+0] & 0xFF) << 24;
    }

    public static long getLong(byte[] array, int index) {
        return   array[index+7] & 0xFF |
            (array[index+6] & 0xFF) << 8 |
            (array[index+5] & 0xFF) << 16 |
            (array[index+4] & 0xFF) << 24 |
            (array[index+3] & 0xFF) << 32 |
            (array[index+2] & 0xFF) << 40 |
            (array[index+1] & 0xFF) << 48 |
            (array[index] & 0xFF) << 56;
    }

    public static byte[] ethMacStringToByteArrayUnchecked(String str) {
        byte[] ret = new byte[6];

        String[] s = str.split(":");

        for (int i = 0; i < ret.length; i++) {
            ret[i] = (byte) Integer.parseInt(s[i], 16);
        }

        return ret;
    }

    public static byte[] ipv4StringToByteArrayUnchecked(String str) {
        byte[] ret = new byte[4];

        String[] s = str.split("\\.");

        for (int i = 0; i < ret.length; i++) {
            ret[i] = (byte) Integer.parseInt(s[i], 10);
        }

        return ret;
    }
}

