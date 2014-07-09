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

import java.util.Comparator;

/**
 * Comparator that compares two raw pcap data instances in form of byte arrays
 * with respect to their timestamps.
 */
public class PcapByteArrayTimeStampComparator implements Comparator <byte[]> {
    
    public int compare(byte[] a, byte[] b) {
        int aSec = ByteArrayHelper.getInt(a, 0);
        int bSec = ByteArrayHelper.getInt(b, 0);

        if (aSec == bSec) {
            int aUSec = ByteArrayHelper.getInt(a, 4);
            int bUSec = ByteArrayHelper.getInt(b, 4);

            if (aUSec < bUSec) {
                return -1;
            } else if (aUSec > bUSec) {
                return 1;
            } else {
                return 0;
            }
        } else if (aSec < bSec) {
            return -1;
        } else {
            return 1;
        }
    }

    public boolean equals(byte[] a, byte[] b) {
        return compare(a, b) == 0;
    }

}

