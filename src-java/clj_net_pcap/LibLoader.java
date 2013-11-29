/*
 *
 * Copyright (C) 2012 Ruediger Gad
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
 * 
 * Loader for native libs. This is needed because calling System.load() from
 * within clojure does not work.
 * 
 * @author Ruediger Gad
 * 
 */
public class LibLoader {

    public static void load(String filename) {
        System.load(filename);
    }

}

