/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap.newstuff;

// TODO: Auto-generated Javadoc
/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface JFieldFormat extends Iterable<String> {

	/**
	 * Is formatted out put multi or single line output.
	 * <p>
	 * Example of multi line output for a sub-header
	 * 
	 * <pre>
	 * 	Icmp:  ******* Icmp offset=36 (0x24) length=8 
	 * 	Icmp: 
	 * 	Icmp:             type = 0x8 (8) [echo request]
	 * 	Icmp:             code = 0x0 (0)
	 * 	Icmp:         checksum = 0x2DC4 (11716) [correct]
	 * 	Icmp: 
	 * 	Icmp: + EchoRequest: offset=4 length=4
	 * 	Icmp:               id = 0x8D64 (36196)
	 * 	Icmp:         sequence = 0x1 (1)
	 * 	Icmp: 
	 * 
	 * </pre>
	 * 
	 * </p>
	 * <p>
	 * Example of single line output for a sub-header
	 * 
	 * <pre>
	 * 	Icmp:  ******* Icmp offset=36 (0x24) length=8 
	 * 	Icmp: 
	 * 	Icmp:             type = 0x8 (8) [echo request]
	 * 	Icmp:             code = 0x0 (0)
	 * 	Icmp:         checksum = 0x2DC4 (11716) [correct]
	 * 	Icmp: 
	 * 	Icmp: + EchoRequest: id = 0x8D64 (36196), sequence = 0x1 (1)
	 * 	Icmp: 
	 * 
	 * </pre>
	 * 
	 * </p>
	 * <p>
	 * Example of table based output for a sub-header
	 * 
	 * <pre>
	 * 	Icmp:  ******* Icmp offset=36 (0x24) length=8 
	 * 	Icmp: 
	 * 	Icmp:             type = 0x8 (8) [echo request]
	 * 	Icmp:             code = 0x0 (0)
	 * 	Icmp:         checksum = 0x2DC4 (11716) [correct]
	 * 	Icmp: 
	 * 	Icmp: + EchoRequest =      Id        | sequence
	 * 	Icmp:                 ---------------+-------------
	 * 	Icmp:           [0] = 0x8D64 (36196) |  0x1 (1)
	 * 	Icmp: 
	 * 
	 * 	Rip2:  ******* Rip2 offset=36 (0x24) length=128 
	 * 	Rip2: 
	 * 	Rip2:          Command = 0x2 (2) [rip request]
	 * 	Rip2:          Version = 0x2 (2)
	 * 	Rip2:         reserved = 0x0 (0)
	 * 	Rip2: 
	 * 	Rip2: + routes =  family | Route Tag |   Address   |    Subnet     |   Next Hop  | Metric
	 * 	Rip2:            --------+-----------+-------------+---------------+-------------+--------
	 * 	Rip2:      [0] =   IN    |  0x4456   | 192.168.1.0 | 255.255.255.0 | 192.168.1.1 |   10
	 * 	Rip2:      [1] =   IN    |  0x4457   | 192.168.1.0 | 255.255.255.0 | 192.168.1.1 |   10
	 * 	Rip2:      [2] =   IN    |  0x4458   | 192.168.1.0 | 255.255.255.0 | 192.168.1.1 |   10
	 * 	Rip2:      [3] =   IN    |  0x4459   | 192.168.1.0 | 255.255.255.0 | 192.168.1.1 |   10
	 * 	Rip2:      [4] =   IN    |  0x4460   | 192.168.1.0 | 255.255.255.0 | 192.168.1.1 |   10
	 * 	Rip2:      [5] =   IN    |  0x4461   | 192.168.1.0 | 255.255.255.0 | 192.168.1.1 |   10
	 * 	Rip2:
	 * 
	 * 	Rtp:  ******* Rip2 offset=36 (0x24) length=128
	 * 	Rtp: 
	 * 	Rtp:          Version = 2
	 * 	Rtp:               cc = 6
	 * 	Rtp:         reserved = 0x0 (0)  
	 * 	Rtp:          CSRC[0] =  0x4456 
	 * 	Rtp:          CSRC[1] =  0x4457 
	 * 	Rtp:          CSRC[2] =  0x4458 
	 * 	Rtp:          CSRC[3] =  0x4459 
	 * 	Rtp:          CSRC[4] =  0x4460 
	 * 	Rtp:          CSRC[5] =  0x4461 
	 * 	Rtp:
	 * 
	 * 	Rtp:  ******* Rip2 offset=36 (0x24) length=128
	 * 	Rtp: 
	 * 	Rtp:          Version = 2
	 * 	Rtp:               cc = 6
	 * 	Rtp:         reserved = 0x0 (0)  
	 * 	Rtp: CSRC[1..3] =  0x4456, 0x4457, 0x4458, 0x4459 
	 * 	Rtp: CSRC[4..5] =  0x4460, 0x4461 
	 * 	Rtp: 
	 *  
	 * </pre>
	 * 
	 * </p>
	 * 
	 * @return true, if is multi line
	 */
	public boolean isMultiLine();

	/**
	 * Checks if is indexed.
	 * 
	 * @return true, if is indexed
	 */
	public boolean isIndexed();

	/**
	 * Checks if is table.
	 * 
	 * @return true, if is table
	 */
	public boolean isTable();
}
