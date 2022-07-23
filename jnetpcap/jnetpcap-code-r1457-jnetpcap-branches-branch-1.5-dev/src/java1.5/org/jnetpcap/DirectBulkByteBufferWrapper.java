/*
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
package org.jnetpcap;

import java.nio.ByteBuffer;

/**
 * @author Ruediger Gad
 */
public class DirectBulkByteBufferWrapper {

    private ByteBuffer buffer;

    public DirectBulkByteBufferWrapper (ByteBuffer buf) {
        buffer = buf;
    }

    public ByteBuffer getBuffer() {
        return buffer;
    }

    @Override
    public String toString() {
        return "DirectBulkByteBufferWrapper: " + (buffer != null ? buffer.toString() : "null"); 
    }

    @Override
    protected void finalize() throws Throwable {
        freeNativeMemory();
        super.finalize();
    }

    public void freeNativeMemory() {
        if (buffer != null && buffer.isDirect()) {
            free(buffer);
            buffer = null;
        }
    }

    private native int free(ByteBuffer buffer);

}
