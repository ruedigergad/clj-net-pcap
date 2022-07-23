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
package org.jnetpcap.util;

import org.jnetpcap.nio.JStruct;

// TODO: Auto-generated Javadoc
/**
 * Specialized debug class that provides debugging and tracing services. There
 * is a low level native debug object compiled into jnetpcap library. The native
 * trace debugger works similar to the way that java logger's do with message
 * levels that can be set which will allow debug information to be printed out.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Debug
    extends
    JStruct {

	/**
	 * Size of native debug_t structure.
	 * 
	 * @return size in bytes
	 */
	public native static int sizeof();

	/**
	 * Instantiates a new debug.
	 * 
	 */
	public Debug() {
		super("class Debug", sizeof());
	}

	/**
	 * Provides access to raw level value.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public interface LevelId {

		/**
		 * Gets the numerical id for this priority level.
		 * 
		 * @return numerical id
		 * @see org.jnetpcap.util.Debug.LevelId#intValue()
		 */
		public int intValue();
	}

	/**
	 * Defines various message severity levels.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Level implements LevelId {
		
		/** The ERROR. */
		ERROR(4),
		
		/** The WARN. */
		WARN(6),
		
		/** The INFO. */
		INFO(8),
		
		/** The TRACE. */
		TRACE(10);

		/** The level. */
		private final int level;

		/**
		 * Instantiates a new level.
		 * 
		 * @param level
		 *          the level
		 */
		private Level(int level) {
			this.level = level;
		}

		/**
		 * Gets the numerical id for this level constant.
		 * 
		 * @return numerical id
		 * @see org.jnetpcap.util.Debug.LevelId#intValue()
		 */
		public int intValue() {
			return level;
		}

		/**
		 * Value of.
		 * 
		 * @param level
		 *          the level
		 * @return the level
		 */
		public static Level valueOf(int level) {
			for (Level l : values()) {
				if (l.level == level) {
					return l;
				}
			}

			return null;
		}
	}

	/**
	 * Sets the level.
	 * 
	 * @param level
	 *          the new level
	 */
	public void setLevel(Debug.LevelId level) {
		setLevel(level.intValue());
	}

	/**
	 * Sets the level.
	 * 
	 * @param level
	 *          the new level
	 */
	public native void setLevel(int level);

	/**
	 * Gets the level.
	 * 
	 * @return the level
	 */
	public native int getLevel();

	/**
	 * Gets the level enum.
	 * 
	 * @return the level enum
	 */
	public Level getLevelEnum() {
		return Level.valueOf(getLevel());
	}
}
