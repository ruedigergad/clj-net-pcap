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
package org.jnetpcap.packet.annotate;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.jnetpcap.PcapDLT;
import org.jnetpcap.packet.JHeader;

// TODO: Auto-generated Javadoc
/**
 * The Interface Header.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Target(ElementType.TYPE)
@Documented
@Retention(RetentionPolicy.RUNTIME)
public @interface Header {
	
	/**
	 * The Enum Layer.
	 */
	public enum Layer {
		
		/** The NULL. */
		NULL,
		
		/** The PHYSICAL. */
		PHYSICAL,
		
		/** The DATALINK. */
		DATALINK,
		
		/** The NETWORK. */
		NETWORK,
		
		/** The TRANSPORT. */
		TRANSPORT,
		
		/** The SESSION. */
		SESSION,
		
		/** The PRESENTATION. */
		PRESENTATION,
		
		/** The APPLICATION. */
		APPLICATION,
	}
	
	/**
	 * The Enum Characteristic.
	 */
	public enum Characteristic {
		
		/** The NULL. */
		NULL,
		
		/** The POIN t_ t o_ point. */
		POINT_TO_POINT,
		
		/** The POIN t_ t o_ multipoint. */
		POINT_TO_MULTIPOINT,
		
		/** The CSM a_ cd. */
		CSMA_CD,

	}
	
	/**
	 * Characteristics.
	 * 
	 * @return the characteristic[]
	 */
	Characteristic[] characteristics() default {};

	/**
	 * Description.
	 * 
	 * @return the string
	 */
	String description() default "";
	
	/**
	 * Dlt.
	 * 
	 * @return the pcap dl t[]
	 */
	PcapDLT[] dlt() default {};
	
	/**
	 * Format.
	 * 
	 * @return the string
	 */
	String format() default "";
	
	/**
	 * Id.
	 * 
	 * @return the int
	 */
	int id() default -1;
	
	/**
	 * Length.
	 * 
	 * @return the int
	 */
	int length() default -1;
	
	/**
	 * Prefix.
	 * 
	 * @return the int
	 */
	int prefix() default -1;
	
	/**
	 * Gap.
	 * 
	 * @return the int
	 */
	int gap() default  -1;
	
	/**
	 * Payload.
	 * 
	 * @return the int
	 */
	int payload() default -1;
	
	/**
	 * Postfix.
	 * 
	 * @return the int
	 */
	int postfix() default -1;
	
	/**
	 * Name.
	 * 
	 * @return the string
	 */
	String name() default "";
	
	/**
	 * Nicname.
	 * 
	 * @return the string
	 */
	String nicname() default "";
	
	/**
	 * Suite.
	 * 
	 * @return the protocol suite
	 */
	ProtocolSuite suite() default ProtocolSuite.OTHER;
	
	/**
	 * Osi.
	 * 
	 * @return the layer
	 */
	Layer osi() default Layer.NULL;
	
	/**
	 * Parent.
	 * 
	 * @return the class<? extends j header>
	 */
	Class<? extends JHeader> parent() default JHeader.class;
	
	/**
	 * Spec.
	 * 
	 * @return the string[]
	 */
	String[] spec() default {};

	/**
	 * Url.
	 * 
	 * @return the string
	 */
	String url() default "";
}
