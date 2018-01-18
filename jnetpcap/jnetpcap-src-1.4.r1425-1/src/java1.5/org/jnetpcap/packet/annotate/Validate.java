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

import org.jnetpcap.packet.JHeader;

// TODO: Auto-generated Javadoc
/**
 * Defines a binding method. Any method annotated with <code>Bind</code> must
 * be of specific java method signature and must supply annotation's 'to'
 * parameter. In addition, bindings that are defined in non <code>JHeader</code>
 * based classes, must also provide the 'from' parameter.
 * <p>
 * The required method signature varies depending how it is declared. Here are
 * the possible binding method declarations and their required Bind annotation
 * parameters.
 * <ul>
 * <li> A static method declared inside a <code>JHeader</code> based class -
 * only requires the 'to' parameter. The 'from' paramter is optional and the
 * default value is the class of the parent header definition that the binding
 * is defined in.</li>
 * <li> A static method declared inside a non <code>JHeader</code> based class -
 * requires both 'to' and 'from' parameters to be defined.</li>
 * <li> A instance method (non static) declared inside an annonymous class that
 * extends <code>Object.class</code> - requires both 'to' and 'from'
 * parameters to be defined.</li>
 * </ul>
 * Bind annotation is allowed only on methods. The name of the method is
 * insignicant as long as the return type and formal parameters the method takes
 * are as specified below. Both static and instance methods are supported but
 * only for the described cases above. The required method signatures are
 * identical in all cases with the exception that the 'static' java modifier is
 * dropped for instance method. The signature is as follows:
 * 
 * <pre name=code class=java:nogutter:nocontrols>
 * Static signature:
 * public static boolean bindSourceClassToDestinationClass(JPacket packet, &lt;? extends JHeader&gt; header);
 * 
 * Instance signature:
 * public boolean bindSourceClassToDestinationClass(JPacket packet, &lt;? extends JHeader&gt; header);
 * </pre>
 * 
 * The method names are irrelevant and are provided in the above only as an
 * example. It is recommended that implementors of binding methods, follow the
 * following method naming convention to be consistent with other implementors
 * and implementations. Here is the recommended naming convention:
 * 
 * <pre>
 * methodName := &quot;bind&quot; fromClass &quot;To&quot; toClass
 * fromClass  := HEADER_NAME
 * toClass    := HEADER_NAME
 * </pre>
 * 
 * The naming convention is not enforced.
 * </p>
 * <p>
 * Here is an example of a complete binding method in a code fragment:
 * 
 * <pre name=code class=java>
 * public class TestBindings {
 * 	&#064;Bind(from = Ip4.class, to = Ethernet.class)
 * 	public static boolean bindIp4ToEthernet(JPacket packet, Ethernet eth) {
 * 		return eth.type() == 0x800;
 * 	}
 * 
 * 	&#064;Bind(from = Ip4.class, to = IEEESnap.class)
 * 	public static boolean bindIp4ToIEEESnap(JPacket packet, IEEESnap snap) {
 * 		return snap.pid() == 0x800;
 * 	}
 * }
 * </pre>
 * 
 * Here is an example of a single instance method.
 * 
 * <pre>
 * Object o = new Object() {
 *  &#064;SuppressWarnings(&quot;unused&quot;)
 *  &#064;Bind(from = Ip4.class, to = Ethernet.class)
 *  public boolean bindIp4ToMyHeader(JPacket packet, Ethernet eth) {
 *    return eth.type() == 0x800;
 * }
 * </pre>
 * 
 * The second parameter to the method must match the 'to' annotation parameter
 * type. The types are verified at runtime and errors generated if those
 * parameters do not match.
 * </p>
 * <p>
 * The <code>Bind</code> annotation also takes an optional "intValue"
 * parameter. This parameter is used for making bindings that matches up with a
 * <code>BindValue</code> marked field. Any field or method that is marked
 * with <code>BindValue</code> annotation within the "to" class, can be used
 * to make a match with "intValue" parameter. Since this is completely optional
 * operation, that may or may not be implemented or utilized, it is also
 * neccessary to provide the complete binding method with its logic as well. The
 * "intValue" parameter is used to optimize bindings that use constant value for
 * linking one protocol to the other.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Target(ElementType.METHOD)
@Documented
@Retention(RetentionPolicy.RUNTIME)
public @interface Validate {

	/**
	 * Binds this validation method as a heuristic discovery method for each
	 * protocol listed.
	 * 
	 * @return a list of protocols to bind as a heuristic validator
	 */
	Class<? extends JHeader>[] hueristics() default {};

	/**
	 * Maximum header length in bytes.
	 * 
	 * @return the maximum allowed
	 */
	int max() default Integer.MAX_VALUE;

	/**
	 * Minimum header length that is allowed by this protocol.
	 * 
	 * @return the minimum allowed
	 */
	int min() default 0;

}
