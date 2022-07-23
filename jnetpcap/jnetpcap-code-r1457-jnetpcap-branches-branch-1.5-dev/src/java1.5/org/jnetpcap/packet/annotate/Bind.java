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
public @interface Bind {

	/**
	 * Defines constants for various binding types that are possible.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Type {
		
		/** This is the primary binding type that is always tried by the scanner. */
		PRIMARY,

		/**
		 * An optional binding type that provides heuristic discovery by scanning
		 * potential header fields to make a best guess at what the next header
		 * might be.
		 */
		HEURISTIC
	}

	/**
	 * (Optional) Constant value that can be used to bind one protocol to another
	 * based on this value. The header specified using the "to" parameter must
	 * supply methods or mark fields with <code>@BindValue</code> annotation.
	 * @return value to use to ia bind-to-value matchup
	 */
	int[] intValue() default Integer.MAX_VALUE;

	/**
	 * (Optional) Constant value that can be used to bind one protocol to another
	 * based on this value. The header specified using the "to" parameter must
	 * supply methods or mark fields with <code>@BindValue</code> annotation.
	 * @return value to use to ia bind-to-value matchup
	 */
	String[] stringValue() default "";

	/**
	 * The protocol that wants to bind to another protocol. In the diagram below B
	 * is binding to A. That is "to" == A.class. This is called the <b>target</b>
	 * protocol.
	 * <p>
	 * In this example, <b>to</b> paramter is assigned to header <b>A class</b>
	 * 
	 * <pre>
	 * +----------+----------------+----------+ 
	 * | Ethernet | =&gt; header A &lt;= | header B |
	 * +----------+----------------+----------+
	 * </pre>
	 * 
	 * </p>
	 * Another words, <b>B header</b> is binding <u>to</u> <b>A header</b>
	 * 
	 * @return a header class that is the target of the binding
	 */
	Class<? extends JHeader> to();

	/**
	 * (Optional in <code>JHeader</code> based declarations) The protocol that
	 * is being bound to. In the diagram below B is binding to A. That is "from" ==
	 * B.class. This is called the <b>source</b> protocol.
	 * <p>
	 * In this example, <b>from</b> paramter is assigned to header <b>B class</b>
	 * 
	 * <pre>
	 * +----------+----------+----------------+ 
	 * | Ethernet | header A | =&gt; header B &lt;= |
	 * +----------+----------+----------------+
	 * </pre>
	 * 
	 * Another words, <b>A header</b> is bind is bound <u>from</u> <b>B header</b>
	 * </p>
	 * 
	 * @return header class that is the source of the binding
	 */
	Class<? extends JHeader> from() default JHeader.class;

	/**
	 * (Optional) parameter that allows the binding to specify via an array of
	 * header classes additional protocol dependencies. This dependency list is
	 * used to optimize the binding making sure that atleast one header in the
	 * list is found within the packet for which binding is being evaluated before
	 * actually checking the binding.
	 * 
	 * @return list of header classes that this binding is dependent on
	 */
	Class<? extends JHeader>[] dependencies() default {};

	/**
	 * Specifies binding types. A binding can be assigned a different type, which
	 * through <code>JRegistry</code> and <code>JScanner</code> operations can
	 * be utilitized under special circumstances. For example
	 * <code>Type.HUERISTIC</code> is a way to define a binding that is only
	 * utilized when heuristic scans (best guess at the binding) are enabled.
	 * 
	 * @return type of binding. The default binding type if none are specified is
	 *         <code>Type.PRIMARY</code>
	 */
	Type type() default Type.PRIMARY;
}
