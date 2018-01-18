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
package org.jnetpcap.protocol.voip;

import org.jnetpcap.packet.AbstractMessageHeader;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * The Session Initiation Protocol (SIP) is an IETF-defined signaling protocol,
 * widely used for controlling multimedia communication sessions such as voice
 * and video calls over Internet Protocol (IP). The protocol can be used for
 * creating, modifying and terminating two-party (unicast) or multiparty
 * (multicast) sessions consisting of one or several media streams. The
 * modification can involve changing addresses or ports, inviting more
 * participants, and adding or deleting media streams. Other feasible
 * application examples include video conferencing, streaming multimedia
 * distribution, instant messaging, presence information, file transfer and
 * online games.
 * <p>
 * SIP was originally designed by Henning Schulzrinne and Mark Handley starting
 * in 1996. The latest version of the specification is RFC 3261 from the IETF
 * Network Working Group. In November 2000, SIP was accepted as a 3GPP signaling
 * protocol and permanent element of the IP Multimedia Subsystem (IMS)
 * architecture for IP-based streaming multimedia services in cellular systems.
 * </p>
 * <p>
 * The SIP protocol is an Application Layer protocol designed to be independent
 * of the underlying transport layer; it can run on Transmission Control
 * Protocol (TCP), User Datagram Protocol (UDP), or Stream Control Transmission
 * Protocol (SCTP). It is a text-based protocol, incorporating many elements of
 * the Hypertext Transfer Protocol (HTTP) and the Simple Mail Transfer Protocol
 * (SMTP).
 * </p>
 * <p>
 * Description Source: http://en.wikipedia.org/wiki/Session_Initiation_Protocol
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header()
public class Sip extends AbstractMessageHeader {

	/**
	 * A table of SIP protocol codes and their meanings.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Code {

		/** Address incomplete field (484). */
		Address_Incomplete(484, "Address Incomplete"),

		/** Alternative service (380). */
		Alternative_Service(380, "Alternative Service"),

		/** Ambiguous (485). */
		Ambiguous(485, "Ambiguous"),

		/** Bad extension (420). */
		Bad_Extension(420, "Bad Extension"),

		/** Bad gateway (502). */
		Bad_Gateway(502, "Bad Gateway"),

		/** Bad request (400). */
		Bad_Request(400, "Bad Request"),

		/** Busy everywhere (600). */
		Busy_Everywhere(600, "Busy Everywhere"),

		/** Busy here (486). */
		Busy_Here(486, "Busy Here"),

		/** Call leg transaction does not exist (481). */
		Call_Leg_Transaction_Does_Not_Exist(481,
				"Call Leg/Transaction Does Not Exist"),

		/** Decline (603). */
		Decline(603, "Decline"),

		/** Does not exist anywhere (604). */
		Does_not_exist_anywhere(604, "Does not exist anywhere"),

		/** Extension required (421). */
		Extension_Required(421, "Extension Required"),

		/** Forbidden (403). */
		Forbidden(403, "Forbidden"),

		/** Gone (410). */
		Gone(410, "Gone"),

		/** Internal Server Error (500). */
		Internal_Server_Error(500, "Internal Server Error"),

		/** Interval too brief (423). */
		Interval_Too_Brief(423, "Interval Too Brief"),

		/** Loop detected (482). */
		Loop_Detected(482, "Loop Detected"),

		/** Message too large (513). */
		Message_Too_Large(513, "Message Too Large"),

		/** Method not allowed (405). */
		Method_Not_Allowed(405, "Method Not Allowed"),

		/** Moved permanently (301). */
		Moved_Permanently(301, "Moved Permanently"),

		/** Moved temporarily (302). */
		Moved_Temporarily(302, "Moved Temporarily"),

		/** Multiple choices (300). */
		MULTIPLE_CHOICES(300, "Multiple Choices"),

		/** Not acceptable here (488). */
		Not_Acceptable_Here(488, "Not Acceptable Here"),

		/** Not acceptable 400 (406). */
		Not_Acceptable400(406, "Not Acceptable"),

		/** Not acceptable 600 (606). */
		Not_Acceptable600(606, "Not Acceptable"),

		/** Not found (404). */
		Not_Found(404, "Not Found"),

		/** Not implemented (501). */
		Not_Implemented(501, "Not Implemented"),

		/** OK (200). */
		OK(200, "OK"),

		/** Payment required (402). */
		Payment_Required(402, "Payment Required"),

		/** Proxy authentication required (407). */
		Proxy_Authentication_Required(407, "Proxy Authentication Required"),

		/** Request entity too large (413). */
		Request_Entity_Too_Large(413, "Request Entity Too Large"),

		/** Request pending (491). */
		Request_Pending(491, "Request Pending"),

		/** Request terminated (487). */
		Request_Terminated(487, "Request Terminated"),

		/** Request timeout (408). */
		Request_Timeout(408, "Request Timeout"),

		/** Request uri too large (414). */
		Request_URI_Too_Large(414, "Request-URI Too Large"),

		/** Server timeout (504). */
		Server_Time_out(504, "Server Time-out"),

		/** Service unavailable (503). */
		Service_Unavailable(503, "Service Unavailable"),

		/** SIP version not supported (505). */
		SIP_Version_not_supported(505, "SIP Version not supported"),

		/** Temporarily not available (480). */
		Temporarily_not_available(480, "Temporarily not available"),

		/** Too many hops (483). */
		Too_Many_Hops(483, "Too Many Hops"),

		/** Unauthorized (401). */
		Unauthorized(401, "Unauthorized"),

		/** Undecipherable (493). */
		Undecipherable(493, "Undecipherable"),

		/** Unsupported media type (415). */
		Unsupported_Media_Type(415, "Unsupported Media Type"),

		/** Unsupported uri scheme (416). */
		Unsupported_URI_Scheme(416, "Unsupported URI Scheme"),

		/** Use proxy (305). */
		Use_Proxy(305, "Use Proxy");

		/** The code. */
		private final int code;

		/** The description. */
		private final String description;

		/**
		 * Instantiates a new code.
		 * 
		 * @param code
		 *            the code
		 * @param description
		 *            the description
		 */
		private Code(final int code, final String description) {
			this.code = code;
			this.description = description;

		}

		/**
		 * Returns the code for this field.
		 * 
		 * @return numerical code value of this feild
		 */
		public final int getCode() {
			return this.code;
		}

		/**
		 * Returns a human readable description of this field.
		 * 
		 * @return a string description of this field
		 */
		public final String getDescription() {
			return this.description;
		}

		/**
		 * Converts a numerical code into a enum constant.
		 * 
		 * @param code
		 *            numerical code value
		 * @return constant if found or null if not convertable
		 */
		public Code valueOf(final int code) {
			for (final Code c : values()) {
				if (c.code == code) {
					return c;
				}
			}

			return null;
		}

		/**
		 * Helper method which expects the code in a string and returns a
		 * corresponding enum constant.
		 * 
		 * @param code
		 *            string containing iteger value
		 * @return corresponding enum code constant or null if not found
		 */
		public Code valueOfUsingCode(final String code) {
			return valueOf(Integer.parseInt(code));
		}

	}

	/**
	 * A table of SIP supported content types.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum ContentType {

		/** Content type other. */
		OTHER,

		/** Application pkcs7-mine type. */
		PKCS7_MIME("application/pkcs7-mime"),

		/** Application pkcs7-signature. */
		PKCS7_SIGNATURE("application/pkcs7-signature"),

		/** DSP content type. */
		SPD("application/SPD"), ;

		/**
		 * Parses a string containing content type ot a enum constant.
		 * 
		 * @param type
		 *            string containing content type
		 * @return constant if found, otherwise returns ContentType.OTHER
		 */
		public static ContentType parseContentType(final String type) {
			if (type == null) {
				return OTHER;
			}

			for (final ContentType t : values()) {
				if (t.name().equalsIgnoreCase(type)) {
					return t;
				}

				for (final String m : t.magic) {
					if (type.startsWith(m)) {
						return t;
					}
				}
			}

			return OTHER;
		}

		/** The magic. */
		private final String[] magic;

		/**
		 * Instantiates a new content type.
		 * 
		 * @param magic
		 *            the magic
		 */
		private ContentType(final String... magic) {
			this.magic = magic;
		}
	}

	/**
	 * A table of SIP specific fields found in a SIP message.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Field
	public enum Fields {

		/** Accept field. */
		Accept,

		/** Accept encoding field. */
		Accept_Encoding,

		/** Accept language field. */
		Accept_Language,

		/** Alert info field. */
		Alert_Info,

		/** Allow field. */
		Allow,

		/** Authentication info field. */
		Authentication_Info,

		/** Authorization field. */
		Authorization,

		/** Call id field. */
		Call_ID,

		/** Call info field. */
		Call_Info,

		/** Contact field. */
		Contact,

		/** Content disposition field. */
		Content_Disposition,

		/** Content encoding field. */
		Content_Encoding,

		/** Content language field. */
		Content_Language,

		/** Content length field (in bytes). */
		Content_Length,

		/** Content type field. */
		Content_Type,

		/** CSequence field. */
		CSeq,

		/** Date field. */
		Date,

		/** Error info field. */
		Error_Info,

		/** Expires field. */
		Expires,

		/** From field. */
		From,

		/** In reply to field. */
		In_Reply_To,

		/** MAX forwards field. */
		Max_Forwards,

		/** MIME version field. */
		MIME_Version,

		/** MIN expires field. */
		Min_Expires,

		/** Organization field. */
		Organization,

		/** Priority field. */
		Priority,

		/** Proxy authenticate field. */
		Proxy_Authenticate,

		/** Proxy authorization field. */
		Proxy_Authorization,

		/** Proxy require field. */
		Proxy_Require,

		/** Record route field. */
		Record_Route,

		/** Reply to field. */
		Reply_To,

		/** Require field. */
		Require,

		/** Retry after field. */
		Retry_After,

		/** Route field. */
		Route,

		/** Server field. */
		Server,

		/** Subject field. */
		Subject,

		/** Supported field. */
		Supported,

		/** Timestamp field. */
		Timestamp,

		/** To field. */
		To,

		/** Unsupported field. */
		Unsupported,

		/** User agent field. */
		User_Agent,

		/** Via field. */
		Via,

		/** Warning field. */
		Warning,

		/** WWW authenticate field. */
		WWW_Authenticate

	}

	/**
	 * A table of supported Request message types.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Field
	public enum Request {

		/** Request type. */
		RequestMethod,

		/** URL field of the request. */
		RequestUrl,

		/** Request version. */
		RequestVersion,

		/** Request user agent. */
		User_Agent,

	}

	/**
	 * A table of supported Response message types.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Field
	public enum Response {

		/** Response url. */
		RequestUrl,

		/** Request version. */
		RequestVersion,

		/** Response code. */
		ResponseCode,

		/** Response code message. */
		ResponseCodeMsg,
	}

	/**
	 * Request method
	 * 
	 * @author Sly Technologies Inc.
	 */
	public enum Method {
		/** [RFC3261] */
		ACK,

		/** [RFC3261] */
		BYE,

		/** [RFC3261] */
		CANCEL,

		/** [RFC6086] */
		INFO,

		/** [RFC3261][RFC6026] */
		INVITE,

		/** [RFC3428] */
		MESSAGE,

		/** [RFC3265] */
		NOTIFY,

		/** [RFC3261] */
		OPTIONS,

		/** [RFC3262] */
		PRACK,

		/** [RFC3903] */
		PUBLISH,

		/** [RFC3515] */
		REFER,

		/** [RFC3261] */
		REGISTER,

		/** [RFC3265] */
		SUBSCRIBE,

		/** [RFC3311] */
		UPDATE

	}

	/** Constant numerial ID for this protocol's header. */
	public static int ID = JProtocol.SIP_ID;
	private Method method;

	/**
	 * Returns the value of the Content_Length field if present.
	 * 
	 * @return returns the value of the field or 0 if field is not preset within
	 *         the message
	 */
	public int contentLength() {
		if (hasField(Fields.Content_Length)) {
			return Integer.parseInt(super.fieldValue(String.class,
					Fields.Content_Length));
		} else {
			return 0;
		}
	}

	/**
	 * Returns the content type of this SIP message.
	 * 
	 * @return A string with value of the Content_Type field
	 */
	public String contentType() {
		return fieldValue(Fields.Content_Type);
	}

	/**
	 * Returns the content type of this SIP message as a enum constant.
	 * 
	 * @return contants from ContentType table
	 */
	public ContentType contentTypeEnum() {
		return ContentType.parseContentType(contentType());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.jnetpcap.packet.AbstractMessageHeader#decodeFirstLine(java.lang.String
	 * )
	 */
	/**
	 * Decode first line.
	 * 
	 * @param line
	 *            the line
	 * @see org.jnetpcap.packet.AbstractMessageHeader#decodeFirstLine(java.lang.String)
	 */
	@Override
	protected void decodeFirstLine(final String line) {
		final String[] c = line.split(" ");
		if (c.length < 3) {
			return; // Can't parse it
		}

		if (c[0].startsWith("SIP")) {
			super.setMessageType(MessageType.RESPONSE);

			super.addField(Response.RequestVersion, c[0], line.indexOf(c[0]));
			super.addField(Response.ResponseCode, c[1], line.indexOf(c[1]));
			super.addField(Response.ResponseCodeMsg, c[2], line.indexOf(c[2]));

			setMethod(null); // Reset

		} else {
			super.setMessageType(MessageType.REQUEST);

			super.addField(Request.RequestMethod, c[0], line.indexOf(c[0]));
			super.addField(Request.RequestUrl, c[1], line.indexOf(c[1]));
			super.addField(Request.RequestVersion, c[2], line.indexOf(c[2]));

			final Method method = Method.valueOf(c[0]);
			setMethod(method);
		}
	}

	@Override
	protected void decodeHeader() {
		super.decodeHeader();
		
		if (getMessageType() == MessageType.RESPONSE) {
			String value = fieldValue(Fields.CSeq);
			if (value != null) {
				String[] c = value.trim().split(" ");
				if (c.length == 2) {
					setMethod(Method.valueOf(c[1]));
				}
			}
		}
	}

	/**
	 * Sets the method for this sip message
	 * 
	 * @param method method or null if not recognized
	 */
	private void setMethod(Method method) {
		this.method = method;
	}

	/**
	 * Gets the "request" method for this Sip message
	 * 
	 * @return method for this sip message or null if not recognized
	 *         (non-standard)
	 */
	public Method getMethod() {
		return this.method;
	}
	
	public boolean hasMethod(Method method) {
		return this.method == method;
	}

	/**
	 * Looks up a field value using Fields table.
	 * 
	 * @param field
	 *            field to lookup
	 * @return the value of the field or null if not present
	 */
	public String fieldValue(final Sip.Fields field) {
		return super.fieldValue(String.class, field);
	}

	/**
	 * Looks up a field value using Request field constant.
	 * 
	 * @param field
	 *            field to lookup
	 * @return the value of the field or null if not present
	 */
	public String fieldValue(final Sip.Request field) {
		return super.fieldValue(String.class, field);
	}

	/**
	 * Looks up a field value using Response field constant.
	 * 
	 * @param field
	 *            field to lookup
	 * @return the value of the field or null if not present
	 */
	public String fieldValue(final Sip.Response field) {
		return super.fieldValue(String.class, field);
	}

	/**
	 * Checks if the message has any content defined.
	 * 
	 * @return true if Content_Type field is used within the message indicating
	 *         that content is preset
	 */
	public boolean hasContent() {
		return hasField(Fields.Content_Type) || hasField(Fields.Content_Type);
	}

	/**
	 * Checks if Content_Type field is present within the message.
	 * 
	 * @return true if content type field is found otherwise false
	 */
	public boolean hasContentType() {
		return hasField(Fields.Content_Type);
	}

	/**
	 * Checks if a specific field is present within the message.
	 * 
	 * @param field
	 *            field to lookup
	 * @return true if field is found within the message otherwise falst
	 */
	public boolean hasField(final Fields field) {
		return super.hasField(field);
	}

	public boolean hasField(final Request field) {
		return super.hasField(field);
	}

	public boolean hasField(final Response field) {
		return super.hasField(field);
	}

	/**
	 * Gets the raw header instead of reconstructing it.
	 * 
	 * @return original raw header
	 */
	public String header() {
		return super.rawHeader;
	}

	/**
	 * Checks if this message is a response message.
	 * 
	 * @return true if response message, otherwise false indicating its a
	 *         request message type
	 */
	public boolean isResponse() {
		return getMessageType() == MessageType.RESPONSE;
	}

}
