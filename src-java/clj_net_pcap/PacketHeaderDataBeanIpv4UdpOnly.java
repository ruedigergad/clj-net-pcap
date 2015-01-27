package clj_net_pcap;

import java.io.Serializable;

/**
 * 
 * Simple POJO for storing header data for IPv4 up to UDP.
 * 
 * @author Ruediger Gad
 * 
 */
public class PacketHeaderDataBeanIpv4UdpOnly implements Serializable, PacketHeaderDataBeanWithIpv4Udp {

    public static final long serialVersionUID = 1L;

	/*
	 * General pcap information
	 */
	public long ts = 0;
	public int len = 0;
	public int hdrLen = 0;
	public int capLen = 0;

	/*
	 * Ethernet
	 */
	public String ethSrc;
	public String ethDst;

	/*
	 * IP
	 */
	public String ipSrc;
	public String ipDst;
	public int ipVer = 0;
	public int ipId = -1;
	public int ipTtl = -1;
	public int ipChecksum = -1;

	/*
	 * UDP
	 */
	public int udpSrc = 0;
	public int udpDst = 0;

	/*
	 * Getter and setter
	 */
	public long getTs() {
		return ts;
	}

	public void setTs(long ts) {
		this.ts = ts;
	}

	public int getLen() {
		return len;
	}

	public void setLen(int len) {
		this.len = len;
	}

	public int getHdrLen() {
		return hdrLen;
	}

	public void setHdrLen(int hdrLen) {
		this.hdrLen = hdrLen;
	}

	public int getCapLen() {
		return capLen;
	}

	public void setCapLen(int capLen) {
		this.capLen = capLen;
	}

	public String getEthSrc() {
		return ethSrc;
	}

	public void setEthSrc(String ethSrc) {
		this.ethSrc = ethSrc;
	}

	public String getEthDst() {
		return ethDst;
	}

	public void setEthDst(String ethDst) {
		this.ethDst = ethDst;
	}

	public String getIpSrc() {
		return ipSrc;
	}

	public void setIpSrc(String ipSrc) {
		this.ipSrc = ipSrc;
	}

	public String getIpDst() {
		return ipDst;
	}

	public void setIpDst(String ipDst) {
		this.ipDst = ipDst;
	}

	public int getIpVer() {
		return ipVer;
	}

	public void setIpVer(int ipVer) {
		this.ipVer = ipVer;
	}

	public int getIpId() {
		return ipId;
	}

	public void setIpId(int ipId) {
		this.ipId = ipId;
	}

	public int getIpTtl() {
		return ipTtl;
	}

	public void setIpTtl(int ipTtl) {
		this.ipTtl = ipTtl;
	}

	public int getIpChecksum() {
		return ipChecksum;
	}

	public void setIpChecksum(int ipChecksum) {
		this.ipChecksum = ipChecksum;
	}

	public int getUdpSrc() {
		return udpSrc;
	}

	public void setUdpSrc(int udpSrc) {
		this.udpSrc = udpSrc;
	}

	public int getUdpDst() {
		return udpDst;
	}

	public void setUdpDst(int udpDst) {
		this.udpDst = udpDst;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("PacketHeaderDataBean: ");
		if (ts > 0) {
			builder.append("ts=");
			builder.append(ts);
		}
		if (len > 0) {
			builder.append(", len=");
			builder.append(len);
		}
		if (hdrLen > 0) {
			builder.append(", hdrLen=");
			builder.append(hdrLen);
		}
		if (capLen > 0) {
			builder.append(", capLen=");
			builder.append(capLen);
		}
		builder.append(", ");
		if (ethSrc != null) {
			builder.append("ethSrc=");
			builder.append(ethSrc);
			builder.append(", ");
		}
		if (ethDst != null) {
			builder.append("ethDst=");
			builder.append(ethDst);
			builder.append(", ");
		}
		if (ipSrc != null) {
			builder.append("ipSrc=");
			builder.append(ipSrc);
			builder.append(", ");
		}
		if (ipDst != null) {
			builder.append("ipDst=");
			builder.append(ipDst);
			builder.append(", ");
		}
		if (ipVer > 0) {
			builder.append("ipVer=");
			builder.append(ipVer);
			builder.append(", ");
		}
		if (ipId > -1) {
			builder.append("ipId=");
			builder.append(ipId);
			builder.append(", ");
		}
		if (ipTtl > -1) {
			builder.append("ipTtl=");
			builder.append(ipTtl);
			builder.append(", ");
		}
		if (ipChecksum > -1) {
			builder.append("ipChecksum=");
			builder.append(ipChecksum);
			builder.append(", ");
		}
		if (udpSrc > 0) {
			builder.append(", udpSrc=");
			builder.append(udpSrc);
		}
		if (udpDst > 0) {
			builder.append(", udpDst=");
			builder.append(udpDst);
		}
		builder.append("]");
		return builder.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + capLen;
		result = prime * result + ((ethDst == null) ? 0 : ethDst.hashCode());
		result = prime * result + ((ethSrc == null) ? 0 : ethSrc.hashCode());
		result = prime * result + hdrLen;
		result = prime * result + ((ipDst == null) ? 0 : ipDst.hashCode());
		result = prime * result + ((ipSrc == null) ? 0 : ipSrc.hashCode());
		result = prime * result + ipVer;
		result = prime * result + ipId;
		result = prime * result + ipTtl;
		result = prime * result + ipChecksum;
		result = prime * result + len;
		result = prime * result + (int) (ts ^ (ts >>> 32));
		result = prime * result + udpDst;
		result = prime * result + udpSrc;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof PacketHeaderDataBeanIpv4UdpOnly))
			return false;
		PacketHeaderDataBeanIpv4UdpOnly other = (PacketHeaderDataBeanIpv4UdpOnly) obj;
		if (capLen != other.capLen)
			return false;
		if (ethDst == null) {
			if (other.ethDst != null)
				return false;
		} else if (!ethDst.equals(other.ethDst))
			return false;
		if (ethSrc == null) {
			if (other.ethSrc != null)
				return false;
		} else if (!ethSrc.equals(other.ethSrc))
			return false;
		if (hdrLen != other.hdrLen)
			return false;
		if (ipDst == null) {
			if (other.ipDst != null)
				return false;
		} else if (!ipDst.equals(other.ipDst))
			return false;
		if (ipSrc == null) {
			if (other.ipSrc != null)
				return false;
		} else if (!ipSrc.equals(other.ipSrc))
			return false;
		if (ipVer != other.ipVer)
			return false;
		if (ipId != other.ipId)
			return false;
		if (ipTtl != other.ipTtl)
			return false;
		if (ipChecksum != other.ipChecksum)
			return false;
		if (len != other.len)
			return false;
		if (ts != other.ts)
			return false;
		if (udpDst != other.udpDst)
			return false;
		if (udpSrc != other.udpSrc)
			return false;
		return true;
	}

}
