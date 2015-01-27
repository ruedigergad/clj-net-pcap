package clj_net_pcap;

import java.io.Serializable;

/**
 * 
 * Simple POJO for storing header data for IPv4 up to UDP.
 * 
 * @author Ruediger Gad
 * 
 */
public interface PacketHeaderDataBeanWithIpv4Udp {

	public long getTs();

	public void setTs(long ts);

	public int getLen();

	public void setLen(int len);

	public int getHdrLen();

	public void setHdrLen(int hdrLen);

	public int getCapLen();

	public void setCapLen(int capLen);

	public String getEthSrc();

	public void setEthSrc(String ethSrc);

	public String getEthDst();

	public void setEthDst(String ethDst);

	public String getIpSrc();

	public void setIpSrc(String ipSrc);

	public String getIpDst();

	public void setIpDst(String ipDst);

	public int getIpVer();

	public void setIpVer(int ipVer);

	public int getIpId();

	public void setIpId(int ipId);

	public int getIpTtl();

	public void setIpTtl(int ipTtl);

	public int getIpChecksum();

	public void setIpChecksum(int ipChecksum);

	public int getUdpSrc();

	public void setUdpSrc(int udpSrc);

	public int getUdpDst();

	public void setUdpDst(int udpDst);

}
