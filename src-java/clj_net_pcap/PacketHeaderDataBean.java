package clj_net_pcap;

/**
 * 
 * Simple POJO for storing header data.
 * 
 * @author Ruediger Gad
 *
 */
public class PacketHeaderDataBean {

	/*
	 * General pcap information
	 */
	private long ts;
	private int len;
	private int hdrLen;
	private int capLen;
	
	/*
	 * Ethernet
	 */
	private String ethSrc;
	private String ethDst;
	
	/*
	 * ARP
	 */
	private String arpOpDesc;
	private String arpTargetMac;
	private String arpTargetIp;
	private String arpSourceMac;
	private String arpSourceIp;
	
	/*
	 * IPv4 
	 */
	private String ip4Src;
	private String ip4Dst;
	
	/*
	 * IPv6
	 */
	private String ip6Src;
	private String ip6Dst;

	/*
	 * ICMP
	 */
	private String icmpType;
	private String icmpEchoSeq;

	/*
	 * TCP
	 */
	private int tcpSrc;
	private int tcpDst;
	private long tcpAck;
	private long tcpSeq;
	private int tcpFlags;
	private long tcpTsval;
	private long tcpTsecr;
	
	/*
	 * UDP
	 */
	private int udpSrc;
	private int udpDst;
	
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
	public String getArpOpDesc() {
		return arpOpDesc;
	}
	public void setArpOpDesc(String arpOpDesc) {
		this.arpOpDesc = arpOpDesc;
	}
	public String getArpTargetMac() {
		return arpTargetMac;
	}
	public void setArpTargetMac(String arpTargetMac) {
		this.arpTargetMac = arpTargetMac;
	}
	public String getArpTargetIp() {
		return arpTargetIp;
	}
	public void setArpTargetIp(String arpTargetIp) {
		this.arpTargetIp = arpTargetIp;
	}
	public String getArpSourceMac() {
		return arpSourceMac;
	}
	public void setArpSourceMac(String arpSourceMac) {
		this.arpSourceMac = arpSourceMac;
	}
	public String getArpSourceIp() {
		return arpSourceIp;
	}
	public void setArpSourceIp(String arpSourceIp) {
		this.arpSourceIp = arpSourceIp;
	}
	public String getIp4Src() {
		return ip4Src;
	}
	public void setIp4Src(String ip4Src) {
		this.ip4Src = ip4Src;
	}
	public String getIp4Dst() {
		return ip4Dst;
	}
	public void setIp4Dst(String ip4Dst) {
		this.ip4Dst = ip4Dst;
	}
	public String getIp6Src() {
		return ip6Src;
	}
	public void setIp6Src(String ip6Src) {
		this.ip6Src = ip6Src;
	}
	public String getIp6Dst() {
		return ip6Dst;
	}
	public void setIp6Dst(String ip6Dst) {
		this.ip6Dst = ip6Dst;
	}
	public String getIcmpType() {
		return icmpType;
	}
	public void setIcmpType(String icmpType) {
		this.icmpType = icmpType;
	}
	public String getIcmpEchoSeq() {
		return icmpEchoSeq;
	}
	public void setIcmpEchoSeq(String icmpEchoSeq) {
		this.icmpEchoSeq = icmpEchoSeq;
	}
	public int getTcpSrc() {
		return tcpSrc;
	}
	public void setTcpSrc(int tcpSrc) {
		this.tcpSrc = tcpSrc;
	}
	public int getTcpDst() {
		return tcpDst;
	}
	public void setTcpDst(int tcpDst) {
		this.tcpDst = tcpDst;
	}
	public long getTcpAck() {
		return tcpAck;
	}
	public void setTcpAck(long tcpAck) {
		this.tcpAck = tcpAck;
	}
	public long getTcpSeq() {
		return tcpSeq;
	}
	public void setTcpSeq(long tcpSeq) {
		this.tcpSeq = tcpSeq;
	}
	public int getTcpFlags() {
		return tcpFlags;
	}
	public void setTcpFlags(int tcpFlags) {
		this.tcpFlags = tcpFlags;
	}
	public long getTcpTsval() {
		return tcpTsval;
	}
	public void setTcpTsval(long tcpTsval) {
		this.tcpTsval = tcpTsval;
	}
	public long getTcpTsecr() {
		return tcpTsecr;
	}
	public void setTcpTsecr(long tcpTsecr) {
		this.tcpTsecr = tcpTsecr;
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
	
}
