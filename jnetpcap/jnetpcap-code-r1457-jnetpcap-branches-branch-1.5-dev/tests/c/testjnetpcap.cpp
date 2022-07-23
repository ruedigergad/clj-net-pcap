#include <iostream>
using namespace std;

#include <pcap.h>
#include <Win32-Extensions.h>

int main() {
	
	char errbuf[1024];
	char source[1024];
	strcpy(source, "rpcap://\\Device\\PF_{BC81C4FC-242F-4F1C-9DAD-EA9523CC992D}");
	char device[1024];
	strcpy(device, "\\Device\\NPF_{04BD71F0-BAD6-4C51-96A4-B05562FAD4F9}");
	
	cout << "source=" << source << "\n";
	
	int snap = 64 * 1024;
	int flags = 8;
	int timeout = 1000;
	pcap_rmtauth *auth = NULL;
	
	cout << "BEFORE\n";
//	pcap_t *p = pcap_open_live(device, snap, flags, timeout, errbuf);
	pcap_t *p = pcap_open(source, snap, flags, timeout, auth, errbuf);
	cout << "AFTER\n";
	
	if(p != NULL) {
		pcap_close(p);
	}
	cout << "CLOSE\n";

	return 0;
}
