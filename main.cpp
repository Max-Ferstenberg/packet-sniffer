#include <iostream>
#include <sstream>
#include <bitset>
#include <memory>
#include <vector>
#include <string>
#include <cctype>
#include <pcap.h>
#include <limits>
#include <cstring>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

#ifndef TH_PSH
#define TH_PSH TH_PUSH
#endif // TH_PSH

using namespace std;

/*
TODO:
- Implement IPv6 parsing
- Non-ethernet parsing
*/

vector<string> searchDevs();
pcap_t* openDev(const char* d);
void callback(u_char* userarg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void displayPayload(const u_char* payload, u_int payload_len);

int main()
{
    vector<string> availableDevs = searchDevs();
    int devSelect;

    cout << "Please enter the number of the device you'd like to access: ";
    cin >> devSelect;
    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    while (devSelect > static_cast<int>(availableDevs.size()) || (devSelect - 1) < 0){
        cout << "Enter a valid device number: ";
        cin >> devSelect;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
    }

    string dev = availableDevs[devSelect-1];
    cout << "Device: " << dev << " selected." << endl;

    //RAII wrapper for pcap_t
    struct PcapCloser { void operator()(pcap_t* p) const {if (p) pcap_close(p); } };
    using PcapHandle = std::unique_ptr<pcap_t, PcapCloser>;
    PcapHandle handle(openDev(dev.c_str()));
    if (!handle){
        cerr << "Failed to open device." << endl;
        return 1;
    }

    string filterExpr;
    cout << "Enter a filter expression (leave blank for no expression): ";
    getline(cin, filterExpr);
    cout << endl;

    bpf_u_int32 netmask;
    in_addr nm{};
    string netmask_str;

    cout << "Enter a netmask (leave blank for no netmask): ";
    getline(cin, netmask_str);
    cout << endl;

    if (netmask_str.empty()) {
        netmask = PCAP_NETMASK_UNKNOWN;
    } else if (inet_pton(AF_INET, netmask_str.c_str(), &nm) == 1){
        netmask = nm.s_addr;
    } else {
        cerr << "Invalid netmask; using UNKNOWN" << endl;
        netmask = PCAP_NETMASK_UNKNOWN;
    }

    cout << "Netmask set to: " << (netmask == PCAP_NETMASK_UNKNOWN ? "UNKNOWN" : netmask_str) << endl;
    cout << endl;

    struct bpf_program fp;

    if (!filterExpr.empty()) {
        cout << "Compiling filter '" << filterExpr << "'..." << endl;
        if (pcap_compile(handle.get(), &fp, filterExpr.c_str(), 1, netmask) == -1) {
            cerr << "Error compiling filter: " << pcap_geterr(handle.get()) << endl;
            pcap_freecode(&fp); //no need to close manually here; RAII will handle it
            return 1;
        }

        cout << "Setting filter..." << endl;
        if (pcap_setfilter(handle.get(), &fp) == -1) {
            cerr << "Error setting filter: " << pcap_geterr(handle.get()) << endl;
            pcap_freecode(&fp);
            return 1;
        }

        pcap_freecode(&fp);
    } else {
        cout << "No filter expression provided. Capturing all packets." << endl;
    }

    cout << "Enter the number of packets you would like to capture: ";
    int cnt;
    cin >> cnt;
    cout << endl;

    int rc = pcap_loop(handle.get(), cnt, callback, nullptr);
    if (rc == -1) {
        cerr << "pcap_loop error: " << pcap_geterr(handle.get()) << endl;
    } else if (rc == -2) cout << "Capture stopped by breakloop" << endl;

    return 0;
}

vector<string> searchDevs(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp = nullptr;
    if (pcap_findalldevs(&alldevsp, errbuf) == PCAP_ERROR){
        cout << "Error finding devices" << endl;
        return {};
    }

    cout << "Devices found: " << endl;
    pcap_if_t *d;
    int i = 0;
    vector<string> availableDevs = {};

    for(d = alldevsp; d != nullptr; d = d->next){
        cout << ++i << "." << d->name;
        availableDevs.push_back(d->name);
        if (d->description){
            cout << "(" << d->description << ")";
        }
        cout << endl;
    }

    pcap_freealldevs(alldevsp);

    return availableDevs;
}

pcap_t* openDev(const char* d){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(d, 262144, 1, 1, errbuf);
    if (handle == NULL){
        cout << "Error opening device: " << d << " with error: " << errbuf << endl;
        return handle;
    }

    cout << "Device: " << d << " opened." << endl;
    return handle;
}

void callback(u_char* userarg, const struct pcap_pkthdr* pkthdr, const u_char* packet_pointer){
    //in here is where you tell the program what to do with the packets
    static int cnt = 1;
    time_t sec = pkthdr->ts.tv_sec;
    char tbuf[64];
    strftime(tbuf, sizeof tbuf, "%Y-%m-%d %H:%M:%S", localtime(&sec));
    cout << "Packet " << cnt << " captured with length " << pkthdr->caplen << " at " << tbuf << "." << pkthdr->ts.tv_usec << endl;
    cnt++;
    /*
    - Read first byte of packet header to determine ethertype and protocol (Link Layer - Layer 2)
    - Use protocol declaration from layer 2 to parse Layer 3 - Network layer
    - Layer 3 should tell you what (if anything) is on Layer 4 - The Transport Layer
    */

    auto advance = [&](const u_char*& p, u_int& rem, u_int n) -> bool {
        if (rem < n) { cout << "Truncated packet\n"; rem = 0; return false; }
        p += n; rem -= n; return true;
    };

    u_int rem_pointer = pkthdr->caplen;
    //pointer arithmetic. This says to move the current pointer along in memory however many bytes the ethernet header is taking up
    if (!advance(packet_pointer, rem_pointer, sizeof(ether_header))) return;
    const struct ether_header* eth_header = reinterpret_cast<const struct ether_header*>(packet_pointer - sizeof(ether_header));


    auto read_u16_be = [](const u_char* p){
        uint16_t v; memcpy(&v, p, 2); return ntohs(v);
    };

    uint16_t eth_type = ntohs(eth_header->ether_type);
    if (eth_type == 0x8100 || eth_type == 0x88a8){
        if (!advance(packet_pointer, rem_pointer, 2)) return; // TCI
        if (!advance(packet_pointer, rem_pointer, 2)) return; // inner EtherType
        eth_type = read_u16_be(packet_pointer - 2);
    }
    cout << "EtherType: 0x" << hex << eth_type << dec << endl;

    auto fmt_mac = [](const u_char* m){ // Lambda function: [] is outside conditions, e.g. other variables it should use, the rest is like defining a regular function. auto lets the compiler decide what the return value should be.
        char buf[18];
        snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                m[0], m[1], m[2], m[3], m[4], m[5]);
        return string(buf);
    };
    cout << "Source MAC address: " << fmt_mac(eth_header->ether_shost) << " Destination MAC address: " << fmt_mac(eth_header->ether_dhost) << endl;


    if(eth_type == ETHERTYPE_IP){
        if (rem_pointer < sizeof(ip)) {cout << "Truncated IPv4 header" << endl; return;}

        ip ip_local{};
        memcpy(&ip_local, packet_pointer, sizeof(ip));
        const struct ip* ip_hdr = &ip_local;

        if (ip_hdr->ip_v != 4) { cout << "Not IPv4" << endl; return;}

        uint32_t ip_hlen = ip_hdr->ip_hl * 4;
        if (ip_hlen < 20 || rem_pointer < ip_hlen){
            cout << "Bad IPv4 header length (" << ip_hlen << ")" << endl;
            return;
        }

        cout << "Source IP: " << inet_ntoa(ip_hdr->ip_src) << " Destination IP: " << inet_ntoa(ip_hdr->ip_dst) << endl;

        uint16_t ip_total = ntohs(ip_hdr->ip_len);
        uint32_t l3_payload_len = (ip_total >= ip_hlen) ? (ip_total - ip_hlen) : 0;

        if (!advance(packet_pointer, rem_pointer, ip_hlen)) return;

        if(ip_hdr->ip_p == IPPROTO_TCP){
            cout << "Protocol: TCP" << endl;
            if (rem_pointer < sizeof(tcphdr)) {cout << "Truncated TCP header" << endl; return;}
            const struct tcphdr* tcp_hdr = reinterpret_cast<const struct tcphdr*>(packet_pointer);
            uint32_t tcp_hlen = tcp_hdr->th_off * 4; // data offset in 32-bit words
            if (tcp_hlen < 20 || rem_pointer < tcp_hlen) {
                cout << "Bad/Truncated TCP header length (" << tcp_hlen << ")" << endl;
                return;
            }
            uint32_t tcp_payload_len = (l3_payload_len > tcp_hlen) ? (l3_payload_len - tcp_hlen) : 0;
            cout << "Source Port: " << ntohs(tcp_hdr->th_sport) << endl;
            cout << "Destination port: " << ntohs(tcp_hdr->th_dport) << endl;
            uint8_t flags = tcp_hdr->th_flags;
            cout << "Flags: "
                 << ((flags & TH_SYN) ? "SYN " : "") // ? IF_TRUE : IF_FALSE - this is saying if the flags have SYN, ACK, etc. set, do the LHS of the : if true, RHS if false.
                 << ((flags & TH_ACK) ? "ACK " : "")
                 << ((flags & TH_FIN) ? "FIN " : "")
                 << ((flags & TH_PSH) ? "PSH" : "")
                 << ((flags & TH_URG) ? "URG" : "")
                 << ((flags & TH_RST) ? "RST " : "") << endl;

            if (!advance(packet_pointer, rem_pointer, tcp_hlen)) return;
            //the packet pointer now points at the TCP payload; size of this is min(tcp_payload_len, rem_pointer)
            displayPayload(packet_pointer, min<uint32_t>(tcp_payload_len, rem_pointer));
        }

        else if(ip_hdr->ip_p == IPPROTO_UDP){
            cout << "Protocol: UDP" << endl;
            if (rem_pointer < sizeof(udphdr)) {cout << "Truncated UDP header" << endl; return;}
            const struct udphdr* udp_hdr = reinterpret_cast<const struct udphdr*>(packet_pointer);
            uint16_t udp_hlen = ntohs(udp_hdr->uh_ulen); // hdr + payload
            if (udp_hlen < sizeof(udphdr)) {cout << "Bad UDP length" << endl; return;}
            uint32_t udp_payload_len = udp_hlen - sizeof(udphdr);

            cout << "Source Port: " << ntohs(udp_hdr->uh_sport) << endl;
            cout << "Destination Port: " << ntohs(udp_hdr->uh_dport) << endl;
            cout << "Checksum: " << ntohs(udp_hdr->uh_sum) << endl;

            if (!advance(packet_pointer, rem_pointer, sizeof(udphdr))) return;

            displayPayload(packet_pointer, min<uint32_t>(udp_payload_len, rem_pointer));
        }

        else if(ip_hdr->ip_p == IPPROTO_ICMP){
            cout << "Protocol: ICMP" << endl;
            if (rem_pointer < sizeof(icmphdr)) {cout << "Truncated ICMP header" << endl; return;}
            const struct icmphdr* icmp_hdr = reinterpret_cast<const struct icmphdr*>(packet_pointer);
            cout << "ICMP type: " << unsigned(icmp_hdr->type)
                 << " code : " << unsigned(icmp_hdr->code)
                 << " checksum: " << ntohs(icmp_hdr->checksum) << endl;

            uint32_t icmp_payload_len = (l3_payload_len >= sizeof(icmphdr)) ? (l3_payload_len - sizeof(icmphdr)) : 0;
            if(!advance(packet_pointer, rem_pointer, sizeof(icmphdr))) return;

            displayPayload(packet_pointer, min<uint32_t>(icmp_payload_len, rem_pointer));
        }

        else{
            cout << "Protocol: " << (int)ip_hdr->ip_p << endl;
        }
    }

    else if (eth_type == ETHERTYPE_ARP){
        cout << "Link Layer: Ethernet ARP" << endl;
        if (rem_pointer < sizeof(arphdr)) { cout << "Truncated ARP header" << endl; return;}
        const struct arphdr* arp_hdr = reinterpret_cast<const struct arphdr*>(packet_pointer);
        if (!advance(packet_pointer, rem_pointer, sizeof(arphdr))) return;

        if (arp_hdr->ar_hrd == ARPHRD_ETHER && arp_hdr->ar_pro == ETHERTYPE_IP && arp_hdr->ar_hln == 6 && arp_hdr->ar_pln == 4){
            fmt_mac(packet_pointer); // should be pointing at sha now
            fmt_mac(packet_pointer + arp_hdr->ar_hln + arp_hdr->ar_pln);
        }

    } else {
        cout << "Other Ethernet Type: " << eth_type << endl;
    }

    cout << "----------------------------------------" << endl;

}

void displayPayload(const u_char* payload, u_int payload_len){
    if (payload == nullptr || payload_len == 0){
        cout << "Payload Empty" << endl;
        return;
    }

    cout << "Payload: ";
    for (u_int i = 0; i < payload_len; i++){
        if(isprint(payload[i])){
            cout << payload[i];
        } else {
            cout << ".";
        }
    }
    cout << endl;
}
