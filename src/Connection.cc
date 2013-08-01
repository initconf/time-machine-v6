#include "types.h"
#include <string>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sstream>
#include "re2/re2.h"
//#include "IP6Address.hh"
#include "Connection.hh"
#include "packet_headers.h"
#include "Fifo.hh"
#include "Query.hh"
#include "tm.h"


static std::string pattern_ip ("(\\d+\\.\\d+\\.\\d+\\.\\d+)");
static std::string pattern_ipport ("(\\d+\\.\\d+\\.\\d+\\.\\d+):(\\d+)");

const H3<uint32_t, UHASH_KEY_SIZE>* h3fcn;







const uint8_t IP6Address::v4_mapped_prefix[12] = { 0, 0, 0, 0,
                                                   0, 0, 0, 0,
                                                   0, 0, 0xff, 0xff };


void IP6Address::Mask(int top_bits_to_keep)
	{
	if ( top_bits_to_keep < 0 || top_bits_to_keep > 128 )
		{
		//reporter->Error("Bad IP6Address::Mask value %d", top_bits_to_keep);
		return;
		}

	uint32_t tmp[4];
	memcpy(tmp, in6.s6_addr, sizeof(in6.s6_addr));

	int word = 3;
	int bits_to_chop = 128 - top_bits_to_keep;

	while ( bits_to_chop >= 32 )
		{
		tmp[word] = 0;
		--word;
		bits_to_chop -= 32;
		}

	uint32_t w = ntohl(tmp[word]);
	w >>= bits_to_chop;
	w <<= bits_to_chop;
	tmp[word] = htonl(w);

	memcpy(in6.s6_addr, tmp, sizeof(in6.s6_addr));
	}

void IP6Address::ReverseMask(int top_bits_to_chop)
	{
	if ( top_bits_to_chop < 0 || top_bits_to_chop > 128 )
		{
		//reporter->Error("Bad IP6Address::ReverseMask value %d", top_bits_to_chop);
		return;
		}

	uint32_t tmp[4];
	memcpy(tmp, in6.s6_addr, sizeof(in6.s6_addr));

	int word = 0;
	int bits_to_chop = top_bits_to_chop;

	while ( bits_to_chop >= 32 )
		{
		tmp[word] = 0;
		++word;
		bits_to_chop -= 32;
		}

	uint32_t w = ntohl(tmp[word]);
	w <<= bits_to_chop;
	w >>= bits_to_chop;
	tmp[word] = htonl(w);

	memcpy(in6.s6_addr, tmp, sizeof(in6.s6_addr));
	}

void IP6Address::init(const std::string& s)
	{
	if ( s.find(':') == std::string::npos ) // IPv4.
		{
		memcpy(in6.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));

		// Parse the address directly instead of using inet_pton since
		// some platforms have more sensitive implementations than others
		// that can't e.g. handle leading zeroes.
		int a[4];
		int n = sscanf(s.c_str(), "%d.%d.%d.%d", a+0, a+1, a+2, a+3);

		if ( n != 4 || a[0] < 0 || a[1] < 0 || a[2] < 0 || a[3] < 0 ||
		     a[0] > 255 || a[1] > 255 || a[2] > 255 || a[3] > 255 )
			{
			//reporter->Error("Bad IP address: %s", s.c_str());
			memset(in6.s6_addr, 0, sizeof(in6.s6_addr));
			return;
			}

		uint32_t addr = (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
		addr = htonl(addr);
		memcpy(&in6.s6_addr[12], &addr, sizeof(uint32_t));
		}

	else
		{
		if ( inet_pton(AF_INET6, s.c_str(), in6.s6_addr) <=0 )
			{
			//reporter->Error("Bad IP address: %s", s.c_str());
			memset(in6.s6_addr, 0, sizeof(in6.s6_addr));
			}
		}
	}

std::string IP6Address::AsString() const
	{
	if ( GetFamily() == IPv4 )
		{
		char s[INET_ADDRSTRLEN];

		if ( ! inet_ntop(AF_INET, &in6.s6_addr[12], s, INET_ADDRSTRLEN) )
			return "<bad IPv4 address conversion";
		else
			return s;
		}
	else
		{
		char s[INET6_ADDRSTRLEN];

		if ( ! inet_ntop(AF_INET6, in6.s6_addr, s, INET6_ADDRSTRLEN) )
			return "<bad IPv6 address conversion";
		else
			return s;
		}
	}

std::string IP6Address::AsHexString() const
	{
	char buf[33];

	if ( GetFamily() == IPv4 )
		{
		uint32_t* p = (uint32_t*) &in6.s6_addr[12];
		snprintf(buf, sizeof(buf), "%08x", (uint32_t) ntohl(*p));
		}
	else
		{
		uint32_t* p = (uint32_t*) in6.s6_addr;
		snprintf(buf, sizeof(buf), "%08x%08x%08x%08x",
				(uint32_t) ntohl(p[0]), (uint32_t) ntohl(p[1]),
				(uint32_t) ntohl(p[2]), (uint32_t) ntohl(p[3]));
		}

	return buf;
	}

std::string IP6Address::PtrName() const
	{
	if ( GetFamily() == IPv4 )
		{
		char buf[256];
		uint32_t* p = (uint32_t*) &in6.s6_addr[12];
		uint32_t a = ntohl(*p);
		uint32_t a3 = (a >> 24) & 0xff;
		uint32_t a2 = (a >> 16) & 0xff;
		uint32_t a1 = (a >> 8) & 0xff;
		uint32_t a0 = a & 0xff;
		snprintf(buf, sizeof(buf), "%u.%u.%u.%u.in-addr.arpa", a0, a1, a2, a3);
		return buf;
		}
	else
		{
		static const char hex_digit[] = "0123456789abcdef";
		std::string ptr_name("ip6.arpa");
		uint32_t* p = (uint32_t*) in6.s6_addr;

		for ( unsigned int i = 0; i < 4; ++i )
			{
			uint32_t a = ntohl(p[i]);
			for ( unsigned int j = 1; j <=8; ++j )
				{
				ptr_name.insert(0, 1, '.');
				ptr_name.insert(0, 1, hex_digit[(a >> (32-j*4)) & 0x0f]);
				}
			}

		return ptr_name;
		}
	}



/****************************************
*****************************************
****************************************/


void init_H3()
	{
	tmlog(TM_LOG_NOTE, "init_H3", "******** h3fcn has been created!!!!!!!! *********");
	h3fcn = new H3<uint32_t, UHASH_KEY_SIZE>();
	}

uint32_t hashword(
const uint32_t *k,                   /* the key, an array of uint32_t values */
size_t          length,               /* the length of the key, in uint32_ts */
uint32_t        initval);         /* the previous hash, or an arbitrary value */
inline uint32_t revert_uint32(uint32_t i) {
	uint32_t r;
	((uint8_t*)&r)[0]=((uint8_t*)&i)[3];
	((uint8_t*)&r)[1]=((uint8_t*)&i)[2];
	((uint8_t*)&r)[2]=((uint8_t*)&i)[1];
	((uint8_t*)&r)[3]=((uint8_t*)&i)[0];

	return r;
}

inline uint16_t revert_uint16(uint16_t i) {
	uint16_t r;
	((uint8_t*)&r)[0]=((uint8_t*)&i)[1];
	((uint8_t*)&r)[1]=((uint8_t*)&i)[0];

	return r;
}

inline bool addr_port_canon_lt(IP6Address s_ip, IP6Address d_ip,
							   uint16_t s_port, uint16_t d_port) {
	if (s_ip == d_ip)
		return (s_port < d_port);
	else
		return (s_ip < d_ip);
}


uint32_t IP6Address::hash() const {
	in6_addr ip1;
	memcpy(ip1.s6_addr, in6.s6_addr, sizeof(in6.s6_addr));
	return (*h3fcn)(&ip1, sizeof(ip1));
}


uint32_t ConnectionID4::hash() const { 
	//TODO: initval

	struct {
		in6_addr ip1;
		in6_addr ip2;
		uint16_t port1;
		uint16_t port2;
		proto_t proto;
	} __attribute__((packed)) key ;

	v.ip1.CopyIP6Address(&key.ip1);
	v.ip2.CopyIP6Address(&key.ip2);
	key.port1 = v.port1;
	key.port2 = v.port2;
	key.proto = v.proto;

	return (*h3fcn)(&key, sizeof(key));
}

uint32_t ConnectionID3::hash() const { 
	//TODO: initval

	struct {
		in6_addr ip1;
		in6_addr ip2;
		uint16_t port2;
		proto_t proto;
	} __attribute__((packed)) key;

	v.ip1.CopyIP6Address(&key.ip1);
	v.ip2.CopyIP6Address(&key.ip2);
	key.port2 = v.port2;
	key.proto = v.proto;

	return (*h3fcn)(&key, sizeof(key));
}

uint32_t ConnectionID2::hash() const { 
	//TODO: initval

	struct {
		in6_addr ip1;
		in6_addr ip2;	
	} __attribute__((packed)) key;

	v.ip1.CopyIP6Address(&key.ip1);
	v.ip2.CopyIP6Address(&key.ip2);

	return (*h3fcn)(&key, sizeof(key));
}




void ConnectionID4::init(proto_t proto,
						 IP6Address s_ip, IP6Address d_ip,
						 uint16_t s_port, uint16_t d_port) {
	v.proto=proto;
	if (addr_port_canon_lt(s_ip,d_ip,s_port,d_port)) {
		//    v.is_canonified=true;
		v.ip1=d_ip;
		v.ip2=s_ip;
		v.port1=d_port;
		v.port2=s_port;
	} else {
		//    v.is_canonified=false;
		v.ip1=s_ip;
		v.ip2=d_ip;
		v.port1=s_port;
		v.port2=d_port;
	}
}

void ConnectionID3::init(proto_t proto,
						 IP6Address ip1, IP6Address ip2,
						 uint16_t port2) {
	v.proto=proto;
	v.ip1=ip1;
	v.ip2=ip2;
	v.port2=port2;
}

void ConnectionID2::init(IP6Address s_ip, IP6Address d_ip) {
	if (addr_port_canon_lt(s_ip,d_ip,0,0)) {
		//    v.is_canonified=true;
		v.ip1=d_ip;
		v.ip2=s_ip;
	} else {
		//    v.is_canonified=false;
		v.ip1=s_ip;
		v.ip2=d_ip;
	}
}

//******NEEDS TO TEST FOR IPV6*/	
ConnectionID4::ConnectionID4(const u_char* packet) {

	switch (IPV(packet)) {
	case IPv4:
		switch (IP(packet)->ip_p) {
		case IPPROTO_UDP:
			init(IP(packet)->ip_p,
				 IP6Address(IP(packet)->ip_src.s_addr), 
				 IP6Address(IP(packet)->ip_dst.s_addr),
				 UDP(packet)->uh_sport, UDP(packet)->uh_dport);
			break;
		case IPPROTO_TCP:
			init(IP(packet)->ip_p,
				 IP6Address(IP(packet)->ip_src.s_addr), 
				 IP6Address(IP(packet)->ip_dst.s_addr),
				 TCP(packet)->th_sport, TCP(packet)->th_dport);
			break;
		default:
			init(IP(packet)->ip_p,
				 IP6Address(IP(packet)->ip_src.s_addr), 
				 IP6Address(IP(packet)->ip_dst.s_addr), 0, 0);
			break;
		} break;
	case IPv6:
		switch (IP6_NXT_HDR(packet)) {
		case IPPROTO_UDP:
			init(IP6_NXT_HDR(packet),
				 IP6Address(IP6(packet)->ip6_src), 
				 IP6Address(IP6(packet)->ip6_dst),
				 UDP(packet)->uh_sport, UDP(packet)->uh_dport);
			break;
		case IPPROTO_TCP:
			init(IP6_NXT_HDR(packet),
				 IP6Address(IP6(packet)->ip6_src), 
				 IP6Address(IP6(packet)->ip6_dst),
				 TCP(packet)->th_sport, TCP(packet)->th_dport);
			break;
		default:
			init(IP6_NXT_HDR(packet),
				 IP6Address(IP6(packet)->ip6_src), 
				 IP6Address(IP6(packet)->ip6_dst), 0, 0);
			break;
		} break;
	default:
		break;	

	}

}


ConnectionID3::ConnectionID3(const u_char* packet, int wildcard_port) {
	
	switch (IPV(packet)) {
	case IPv4:
		switch (IP(packet)->ip_p) {
		case IPPROTO_UDP:
			if (wildcard_port) 
				init(IP(packet)->ip_p,
					 IP6Address(IP(packet)->ip_src.s_addr), 
				 	 IP6Address(IP(packet)->ip_dst.s_addr),
					 UDP(packet)->uh_dport);
			else
				init(IP(packet)->ip_p,
					 IP6Address(IP(packet)->ip_dst.s_addr), 
					 IP6Address(IP(packet)->ip_src.s_addr),
					 UDP(packet)->uh_sport);
			break;
		case IPPROTO_TCP:
			if (wildcard_port) 
				init(IP(packet)->ip_p,
					 IP6Address(IP(packet)->ip_src.s_addr), 
					 IP6Address(IP(packet)->ip_dst.s_addr),
					 TCP(packet)->th_dport);
			else
				init(IP(packet)->ip_p,
					 IP6Address(IP(packet)->ip_dst.s_addr), 
					 IP6Address(IP(packet)->ip_src.s_addr),
					 TCP(packet)->th_sport);
			break;
		default:
			if (wildcard_port) 
				init(IP(packet)->ip_p,
					 IP6Address(IP(packet)->ip_src.s_addr), 
					 IP6Address(IP(packet)->ip_dst.s_addr),
					 0);
			else
				init(IP(packet)->ip_p,
					 IP6Address(IP(packet)->ip_dst.s_addr), 
					 IP6Address(IP(packet)->ip_src.s_addr),
					 0);
			break;
		}break;
	case IPv6:
		switch (IP6_NXT_HDR(packet)) {
		case IPPROTO_UDP:
			if (wildcard_port) 
				init(IP6_NXT_HDR(packet),
					 IP6Address(IP6(packet)->ip6_src), 
					 IP6Address(IP6(packet)->ip6_dst),
					 UDP(packet)->uh_dport);
			else
				init(IP6_NXT_HDR(packet),
					 IP6Address(IP6(packet)->ip6_dst), 
					 IP6Address(IP6(packet)->ip6_src),
					 UDP(packet)->uh_sport);
			break;
		case IPPROTO_TCP:
			if (wildcard_port) 
				init(IP6_NXT_HDR(packet),
					 IP6Address(IP6(packet)->ip6_src), 
					 IP6Address(IP6(packet)->ip6_dst),
					 TCP(packet)->th_dport);
			else
				init(IP6_NXT_HDR(packet),
					 IP6Address(IP6(packet)->ip6_dst), 
					 IP6Address(IP6(packet)->ip6_src),
					 TCP(packet)->th_sport);
			break;
		default:
			if (wildcard_port) 
				init(IP6_NXT_HDR(packet),
					 IP6Address(IP6(packet)->ip6_src), 
					 IP6Address(IP6(packet)->ip6_dst),
					 0);
			else
				init(IP6_NXT_HDR(packet),
					 IP6Address(IP6(packet)->ip6_dst), 
					 IP6Address(IP6(packet)->ip6_src),
					 0);
			break;
		}break;
	default: break;
	}
}


ConnectionID2::ConnectionID2(const u_char* packet) {
	switch (IPV(packet)) {
	case IPv4: 
		init(IP6Address(IP(packet)->ip_src.s_addr), 
			IP6Address(IP(packet)->ip_dst.s_addr));
		break;
	case IPv6: 
		init(IP6Address(IP6(packet)->ip6_src), 
			IP6Address(IP6(packet)->ip6_dst));
		break;
	default: return;
	}
}


//TODO: MAke this inline (i.e. move to Connection.hh so that it is
//consistent with ConnectionID4
bool ConnectionID3::operator==(const ConnectionID& other) const {
	return (v.proto == ((ConnectionID3*)&other)->v.proto)
		   && (v.ip1 == ((ConnectionID3*)&other)->v.ip1)
		   && (v.ip2 == ((ConnectionID3*)&other)->v.ip2)
		   && (v.port2 == ((ConnectionID3*)&other)->v.port2);
}

//TODO: MAke this inline (i.e. move to Connection.hh so that it is
//consistent with ConnectionID4
bool ConnectionID2::operator==(const ConnectionID& other) const {
	return (v.ip1 == ((ConnectionID2*)&other)->v.ip1)
		   && (v.ip2 == ((ConnectionID2*)&other)->v.ip2);
}

void ConnectionID4::getStr(char* s, int maxsize) const {
	getStr().copy(s, maxsize);

}

void ConnectionID3::getStr(char* s, int maxsize) const {
	getStr().copy(s, maxsize);
}

void ConnectionID2::getStr(char* s, int maxsize) const {
	getStr().copy(s, maxsize);
}

std::string ConnectionID4::getStr() const {
#define UCP(x) ((unsigned char *)&x)

	std::stringstream ss;

	//uint32_t s_ip=v.ip1; 
	//uint32_t d_ip=v.ip2; 

	ss << " ConnectionID4 "
	/*
	 << " Proto " << 0+get_proto()
	 << " canonified " << get_is_canonified() << " "
	*/
	<< v.ip1.AsURIString()
	<< ":"
	<< ntohs(get_port1())
	<< " - "
	<< v.ip2.AsURIString()
	<< ":"
	<< ntohs(get_port2());
	return ss.str();
}


std::string ConnectionID3::getStr() const {
#define UCP(x) ((unsigned char *)&x)

	std::stringstream ss;

	//uint32_t s_ip=get_ip1();//get_s_ip();
	//uint32_t d_ip=get_ip2();//get_d_ip();

	ss << " ConnectionID3 "
	<< v.ip1.AsURIString()
	<< " - "
	<< v.ip2.AsURIString()
	<< ":"
	<< get_port();
	return ss.str();
}

std::string ConnectionID2::getStr() const {
#define UCP(x) ((unsigned char *)&x)

	std::stringstream ss;

	//uint32_t s_ip=get_ip1();//get_s_ip();
	//uint32_t d_ip=get_ip2();//get_d_ip();

	ss << " ConnectionID2 "
	<< v.ip1.AsURIString()
	<< " - "
	<< v.ip2.AsURIString();
	return ss.str();
}



// Static Member initialization
std::string ConnectionID4::pattern_connection4 = "\\s*(\\w+)\\s+"
	+ pattern_ipport + "\\s+" + pattern_ipport + "\\s*";
RE2 ConnectionID4::re(ConnectionID4::pattern_connection4);

ConnectionID4* ConnectionID4::parse(const char *str) {
	std::string protostr, src_ip, dst_ip;
	unsigned src_port, dst_port;
	proto_t proto;

	if (!RE2::FullMatch(str, re, &protostr, &src_ip, &src_port, &dst_ip, &dst_port)) {
		return NULL;
	}
	if (protostr == std::string("tcp"))
		proto = IPPROTO_TCP;
	else 
		proto = IPPROTO_UDP;
		
	return new ConnectionID4(proto, inet_addr(src_ip.c_str()), inet_addr(dst_ip.c_str()),
			htons(src_port), htons(dst_port));
}

/* technically dont need packet */
void Connection::addPkt(const struct pcap_pkthdr* header, const u_char* packet) {
	last_ts=to_tm_time(&header->ts);
	tot_pkts++;
	tot_pktbytes+=header->caplen;
}

int Connection::deleteSubscription() {
	//fprintf(stderr, "DEBUG deleteSubscription called\n");
	if (subscription) {
		subscription->decUsage();
		if (subscription->getUsage() == 0)  {
			delete(subscription);
			//fprintf(stderr, "DEBUG subscription deleted\n");
		}
		return 1;
	}
	return 0;
}


void Connection::init(ConnectionID4 *id) {
	last_ts=tot_pktbytes=tot_pkts=0;
	subscription=NULL;
	fifo=NULL;
	suspend_cutoff=suspend_timeout=false;

	col_next = col_prev = NULL;
	q_older = q_newer = NULL;
	c_id = id;
}

Connection::Connection(Connection *c) {
	last_ts = c->last_ts;
	tot_pktbytes = c->tot_pktbytes;
	tot_pkts = c->tot_pkts;
	fifo = c->fifo;
	//FIXME: TODO: should we make a deep copy here??
	subscription = c->subscription;
	suspend_cutoff = c->suspend_cutoff;
	suspend_timeout = c->suspend_timeout;

	col_next = col_prev = NULL;
	q_older = q_newer = NULL;

	c_id = new ConnectionID4(c->c_id);
}


std::string Connection::getStr() const {
	std::stringstream ss;
	ss.setf(std::ios::fixed);
	ss << tot_pkts << " pkts, " << tot_pktbytes << " bytes"
	<< ", last packet at " << last_ts
	<< std::endl
	<< (fifo ? "class "+fifo->getClassname() :
		"no class associated")
	<< (suspend_cutoff ? ", cutoff suspended" : "")
	<< (suspend_timeout ? ", timeout suspended" : "")
	<< (subscription ? ", subscription to "+subscription->getStr() : "")
	;
	return c_id->getStr() + " " + ss.str();
}

