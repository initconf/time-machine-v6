#ifndef CONNECTION_HH
#define CONNECTION_HH

#include <string.h>

//#include "IP6Address.hh"
#include <netinet/in.h>
#include <arpa/inet.h>
#include "types.h"
#include "packet_headers.h"
#include "tm.h"

#include "jhash3.h"
#include "re2/re2.h"

#define UHASH_KEY_SIZE 36
#if defined(__NetBSD__) || defined(__FreeBSD__)
#include <sys/types.h>
#include <sys/socket.h>
#endif


void init_H3();

/*const uint8_t v4_mapped_prefix[12] = { 0, 0, 0, 0,
                                       0, 0, 0, 0,
                                       0, 0, 0xff, 0xff }; // top 96 bits of v4-mapped-addr*/

/**
 * Class storing both IPv4 and IP6Address addresses.
 */
class IP6Address
{
public:

	/**
	 * Byte order.
	 */
	enum ByteOrder { Host, Network };

	/**
	 * Constructs the unspecified IP6Address address (all 128 bits zeroed).
	 */
	IP6Address()
		{
		memset(in6.s6_addr, 0, sizeof(in6.s6_addr));
		}

	/**
	 * Constructs an address instance from an IPv4 address.
	 *
	 * @param in6 The IP6Address address.
	 */
	explicit IP6Address(const in_addr& in4)
		{
		memcpy(in6.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
		memcpy(&in6.s6_addr[12], &in4.s_addr, sizeof(in4.s_addr));
		}

	/**
	 * Constructs an address instance from an IP6Address address.
	 *
	 * @param in6 The IP6Address address.
	 */
	explicit IP6Address(const in6_addr& arg_in6) : in6(arg_in6) { }

	/**
	 * Constructs an address instance from a string representation.
	 *
	 * @param s String containing an IP address as either a dotted IPv4
	 * address or a hex IP6Address address.
	 */
	IP6Address(const std::string& s)
		{
		init(s);
		}

	/**
	 * Constructs an address instance from a string representation.
	 *
	 * @param s ASCIIZ string containing an IP address as either a
	 * dotted IPv4 address or a hex IP6Address address.
	 */
	IP6Address(const char* s)
		{
		init(s);
		}

	IP6Address(const uint32_t ip)
		{
			char ipstr[INET_ADDRSTRLEN];
			if(inet_ntop(AF_INET, &ip, ipstr, INET_ADDRSTRLEN) == NULL) {
				tmlog(TM_LOG_ERROR, "IP6Address",  "IPv6 source address invalid");
			}
			init(ipstr);
		}

	/**
	 * Copy constructor.
	 */
	IP6Address(const IP6Address& other) : in6(other.in6) { };

	/**
	 * Destructor.
	 */
	~IP6Address() { };

	uint32_t hash() const;
	/**
	 * Returns the address' family.
	 */
	uint32_t GetFamily() const
		{
		if ( memcmp(in6.s6_addr, v4_mapped_prefix, 12) == 0 )
			return IPv4;
		else
			return IPv6;
		}

	/**
	 * Returns true if the address represents a loopback device.
	 */
	bool IsLoopback() const;

	/**
	 * Returns true if the address represents a multicast address.
	 */
	bool IsMulticast() const
		{
		if ( GetFamily() == IPv4 )
			return in6.s6_addr[12] == 224;
		else
			return in6.s6_addr[0] == 0xff;
		}

	/**
	 * Returns true if the address represents a broadcast address.
	 */
	bool IsBroadcast() const
		{
		if ( GetFamily() == IPv4 )
			return ((in6.s6_addr[12] == 0xff) && (in6.s6_addr[13] == 0xff)
				&& (in6.s6_addr[14] == 0xff) && (in6.s6_addr[15] == 0xff));
		else
			return false;
		}

	/**
	 * Retrieves the raw byte representation of the address.
	 *
	 * @param bytes The pointer to which \a bytes points will be set to
	 * the address of the raw representation in network-byte order.
	 * The return value indicates how many 32-bit words are valid starting at
	 * that address. The pointer will be valid as long as the address instance
	 * exists.
	 *
	 * @return The number of 32-bit words the raw representation uses. This
	 * will be 1 for an IPv4 address and 4 for an IP6Address address.
	 */
	int GetBytes(const uint32_t** bytes) const
		{
		if ( GetFamily() == IPv4 )
			{
			*bytes = (uint32_t*) &in6.s6_addr[12];
			return 1;
			}
		else
			{
			*bytes = (uint32_t*) in6.s6_addr;
			return 4;
			}
		}

	/**
	 * Retrieves a copy of the IP6Address raw byte representation of the address.
	 * If the internal address is IPv4, then the copied bytes use the
	 * IPv4 to IP6Address address mapping to return a full 16 bytes.
	 *
	 * @param bytes The pointer to a memory location in which the
	 * raw bytes of the address are to be copied.
	 *
	 * @param order The byte-order in which the returned raw bytes are copied.
	 * The default is network order.
	 *
	void CopyIP6Address(uint32_t* bytes, ByteOrder order = Network) const
		{
		memcpy(bytes, in6.s6_addr, sizeof(in6.s6_addr));

		if ( order == Host )
			{
			for ( unsigned int i = 0; i < 4; ++i )
				bytes[i] = ntohl(bytes[i]);
			}
		}*/

	/**
	 * Retrieves a copy of the IP6Address raw byte representation of the address.
	 * @see CopyIP6Address(uint32_t)
	 */
	void CopyIP6Address(in6_addr* arg_in6) const
		{
		memcpy(arg_in6->s6_addr, in6.s6_addr, sizeof(in6.s6_addr));
		}

	/**
	 * Retrieves a copy of the IPv4 raw byte representation of the address.
	 * The caller should verify the address is of the IPv4 family type
	 * beforehand.  @see GetFamily().
	 *
	 * @param in4 The pointer to a memory location in which the raw bytes
	 * of the address are to be copied in network byte-order.
	 */
	void CopyIPv4(in_addr* in4) const
		{
		memcpy(&in4->s_addr, &in6.s6_addr[12], sizeof(in4->s_addr));
		}



	/**
	 * Masks out lower bits of the address.
	 *
	 * @param top_bits_to_keep The number of bits \a not to mask out,
	 * counting from the highest order bit. The value is always
	 * interpreted relative to the IP6Address bit width, even if the address
	 * is IPv4. That means if compute ``192.168.1.2/16``, you need to
	 * pass in 112 (i.e., 96 + 16). The value must be in the range from
	 * 0 to 128.
	 */
	void Mask(int top_bits_to_keep);

	/**
	 * Masks out top bits of the address.
	 *
	 * @param top_bits_to_chop The number of bits to mask out, counting
	 * from the highest order bit.  The value is always interpreted relative
	 * to the IP6Address bit width, even if the address is IPv4.  So to mask out
	 * the first 16 bits of an IPv4 address, pass in 112 (i.e., 96 + 16).
	 * The value must be in the range from 0 to 128.
	 */
	void ReverseMask(int top_bits_to_chop);

	/**
	 * Assignment operator.
	 */
	IP6Address& operator=(const IP6Address& other)
		{
		// No self-assignment check here because it's correct without it and
		// makes the common case faster.
		in6 = other.in6;
		return *this;
		}

	/**
	 * Bitwise OR operator returns the IP address resulting from the bitwise
	 * OR operation on the raw bytes of this address with another.
	 */
	IP6Address operator|(const IP6Address& other)
		{
		in6_addr result;
		for ( int i = 0; i < 16; ++i )
			result.s6_addr[i] = this->in6.s6_addr[i] | other.in6.s6_addr[i];

		return IP6Address(result);
		}

	/**
	 * Returns a string representation of the address. IPv4 addresses
	 * will be returned in dotted representation, IP6Address addresses in
	 * compressed hex.
	 */
	std::string AsString() const;

	/**
	 * Returns a string representation of the address suitable for inclusion
	 * in an URI.  For IPv4 addresses, this is the same as AsString(), but
	 * IP6Address addresses are encased in square brackets.
	 */
	std::string AsURIString() const
		{
		if ( GetFamily() == IPv4 )
			return AsString();
		else
			return std::string("[") + AsString() + "]";
		}
	
	/**
	 * Returns a host-order, plain hex string representation of the address.
	 */
	std::string AsHexString() const;

	/**
	 * Returns a string representation of the address. This returns the
	 * same as AsString().
	 */
	//operator std::string() const { return AsString(); }

	/**
	 * Returns a reverse pointer name associated with the IP address.
	 * For example, 192.168.0.1's reverse pointer is 1.0.168.192.in-addr.arpa.
	 */
	std::string PtrName() const;

	/**
	 * Comparison operator for IP address.
	 */
	friend bool operator==(const IP6Address& addr1, const IP6Address& addr2)
		{
		return memcmp(&addr1.in6, &addr2.in6, sizeof(in6_addr)) == 0;
		}

	friend bool operator!=(const IP6Address& addr1, const IP6Address& addr2)
		{
		return ! (addr1 == addr2);
		}

	/**
	 * Comparison operator IP addresses. This defines a well-defined order for
	 * IP addresses. However, the order does not necessarily correspond to
	 * their numerical values.
	 */
	friend bool operator<(const IP6Address& addr1, const IP6Address& addr2)
		{
		return memcmp(&addr1.in6, &addr2.in6, sizeof(in6_addr)) < 0;
		}

	/** Converts the address into the type used internally by the
	  * inter-thread communication.
	  */
	//void ConvertToThreadingValue(threading::Value::addr_t* v) const;

	//friend HashKey* BuildConnIDHashKey(const ConnID& id);
	//friend HashKey* BuildExpectedConnHashKey(const ExpectedConn& c);

	//unsigned int MemoryAllocation() const { return padded_sizeof(*this); }

private:
	

	/**
	 * initializes an address instance from a string representation.
	 *
	 * @param s String containing an IP address as either a dotted IPv4
	 * address or a hex IP6Address address.
	 */
	void init(const std::string& s);

	in6_addr in6; // IP6Address or v4-to-v6-mapped address
	static const uint8_t v4_mapped_prefix[12]; // top 96 bits of v4-mapped-addr
};


inline bool IP6Address::IsLoopback() const
	{
	if ( GetFamily() == IPv4 )
		return in6.s6_addr[12] == 127;

	else
		return ((in6.s6_addr[0] == 0) && (in6.s6_addr[1] == 0)
			&& (in6.s6_addr[2] == 0) && (in6.s6_addr[3] == 0)
			&& (in6.s6_addr[4] == 0) && (in6.s6_addr[5] == 0)
			&& (in6.s6_addr[6] == 0) && (in6.s6_addr[7] == 0)
			&& (in6.s6_addr[8] == 0) && (in6.s6_addr[9] == 0)
			&& (in6.s6_addr[10] == 0) && (in6.s6_addr[11] == 0)
			&& (in6.s6_addr[12] == 0) && (in6.s6_addr[13] == 0)
			&& (in6.s6_addr[14] == 0) && (in6.s6_addr[15] == 1));
	}


class QueryResult;
class Fifo;


class ConnectionID {
public:
	virtual ~ConnectionID() { }
	//  virtual hash_t hash() const = 0;
	virtual bool operator==(const ConnectionID& other) const = 0;
	//  virtual void* getVPtr() = 0;
	//  virtual const void* getConstVPtr() const = 0;
	virtual void getStr(char* s, int maxsize) const = 0;
	virtual std::string getStr() const = 0;
};

class ConnectionID4: public ConnectionID {
public:
	ConnectionID4(proto_t proto,
				  uint32_t s_ip, uint32_t d_ip,
				  uint16_t s_port, uint16_t d_port) {
		init(proto, IP6Address(s_ip), IP6Address(d_ip), s_port, d_port);
	}

	

	ConnectionID4(ConnectionID4 *c_id) {
		v.ip1 = c_id->v.ip1;
		v.ip2 = c_id->v.ip2;
		v.port1 = c_id->v.port1;
		v.port2 = c_id->v.port2;
		v.proto = c_id->v.proto;
	}
	ConnectionID4(const u_char* packet);
	ConnectionID4() {};
	virtual ~ConnectionID4() {};
	uint32_t hash() const;

	bool operator==(const ConnectionID& other) const { 
		return (v.ip1 == ((ConnectionID4*)&other)->v.ip1)
			   && (v.ip2 == ((ConnectionID4*)&other)->v.ip2)
			   && (v.port1 == ((ConnectionID4*)&other)->v.port1)
			   && (v.port2 == ((ConnectionID4*)&other)->v.port2)
			   && (v.proto == ((ConnectionID4*)&other)->v.proto);
	}

	static ConnectionID4 *parse(const char *str);

	proto_t get_proto() const {
		return v.proto;
	}
	IP6Address get_ip1() const {
		return v.ip1;
	}
	IP6Address get_ip2() const {
		return v.ip2;
	}
	uint16_t get_port1() const {
		return v.port1;
	}
	uint16_t get_port2() const {
		return v.port2;
	}
	//  bool get_is_canonified() const { return v.is_canonified; }
	/*
	uint32_t get_s_ip() const {
	  return v.is_canonified ? v.ip2 : v.ip1 ; }
	uint32_t get_d_ip() const {
	  return v.is_canonified ? v.ip1 : v.ip2 ; }
	uint16_t get_s_port() const {
	  return v.is_canonified ? v.port2 : v.port1 ; }
	uint16_t get_d_port() const {
	  return v.is_canonified ? v.port1 : v.port2 ; }
	*/
	typedef struct {
		//  time locality
		//    uint32_t ts;
		IP6Address ip1;
		IP6Address ip2;
		uint16_t port1;
		uint16_t port2;
		proto_t proto;
		//    bool is_canonified;
	} v_t;

	v_t* getV() {
		return &v;
	}
	const v_t* getConstV() const {
		return &v;
	}
	void getStr(char* s, int maxsize) const;
	std::string getStr() const;
protected:
	void init(proto_t proto, IP6Address s_ip, IP6Address d_ip,
			  uint16_t s_port, uint16_t d_port);
	v_t v;
private:
	static std::string pattern_connection4;
	static RE2 re;
};

class ConnectionID3: public ConnectionID {
public:
	ConnectionID3(proto_t proto,
				  uint32_t ip1, uint32_t ip2,
				  uint16_t port2) {
		init(proto, IP6Address(ip1), IP6Address(ip2), port2);
	}
	ConnectionID3(const u_char* packet, int wildcard_port);
	ConnectionID3() {};
	virtual ~ConnectionID3() {};
	uint32_t hash() const;
	bool operator==(const ConnectionID& other) const;
	proto_t get_proto() const {
		return v.proto;
	}
	IP6Address get_ip1() const {
		return v.ip1;
	}
	IP6Address get_ip2() const {
		return v.ip2;
	}
	uint16_t get_port() const {
		return v.port2;
	}
	/*
	bool get_is_canonified() const { return v.is_canonified; }
	uint32_t get_s_ip() const {
	  return v.is_canonified ? v.ip2 : v.ip1 ; }
	uint32_t get_d_ip() const {
	  return v.is_canonified ? v.ip1 : v.ip2 ; }
	*/
	typedef struct {
		//  time locality
		//    uint32_t ts;
		IP6Address ip1;
		IP6Address ip2;
		uint16_t port2;
		proto_t proto;
		//    bool is_canonified;
	} v_t;

	v_t* getV() {
		return &v;
	}
	const v_t* getConstV() const {
		return &v;
	}

	void getStr(char* s, int maxsize) const;
	std::string getStr() const;
protected:
	void init(proto_t proto, IP6Address s_ip, IP6Address d_ip, uint16_t port);
	v_t v;
};


class ConnectionID2: public ConnectionID {
public:
	ConnectionID2( uint32_t s_ip, uint32_t d_ip) {
		init(IP6Address(s_ip), IP6Address(d_ip));
	}
	ConnectionID2(const u_char* packet);
	ConnectionID2() {};
	virtual ~ConnectionID2() {};
	uint32_t hash() const;
	bool operator==(const ConnectionID& other) const;
	IP6Address get_ip1() const {
		return v.ip1;
	}
	IP6Address get_ip2() const {
		return v.ip2;
	}
	/*
	bool get_is_canonified() const { return v.is_canonified; }
	uint32_t get_s_ip() const {
	  return v.is_canonified ? v.ip2 : v.ip1 ; }
	uint32_t get_d_ip() const {
	  return v.is_canonified ? v.ip1 : v.ip2 ; }
	*/
	typedef struct {
		//  time locality
		//    uint32_t ts;
		IP6Address ip1;
		IP6Address ip2;
		//    bool is_canonified;
	} v_t;

	v_t* getV() {
		return &v;
	}
	const v_t* getConstV() const {
		return &v;
	}
	void getStr(char* s, int maxsize) const;
	std::string getStr() const;
protected:
	void init(IP6Address s_ip, IP6Address d_ip);
	v_t v;
};


class Connection {
public:
	/*
	Connection(proto_t proto,
	    uint32_t s_ip, uint32_t d_ip,
	    uint16_t s_port, uint16_t d_port);
	Connection(ConnectionID&);
	*/
	/* id  will be owned by Connection class and freed by it */
	Connection(ConnectionID4 *id) {
		init(id);
	}
	Connection(Connection *c);
	virtual ~Connection() {
		delete c_id;
	}
	void addPkt(const struct pcap_pkthdr* header, const u_char* packet);
	tm_time_t getLastTs() {
		return last_ts;
	}
	uint64_t getTotPktbytes() {
		return tot_pktbytes;
	}
	//  ConnectionID* getKey() { return key; }
	Fifo* getFifo() {
		return fifo;
	}
	void setFifo(Fifo *f) {
		fifo=f;
	}
	void setSuspendCutoff(bool b) {
		suspend_cutoff=b;
	}
	bool getSuspendCutoff() {
		return suspend_cutoff;
	}
	void setSuspendTimeout(bool b) {
		suspend_timeout=b;
	}
	bool getSuspendTimeout() {
		return suspend_timeout;
	}
	std::string getStr() const;
	void setSubscription(QueryResult *q) {
		subscription=q;
	}
	QueryResult* getSubscription() {
		return subscription;
	}
	int deleteSubscription();

	friend class Connections;
protected:
	ConnectionID4 *c_id;
	//  ConnectionID* key;
	//  struct ConnectionID c_id;
	tm_time_t last_ts;

	/* cache to which class this connection belongs */
	Fifo* fifo;
	/* is there a subscription for this connection? */
	QueryResult* subscription;
	/* true if cutoff should not be done for this connection */
	bool suspend_cutoff;
	/* true if inactivity timeout should not be done for this connection */
	bool suspend_timeout;

	//	bool tcp_syn;

	uint64_t tot_pkts;
	uint64_t tot_pktbytes;

	//  hash_t hash() const;
	//  bool operator==(const Connection& other) const { return c_id==other.c_id; }
	void init(ConnectionID4 *);

	/* hash collision queue */
	Connection *col_next;             // the index given to this connection might have the
	Connection *col_prev;             //    same index in the htable thus these variables
                                          //    state the next and previous Connections in the
					  //    collision list

	/* timeout queue */ 
	Connection *q_newer;              // points to older and newer Connections in the timeout Q
	Connection *q_older;

	
};

#endif
