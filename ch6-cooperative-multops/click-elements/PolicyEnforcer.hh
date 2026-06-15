#ifndef CLICK_POLICYENFORCER_HH
#define CLICK_POLICYENFORCER_HH
#include <click/element.hh>
#include <click/timer.hh>
#include <clicknet/ip.h>
#include "iproutetable.hh" // The perfect data structure for a blocklist
#include "radixiplookup.hh" // Use the concrete RadixIPLookup class

CLICK_DECLS

// --- Drop Policy Protocol Definition ---
// This MUST match the Python struct: "!IBxxx"
// It's 8 bytes total: 4 (uint32_t) + 1 (uint8_t) + 3 (padding)
#pragma pack(push, 1)
struct DropPolicyRecord {
    uint32_t ip_prefix;  // Network byte order
    uint8_t  prefix_len;
    // 3 bytes of implicit padding will be here
};
#pragma pack(pop)


class PolicyEnforcer : public Element {
public:
    PolicyEnforcer() CLICK_COLD;
    ~PolicyEnforcer() CLICK_COLD;

    const char *class_name() const  { return "PolicyEnforcer"; }
    const char *port_count() const  { return "1/1"; } // 1 input, 1 output

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    int initialize(ErrorHandler *) CLICK_COLD;
    void cleanup(CleanupStage) CLICK_COLD;

    // This function is called for every packet that passes through
    void push(int port, Packet *p);

private:
    // --- Our new functions ---
    void run_timer(Timer *); // The callback for our UDP listener
    static int write_handler(const String &, Element *, void *, ErrorHandler *);

    // --- Member Variables ---
    int _listen_port; // Port to listen on (e.g., 50001)
    int _sock;        // The UDP socket file descriptor
    Timer _timer;     // Timer to periodically check the socket
    
    
    RadixIPLookup _blocklist; // Use the concrete RadixIPLookup class
};

CLICK_ENDDECLS
#endif /* CLICK_POLICYENFORCER_HH */
