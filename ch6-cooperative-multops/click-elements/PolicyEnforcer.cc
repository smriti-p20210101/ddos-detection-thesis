// #include <click/config.h>
// #include "policyenforcer.hh" // Include the header
// #include "radixiplookup.hh" // Using RadixIPLookup
// #include <click/args.hh>
// #include <click/error.hh> // Reverted: Removed ErrorHandler include for now
// #include <click/glue.hh>
// #include <click/packet_anno.hh>
// #include <click/router.hh>
// #include <click/straccum.hh>
// #include <cstdio>          // For snprintf

// // Includes for socket programming
// #include <sys/types.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <arpa/inet.h>
// #include <unistd.h>
// #include <fcntl.h>
// #include <cerrno>
// #include <cstring>


// CLICK_DECLS

// PolicyEnforcer::PolicyEnforcer()
//     : _listen_port(0), _sock(-1), _timer(this)
// {
// }

// PolicyEnforcer::~PolicyEnforcer()
// {
// }

// int
// PolicyEnforcer::configure(Vector<String> &conf, ErrorHandler *errh)
// {
//     if (Args(conf, this, errh)
//         .read_mp("LISTEN_PORT", _listen_port)
//         .complete() < 0)
//         return -1;

//     if (_listen_port <= 0 || _listen_port > 65535)
//         return errh->error("LISTEN_PORT must be between 1 and 65535");

//     // Reverted: Removed _blocklist.configure() call here

//     return 0;
// }

// int
// PolicyEnforcer::initialize(ErrorHandler *errh)
// {
//     // --- Setup UDP Socket ---
//     _sock = socket(AF_INET, SOCK_DGRAM, 0);
//     if (_sock < 0) {
//         return errh->error("Could not create UDP socket: %s", strerror(errno));
//     }

//     // --- Make socket non-blocking ---
//     int flags = fcntl(_sock, F_GETFL, 0);
//     if (flags < 0 || fcntl(_sock, F_SETFL, flags | O_NONBLOCK) < 0) {
//         close(_sock);
//         _sock = -1;
//         return errh->error("Could not set socket to non-blocking: %s", strerror(errno));
//     }

//     // --- Bind socket to the listening port ---
//     struct sockaddr_in serv_addr;
//     memset(&serv_addr, 0, sizeof(serv_addr));
//     serv_addr.sin_family = AF_INET;
//     serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
//     serv_addr.sin_port = htons(_listen_port);

//     if (bind(_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
//         close(_sock);
//         _sock = -1;
//         return errh->error("Could not bind UDP socket to port %d: %s", _listen_port, strerror(errno));
//     }

//     click_chatter("PolicyEnforcer: Listening for commands on UDP port %d", _listen_port);

//     // --- Initialize and schedule the timer ---
//     _timer.initialize(this);
//     _timer.schedule_now();

//     // Reverted: Removed _blocklist.initialize() call here

//     return 0;
// }

// void
// PolicyEnforcer::cleanup(CleanupStage s)
// {
//     if (_sock >= 0) {
//         close(_sock);
//         _sock = -1;
//     }
//      // Reverted: Removed _blocklist.cleanup() call here
// }

// void
// PolicyEnforcer::run_timer(Timer *)
// {
//     if (_sock < 0) return;

//     struct sockaddr_in cli_addr;
//     socklen_t clilen = sizeof(cli_addr);
//     unsigned char buffer[sizeof(DropPolicyRecord)];

//     ssize_t n = recvfrom(_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&cli_addr, &clilen);

//     if (n < 0) {
//         if (errno != EAGAIN && errno != EWOULDBLOCK) {
//             click_chatter("PolicyEnforcer: recvfrom error: %s", strerror(errno));
//         }
//     } else {
//         // --- DEBUG Prints Kept ---
//         click_chatter("PolicyEnforcer: Received %d bytes.", (int)n);
//         StringAccum sa;
//         char hex_byte[4];
//         for (int i=0; i < n; ++i) {
//              snprintf(hex_byte, sizeof(hex_byte), "%02X ", buffer[i]);
//              sa << hex_byte;
//         }
//         click_chatter("PolicyEnforcer: Raw bytes: %s", sa.c_str());
//         // --- END DEBUG ---

//         if (n == sizeof(DropPolicyRecord)) {
//             // --- Using memcpy (Kept this fix as it was correct) ---
//             DropPolicyRecord rec;
//             memcpy(&rec.ip_prefix, buffer, sizeof(rec.ip_prefix));
//             memcpy(&rec.prefix_len, buffer + sizeof(rec.ip_prefix), sizeof(rec.prefix_len));
//             // ---

//             // --- DEBUG Prints Kept ---
//             uint32_t prefix_net_order = rec.ip_prefix;
//             uint32_t prefix_host_order = ntohl(prefix_net_order);
//             uint8_t len = rec.prefix_len;
//             click_chatter("PolicyEnforcer: Parsed prefix (net): 0x%08X, prefix (host): 0x%08X (%s), len: %u",
//                           prefix_net_order, prefix_host_order, IPAddress(prefix_host_order).unparse().c_str(), (unsigned)len);
//              // --- END DEBUG ---


//             if (len > 0 && len <= 32) {
//                 IPAddress prefix_addr(prefix_host_order);
//                 IPAddress dummy_gw(0);
//                 IPRoute route_to_add(prefix_addr, len, dummy_gw, 0);

//                 // Reverted: Removed the lookup_route check
//                 // Reverted: Changed last argument back to 0 from ErrorHandler::default_handler()
//                 int result = _blocklist.add_route(route_to_add, false, 0, 0);

//                 if (result >= 0) {
//                     click_chatter("PolicyEnforcer: Added %s/%d to blocklist", prefix_addr.unparse().c_str(), len);
//                 } else {
//                     // Reverted: Removed ErrorHandler::strerror
//                     click_chatter("PolicyEnforcer: Failed to add %s/%d to blocklist (Error %d)",
//                                   prefix_addr.unparse().c_str(), len, result);
//                 }

//             } else {
//                 click_chatter("PolicyEnforcer: Received invalid prefix length %u", (unsigned)len);
//             }

//         } else {
//             click_chatter("PolicyEnforcer: Received UDP packet of unexpected size %d (expected %d)", (int)n, (int)sizeof(DropPolicyRecord));
//         }
//     }

//     _timer.reschedule_after_msec(10);
// }


// void
// PolicyEnforcer::push(int, Packet *p)
// {
//     const click_ip *iph = p->ip_header();
//     if (!iph) {
//         output(0).push(p);
//         return;
//     }

//     IPAddress dst_addr = iph->ip_dst;
//     IPAddress nexthop_ignored;
//     int lookup_result = _blocklist.lookup_route(dst_addr, nexthop_ignored);

//     if (lookup_result >= 0) {
//         p->kill();
//     } else {
//         output(0).push(p);
//     }
// }


// EXPORT_ELEMENT(PolicyEnforcer)
// // Reverted: Removed ELEMENT_REQUIRES(iproute) for now, RadixIPLookup might implicitly require it
// ELEMENT_REQUIRES(userlevel) // Keep userlevel requirement
// CLICK_ENDDECLS

#include <click/config.h>
#include "policyenforcer.hh" // Include the header
#include "radixiplookup.hh" // Using RadixIPLookup
#include <click/args.hh>
#include <click/error.hh>    // Need this for ErrorHandler in .hh and strerror
#include <click/glue.hh>
#include <click/packet_anno.hh>
#include <click/router.hh>
#include <click/straccum.hh>
#include <cstdio>          // For snprintf

// Includes for socket programming
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <cstring>


CLICK_DECLS

PolicyEnforcer::PolicyEnforcer()
    : _listen_port(0), _sock(-1), _timer(this)
{
}

PolicyEnforcer::~PolicyEnforcer()
{
}

int
PolicyEnforcer::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (Args(conf, this, errh)
        .read_mp("LISTEN_PORT", _listen_port)
        .complete() < 0)
        return -1;

    if (_listen_port <= 0 || _listen_port > 65535)
        return errh->error("LISTEN_PORT must be between 1 and 65535");

    // Initialize the RadixIPLookup table here
    Vector<String> blocklist_conf;
     if (_blocklist.configure(blocklist_conf, errh) < 0) {
         return errh->error("Failed to configure internal RadixIPLookup");
    }

    return 0;
}

int
PolicyEnforcer::initialize(ErrorHandler *errh)
{
    // --- Setup UDP Socket ---
    _sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (_sock < 0) {
        return errh->error("Could not create UDP socket: %s", strerror(errno));
    }

    // --- Make socket non-blocking ---
    int flags = fcntl(_sock, F_GETFL, 0);
    if (flags < 0 || fcntl(_sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(_sock);
        _sock = -1;
        return errh->error("Could not set socket to non-blocking: %s", strerror(errno));
    }

    // --- Bind socket to the listening port ---
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(_listen_port);

    if (bind(_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(_sock);
        _sock = -1;
        return errh->error("Could not bind UDP socket to port %d: %s", _listen_port, strerror(errno));
    }

    click_chatter("PolicyEnforcer: Listening for commands on UDP port %d", _listen_port);

    // --- Initialize and schedule the timer ---
    _timer.initialize(this);
    _timer.schedule_now();

    // --- Initialize the RadixIPLookup table ---
    // Make sure it's initialized after being configured
     if (_blocklist.initialize(errh) < 0) {
         close(_sock); // Close socket if Radix init fails
         _sock = -1;
         return errh->error("Failed to initialize internal RadixIPLookup");
    }

    return 0;
}

void
PolicyEnforcer::cleanup(CleanupStage s)
{
    if (_sock >= 0) {
        close(_sock);
        _sock = -1;
    }
    _blocklist.cleanup(s); // Cleanup the member element
}

void
PolicyEnforcer::run_timer(Timer *)
{
    if (_sock < 0) return;

    struct sockaddr_in cli_addr;
    socklen_t clilen = sizeof(cli_addr);
    unsigned char buffer[sizeof(DropPolicyRecord)];

    ssize_t n = recvfrom(_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&cli_addr, &clilen);

    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            click_chatter("PolicyEnforcer: recvfrom error: %s", strerror(errno));
        }
    } else {
        // DEBUG Prints
        click_chatter("PolicyEnforcer: Received %d bytes.", (int)n);
        StringAccum sa;
        char hex_byte[4];
        for (int i=0; i < n; ++i) {
             snprintf(hex_byte, sizeof(hex_byte), "%02X ", buffer[i]);
             sa << hex_byte;
        }
        click_chatter("PolicyEnforcer: Raw bytes: %s", sa.c_str());

        if (n == sizeof(DropPolicyRecord)) {
            // Using memcpy
            DropPolicyRecord rec;
            memcpy(&rec.ip_prefix, buffer, sizeof(rec.ip_prefix));
            memcpy(&rec.prefix_len, buffer + sizeof(rec.ip_prefix), sizeof(rec.prefix_len));

            // DEBUG Prints
            uint32_t prefix_net_order = rec.ip_prefix;
            uint32_t prefix_host_order = ntohl(prefix_net_order);
            uint8_t len = rec.prefix_len;
            click_chatter("PolicyEnforcer: Parsed prefix (net): 0x%08X, prefix (host): 0x%08X (%s), len: %u",
                          prefix_net_order, prefix_host_order, IPAddress(prefix_host_order).unparse().c_str(), (unsigned)len);


            if (len > 0 && len <= 32) {
                IPAddress prefix_addr(prefix_host_order);
                IPAddress dummy_gw(0);
                IPRoute route_to_add(prefix_addr, len, dummy_gw, 0); // Interface 0

                // ==========================================================
                // === RE-APPLYING FIX: Check if route exists before adding ===
                // ==========================================================
                IPAddress check_gw; // Dummy gateway for lookup
                int existing_route = _blocklist.lookup_route(prefix_addr, check_gw);
                bool already_exists = false;
                // lookup_route returns >= 0 if a matching or covering prefix is found
                if (existing_route >= 0) {
                    // This lookup finds the *longest* prefix match, not exact.
                    // For a blocklist, if *any* covering route exists, assume blocked.
                    click_chatter("PolicyEnforcer: Route covering %s already exists.", prefix_addr.unparse().c_str());
                    already_exists = true;
                }

                if (!already_exists) {
                    // Call simple add_route (using 0 for ErrorHandler)
                    int result = _blocklist.add_route(route_to_add, false, 0, 0);

                    if (result >= 0) {
                        click_chatter("PolicyEnforcer: Added %s/%d to blocklist", prefix_addr.unparse().c_str(), len);
                    } else {
                        // Use basic strerror for now
                        click_chatter("PolicyEnforcer: Failed to add %s/%d to blocklist (Error %d: %s)",
                                      prefix_addr.unparse().c_str(), len, result, strerror(-result)); // Use strerror for standard errors
                    }
                }
                // ==========================================================

            } else {
                click_chatter("PolicyEnforcer: Received invalid prefix length %u", (unsigned)len);
            }

        } else {
            click_chatter("PolicyEnforcer: Received UDP packet of unexpected size %d (expected %d)", (int)n, (int)sizeof(DropPolicyRecord));
        }
    }

    _timer.reschedule_after_msec(10);
}


void
PolicyEnforcer::push(int, Packet *p)
{
    const click_ip *iph = p->ip_header();
    if (!iph) {
        output(0).push(p);
        return;
    }

    IPAddress dst_addr = iph->ip_dst;
    IPAddress nexthop_ignored;
    int lookup_result = _blocklist.lookup_route(dst_addr, nexthop_ignored);

    if (lookup_result >= 0) { // Match found
        p->kill();
    } else { // No match
        output(0).push(p);
    }
}


EXPORT_ELEMENT(PolicyEnforcer)
// Keep userlevel requirement. iproute might be implicitly needed by RadixIPLookup,
// but let's try compiling without explicitly requiring it first.
ELEMENT_REQUIRES(userlevel)
CLICK_ENDDECLS

