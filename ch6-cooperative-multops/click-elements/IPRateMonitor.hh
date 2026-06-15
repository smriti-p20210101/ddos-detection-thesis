#ifndef CLICK_IPRATEMON_HH
#define CLICK_IPRATEMON_HH
#include <click/glue.hh>
#include <clicknet/ip.h>
#include <click/element.hh>
#include <click/timer.hh> // Include Timer header
#include <click/ewma.hh>
#include <click/vector.hh>
#include <click/packet_anno.hh>

// --- NEW: For static_assert ---
#include <cassert>
// --- END NEW ---

CLICK_DECLS

/*
 * =c
 * IPRateMonitor(TYPE, RATIO, THRESH [, MEMORY, ANNO, AGGREGATOR, INTERVAL]) // Added AGGREGATOR, INTERVAL
 * =s ipmeasure
 * measures coming and going IP traffic rates, optionally sends stats
 * ... (rest of element documentation remains largely the same) ...
 */

// --- ADDED: Packed Struct Definitions (Outside the Class) ---
#pragma pack(push, 1)

// Header for statistics packet
// Matches Python format: "!IH" (4 + 2 = 6 bytes)
struct StatsPacketHeader {
    uint32_t auth_key;      // Network byte order
    uint16_t record_count;  // Network byte order
};
static_assert(sizeof(StatsPacketHeader) == 6, "StatsPacketHeader size mismatch");

// Data for a single IP prefix statistics record
// Matches Python format: "!IBxxxII" (4 + 1 + 3_pad + 4 + 4 = 16 bytes)
struct PrefixStatsRecord {
    uint32_t ip_prefix;     // Network byte order
    uint8_t  prefix_len;
    uint8_t  _padding[3];   // Explicit padding
    uint32_t to_rate;       // Host byte order (simple integers)
    uint32_t from_rate;     // Host byte order (simple integers)
};
static_assert(sizeof(PrefixStatsRecord) == 16, "PrefixStatsRecord size mismatch");

#pragma pack(pop)
// --- END ADDED ---


class Spinlock; // Forward declaration

// The main IPRateMonitor element class
class IPRateMonitor : public Element {
public:

    // --- Original Enums and Structs ---
    enum {
        stability_shift = 5,
        scale = 10
    };

    struct EWMAParameters : public FixedEWMAXParameters<stability_shift, scale> {
        enum { rate_count = 2 };
        static unsigned epoch() { return click_jiffies() >> 3; }
        static unsigned epoch_frequency() { return CLICK_HZ >> 3; }
    };

    typedef RateEWMAX<EWMAParameters> MyEWMA;

    // Forward declare nested structs
    struct Stats;
    struct Counter;

    // Nested Counter struct (Original)
    struct Counter {
        MyEWMA fwd_and_rev_rate;
        Stats *next_level;
        unsigned anno_this;
        Counter() : next_level(0), anno_this(0) {}
        Counter(const MyEWMA &ewma) : fwd_and_rev_rate(ewma), next_level(0), anno_this(0) {}
    };

    // Nested Stats struct (Original)
    struct Stats {
        enum { MAX_COUNTERS = 256 };
        Counter *_parent;
        Stats *_prev, *_next;
        Counter* counter[MAX_COUNTERS];
        Stats(IPRateMonitor *m); // Constructor definition in .cc
        ~Stats() CLICK_COLD;    // Destructor definition in .cc
    private:
        IPRateMonitor *_rm;     // Pointer back to parent IPRateMonitor
    };
    // --- End Original Enums and Structs ---

    // --- NEW: Enum for Handler IDs ---
    enum {
        h_aggregator, h_interval
    };
    // --- END NEW ---

    // --- Original Public Methods ---
    IPRateMonitor() CLICK_COLD;
    ~IPRateMonitor() CLICK_COLD;

    const char *class_name() const { return "IPRateMonitor"; }
    const char *port_count() const { return "1-2/1-2"; } // Retain original port count

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    int initialize(ErrorHandler *) CLICK_COLD;
    void cleanup(CleanupStage) CLICK_COLD;

    void set_resettime() { _resettime = EWMAParameters::epoch(); } // Original inline
    void set_anno_level(unsigned addr, unsigned level, unsigned when); // Original inline below

    void push(int port, Packet *p); // Definition in .cc
    Packet *pull(int port);         // Definition in .cc

    int llrpc(unsigned, void *);    // Definition in .cc
    // --- End Original Public Methods ---

protected:
    // --- Original Protected Members ---
    friend struct Stats; // Allow Stats destructor access
    void set_prev(Stats *s) { _prev_deleted = s; }
    void set_next(Stats *s) { _next_deleted = s; }
    void set_first(Stats *s) { _first = s; }
    void set_last(Stats *s) { _last = s; }
    void update_alloced_mem(ssize_t m) { _alloced_mem += m; }
    // --- End Original Protected Members ---

private:
    // --- Original Private Members ---
    enum { MAX_SHIFT = 24, PERIODIC_FOLD_INIT = 8192, MEMMAX_MIN = 100 };

    bool _count_packets;
    bool _anno_packets;
    int _thresh;
    size_t _memmax;
    unsigned int _ratio;
    Spinlock* _lock;

    Stats *_base;
    long unsigned int _resettime;
    size_t _alloced_mem;
    Stats *_first, *_last;
    Stats *_prev_deleted, *_next_deleted; // HACK for fold interaction
    // --- End Original Private Members ---

    // --- NEW MEMBERS for cooperative detection ---
    IPAddress _aggregator_addr; // Destination IP for stats
    int _aggregator_port;       // Destination UDP port
    Timer _timer;               // The timer to trigger sending
    Timestamp _interval;        // Interval for sending stats
    // --- END NEW MEMBERS ---

    // --- Original Private Methods ---
    void update_rates(Packet *, bool, bool); // Original inline below
    void update(unsigned, int, Packet *, bool, bool); // Original inline below
    void forced_fold(); // Definition in .cc
    void fold(int);     // Definition in .cc
    Counter *make_counter(Stats *, unsigned char, MyEWMA *); // Definition in .cc

    void show_agelist(void); // Definition in .cc
    String print(Stats *s, String ip = ""); // Definition in .cc

    void add_handlers() CLICK_COLD; // Definition in .cc
    static String look_read_handler(Element *e, void *) CLICK_COLD; // Definition in .cc
    static String what_read_handler(Element *e, void *) CLICK_COLD; // Definition in .cc (may be unused)
    static int reset_write_handler(const String &, Element *, void *, ErrorHandler *) CLICK_COLD; // Definition in .cc
    static int memmax_write_handler(const String &, Element *, void *, ErrorHandler *) CLICK_COLD; // Definition in .cc
    static int anno_level_write_handler(const String &, Element *, void *, ErrorHandler *) CLICK_COLD; // Definition in .cc
    // --- End Original Private Methods ---

    // --- NEW Private Methods for cooperative sending ---
    void run_timer(Timer *); // Definition in .cc
    // Pass current_prefix as host order for easier bit manipulation inside
    void collect_stats_recursive(Stats *s, uint32_t current_prefix_host, int depth, Vector<PrefixStatsRecord> &records); // Definition in .cc
    void send_stats_packet(const Vector<PrefixStatsRecord> &records); // Definition in .cc

    // Declare our new handler as a static member
    static int write_handler(const String &, Element *, void *, ErrorHandler *); // Definition in .cc
    // --- END NEW ---
};


// --- Original Inline Method Implementations ---
// (These were previously at the end of the file, keep them here)

inline void
IPRateMonitor::set_anno_level(unsigned addr, unsigned level, unsigned when)
{
    Stats *s = _base;
    Counter *c = 0;
    int bitshift;

    addr = ntohl(addr);

    // zoom in to the specified level
    for (bitshift = 24; bitshift >= 0; bitshift -= 8) {
        unsigned char byte = (addr >> bitshift) & 255;

        if (!(c = s->counter[byte]))
            return;

        if (level == 0) {
            c->anno_this = when;
            delete c->next_level;
            c->next_level = 0;
            return;
        }

        if (!c->next_level)
            return;

        s = c->next_level;
        level--;
    }
}

// Dives in tables based on addr and raises all rates by val.
inline void
IPRateMonitor::update(unsigned addr, int val, Packet *p,
                      bool forward, bool update_ewma)
{
    Stats *s = _base;
    Counter *c = 0;
    unsigned now = EWMAParameters::epoch();
    static unsigned prev_fold_time = now; // Static variable, might need care in multithreading?

    // zoom in to deepest opened level
    addr = ntohl(addr);   // need it in host order for bit shifts

    int bitshift;
    for (bitshift = 24; bitshift >= 0; bitshift -= 8) {
        unsigned char byte = (addr >> bitshift) & 255;

        // allocate Counter if it doesn't exist yet
        if (!(c = s->counter[byte]))
            if (!(c = make_counter(s, byte, NULL)))
                return; // Allocation failed

        // update is done on every level. Result: Counter has sum of all the rates
        // of its children
        if(update_ewma) {
            if (forward)
                c->fwd_and_rev_rate.update(val,0);
            else
                c->fwd_and_rev_rate.update(val,1);
        }

        // zoom in on subnet or host
        if (!c->next_level)
            break; // Reached deepest level for this address
        s = c->next_level;
    }

    // --- Calculate unscaled rates for annotation and threshold check ---
    // Make sure 'c' is not NULL (shouldn't happen if make_counter succeeds)
    if (!c) return;

    int fwd_rate = c->fwd_and_rev_rate.scaled_average(0);
    int rev_rate = c->fwd_and_rev_rate.scaled_average(1);
    int freq = EWMAParameters::epoch_frequency();
    fwd_rate = (fwd_rate * freq) >> scale;
    rev_rate = (rev_rate * freq) >> scale;

    if (_anno_packets) {
        // annotate packet with fwd and rev rates for inspection by CompareBlock
        SET_FWD_RATE_ANNO(p, fwd_rate);
        SET_REV_RATE_ANNO(p, rev_rate);
    }

    // Zoom in logic (mostly original)
    if (c->anno_this < now &&
        (fwd_rate >= _thresh || rev_rate >= _thresh) &&
        ((bitshift > 0) && // Check if we can zoom deeper (bitshift becomes < 0 at last level)
         (!_memmax || (_alloced_mem+sizeof(Counter)+sizeof(Stats)) <= _memmax)))
    {
        bitshift -= 8; // Move to the next byte level
        unsigned char next_byte = (addr >> bitshift) & 255;
        if (!(c->next_level = new Stats(this)) ||
            !make_counter(c->next_level, next_byte, &c->fwd_and_rev_rate))
        {
            if(c->next_level) {   // new Stats() may have succeeded: kill it.
                delete c->next_level;
                c->next_level = 0;
            }
            // Memory allocation failed or limit reached, cannot zoom
            return;
        }

        // tell parent about newly created Stats and make it youngest in age-list
        c->next_level->_parent = c;

        // append to end of list
        if (_last) { // Ensure _last is not NULL
             _last->_next = c->next_level;
        } else { // List was empty (should only happen if _base wasn't _first/_last initially)
             _first = c->next_level;
        }
        c->next_level->_next = 0;
        c->next_level->_prev = _last;
        _last = c->next_level;
    }

    // Periodic fold check (Original)
    if(now - prev_fold_time >= EWMAParameters::epoch_frequency()) {
        fold(_thresh);
        prev_fold_time = now;
    }
}


// for forward packets (port 0), update based on src IP address;
// for reverse packets (port 1), update based on dst IP address.
inline void
IPRateMonitor::update_rates(Packet *p, bool forward, bool update_ewma)
{
    const click_ip *ip = p->ip_header();
    // Ensure packet has a valid IP header before proceeding
    if (!ip) return;
    int val = _count_packets ? 1 : ntohs(ip->ip_len);

    if (forward)
        update(ip->ip_src.s_addr, val, p, true, update_ewma);
    else
        update(ip->ip_dst.s_addr, val, p, false, update_ewma);
}

// --- End Original Inline Method Implementations ---


CLICK_ENDDECLS
#endif /* CLICK_IPRATEMON_HH */

