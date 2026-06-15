// test-full.click (CORRECTED VERSION)
// Simulates a high-speed one-way attack (to 18.0.0.1)
// AND a slow, two-way legitimate flow (between 192.168.1.1 and 192.168.1.2)

// --- 1. Element Definitions ---
mon_ab :: IPRateMonitor(TYPE PACKETS, RATIO 1.0, THRESH 100)
mon_ba :: IPRateMonitor(TYPE PACKETS, RATIO 1.0, THRESH 100)
enforcer :: PolicyEnforcer(LISTEN_PORT 50001)
ctr :: Counter        // This will count the ATTACK packets that get through
ctr_good :: Counter // This will count the LEGITIMATE packets that get through

// This classifier will split the traffic *after* the enforcer
classifier :: IPClassifier(
    ip src 10.0.0.1,     // Output 0: Attack traffic
    ip src 192.168.1.1,  // Output 1: Legitimate traffic
    -                    // Output 2: Default (discard)
);

// --- 2. Traffic Generation ---

// Attack Traffic (A -> B)
RatedSource(RATE 10000)
    -> UDPIPEncap(SRC 10.0.0.1, SPORT 5000, DST 18.0.0.1, DPORT 80)
    -> [0]mon_ab; // Send to monitor

// Legitimate Traffic (X -> Y)
RatedSource(RATE 50)
    -> UDPIPEncap(SRC 192.168.1.1, SPORT 1234, DST 192.168.1.2, DPORT 500)
    -> [0]mon_ab; // Send to same monitor

// Legitimate Return Traffic (Y -> X)
RatedSource(RATE 50)
    -> UDPIPEncap(SRC 192.168.1.2, SPORT 500, DST 192.168.1.1, DPORT 1234)
    -> [0]mon_ba -> Discard; // Send to return monitor and discard

// --- 3. Main Processing Pipeline ---
// All traffic from mon_ab goes to the enforcer
mon_ab
    -> enforcer     // Enforcer blocks traffic based on aggregator commands
    -> classifier;  // Send ALL passed traffic to the classifier

// --- 4. Counter Pipelines ---
// Split the traffic from the classifier to the counters
classifier[0] -> ctr;       // Output 0 (Attack) -> attack counter
classifier[1] -> ctr_good;  // Output 1 (Legit) -> legit counter
classifier[2] -> Discard;   // Output 2 (Default) -> discard

// Terminate the counter pipelines
ctr -> Discard;
ctr_good -> Discard;

// --- 5. Control Script ---
Script(
    TYPE ACTIVE,
    write mon_ab.aggregator 127.0.0.1:49555,
    write mon_ab.interval 1s,
    write mon_ba.aggregator 127.0.0.1:49555,
    write mon_ba.interval 1s
);

ControlSocket(TCP, 7777);