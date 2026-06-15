// test-full.click - Test the complete detection and enforcement loop

// --- Traffic Generation ---
// Generate UDP packets simulating a one-way attack
src :: RatedSource(RATE 10000)
-> UDPIPEncap(
SRC 10.0.0.1, SPORT 5000,
DST 18.0.0.1, DPORT 80
)
-> CheckIPHeader(CHECKSUM false)

// --- Detection Element ---
-> mon :: IPRateMonitor(
TYPE PACKETS,
RATIO 1.0,
THRESH 100
)

// --- Enforcement Element ---
-> enf :: PolicyEnforcer(
LISTEN_PORT 50001 // The port where it listens for commands
)

// --- Verification Element ---
// Counter will count packets after the enforcer.
// If the enforcer blocks traffic, this count should stop increasing.
-> ctr :: Counter
-> Discard;

// --- Configuration Script ---
// Use Script to configure the IPRateMonitor after it starts
config_script :: Script(
TYPE ACTIVE,
// Tell IPRateMonitor where the aggregator is and how often to send stats
write mon.aggregator 127.0.0.1:49555,
write mon.interval 1s
);

// Optional: Control Socket for inspecting the counter
ControlSocket(TCP, 7777);