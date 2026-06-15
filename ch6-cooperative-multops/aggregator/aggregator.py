# # import socket
# # import struct
# # import threading

# # # -- Configuration --
# # LISTEN_IP = "0.0.0.0"
# # LISTEN_PORT = 49555
# # ANALYSIS_INTERVAL = 1.0  # seconds
# # ATTACK_THRESHOLD = 10.0  # to_rate is 10x from_rate

# # # -- Protocol Definitions --
# # # These formats must EXACTLY match the C++ structs in ipratemon.hh
# # HEADER_FORMAT = "!IH"
# # HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
# # RECORD_FORMAT = "!IBxxxII"
# # RECORD_SIZE = struct.calcsize(RECORD_FORMAT)

# # # --- Main Data Storage ---
# # traffic_stats = {}
# # stats_lock = threading.Lock() # A lock to prevent race conditions

# # # --- Thread Control ---
# # # This Event will act as a "stop sign" for our timer thread.
# # stop_event = threading.Event()

# # def analyze_and_reset_stats():
# #     """
# #     This function is called by a recurring timer to analyze collected stats,
# #     print alerts, and then reset the data for the next time window.
# #     """
# #     global traffic_stats

# #     # Acquire the lock to safely access the shared traffic_stats dictionary
# #     with stats_lock:
# #         print("\n--- Analyzing Stats for the Last Second ---")
# #         if not traffic_stats:
# #             print("No traffic received in this window.")
# #         else:
# #             for prefix, rates in traffic_stats.items():
# #                 to_rate = rates['to_rate']
# #                 from_rate = rates['from_rate']

# #                 # Avoid division by zero when calculating the ratio
# #                 if from_rate > 0:
# #                     ratio = to_rate / from_rate
# #                     print(f"  Prefix: {prefix}, To-Rate: {to_rate}, From-Rate: {from_rate}, Ratio: {ratio:.2f}")

# #                     # Check if the calculated ratio exceeds our attack threshold
# #                     if ratio > ATTACK_THRESHOLD:
# #                         print(f"  🚨 ALERT: Asymmetric attack detected for {prefix}! Ratio is {ratio:.2f}")
# #                 else:
# #                     # If from_rate is 0 but to_rate is high, it's also a potential attack
# #                     print(f"  Prefix: {prefix}, To-Rate: {to_rate}, From-Rate: 0")
# #                     if to_rate > 100: # Use an arbitrary threshold for one-way traffic
# #                         print(f"  🚨 ALERT: One-way flood detected for {prefix}!")

# #         # CRITICAL: Reset the stats dictionary for the next analysis window
# #         traffic_stats = {}

# #     # Reschedule the timer ONLY if the stop event has NOT been set.
# #     if not stop_event.is_set():
# #         threading.Timer(ANALYSIS_INTERVAL, analyze_and_reset_stats).start()


# # # --- Server Setup ---
# # # 1. Create and bind the UDP socket
# # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# # server_address = (LISTEN_IP, LISTEN_PORT)
# # sock.bind(server_address)
# # print(f"✅ Aggregator is listening on {LISTEN_IP}:{LISTEN_PORT}")

# # # 2. Start the first analysis timer, which will then run recursively
# # print(f"Analysis will run every {ANALYSIS_INTERVAL} second(s).")
# # threading.Timer(ANALYSIS_INTERVAL, analyze_and_reset_stats).start()

# # print("Waiting to receive messages...")

# # # --- Main Loop ---
# # # This loop runs forever, receiving and processing UDP packets.
# # try:
# #     while True:
# #         # Wait for a UDP packet
# #         raw_data, address = sock.recvfrom(4096)

# #         # Unpack the header to find out how many records are in the payload
# #         auth_key, record_count = struct.unpack(HEADER_FORMAT, raw_data[:HEADER_SIZE])

# #         # Loop through and process each record
# #         for i in range(record_count):
# #             offset = HEADER_SIZE + (i * RECORD_SIZE)
# #             record_data = raw_data[offset : offset + RECORD_SIZE]

# #             ip_prefix_int, prefix_len, to_rate, from_rate = struct.unpack(RECORD_FORMAT, record_data)

# #             # Convert binary IP to a human-readable string
# #             ip_prefix_str = socket.inet_ntoa(struct.pack('!I', ip_prefix_int))
# #             prefix = f"{ip_prefix_str}/{prefix_len}"

# #             # Acquire the lock before modifying the shared dictionary
# #             with stats_lock:
# #                 if prefix not in traffic_stats:
# #                     traffic_stats[prefix] = {'to_rate': 0, 'from_rate': 0}

# #                 # Add the new rates to the running totals
# #                 traffic_stats[prefix]['to_rate'] += to_rate
# #                 traffic_stats[prefix]['from_rate'] += from_rate

# # except KeyboardInterrupt:
# #     print("\nShutting down aggregator...")
# #     # Set the "stop sign" for the timer thread
# #     stop_event.set()
# #     sock.close()


# import socket
# import struct
# import threading
# import time

# # -- Configuration --
# LISTEN_IP = "0.0.0.0"
# LISTEN_PORT = 49555
# ANALYSIS_INTERVAL = 1.0  # seconds
# ATTACK_THRESHOLD = 10.0  # to_rate is 10x from_rate

# # --- NEW: Policy Enforcement Config ---
# ROUTER_CMD_IP = "127.0.0.1"  # IP of the Click router
# ROUTER_CMD_PORT = 50001        # Port the RatioBlocker will listen on

# # -- Protocol Definitions (from Phase 1) --
# STATS_HEADER_FORMAT = "!IH"
# STATS_HEADER_SIZE = struct.calcsize(STATS_HEADER_FORMAT)
# STATS_RECORD_FORMAT = "!IBxxxII"
# STATS_RECORD_SIZE = struct.calcsize(STATS_RECORD_FORMAT)

# # --- NEW: Drop Policy Protocol Definition ---
# # struct DropPolicyRecord { uint32_t ip_prefix; uint8_t prefix_len; };
# # We add 3 bytes of padding 'xxx' to match C++ struct alignment
# DROP_POLICY_FORMAT = "!IBxxx"
# DROP_POLICY_SIZE = struct.calcsize(DROP_POLICY_FORMAT)

# # --- Main Data Storage ---
# traffic_stats = {}
# stats_lock = threading.Lock()
# stop_event = threading.Event()

# # --- NEW: Socket for sending commands ---
# # We use a separate socket for sending commands to the router
# command_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# def ip_str_to_int(ip_str):
#     """Converts a dotted-decimal IP string to a 32-bit integer."""
#     return struct.unpack("!I", socket.inet_aton(ip_str))[0]

# def send_drop_command(prefix_str):
#     """
#     NEW: Packs and sends a drop command to the router.
#     """
#     try:
#         ip_str, len_str = prefix_str.split('/')
#         ip_int = ip_str_to_int(ip_str)
#         prefix_len = int(len_str)
        
#         # Pack the data into the binary struct format
#         payload = struct.pack(DROP_POLICY_FORMAT, ip_int, prefix_len)
        
#         # Send the UDP packet to the router's command port
#         command_socket.sendto(payload, (ROUTER_CMD_IP, ROUTER_CMD_PORT))
#         print(f"  📡 Sent DROP command for {prefix_str} to {ROUTER_CMD_IP}:{ROUTER_CMD_PORT}")
        
#     except Exception as e:
#         print(f"  Error sending drop command: {e}")

# def analyze_and_reset_stats():
#     """
#     This function is called by the timer to analyze collected stats.
#     """
#     global traffic_stats
    
#     with stats_lock:
#         print("\n--- Analyzing Stats for the Last Second ---")
#         if not traffic_stats:
#             print("No traffic received in this window.")
#         else:
#             for prefix, rates in traffic_stats.items():
#                 to_rate = rates['to_rate']
#                 from_rate = rates['from_rate']

#                 if from_rate > 0:
#                     ratio = to_rate / from_rate
#                     print(f"  Prefix: {prefix}, To-Rate: {to_rate}, From-Rate: {from_rate}, Ratio: {ratio:.2f}")
                    
#                     if ratio > ATTACK_THRESHOLD:
#                         print(f"  🚨 ALERT: Asymmetric attack detected for {prefix}! Ratio is {ratio:.2f}")
#                         # --- MODIFIED: Send drop command on detection ---
#                         send_drop_command(prefix)
#                 else:
#                     print(f"  Prefix: {prefix}, To-Rate: {to_rate}, From-Rate: 0")
#                     if to_rate > 100:
#                          print(f"  🚨 ALERT: One-way flood detected for {prefix}!")
#                          # --- MODIFIED: Send drop command on detection ---
#                          send_drop_command(prefix)

#         # CRITICAL: Reset the stats for the next window
#         traffic_stats = {}
    
#     # Reschedule the timer to run again, if not stopped
#     if not stop_event.is_set():
#         threading.Timer(ANALYSIS_INTERVAL, analyze_and_reset_stats).start()

# # --- Server Setup (for receiving stats) ---
# stats_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# server_address = (LISTEN_IP, LISTEN_PORT)
# stats_sock.bind(server_address)
# print(f"✅ Aggregator is listening for stats on {LISTEN_IP}:{LISTEN_PORT}")

# # Start the first analysis timer
# threading.Timer(ANALYSIS_INTERVAL, analyze_and_reset_stats).start()

# print("Waiting to receive stats...")

# try:
#     while True:
#         # Check if the stop event has been set (e.g., by KeyboardInterrupt)
#         if stop_event.is_set():
#             break
            
#         # Set a timeout on the socket so the loop can check the stop_event
#         stats_sock.settimeout(1.0)
        
#         try:
#             raw_data, address = stats_sock.recvfrom(4096)
#         except socket.timeout:
#             continue # Timeout occurred, loop back and check stop_event
            
#         # --- Data Reception and Fusion (Unchanged) ---
#         auth_key, record_count = struct.unpack(STATS_HEADER_FORMAT, raw_data[:STATS_HEADER_SIZE])
        
#         for i in range(record_count):
#             offset = STATS_HEADER_SIZE + (i * STATS_RECORD_SIZE)
#             record_data = raw_data[offset : offset + STATS_RECORD_SIZE]
            
#             ip_prefix_int, prefix_len, to_rate, from_rate = struct.unpack(STATS_RECORD_FORMAT, record_data)
            
#             # Convert the 32-bit integer IP back to a string
#             ip_prefix_str = socket.inet_ntoa(struct.pack('!I', ip_prefix_int))
#             prefix = f"{ip_prefix_str}/{prefix_len}"
            
#             with stats_lock:
#                 if prefix not in traffic_stats:
#                     traffic_stats[prefix] = {'to_rate': 0, 'from_rate': 0}
                
#                 traffic_stats[prefix]['to_rate'] += to_rate
#                 traffic_stats[prefix]['from_rate'] += from_rate

# except KeyboardInterrupt:
#     print("\nShutting down aggregator...")

# finally:
#     stop_event.set()
#     stats_sock.close()
#     command_socket.close()
#     print("Aggregator stopped.")

import socket
import struct
import threading
import time

# -- Configuration --
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 49555
ANALYSIS_INTERVAL = 1.0  # seconds
ATTACK_THRESHOLD = 10.0  # to_rate is 10x from_rate (or from_rate is 0)
ONE_WAY_FLOOD_MIN_RATE = 100 # Min rate to trigger one-way flood alert if from_rate is 0

# --- Policy Enforcement Config ---
ROUTER_CMD_IP = "127.0.0.1"  # IP of the Click router
ROUTER_CMD_PORT = 50001        # Port the PolicyEnforcer will listen on

# -- Protocol Definitions (from Phase 1) --
STATS_HEADER_FORMAT = "!IH" # Network Order (!), uint32 (I), uint16 (H)
STATS_HEADER_SIZE = struct.calcsize(STATS_HEADER_FORMAT)
# struct PrefixStatsRecord { uint32_t ip_prefix; uint8_t prefix_len; uint32_t to_rate; uint32_t from_rate; };
# Need padding to match C++ struct alignment
STATS_RECORD_FORMAT = "!IBxxxII" # Network Order (!), uint32 (I), uint8 (B), 3 pad bytes (xxx), uint32 (I), uint32 (I)
STATS_RECORD_SIZE = struct.calcsize(STATS_RECORD_FORMAT)

# --- Drop Policy Protocol Definition ---
# struct DropPolicyRecord { uint32_t ip_prefix; uint8_t prefix_len; }; + padding
# Use pragma pack(1) on C++ side to avoid padding issues if possible,
# otherwise match assumed padding here.
DROP_POLICY_FORMAT = "!IBxxx" # Network Order (!), uint32 (I), uint8 (B), 3 pad bytes (xxx)
DROP_POLICY_SIZE = struct.calcsize(DROP_POLICY_FORMAT)

# --- Main Data Storage ---
traffic_stats = {}
stats_lock = threading.Lock()
stop_event = threading.Event() # Used to signal threads to stop

# --- Socket for sending commands ---
command_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def ip_str_to_int(ip_str):
    """Converts a dotted-decimal IP string to a 32-bit integer (network byte order)."""
    # socket.inet_aton already returns bytes in network byte order
    packed_ip_bytes = socket.inet_aton(ip_str)
    # Unpack as network byte order integer (struct.pack needs integers)
    return struct.unpack("!I", packed_ip_bytes)[0]

def send_drop_command(prefix_str):
    """
    Packs and sends a drop command (IP prefix and length) to the router.
    """
    try:
        ip_str, len_str = prefix_str.split('/')
        # Get integer representation in network byte order
        ip_int_net_order = ip_str_to_int(ip_str)
        prefix_len = int(len_str)

        # Basic validation
        if not (0 < prefix_len <= 32):
             print(f"  Error: Invalid prefix length {prefix_len} for {ip_str}. Cannot send command.")
             return

        # --- DEBUG: Verify values before packing ---
        print(f"  DEBUG: Preparing to pack IP={ip_str} (int: {ip_int_net_order}, hex: {hex(ip_int_net_order)} net order), len={prefix_len}")
        # --- END DEBUG ---

        # Pack the data into the binary struct format using network byte order int
        payload = struct.pack(DROP_POLICY_FORMAT, ip_int_net_order, prefix_len)

        # --- DEBUG: Print bytes before sending ---
        print(f"  DEBUG: Sending raw bytes: {' '.join(f'{b:02X}' for b in payload)}")
        # --- END DEBUG ---

        # Send the UDP packet to the router's command port
        command_socket.sendto(payload, (ROUTER_CMD_IP, ROUTER_CMD_PORT))
        print(f"  📡 Sent DROP command for {prefix_str} to {ROUTER_CMD_IP}:{ROUTER_CMD_PORT}")

    except ValueError:
        print(f"  Error: Could not parse prefix string: {prefix_str}")
    except socket.error as e:
        print(f"  Socket error sending drop command: {e}")
    except Exception as e:
        print(f"  Unexpected error sending drop command: {e}")

def analyze_and_reset_stats():
    """
    Timer callback function: Analyzes collected stats, sends drop commands, and resets.
    """
    global traffic_stats

    # Use lock to safely access/modify shared data
    with stats_lock:
        print("\n--- Analyzing Stats for the Last Second ---")
        if not traffic_stats:
            print("No traffic received in this window.")
        else:
            # Create a copy of items to analyze to avoid modifying dict during iteration
            items_to_analyze = list(traffic_stats.items())
            for prefix, rates in items_to_analyze:
                to_rate = rates['to_rate']
                from_rate = rates['from_rate']
                attack_detected = False

                if from_rate > 0:
                    ratio = to_rate / from_rate
                    print(f"  Prefix: {prefix}, To-Rate: {to_rate}, From-Rate: {from_rate}, Ratio: {ratio:.2f}")

                    if ratio > ATTACK_THRESHOLD:
                        print(f"  🚨 ALERT: Asymmetric attack detected for {prefix}! Ratio exceeds threshold ({ATTACK_THRESHOLD:.1f})")
                        attack_detected = True
                else: # from_rate is 0 or was not seen
                    print(f"  Prefix: {prefix}, To-Rate: {to_rate}, From-Rate: {from_rate}")
                    if to_rate > ONE_WAY_FLOOD_MIN_RATE:
                         print(f"  🚨 ALERT: One-way flood detected for {prefix}! To-Rate exceeds threshold ({ONE_WAY_FLOOD_MIN_RATE})")
                         attack_detected = True

                # Send drop command if an attack was flagged for this prefix
                if attack_detected:
                    send_drop_command(prefix)

        # CRITICAL: Reset the stats dictionary for the next analysis window
        traffic_stats = {}

    # Reschedule the timer ONLY if the stop event hasn't been set
    if not stop_event.is_set():
        threading.Timer(ANALYSIS_INTERVAL, analyze_and_reset_stats).start()
    else:
        print("Timer: Stop event detected, not rescheduling.")


# --- Server Setup (for receiving stats) ---
try:
    stats_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (LISTEN_IP, LISTEN_PORT)
    stats_sock.bind(server_address)
    print(f"✅ Aggregator is listening for stats on {LISTEN_IP}:{LISTEN_PORT}")
except socket.error as e:
    print(f"Fatal Error: Could not bind stats socket to {LISTEN_IP}:{LISTEN_PORT}: {e}")
    exit(1) # Exit if we can't bind the main socket

# Start the first analysis timer
print(f"Starting analysis timer (interval: {ANALYSIS_INTERVAL}s)")
threading.Timer(ANALYSIS_INTERVAL, analyze_and_reset_stats).start()

print("Waiting to receive stats...")

# --- Main Loop (Receiving Stats) ---
try:
    while not stop_event.is_set():
        # Set a timeout on the socket so the loop isn't blocked indefinitely
        # This allows checking the stop_event regularly
        stats_sock.settimeout(1.0) # Check every 1 second

        try:
            # Wait for a UDP packet containing stats
            raw_data, address = stats_sock.recvfrom(4096) # Buffer size
        except socket.timeout:
            # No packet received within the timeout, loop again to check stop_event
            continue
        except socket.error as e:
             # Handle other potential socket errors during recvfrom
             if not stop_event.is_set(): # Don't report error if we're shutting down
                print(f"Socket error receiving data: {e}")
             continue # Attempt to continue if possible

        # --- Data Reception and Fusion Logic ---
        try:
            # 1. Parse the header
            if len(raw_data) < STATS_HEADER_SIZE:
                print(f"  Warning: Received packet too short for header from {address}. Size: {len(raw_data)}")
                continue

            auth_key, record_count = struct.unpack(STATS_HEADER_FORMAT, raw_data[:STATS_HEADER_SIZE])

            # Basic validation on record_count
            expected_total_size = STATS_HEADER_SIZE + (record_count * STATS_RECORD_SIZE)
            if len(raw_data) < expected_total_size:
                 print(f"  Warning: Packet from {address} is shorter ({len(raw_data)} bytes) than expected ({expected_total_size} bytes) for {record_count} records. Processing available data.")
                 # Adjust record_count if packet is truncated
                 record_count = (len(raw_data) - STATS_HEADER_SIZE) // STATS_RECORD_SIZE


            # 2. Loop through and parse all records in the packet
            for i in range(record_count):
                offset = STATS_HEADER_SIZE + (i * STATS_RECORD_SIZE)
                # Slice the data for the current record
                record_data = raw_data[offset : offset + STATS_RECORD_SIZE]

                # Check if slice is correct size (paranoid check after potential truncation)
                if len(record_data) != STATS_RECORD_SIZE:
                    print(f"  Warning: Incorrect record size at index {i}. Expected {STATS_RECORD_SIZE}, got {len(record_data)}. Skipping rest.")
                    break

                # Unpack the record from binary format
                ip_prefix_int, prefix_len, to_rate, from_rate = struct.unpack(STATS_RECORD_FORMAT, record_data)

                # Convert the 32-bit integer IP back to a readable string
                ip_prefix_str = socket.inet_ntoa(struct.pack('!I', ip_prefix_int))

                # Validate prefix_len received from C++
                if not (0 < prefix_len <= 32):
                    print(f"  Warning: Received invalid prefix length {prefix_len} for IP {ip_prefix_str} from {address}. Skipping record.")
                    continue

                # Construct the prefix string correctly using the received length
                prefix = f"{ip_prefix_str}/{prefix_len}"

                # 3. FUSE THE DATA (using lock for thread safety)
                with stats_lock:
                    if prefix not in traffic_stats:
                        # First time seeing this prefix in this window
                        traffic_stats[prefix] = {'to_rate': 0, 'from_rate': 0}

                    # Add the new rates to the existing totals for this window
                    traffic_stats[prefix]['to_rate'] += to_rate
                    traffic_stats[prefix]['from_rate'] += from_rate

        except struct.error as e:
            print(f"  Error unpacking packet data from {address}: {e}. Packet size: {len(raw_data)}")
        except Exception as e:
             print(f"  Unexpected error processing packet from {address}: {e}")

# --- Shutdown ---
except KeyboardInterrupt:
    print("\nCtrl+C detected. Shutting down aggregator...")

finally:
    print("Signaling threads to stop...")
    stop_event.set() # Signal the timer thread to stop rescheduling
    # Wait a moment for the timer thread to potentially finish its current run
    time.sleep(ANALYSIS_INTERVAL + 0.2)
    print("Closing sockets...")
    stats_sock.close()
    command_socket.close()
    print("Aggregator stopped.")

