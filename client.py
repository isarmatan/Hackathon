import socket
import struct
import threading
from scapy.all import sniff, UDP, IP, Raw
import time

# --- Constants ---
MAGIC_COOKIE = 0xabcddcba  # Unique identifier for offer/request messages
MESSAGE_TYPE_OFFER = 0x2   # Message type for broadcast offer
MESSAGE_TYPE_REQUEST = 0x3 # Message type for client request
PAYLOAD_TYPE = 0x4         # Message type for payload packets
BUFFER_SIZE = 65536         # Buffer size for receiving data

# --- ANSI Color Helper ---

def colorize(text, style=0, text_color=37, bg_color=40):
    """
    Format text with ANSI escape codes for colored terminal output.

    Args:
        text (str): The text to format.
        style (int): Text style (0=normal, 1=bold, 4=underline).
        text_color (int): Text color (e.g., 31=red, 32=green, etc.).
        bg_color (int): Background color (e.g., 40=black, 41=red, etc.).

    Returns:
        str: Formatted text with ANSI escape codes.
    """
    return f"\033[{style};{text_color};{bg_color}m{text}\033[0m"

# --- Sniff Broadcast Offers ---

def is_valid_broadcast(packet):
    """
    Validate and parse a broadcast packet. A valid offer packet must include:
    - Magic cookie (4 bytes)
    - Message type (1 byte, should equal MESSAGE_TYPE_OFFER)
    - UDP port (2 bytes)
    - TCP port (2 bytes)

    Args:
        packet: The raw packet captured by Scapy.

    Returns:
        tuple or None: (server_ip, udp_port, tcp_port) if valid, else None.
    """
    try:
        if UDP in packet and Raw in packet:
            data = packet[Raw].load
            if len(data) >= 9:  # Minimum size for valid offer message
                magic_cookie, msg_type, udp_port, tcp_port = struct.unpack("!I B H H", data[:9])
                if magic_cookie == MAGIC_COOKIE and msg_type == MESSAGE_TYPE_OFFER:
                    return packet[IP].src, udp_port, tcp_port
    except Exception as e:
        print(colorize(f"Error parsing broadcast packet: {e}", text_color=31))
    return None

def sniff_broadcast_packets(timeout=10):
    """
    Sniff for UDP broadcast packets and extract server details.

    Args:
        timeout (int): Time to sniff packets (in seconds).

    Returns:
        dict or None: Server information (IP, UDP port, TCP port) if an offer is detected, else None.
    """
    detected_info = {}

    def process_packet(packet):
        nonlocal detected_info
        result = is_valid_broadcast(packet)
        if result:
            ip, udp_port, tcp_port = result
            print(colorize(f"Received offer from {ip} (UDP Port={udp_port}, TCP Port={tcp_port})", text_color=32))
            detected_info = {"ip": ip, "udp_port": udp_port, "tcp_port": tcp_port}

    sniff(filter="udp", prn=process_packet, timeout=timeout)
    return detected_info if detected_info else None

# --- TCP Transfer ---

def handle_tcp_connection(server_ip, tcp_port, connection_id, file_size):
    """
    Handle a TCP connection to the server to request and receive a file.

    Args:
        server_ip (str): Server's IP address.
        tcp_port (int): TCP port number on the server.
        connection_id (int): ID for the TCP connection.
        file_size (int): Size of the file to request.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
            tcp_socket.connect((server_ip, tcp_port))
            print(colorize(f"[TCP {connection_id}] Connected to {server_ip}:{tcp_port}", text_color=32))

            # Send the requested file size
            tcp_socket.sendall(f"{file_size}\n".encode())

            # Receive the file and measure performance
            start_time = time.time()
            received_bytes = 0
            while received_bytes < file_size:
                data = tcp_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                received_bytes += len(data)
            end_time = time.time()

            # Calculate and display performance
            duration = end_time - start_time
            speed = received_bytes * 8 / duration / 1e6  # Mbps
            print(colorize(f"[TCP {connection_id}] Transfer complete: {received_bytes} bytes in {duration:.2f}s ({speed:.2f} Mbps)", text_color=33))
    except Exception as e:
        print(colorize(f"[TCP {connection_id}] Error: {e}", text_color=31))

# --- UDP Transfer ---

def handle_udp_connection(server_ip, udp_port, connection_id, file_size):
    """
    Handle a UDP connection to the server to request and receive a file in segments.

    Args:
        server_ip (str): Server's IP address.
        udp_port (int): UDP port number on the server.
        connection_id (int): ID for the UDP connection.
        file_size (int): Size of the file to request.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
            udp_socket.settimeout(2)

            # Send the request message
            request_packet = struct.pack("!IbQ", MAGIC_COOKIE, MESSAGE_TYPE_REQUEST, file_size)
            udp_socket.sendto(request_packet, (server_ip, udp_port))

            print(colorize(f"[UDP {connection_id}] Request sent to {server_ip}:{udp_port}", text_color=32))

            # Receive payload packets and calculate performance
            received_segments = set()
            total_segments_expected = None
            start_time = time.time()

            while True:
                try:
                    data, _ = udp_socket.recvfrom(BUFFER_SIZE + 20)
                    if len(data) >= 21:  # Header size: 4 + 1 + 8 + 8
                        cookie, msg_type, total_segments, segment_num = struct.unpack("!IbQQ", data[:21])
                        if cookie == MAGIC_COOKIE and msg_type == PAYLOAD_TYPE:
                            received_segments.add(segment_num)
                            total_segments_expected = total_segments
                except socket.timeout:
                    break

            end_time = time.time()
            duration = end_time - start_time
            packets_received = len(received_segments)

            # Handle case where total_segments_expected is None or 0
            if not total_segments_expected or total_segments_expected == 0:
                print(colorize(f"[UDP {connection_id}] No segments received or server disconnected unexpectedly.", text_color=31))
                return

            # Calculate packet loss and speed
            packet_loss = 100 * (1 - packets_received / total_segments_expected)
            speed = packets_received * BUFFER_SIZE * 8 / duration / 1e6  # Mbps
            print(colorize(f"[UDP {connection_id}] Transfer complete: {packets_received}/{total_segments_expected} packets in {duration:.2f}s, Loss: {packet_loss:.2f}%, Speed: {speed:.2f} Mbps", text_color=33))
    except Exception as e:
        print(colorize(f"[UDP {connection_id}] Error: {e}", text_color=31))

# --- Main Client Logic ---

def main():
    """
    Main function to interact with the user and manage TCP/UDP transfers.
    """
    try:
        # Get user input
        file_size = int(input(colorize("Enter the file size (in bytes): ", text_color=36)))
        num_tcp_connections = int(input(colorize("Enter the number of TCP connections: ", text_color=36)))
        num_udp_connections = int(input(colorize("Enter the number of UDP connections: ", text_color=36)))
    except ValueError:
        print(colorize("Invalid input! Please enter integers for the file size and connection counts.", text_color=31))
        return

    while True:
        print(colorize("Sniffing for broadcast packets...", style=1, text_color=34))
        info = sniff_broadcast_packets(timeout=10)
        if info is None:
            print(colorize("No offers received. Retrying...\n", text_color=31))
            continue

        # Extract server details
        server_ip = info["ip"]
        udp_port = info["udp_port"]
        tcp_port = info["tcp_port"]

        print(colorize(f"Connecting to server at {server_ip} (TCP port: {tcp_port}, UDP port: {udp_port})", text_color=32))

        # Launch TCP transfers
        tcp_threads = []
        for i in range(num_tcp_connections):
            t = threading.Thread(target=handle_tcp_connection, args=(server_ip, tcp_port, i + 1, file_size))
            t.start()
            tcp_threads.append(t)

        # Launch UDP transfers
        udp_threads = []
        for i in range(num_udp_connections):
            t = threading.Thread(target=handle_udp_connection, args=(server_ip, udp_port, i + 1, file_size))
            t.start()
            udp_threads.append(t)

        # Wait for all threads to finish
        for t in tcp_threads + udp_threads:
            t.join()

        print(colorize("All transfers complete. Listening for new offers...\n", style=1, text_color=34))

if __name__ == "__main__":
    main()