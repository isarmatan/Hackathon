import socket
import struct
import threading
import time

# --- Constants ---
MAGIC_COOKIE = 0xabcddcba  # Unique identifier for offer/request messages
MSG_TYPE_OFFER = 0x2       # Message type for broadcast offer
MSG_TYPE_REQUEST = 0x3     # Message type for client request
MSG_TYPE_PAYLOAD = 0x4     # Message type for payload packets
SEGMENT_SIZE = 1400        # Maximum payload size for each segment

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

# --- Helper Functions ---

def get_available_port(socket_type):
    """
    Get an available port dynamically assigned by the OS.

    Args:
        socket_type: The type of socket (e.g., SOCK_DGRAM, SOCK_STREAM).

    Returns:
        int: The assigned port number.
    """
    temp_socket = socket.socket(socket.AF_INET, socket_type)
    temp_socket.bind(("", 0))  # Bind to an ephemeral port assigned by the OS
    port = temp_socket.getsockname()[1]  # Retrieve the assigned port
    temp_socket.close()
    return port

def pack_offer_message(udp_port, tcp_port):
    """
    Pack an offer message to be broadcasted.

    Args:
        udp_port (int): UDP port number for client connections.
        tcp_port (int): TCP port number for client connections.

    Returns:
        bytes: The packed offer message.
    """
    return struct.pack("!IBHH", MAGIC_COOKIE, MSG_TYPE_OFFER, udp_port, tcp_port)

def unpack_request_message(data):
    """
    Unpack a request message from the client.

    Args:
        data (bytes): The raw message received from the client.

    Returns:
        int or None: The requested file size in bytes, or None if invalid.
    """
    try:
        magic_cookie, message_type, file_size = struct.unpack("!IBQ", data)
        if magic_cookie != MAGIC_COOKIE or message_type != MSG_TYPE_REQUEST:
            raise ValueError("Invalid request message")
        return file_size
    except Exception as e:
        print(colorize(f"[SERVER] Failed to unpack request message: {e}", text_color=31))
        return None

def pack_payload_message(total_segments, current_segment, payload):
    """
    Pack a UDP payload message to be sent to the client.

    Args:
        total_segments (int): Total number of segments in the file.
        current_segment (int): The current segment number.
        payload (bytes): The payload data.

    Returns:
        bytes: The packed payload message.
    """
    header = struct.pack("!IBQQ", MAGIC_COOKIE, MSG_TYPE_PAYLOAD, total_segments, current_segment)
    return header + payload

# --- Server Logic ---

def server_broadcast_offer(udp_port, tcp_port, broadcast_port):
    """
    Broadcast offer messages via UDP at regular intervals.

    Args:
        udp_port (int): UDP port for client connections.
        tcp_port (int): TCP port for client connections.
        broadcast_port (int): Port used for broadcasting.
    """
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        offer_message = pack_offer_message(udp_port, tcp_port)
        try:
            broadcast_socket.sendto(offer_message, ("<broadcast>", broadcast_port))
            print(colorize(f"[SERVER] Broadcasting offer on UDP port {broadcast_port}", text_color=34))
        except Exception as e:
            print(colorize(f"[SERVER] Error broadcasting offer: {e}", text_color=31))
        time.sleep(1)

def handle_tcp_connection(client_socket):
    """
    Handle a single TCP client connection.

    Args:
        client_socket: The socket representing the client connection.
    """
    try:
        request = client_socket.recv(1024).decode().strip()
        file_size = int(request)
        print(colorize(f"[SERVER] Received TCP request for {file_size} bytes", text_color=32))
        data = b"x" * file_size
        client_socket.sendall(data)
    except Exception as e:
        print(colorize(f"[SERVER] Error handling TCP connection: {e}", text_color=31))
    finally:
        client_socket.close()

def start_tcp_server(tcp_port):
    """
    Start the TCP server to handle incoming connections.

    Args:
        tcp_port (int): The TCP port to listen on.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("", tcp_port))
    server_socket.listen(5)
    print(colorize(f"[SERVER] TCP server listening on port {tcp_port}", text_color=34))
    while True:
        client_socket, client_address = server_socket.accept()
        print(colorize(f"[SERVER] Accepted TCP connection from {client_address}", text_color=32))
        threading.Thread(target=handle_tcp_connection, args=(client_socket,), daemon=True).start()

def handle_udp_request(data, client_address, udp_socket):
    """
    Handle a single UDP client request.

    Args:
        data (bytes): The raw request message from the client.
        client_address: The client's address and port.
        udp_socket: The UDP server socket.
    """
    file_size = unpack_request_message(data)
    if file_size:
        print(colorize(f"[SERVER] Received UDP request from {client_address} for {file_size} bytes", text_color=32))
        total_segments = file_size // SEGMENT_SIZE
        if file_size % SEGMENT_SIZE:
            total_segments += 1

        for segment in range(total_segments):
            bytes_left = file_size - segment * SEGMENT_SIZE
            segment_size = min(SEGMENT_SIZE, bytes_left)
            payload = b"x" * segment_size
            packet = pack_payload_message(total_segments, segment, payload)
            try:
                udp_socket.sendto(packet, client_address)
            except Exception as e:
                print(colorize(f"[SERVER] Error sending UDP segment {segment}: {e}", text_color=31))

def start_udp_server(udp_port):
    """
    Start the UDP server to handle incoming requests.

    Args:
        udp_port (int): The UDP port to listen on.
    """
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("", udp_port))
    print(colorize(f"[SERVER] UDP server listening on port {udp_port}", text_color=34))
    while True:
        data, client_address = udp_socket.recvfrom(65536)
        threading.Thread(target=handle_udp_request, args=(data, client_address, udp_socket), daemon=True).start()

# --- Main Function ---

def server_main():
    """
    Main function to start the server, initialize ports, and launch services.
    """
    udp_port = get_available_port(socket.SOCK_DGRAM)
    tcp_port = get_available_port(socket.SOCK_STREAM)
    broadcast_port = get_available_port(socket.SOCK_DGRAM)

    print(colorize(f"[SERVER] Server started, listening on UDP port {udp_port}, TCP port {tcp_port}, Broadcast port {broadcast_port}", style=1, text_color=34))

    threading.Thread(target=server_broadcast_offer, args=(udp_port, tcp_port, broadcast_port), daemon=True).start()
    threading.Thread(target=start_tcp_server, args=(tcp_port,), daemon=True).start()
    start_udp_server(udp_port)

if __name__ == '__main__':
    server_main()