# Hackathon 
Submitted by: 211973631, 318896693
This git is owned by 2025 hackathon winners, Mr.Matan Isar aka wooclapEnjoyer and Mr.Ariel Mezhi aka MezhiMage aka Don Patron aka 0wooclapSubmitor
--------------------------------------------------------------------------------------------------------------------------------------------------

Client-Server Network Speed Test
================================

This project implements a client-server network speed test to compare UDP and TCP download performance.


Features:
---------
- Dynamic server discovery using UDP broadcasts.
- Multi-threaded server and client for handling multiple connections.
- TCP and UDP transfers with performance measurements.
- Graceful error handling for server disconnections.
- ANSI color-coded output for better readability.


Usage:
------
1. Run the server:
   python server.py

2. Run the client:
   python client.py

3. Follow prompts on the client to:
   - Enter file size (in bytes).
   - Specify the number of TCP and UDP connections.

4. Observe transfer statistics and any errors in the terminal.


Error Handling
--------------
-Server Disconnection:
    Clients log an error and return to listening for new offers.
-Packet Loss:
    UDP transfers report the percentage of lost packets.
-Invalid Messages:
    Invalid or corrupted packets are ignored, and appropriate logs are generated.


Dependencies:
-------------
- Python 3.11 or later
- Scapy (Install via: pip install scapy)
