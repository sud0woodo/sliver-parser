from collections import OrderedDict
import dpkt
import hashlib
import struct


class TCP:

    def __init__(self, pcap_file: str, loopback: bool):

        self.pcap_file = pcap_file
        self.loopback = loopback

    def parse_tcp(self) -> OrderedDict:

        def pcap_generator():
            for ts, buf in self.pcap_file:
                yield ts, buf

        sliver_sessions = OrderedDict()
        sliver_streams = []

        req_length = 0

        tmp_buffer = b''
        
        for ts, buf in pcap_generator():
            
            if self.loopback:
                eth = dpkt.loopback.Loopback(buf)
            else:
                eth = dpkt.ethernet.Ethernet(buf)

            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip = eth.data

            # Check for TCP in the transport layer
            if isinstance(ip.data, dpkt.tcp.TCP):

                # Set the TCP data
                tcp = ip.data

                # Keep track of the unique TCP sessions, store as single value
                tcp_session = (ip.src, ip.dst, tcp.sport, tcp.dport)

                # Check for possible sliver named pipe
                if b'tcppivot://' in tcp.data:

                    # Add both port and address combinations to keep track of streams
                    sliver_streams.append((ip.src, ip.dst, tcp.sport, tcp.dport))
                    sliver_streams.append((ip.dst, ip.src, tcp.dport, tcp.sport))

                    # This is a brittle way of identifying the same stream but I couldn't
                    # come up with a better way. This will obviously break if the source
                    # and destination port in a different combination adds up to the 
                    # same amount...
                    conn_sum = bytes(str(tcp.sport + tcp.dport), encoding='utf8')
                    sliver_session = hashlib.md5(conn_sum).hexdigest()

                    sliver_sessions[sliver_session] = []
                    sliver_sessions[sliver_session].append((ts, tcp.data))
                    continue

                if tcp_session in sliver_streams and len(tcp.data) > 0:
                    conn_sum = bytes(str(tcp.sport + tcp.dport), encoding='utf8')
                    sliver_session = hashlib.md5(conn_sum).hexdigest()

                    if len(tmp_buffer) != req_length:
                        tmp_buffer += tcp.data
                    
                    if len(tmp_buffer) == req_length:
                        sliver_sessions[sliver_session].append((ts, tmp_buffer))

                    # Check length of request
                    # If request length is 4, this indicates teh size of the next command
                    if len(tcp.data) == 4:
                        req_length = struct.unpack('<I', tcp.data)[0]
                        tmp_buffer = b''
        
        return sliver_sessions

