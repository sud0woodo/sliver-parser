from collections import defaultdict
import ctypes
from enum import IntEnum
import hashlib
import io
import struct
from typing import OrderedDict
import uuid

# External dependencies
import dpkt


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4
class SMB_HEADER(ctypes.Structure):
    _fields_ = [
        ('ProtocolId', ctypes.c_byte * 4),
        ('StructureSize', ctypes.c_byte * 2),
        ('CreditCharge', ctypes.c_byte * 2),
        ('Status', ctypes.c_byte * 4),
        ('Command', ctypes.c_byte * 2),
        ('Credits', ctypes.c_byte * 2),
        ('Flags', ctypes.c_byte * 4),
        ('NextCommand', ctypes.c_byte * 4),
        ('MessageId', ctypes.c_byte * 8),
        ('Reserved', ctypes.c_byte * 4),
        ('TreeId', ctypes.c_byte * 4),
        ('SessionId', ctypes.c_byte * 8),
        ('Signature', ctypes.c_byte * 16)
    ]


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/832d2130-22e8-4afb-aafd-b30bb0901798
class TREE_CONNECT_REQ(ctypes.Structure):
    _fields_ = [
        ('StructureSize', ctypes.c_byte * 2),
        ('Reserved', ctypes.c_byte * 2),
        ('PathOffset', ctypes.c_byte * 2),
        ('PathLength', ctypes.c_byte * 2),
        ('Buffer', ctypes.c_byte * 1024)

    ]


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/dd34e26c-a75e-47fa-aab2-6efc27502e96
class TREE_CONNECT_RESP(ctypes.Structure):
    _fields_ = [
        ('StructureSize', ctypes.c_byte * 2),
        ('ShareType', ctypes.c_byte),
        ('Reserved', ctypes.c_byte),
        ('ShareFlags', ctypes.c_byte * 4),
        ('Capabilities', ctypes.c_byte * 4),
        ('MaximalAccess', ctypes.c_byte * 4)
    ]


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e8fb45c1-a03d-44ca-b7ae-47385cfd7997
class CREATE_REQUEST(ctypes.Structure):
    _fields_ = [
        ('StructureSize', ctypes.c_byte * 2),
        ('SecurityFlags', ctypes.c_byte),
        ('RequestedOplockLevel', ctypes.c_byte),
        ('ImpersonationLevel', ctypes.c_byte * 4),
        ('SmbCreateFlags', ctypes.c_byte * 8),
        ('Reserved', ctypes.c_byte * 8),
        ('DesiredAccess', ctypes.c_byte * 4),
        ('FileAttributes', ctypes.c_byte * 4),
        ('ShareAccess', ctypes.c_byte * 4),
        ('CreateDisposition', ctypes.c_byte * 4),
        ('CreateOptions', ctypes.c_byte * 4),
        ('NameOffset', ctypes.c_byte * 2),
        ('NameLength', ctypes.c_byte * 2),
        ('CreateContextOffset', ctypes.c_byte * 4),
        ('CreateContextLength', ctypes.c_byte * 4),
        ('Buffer', ctypes.c_byte * 1024)
    ]


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d166aa9e-0b53-410e-b35e-3933d8131927
class CREATE_RESPONSE(ctypes.Structure):
    _fields_ = [
        ('StructureSize', ctypes.c_byte * 2),
        ('OplockLevel', ctypes.c_byte),
        ('Flags', ctypes.c_byte),
        ('CreateAction', ctypes.c_byte * 4),
        ('CreationTime', ctypes.c_byte * 8),
        ('LastAccessTime', ctypes.c_byte * 8),
        ('LastWriteTime', ctypes.c_byte * 8),
        ('ChangeTime', ctypes.c_byte * 8),
        ('AllocationSize', ctypes.c_byte * 8),
        ('EndofFile', ctypes.c_byte * 8),
        ('FileAttributes', ctypes.c_byte * 4),
        ('Reserved2', ctypes.c_byte * 4),
        ('FileId', ctypes.c_byte * 16),
        ('CreateContextsOffset', ctypes.c_byte * 4),
        ('CreateContextsLength', ctypes.c_byte * 4),
        ('Buffer', ctypes.c_byte * 1024)
    ]


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/320f04f3-1b28-45cd-aaa1-9e5aed810dca
class READ_REQUEST(ctypes.Structure):
    _fields_ = [
        ('StructureSize', ctypes.c_byte * 2),
        ('Padding', ctypes.c_byte),
        ('Flags', ctypes.c_byte),
        ('Length', ctypes.c_byte * 4),
        ('Offset', ctypes.c_byte * 8),
        ('FileId', ctypes.c_byte * 16),
        ('MinimumCount', ctypes.c_byte * 4),
        ('Channel', ctypes.c_byte * 4),
        ('RemainingBytes', ctypes.c_byte * 4),
        ('ReadChannelInfoOffset', ctypes.c_byte * 2),
        ('ReadChannelInfoLength', ctypes.c_byte * 2),
        ('Buffer', ctypes.c_byte * 1024)
    ]


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3e3d2f2c-0e2f-41ea-ad07-fbca6ffdfd90
class READ_RESPONSE(ctypes.Structure):
    _fields_ = [
        ('StructureSize', ctypes.c_byte * 2),
        ('DataOffset', ctypes.c_byte),
        ('Reserved', ctypes.c_byte),
        ('DataLength', ctypes.c_byte * 4),
        ('DataRemaining', ctypes.c_byte * 4),
        ('Reserved2', ctypes.c_byte * 4),
        ('Buffer', ctypes.c_byte * 1024)
    ]


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e7046961-3318-4350-be2a-a8d69bb59ce8
class WRITE_REQUEST(ctypes.Structure):
    _fields_ = [
        ('StructureSize', ctypes.c_byte * 2),
        ('DataOffset', ctypes.c_byte * 2),
        ('Length', ctypes.c_byte * 4),
        ('Offset', ctypes.c_byte * 8),
        ('FileId', ctypes.c_byte * 16),
        ('Channel', ctypes.c_byte * 4),
        ('RemainingBytes', ctypes.c_byte * 4),
        ('WriteChannelInfoOffset', ctypes.c_byte * 2),
        ('WriteChannelInfoLength', ctypes.c_byte * 2),
        ('Flags', ctypes.c_byte * 4),
        ('Buffer', ctypes.c_byte * 1024)
    ]


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7b80a339-f4d3-4575-8ce2-70a06f24f133
class WRITE_RESPONSE(ctypes.Structure):
    _fields_ = [
        ('StructureSize', ctypes.c_byte * 2),
        ('Reserved', ctypes.c_byte * 2),
        ('Count', ctypes.c_byte * 4),
        ('Remaining', ctypes.c_byte * 4),
        ('WriteChannelInfoOffset', ctypes.c_byte * 2),
        ('WriteChannelInfoLength', ctypes.c_byte * 2)
    ]


# Only specified the ones we're using
class SMB_COMMAND(IntEnum):
    SMB_TREE_CONNECT    = 0x03
    SMB_CREATE          = 0x05
    SMB_READ            = 0x08
    SMB_WRITE           = 0x09


NULL_SESSION = b'\x00\x00\x00\x00\x00\x00\x00\x00'


class SMB:

    def __init__(self, pcap_file: str, loopback: bool):

        self.pcap_file = pcap_file
        self.loopback = loopback

        self.smb_packet = None

        self.smb_flags = None
        self.named_pipe = False
    
    # @profile
    def parse_smb(self) -> OrderedDict:

        file_id = None
        smb_pipename = None

        sliver_sessions = OrderedDict()
        sliver_streams = defaultdict(set)

        read_buffer_size = 0
        write_buffer_size = 0

        tmp_read_buf = b''
        tmp_write_buf = b''

        def pcap_generator():
            for ts, buf in self.pcap_file:
                yield ts, buf

        # Very ugly but about 100 times as fast as scapy
        for ts, buf in pcap_generator():

            if self.loopback:
                eth_layer = dpkt.loopback.Loopback(buf)
            else:
                eth_layer = dpkt.ethernet.Ethernet(buf)
            
            if not isinstance(eth_layer.data, dpkt.ip.IP):
                continue

            ip = eth_layer.data

            # Check for TCP in the transport layer
            if isinstance(ip.data, dpkt.tcp.TCP):

                # Set the TCP data
                tcp = ip.data

                if b'\xfeSMB' in tcp.data[4:9]:
                    self.smb_packet = io.BytesIO(tcp.data[4:])

                smb_header = self.parse_header()
                
                # Skip the session setup, we don't need to do anything with it
                if bytes(smb_header.SessionId) == NULL_SESSION:
                    continue
                
                self.smb_flags = struct.unpack('<HH', bytes(smb_header.Flags))[0]

                # A Tree Connect request to IPC$ will need to occur before
                # a named pipe connection can be made
                smb_command = struct.unpack('<H', bytes(smb_header.Command))[0]
                if smb_command == SMB_COMMAND.SMB_TREE_CONNECT:
                    
                    # SMB Tree Connect Request
                    # Don't need to do anything with this for now
                    if self.smb_flags & (1 << 0) == 0:
                        continue

                    # SMB Tree Connect Response
                    if self.smb_flags & (1 << 0) == 1:
                        tree_connect_resp = self.tree_connect_response()
                        if tree_connect_resp.ShareType == 0x02:
                            self.named_pipe = True
    
                # Get the filename used for the named pipe
                if smb_command == SMB_COMMAND.SMB_CREATE:
                    # SMB Create Request
                    if self.smb_flags & (1 << 0) == 0:
                        create_request = self.create_request()
                        
                        if self.named_pipe:
                            # MD5 hash the SMB session for uniformity with TCP pivot
                            smb_session = hashlib.md5(uuid.uuid4().bytes).hexdigest()

                            sliver_sessions[smb_session] = {}
                            smb_pipename = bytes(create_request.Buffer).decode().replace('\x00', '')

                    # SMB Create Response
                    elif self.smb_flags & (1 << 0) == 1:
                        create_response = self.create_response()

                        if self.named_pipe:
                            file_id = str(uuid.UUID(bytes(create_response.FileId).hex()))
                            # Add the file ID of the named pipe session if a Sliver named pipe was observed
                            try:
                                sliver_streams[smb_pipename].add(file_id)
                            except KeyError:
                                pass
                            # Marks a new smb_session
                            sliver_sessions[smb_session] = []
                            self.named_pipe = False

                # READ / WRITE SECTION
                # First read/write specifies size, next sequences contain the actual data
                # Get the data written to pipe: C2 -> implant
                # (actually it's implant to implant, but the one creating the request is the client)
                # Really only need to read responses if we know it's a Sliver session

                # So this sucks a little bit because we will get killed by an OOM
                # if the PCAP is really big, this is annoying but can't really be helped
                if smb_command == SMB_COMMAND.SMB_READ:
                    try:
                        if file_id in sliver_streams[smb_pipename]:
                            # SMB Read Request
                            # Don't need to do anything with this for now
                            if self.smb_flags & (1 << 0) == 0:
                                # read_request = self.read_request()
                                continue

                            # SMB Read Reponse
                            elif self.smb_flags & (1 << 0) == 1:
                                smb_status = int.from_bytes(smb_header.Status, byteorder='little')
                                # If STATUS_SUCCESS
                                if smb_status == 0x0:
                                    
                                    read_response = self.read_response()
                                    read_buffer = bytes(read_response.Buffer)
                                    buffer_length = struct.unpack('<HH', bytes(read_response.DataLength))[0]

                                    if buffer_length == 4:
                                        read_buffer_size = int.from_bytes(read_buffer[:4], byteorder='little')
                                        tmp_read_buf = b''
                                        continue

                                    if len(tmp_read_buf) != read_buffer_size:
                                        tmp_read_buf += read_buffer[:buffer_length]
                                    
                                    if len(tmp_read_buf) == read_buffer_size:
                                        try:
                                            sliver_sessions[smb_session].append((ts, tmp_read_buf))
                                        except KeyError:
                                            continue               
                                    
                    except KeyError:
                        continue
                        
                # Get the data written to pipe: implant -> C2 
                # (actually it's implant to implant, but the one creating the request is the client)
                if smb_command == SMB_COMMAND.SMB_WRITE:
                    # SMB Write Request
                    if self.smb_flags & (1 << 0) == 0:
                        write_request = self.write_request()
                        write_buffer = bytes(write_request.Buffer)

                        buffer_length = struct.unpack('<HH', bytes(write_request.Length))[0]

                        # When a Sliver named pipe has been observed -> mark that stream using the file ID
                        if b'namedpipe://' in write_buffer.rstrip(b'\x00'):
                            sliver_streams[smb_pipename].add(file_id)
                            
                            print(f"[+] Possible Sliver SMB pipename: {smb_pipename}")

                            if len(write_buffer.rstrip(b'\x00')) == buffer_length:

                                    sliver_sessions[smb_session].append((ts, write_buffer.rstrip(b'\x00')))
                                    continue
            
                        try:
                            # Only do something with the data if the SMB file ID is known (Sliver named pipe)
                            if file_id in sliver_streams[smb_pipename]:

                                if len(tmp_write_buf) != write_buffer_size:
                                    tmp_write_buf += write_buffer[:buffer_length]

                                if len(tmp_write_buf) == write_buffer_size:
                                    
                                    sliver_sessions[smb_session].append((ts, tmp_write_buf))
                                
                                # Marks a new command
                                if buffer_length == 4:
                                    write_buffer_size = int.from_bytes(write_buffer[:4], byteorder='little')
                                    tmp_write_buf = b''
                                    
                        except KeyError:
                            continue

                    # SMB Write Reponse
                    # Don't need to do anything with this for now
                    if self.smb_flags & (1 << 0) == 1:
                        # write_response = self.write_response()
                        continue

        return sliver_sessions
        
        
    
    def parse_header(self) -> ctypes.Structure:

        smb_header = SMB_HEADER()

        self.smb_packet.readinto(smb_header.ProtocolId)
        self.smb_packet.readinto(smb_header.StructureSize)
        self.smb_packet.readinto(smb_header.CreditCharge)
        self.smb_packet.readinto(smb_header.Status)
        self.smb_packet.readinto(smb_header.Command)
        self.smb_packet.readinto(smb_header.Credits)
        self.smb_packet.readinto(smb_header.Flags)
        self.smb_packet.readinto(smb_header.NextCommand)
        self.smb_packet.readinto(smb_header.MessageId)
        self.smb_packet.readinto(smb_header.Reserved)
        self.smb_packet.readinto(smb_header.TreeId)
        self.smb_packet.readinto(smb_header.SessionId)
        self.smb_packet.readinto(smb_header.Signature)

        return smb_header

    def tree_connect_request(self) -> ctypes.Structure:

        tree_connect_req = TREE_CONNECT_REQ()

        self.smb_packet.readinto(tree_connect_req.StructureSize)
        self.smb_packet.readinto(tree_connect_req.Reserved)
        self.smb_packet.readinto(tree_connect_req.PathOffset)
        self.smb_packet.readinto(tree_connect_req.PathLength)

        path_length = struct.unpack('<H', tree_connect_req.PathLength)[0]

        buffer = self.smb_packet.read(path_length)

        io.BytesIO(buffer).readinto(tree_connect_req.Buffer)

        return tree_connect_req

    def tree_connect_response(self) -> ctypes.Structure:
        
        tree_connect_resp = TREE_CONNECT_RESP()

        self.smb_packet.readinto(tree_connect_resp.StructureSize)

        # Need to convert since the C type is int
        share_type = self.smb_packet.read(1)
        tree_connect_resp.ShareType = int.from_bytes(
            share_type,
            byteorder='little'
        )

        self.smb_packet.readinto(bytearray(tree_connect_resp.Reserved))
        self.smb_packet.readinto(tree_connect_resp.ShareFlags)
        self.smb_packet.readinto(tree_connect_resp.Capabilities)
        self.smb_packet.readinto(tree_connect_resp.MaximalAccess)

        return tree_connect_resp

    def create_request(self) -> ctypes.Structure:
        
        create_request = CREATE_REQUEST()

        self.smb_packet.readinto(create_request.StructureSize)

        security_flags = self.smb_packet.read(1)
        create_request.SecurityFlags = int.from_bytes(
            security_flags,
            byteorder='little'
        )

        requested_oplock_level = self.smb_packet.read(1)
        create_request.RequestedOplockLevel = int.from_bytes(
            requested_oplock_level,
            byteorder='little'
        )

        self.smb_packet.readinto(create_request.ImpersonationLevel)
        self.smb_packet.readinto(create_request.SmbCreateFlags)
        self.smb_packet.readinto(create_request.Reserved)
        self.smb_packet.readinto(create_request.DesiredAccess)
        self.smb_packet.readinto(create_request.FileAttributes)
        self.smb_packet.readinto(create_request.ShareAccess)
        self.smb_packet.readinto(create_request.CreateDisposition)
        self.smb_packet.readinto(create_request.CreateOptions)
        self.smb_packet.readinto(create_request.NameOffset)
        self.smb_packet.readinto(create_request.NameLength)
        self.smb_packet.readinto(create_request.CreateContextOffset)
        self.smb_packet.readinto(create_request.CreateContextLength)

        name_length = struct.unpack('<H', create_request.NameLength)[0]
        buffer = self.smb_packet.read(name_length)

        io.BytesIO(buffer).readinto(create_request.Buffer)

        return create_request

    def create_response(self) -> ctypes.Structure:
        
        create_response = CREATE_RESPONSE()

        self.smb_packet.readinto(create_response.StructureSize)

        oplock_level = self.smb_packet.read(1)
        create_response.OplockLevel = int.from_bytes(
            oplock_level,
            byteorder='little'
        )

        flags = self.smb_packet.read(1)
        create_response.Flags = int.from_bytes(
            flags,
            byteorder='little'
        )

        self.smb_packet.readinto(create_response.CreateAction)
        self.smb_packet.readinto(create_response.CreationTime)
        self.smb_packet.readinto(create_response.LastAccessTime)
        self.smb_packet.readinto(create_response.LastWriteTime)
        self.smb_packet.readinto(create_response.ChangeTime)
        self.smb_packet.readinto(create_response.AllocationSize)
        self.smb_packet.readinto(create_response.EndofFile)
        self.smb_packet.readinto(create_response.FileAttributes)
        self.smb_packet.readinto(create_response.Reserved2)
        self.smb_packet.readinto(create_response.FileId)
        self.smb_packet.readinto(create_response.CreateContextsOffset)
        self.smb_packet.readinto(create_response.CreateContextsLength)
        self.smb_packet.readinto(create_response.Buffer)    # We're not using this I think

        return create_response

    def read_request(self) -> ctypes.Structure:
        
        read_request = READ_REQUEST()

        self.smb_packet.readinto(read_request.StructureSize)

        padding = self.smb_packet.read(1)
        read_request.Padding = int.from_bytes(
            padding,
            byteorder='little'
        )

        flags = self.smb_packet.read(1)
        read_request.Flags = int.from_bytes(
            flags,
            byteorder='little'
        )

        self.smb_packet.readinto(read_request.Length)
        self.smb_packet.readinto(read_request.Offset)
        self.smb_packet.readinto(read_request.FileId)
        self.smb_packet.readinto(read_request.MinimumCount)
        self.smb_packet.readinto(read_request.Channel)
        self.smb_packet.readinto(read_request.RemainingBytes)
        self.smb_packet.readinto(read_request.ReadChannelInfoOffset)
        self.smb_packet.readinto(read_request.ReadChannelInfoLength)
        self.smb_packet.readinto(read_request.Buffer)   # We don't use this yet

        return read_request

    def read_response(self) -> ctypes.Structure:
        
        read_response = READ_RESPONSE()

        self.smb_packet.readinto(read_response.StructureSize)

        data_offset = self.smb_packet.read(1)
        read_response.DataOffset = int.from_bytes(
            data_offset,
            byteorder='little'
        )

        reserved = self.smb_packet.read(1)
        read_response.Reserved = int.from_bytes(
            reserved,
            byteorder='little'
        )

        self.smb_packet.readinto(read_response.DataLength)
        self.smb_packet.readinto(read_response.DataRemaining)
        self.smb_packet.readinto(read_response.Reserved2)

        data_length = struct.unpack('<HH', read_response.DataLength)[0]

        buffer = self.smb_packet.read(data_length)

        io.BytesIO(buffer).readinto(read_response.Buffer)

        return read_response

    def write_request(self) -> ctypes.Structure:
        
        write_request = WRITE_REQUEST()

        self.smb_packet.readinto(write_request.StructureSize)
        self.smb_packet.readinto(write_request.DataOffset)
        self.smb_packet.readinto(write_request.Length)
        self.smb_packet.readinto(write_request.Offset)
        self.smb_packet.readinto(write_request.FileId)
        self.smb_packet.readinto(write_request.Channel)
        self.smb_packet.readinto(write_request.RemainingBytes)
        self.smb_packet.readinto(write_request.WriteChannelInfoOffset)
        self.smb_packet.readinto(write_request.WriteChannelInfoLength)
        self.smb_packet.readinto(write_request.Flags)

        length = struct.unpack('<HH', write_request.Length)[0]

        buffer = self.smb_packet.read(length)

        io.BytesIO(buffer).readinto(write_request.Buffer)

        return write_request

    def write_response(self) -> ctypes.Structure:
        
        write_response = WRITE_RESPONSE()

        self.smb_packet.readinto(write_response.StructureSize)
        self.smb_packet.readinto(write_response.Reserved)
        self.smb_packet.readinto(write_response.Count)
        self.smb_packet.readinto(write_response.Remaining)
        self.smb_packet.readinto(write_response.WriteChannelInfoOffset)
        self.smb_packet.readinto(write_response.WriteChannelInfoLength)

        return write_response

