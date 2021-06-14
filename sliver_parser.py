import argparse
import pathlib

# External dependencies
import dpkt

# Local imports
from comms import sliver_comms
from packet_parser import smb_parse, tcp_parse


def parse_pcap(pcap_file: str, loopback: bool, protocol: str, dump_dir:str, sliver_output: str):

    f = open(pcap_file, 'rb')

    if pcap_file.endswith('.pcapng'):
        pcap = dpkt.pcapng.Reader(f)
    else:
        pcap = dpkt.pcap.Reader(f)

    parse_sliver = sliver_comms.ParseSliver(
        sliver_output=sliver_output,
        dump_dir=dump_dir
    )

    if protocol == "SMB":
        smb = smb_parse.SMB(pcap_file=pcap, loopback=loopback)
        sliver_sessions = smb.parse_smb()

        parse_sliver.parse_buffers(
            sliver_protobuffer=sliver_sessions,
            dump_dir=dump_dir
        )

    elif protocol == "TCP":
        tcp = tcp_parse.TCP(pcap_file=pcap, loopback=loopback)
        sliver_sessions = tcp.parse_tcp()

        parse_sliver.parse_buffers(
            sliver_protobuffer=sliver_sessions,
            dump_dir=dump_dir
        )

    # Close the handle to the PCAP file
    f.close()
            

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument('--pcap', required=True, help='PCAP file to parse')
    parser.add_argument('--loopback', required=False, action='store_true', help='Enable this for loopback captures')
    parser.add_argument('--named-pipe', required=False, action='store_true', help='Parse Sliver named-pipe communication')
    parser.add_argument('--tcp-pivot', required=False, action='store_true', help='Parse Sliver tcp-pivot communication')
    parser.add_argument('--dump-dir', required=False, help='Directory to write output files to [default: output/]')
    parser.add_argument('--sliver-output', required=True, help='File to output Sliver communications to')

    args = parser.parse_args()

    pcap_file = args.pcap

    loopback = args.loopback

    if args.named_pipe:
        protocol = "SMB"
    elif args.tcp_pivot:
        protocol = "TCP"

    dump_dir = args.dump_dir
    
    if not dump_dir:
        cwd = pathlib.Path.cwd()
        dump_dir = f"{cwd}/output"

        pathlib.Path(f'{cwd}/output').mkdir(parents=True, exist_ok=True)

    print(f"[*] Dumping files into: {dump_dir}")

    sliver_output = args.sliver_output
    with open(sliver_output, 'w'): pass

    print(f"[*] Parsing PCAP: {pcap_file}")
    parse_pcap(
        pcap_file=pcap_file,
        loopback=loopback,
        protocol=protocol,
        dump_dir=dump_dir,
        sliver_output=sliver_output
    )


if __name__ == "__main__":
    main()
