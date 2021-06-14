# sliver-parser
Parser for PCAPs containing Sliver TCP and Named Pipe Pivots

## Preparation

Install `protoc`, refer to the Google documentation for your distro: https://grpc.io/docs/protoc-installation/

Before executing the script, the Python protobuf files need to be compiled using the protobuf compiler.

Assuming the current working directory is the root of this project:

```sh
protoc -I=protofiles/ --python_out=protofiles/ protofiles/*.proto
```

This is entirely due to my lack of understanding how this exactly works, but after the `protoc` command we need to patch the `common_pb2.py` file and change the following line:

```py
import common_pb2.py as common__pb2
```

to:

```py
from protofiles import common_pb2 as common__pb2
```

Install the Python packages:

```sh
python -m pip install -r requirements.txt
```

## Usage

Only tested using Python version 3.8.5

Parsing a PCAP with Sliver named pipe traffic:

```sh
python3 sliver_parser.py --pcap sliver_named_pipe_pivot.pcapng --named-pipe --sliver-output sliver_output.txt
```

Parsing a PCAP with Sliver TCP-Pivot traffic:

```sh
python3 sliver_parser.py --pcap sliver_tcp_pivot.pcapng --tcp-pivot --sliver-output sliver_output.txt
```

## Notes

There's probably a lot of pitfalls with this script, the TCP-Pivot parsing is very slow in its current state when a lot of data is being transferred between the C2 and the implant. The project was made to play around with Sliver and to get to know its inner workings a little bit better. 
