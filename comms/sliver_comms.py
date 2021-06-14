from enum import IntEnum
import hashlib
import time

# External dependencies
from google.protobuf.message import DecodeError

# Local imports
from protofiles import sliver_pb2


# https://github.com/BishopFox/sliver/blob/516f05622ffa9e408d8cf4ac97939fc98421836e/protobuf/sliverpb/constants.go
class MsgType(IntEnum):
    MsgRegister = 1
    MsgTaskReq = 2
    MsgPing = 3
    MsgKillSessionReq = 4
    MsgLsReq = 5
    MsgLs = 6
    MsgDownloadReq = 7
    MsgDownload = 8
    MsgUploadReq = 9
    MsgUpload = 10
    MsgCdReq = 11
    MsgPwdReq = 12
    MsgPwd = 13
    MsgRmReq = 14
    MsgRm = 15
    MsgMkdirReq = 16
    MsgMkdir = 17
    MsgPsReq = 18
    MsgPs = 19
    MsgShellReq = 20
    MsgShell = 21
    MsgTunnelData = 22
    MsgTunnelClose = 23
    MsgProcessDumpReq = 24
    MsgProcessDump = 25
    MsgImpersonateReq = 26
    MsgImpersonate = 27
    MsgRunAsReq = 28
    MsgRunAs = 29
    MsgRevToSelf = 30
    MsgRevToSelfReq = 31
    MsgInvokeGetSystemReq = 32
    MsgGetSystem = 33
    MsgInvokeExecuteAssemblyReq = 34
    MsgExecuteAssemblyReq = 35
    MsgExecuteAssembly = 36
    MsgInvokeMigrateReq = 37
    MsgSideloadReq = 38
    MsgSideload = 39
    MsgSpawnDllReq = 40
    MsgSpawnDll = 41
    MsgIfconfigReq = 42
    MsgIfconfig = 43
    MsgExecuteReq = 44
    MsgTerminateReq = 45
    MsgTerminate = 46
    MsgScreenshotReq = 47
    MsgScreenshot = 48
    MsgNetstatReq = 49
    MsgNamedPipesReq = 50
    MsgNamedPipes = 51
    MsgTCPPivotReq = 52
    MsgTCPPivot = 53
    MsgPivotListReq = 54
    MsgPivotOpen = 55
    MsgPivotClose = 56
    MsgPivotData = 57
    MsgStartServiceReq = 58
    MsgStartService = 59
    MsgStopServiceReq = 60
    MsgRemoveServiceReq = 61
    MsgMakeTokenReq = 62
    MsgMakeToken = 63
    MsgEnvReq = 64
    MsgEnvInfo = 65
    MsgSetEnvReq = 66
    MsgSetEnv = 67
    MsgExecuteTokenReq = 68
    MsgRegistryReadReq = 69
    MsgRegistryWriteReq = 70
    MsgRegistryCreateKeyReq = 71
    MsgWGStartPortFwdReq = 72
    MsgWGStopPortFwdReq = 73
    MsgWGStartSocksReq = 74
    MsgWGStopSocksReq = 75
    MsgWGListForwardersReq = 76
    MsgWGListSocksReq = 77
    MsgPortfwdReq = 78
    MsgPortfwd = 79
    MsgReconnectIntervalReq = 80
    MsgReconnectInterval = 81
    MsgPollIntervalReq = 82
    MsgPollInterval = 83
    MsgUnsetEnvReq = 84


class ParseSliver:

    def __init__(self, sliver_output: str, dump_dir: str):

        self.output_file = sliver_output
        self.dump_dir = dump_dir

        self.sliver_session = None

    def parse_buffers(self, sliver_protobuffer: dict, dump_dir: str):

        tasks = dict()
        
        # Create the tasks dictionary
        # Differentiate between sliver sessions
        for sliver_session, sliver_buffers in sliver_protobuffer.items():
            self.sliver_session = sliver_session

            for time_stamp, sliver_proto in sliver_buffers:

                # Convert time to UTC
                utc_ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time_stamp))

                try:
                    envelope = sliver_pb2.Envelope()
                    envelope.ParseFromString(sliver_proto)
                except DecodeError:
                    return

                msg_type = envelope.Type
                msg_id = envelope.ID
                msg_data = envelope.Data
                
                if msg_type == 1:
                    self.sliver_register(register_proto=msg_data, utc_ts=utc_ts)
                # Add response for ID key if it doesn't exist yet
                elif msg_type == 0:
                    try:
                        tasks[msg_id]['response'] = msg_data
                    except KeyError:
                        tasks[msg_id] = {'response': msg_data}

                # Add the request and the data to the ID if it doesn't exist yet
                else:
                    try:
                        command = [msg.name for msg in MsgType if msg.value == msg_type][0]
                    except IndexError:
                        print(f"[!] Unkown command: {msg_type}")

                    try:
                        tasks[msg_id]['request'] = msg_data
                        tasks[msg_id]['request_time'] = utc_ts
                        tasks[msg_id]['command'] = command
                    except KeyError:
                        tasks[msg_id] = {'request': msg_data, 'request_time': utc_ts, 'command': command}
        
        # Parse the tasks
        # Unfortunately we can't fix the order of the executed commands
        # due to the random generated ID used by Sliver
        for task_id, comm_dict in tasks.items():    
            self.parse_command(task_id=task_id, comm_dict=comm_dict)

    # # https://github.com/BishopFox/sliver/blob/ea6a17c3e6c51da2c89f23cc8465424e2c0f57d2/server/handlers/sessions.go#L62
    def sliver_register(self, register_proto: bytes, utc_ts: str):

        register_pivot = sliver_pb2.Register()
        register_pivot.ParseFromString(register_proto)

        register_format = f"SLIVER IMPLANT NAME: {register_pivot.Name}\n"
        register_format += f"Named pipe created at: {utc_ts}\n"
        register_format += f"\tActive C2: {register_pivot.ActiveC2}\n"
        register_format += f"\tProxy URL: {register_pivot.ProxyURL}\n"
        register_format += f"\tReconnect Interval: {register_pivot.ReconnectInterval}\n"
        register_format += f"\tPoll Interval: {register_pivot.PollInterval}\n\n"
        register_format += f"\tPivot Name: {register_pivot.Name}\n"
        register_format += f"\tPivot Filename: {register_pivot.Filename}\n"
        register_format += f"\tPivot PID: {register_pivot.Pid}\n"
        register_format += f"\tPivot Hostname: {register_pivot.Hostname}\n"
        register_format += f"\tPivot Username: {register_pivot.Username}\n"
        register_format += f"\tPivot OS: {register_pivot.Os}\n"
        register_format += f"\tPivot Architecture: {register_pivot.Arch}\n"
        register_format += f"\tPivot OS Version: {register_pivot.Version}\n\n"
        register_format += f"\tPivot UID: {register_pivot.Uid}\n"
        register_format += f"\tPivot UUID: {register_pivot.Uuid}\n"
        register_format += f"\tPivot GID: {register_pivot.Gid}\n\n"

        with open(self.output_file, 'a+') as sliver_output:
            sliver_output.write(register_format)

    def parse_command(self, task_id: int, comm_dict: dict):
        """ Award for the most horrible function ever made """

        request_data = None
        request_time = None

        command_data = None
        command = None
        
        # TODO: Fix the problem where the request/response is parsed in the wrong order
        # if we change the order the getsystem works, but otherwise it displays missing response
        try:

            command = comm_dict['command']
            request_data = comm_dict['request']
            request_time = comm_dict['request_time']

            command_data = comm_dict['response']

        except KeyError as comm_type:

            with open(self.output_file, 'a') as command_output:
                command_output.write(f"\n{request_time}\tTASK ID: {task_id}\t TASK: <MISSING>\n")
                if command:
                    command_output.write(f"\n\tCOMMAND: {command}\tMissing: {comm_type}")
                if command_data:
                    command_output.write(f"\n\tMissing C2 command.\n\tCOMMAND DATA:\n{command_data}\n\n")

            return

        # COMMAND PARSING START
            # TODO:
            #   - MsgTunnelData/Close
            #   - MsgWGListForwardersReq
            #   - MsgWGListSocksReq

        # DEBUG
        # print(command, request_data[:32])
        
        if command == "MsgTaskReq":
            task_req = sliver_pb2.TaskReq()
            task_req.ParseFromString(request_data)

            session_id = task_req.Request.SessionID

            task_data = task_req.Data

            with open(self.output_file, 'a') as task_output:
                task_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\tTASK: {command}\n")

                if len(task_data) > 0:
                    task_md5 = hashlib.md5(task_data).digest()

                    task_filename = f"{self.dump_dir}/{self.sliver_session}_{command}_{task_md5.hex()}.bin"

                    with open(task_filename, 'wb') as dump_file:
                        dump_file.write(task_data)

                    task_output.write(f"\n\tDumped shellcode in: {task_filename}\n")

        elif command == "MsgPing":
            ping_handler = sliver_pb2.Ping()
            ping_handler.ParseFromString(command_data)

            session_id = ping_handler.Request.SessionID

            ping_nonce = ping_handler.Nonce
            
            with open(self.output_file, 'a') as ping_output:
                ping_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\tTASK: {command}\n")
                ping_output.write(f"\n\tReceived Ping Nonce: {ping_nonce}\n")

        elif command == "MsgKillSessionReq":
            kill_req = sliver_pb2.KillSessionReq()
            kill_req.ParseFromString(request_data)

            session_id = kill_req.Request.SessionID

            with open(self.output_file, 'a') as kill_output:
                kill_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\tTASK: {command}\n")
                kill_output.write(f"\n\tForce: {kill_req.Force}\n")

        elif command == "MsgLsReq":
            ls_req = sliver_pb2.LsReq()
            ls_req.ParseFromString(request_data)

            session_id = ls_req.Request.SessionID
            
            ls_handler = sliver_pb2.Ls()
            ls_handler.ParseFromString(command_data)

            path = ls_handler.Path
            files = ls_handler.Files
            
            with open(self.output_file, 'a') as ls_output:
                ls_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\tTASK: {command}\n")
                ls_output.write(f"\n\tPath: {path}\n\t{'-' * 50}\n")

                for file in files:
                    if file.IsDir:
                        ls_output.write(f"\t<dir>\t\t{file.Name}\n")
                    else:
                        ls_output.write(f"\t{file.Size}\t\t{file.Name}\n")

        elif command == "MsgDownloadReq":
            download_req = sliver_pb2.DownloadReq()
            download_req.ParseFromString(request_data)

            session_id = download_req.Request.SessionID

            download_handler = sliver_pb2.Download()
            download_handler.ParseFromString(command_data)

            path = download_handler.Path
            encoder = download_handler.Encoder
            response = download_handler.Response
            download_data = download_handler.Data
            
            with open(self.output_file, 'a') as download_output:
                download_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                download_output.write(f"\n\tDownloading: {path} - Encoder: {encoder}\n")

                if len(download_data) > 0:
                    download_md5 = hashlib.md5(download_data).digest()

                    download_filename = f"{self.dump_dir}/{self.sliver_session}_{command}_{download_md5.hex()}"

                    with open(download_filename, 'wb') as dump_file:
                        dump_file.write(download_data)
                    
                    download_output.write(f"\n\tDumped file in: {download_filename}\n")
                else:
                    download_output.write(f"\n\t{response}\n")

        elif command == "MsgUploadReq":
            upload = sliver_pb2.UploadReq()
            upload.ParseFromString(request_data)

            session_id = upload.Request.SessionID
            
            upload_data = upload.Data

            upload_handler = sliver_pb2.UploadReq()
            upload_handler.ParseFromString(command_data)

            path = upload_handler.Path
            encoder = upload.Encoder

            with open(self.output_file, 'a') as upload_output:
                upload_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                upload_output.write(f"\n\tUploaded: {path} - Encoder: {encoder}\n")
            
                if len(upload_data) > 0:
                    upload_md5 = hashlib.md5(upload_data).digest()

                    upload_filename = f"{self.dump_dir}/{self.sliver_session}_{command}_{upload_md5.hex()}"

                    with open(upload_filename, 'wb') as dump_file:
                        dump_file.write(upload_data)

                    upload_output.write(f"\n\tDumped file in: {upload_filename}\n")
                else:
                    upload_output.write(f"\n\tUpload failed\n")

        elif command == "MsgCdReq":
            cd_req = sliver_pb2.CdReq()
            cd_req.ParseFromString(request_data)

            session_id = cd_req.Request.SessionID

            cd_handler = sliver_pb2.CdReq()
            cd_handler.ParseFromString(command_data)
        
            cd_path = cd_handler.Path

            with open(self.output_file, 'a') as cd_output:
                cd_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                if len(cd_path) > 0:
                    cd_output.write(f"\n\tWorking directory: {cd_path}\n")

        elif command == "MsgPwdReq":
            pwd_req = sliver_pb2.PwdReq()
            pwd_req.ParseFromString(request_data)

            session_id = pwd_req.Request.SessionID

            pwd_handler = sliver_pb2.Pwd()
            pwd_handler.ParseFromString(command_data)

            with open(self.output_file, 'a') as pwd_output:
                pwd_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n\n")
                pwd_output.write(f"\t{pwd_handler}\n")

        elif command == "MsgRmReq":
            rm_req = sliver_pb2.RmReq()
            rm_req.ParseFromString(request_data)

            session_id = rm_req.Request.SessionID

            rm_handler = sliver_pb2.Rm()
            rm_handler.ParseFromString(command_data)

            path = rm_handler.Path
            response = rm_handler.Response
            
            with open(self.output_file, 'a') as rm_output:
                rm_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n\n")

                rm_output.write(f"\tRemoving directory: {path}\n")
                rm_output.write(f"\t{response}\n")

        elif command == "MsgMkdirReq":
            mkdir_req = sliver_pb2.MkdirReq()
            mkdir_req.ParseFromString(request_data)

            session_id = mkdir_req.Request.SessionID

            mkdir_handler = sliver_pb2.Mkdir()
            mkdir_handler.ParseFromString(command_data)

            path = mkdir_handler.Path
            response = mkdir_handler.Response

            with open(self.output_file, 'a') as mkdir_output:
                mkdir_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n\n")

                mkdir_output.write(f"\tCreating directory: {path}\n")
                mkdir_output.write(f"\t{response}\n")
        
        elif command == "MsgPsReq":
            ps_req = sliver_pb2.PsReq()
            ps_req.ParseFromString(request_data)

            session_id = ps_req.Request.SessionID

            ps_handler = sliver_pb2.Ps()
            ps_handler.ParseFromString(command_data)

            processes = ps_handler.Processes

            with open(self.output_file, 'a') as ps_output:
                ps_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\tTASK: {command}\n")

                for proc in processes:
                    ps_output.write(f"\tPID: {proc.Pid}\t- PPID: {proc.Ppid}\t- Process Name: {proc.Executable}\n")

        elif command == "MsgShellReq":

            # TODO
            # Currently Tunnels are not followed in the traffic
            # Workaround -> store the PID and do some manual analysis on the pid started
            # OR: buildin extra check that checks for tunnel ID and read everything on the pipe (store as protobuf or something)
            shell_req = sliver_pb2.ShellReq()
            shell_req.ParseFromString(request_data)

            session_id = shell_req.Request.SessionID

            shell_handler = sliver_pb2.Shell()
            shell_handler.ParseFromString(command_data)

            tunnel_id = shell_req.TunnelID
            pid = shell_handler.Pid

            with open(self.output_file, 'a') as shell_output:
                shell_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\tTASK: {command}\n")
                shell_output.write(f"\n\tTUNNEL ID: {tunnel_id}\tPID: {pid}\n")

        elif command == "MsgTunnelData":
            pass

        elif command == "MsgTunnelClose":
            pass

        # NOTE: THIS SEEMS BROKEN -> dunno how to fix
        elif command == "MsgProcessDumpReq":
            procdump_req = sliver_pb2.ProcessDumpReq()
            procdump_req.ParseFromString(request_data)

            session_id = procdump_req.Request.SessionID
            pid = procdump_req.Pid

            procdump_resp = sliver_pb2.ProcessDump()
            procdump_resp.ParseFromString(command_data)

            procdump = procdump_resp.Data

            with open(self.output_file, 'a') as procdump_output:
                procdump_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                procdump_output.write(f"\n\tRequested process dump for: {pid}\n")

                if len(procdump) > 0:
                    memdump_md5 = hashlib.md5(procdump).digest()
                    memdump_filename = f"{self.dump_dir}_{self.sliver_session}_{command}_{memdump_md5.hex()}.bin"
                    with open(memdump_filename, 'wb') as dump_file:
                        dump_file.write(procdump)

                    procdump_output.write(f"\n\tMemdump file saved to: {memdump_filename}\n")     

        elif command == "MsgImpersonateReq":
            impersonate_req = sliver_pb2.ImpersonateReq()
            impersonate_req.ParseFromString(request_data)

            session_id = impersonate_req.Request.SessionID
            username = impersonate_req.Username

            impersonate_handler = sliver_pb2.Impersonate()
            impersonate_handler.ParseFromString(command_data)

            response = str(impersonate_handler.Response)
            
            with open(self.output_file, 'a') as impersonate_output:
                impersonate_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                if response:
                    impersonate_output.write(f"\n\t{response}\n")
                else:
                    impersonate_output.write(f"\n\tImpersonated: {username}\n")

        elif command == "MsgRunAsReq":
            runas_req = sliver_pb2.RunAsReq()
            runas_req.ParseFromString(request_data)

            session_id = runas_req.Request.SessionID
            username = runas_req.Username
            procname = runas_req.ProcessName
            args = runas_req.Args

            runas_handler = sliver_pb2.RunAs()
            runas_handler.ParseFromString(command_data)

            response = str(runas_handler.Response)

            with open(self.output_file, 'a') as runas_output:
                runas_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")

                runas_output.write(f"\n\tUsername: {username}\tProcess: {procname}\tArgs:{args}\n")

                if len(response) > 0:
                    runas_output.write(f"\t{response}\n")

        elif command == "MsgRevToSelfReq":
            revtoself_req = sliver_pb2.RevToSelfReq()
            revtoself_req.ParseFromString(request_data)

            session_id = revtoself_req.Request.SessionID

            revtoself_handler = sliver_pb2.RevToSelf()
            revtoself_handler.ParseFromString(command_data)

            response = str(revtoself_handler.Response)
            
            with open(self.output_file, 'a') as revtoself_output:
                revtoself_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                if len(response) > 0:
                    revtoself_output.write(f"\t{response}\n")
                else:
                    revtoself_output.write("\n\tSuccessfully reverted token\n")

        elif command == "MsgInvokeGetSystemReq":
            getsystem_req = sliver_pb2.InvokeGetSystemReq()
            getsystem_req.ParseFromString(request_data)

            session_id = getsystem_req.Request.SessionID
            hostproc = getsystem_req.HostingProcess

            implant = getsystem_req.Data

            with open(self.output_file, 'a') as getsystem_output:
                getsystem_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                getsystem_output.write(f"\n\tImplant session spawned in {hostproc}\n")

                if len(implant) > 0:
                    implant_md5 = hashlib.md5(implant).digest()
                    implant_filename = f"{self.dump_dir}/{self.sliver_session}_{command}_{implant_md5.hex()}"
                    with open(implant_filename, 'wb') as implant_file:
                        implant_file.write(implant)

                    getsystem_output.write(f"\n\tGetSystem session implant written to: {implant_filename}\n")

        elif command == "MsgInvokeExecuteAssemblyReq":
            exec_assembly_req = sliver_pb2.InvokeExecuteAssemblyReq()
            exec_assembly_req.ParseFromString(request_data)

            session_id = exec_assembly_req.Request.SessionID

            assembly = exec_assembly_req.Data
            pid = exec_assembly_req.Pid

            with open(self.output_file, 'a') as assembly_output:
                assembly_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                assembly_output.write(f"\n\tTasked to execute assembly into: {pid}\n")

                assembly_md5 = hashlib.md5(assembly).digest()
                assembly_filename = f"{self.dump_dir}_{self.sliver_session}_{command}_{assembly_md5.hex()}.bin"
                with open(assembly_filename, 'wb') as assembly_file:
                    assembly_file.write(assembly)

                assembly_output.write(f"\n\tWritten assembly to: {assembly_filename}\n")

        elif command == "MsgExecuteAssemblyReq":
            exec_assembly_req = sliver_pb2.ExecuteAssemblyReq()
            exec_assembly_req.ParseFromString(request_data)

            session_id = exec_assembly_req.Request.SessionID

            assembly = exec_assembly_req.Assembly
            args = exec_assembly_req.Args
            process = exec_assembly_req.Process
            dll = exec_assembly_req.IsDLL
            arch = exec_assembly_req.Arch
            classname = exec_assembly_req.ClassName
            method = exec_assembly_req.Method
            appdomain = exec_assembly_req.AppDomain

            with open(self.output_file, 'a') as assembly_output:
                assembly_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                assembly_output.write(f"\n\tExecute assembly request:\n")
                assembly_output.write(f"\n\t\tArgs: {args}\n\t\tProcess: {process}\n\t\tDLL: {dll}\n\t\tArch: {arch}\n\t\tClassName: {classname}\n\t\tMethod: {method}\n\t\tAppDomain{appdomain}")

                assembly_md5 = hashlib.md5(assembly).digest()
                assembly_filename = f"{self.dump_dir}_{self.sliver_session}_{command}_{assembly_md5.hex()}.bin"
                with open(assembly_filename, 'wb') as assembly_file:
                    assembly_file.write(assembly)

                assembly_output.write(f"\n\tWritten assembly to: {assembly_filename}\n")

        elif command == "MsgInvokeMigrateReq":
            migrate_handler = sliver_pb2.InvokeMigrateReq()
            migrate_handler.ParseFromString(request_data)

            session_id = migrate_handler.Request.SessionID
            
            shellcode = migrate_handler.Data
            pid = migrate_handler.Pid
            
            with open(self.output_file, 'a') as migrate_output:
                migrate_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                migrate_output.write(f"\n\tMigrated into PID: {pid}\n")

                if len(shellcode) > 0:
                    shellcode_md5 = hashlib.md5(shellcode).digest()
                    shellcode_filename = f"{self.dump_dir}/{self.sliver_session}_{command}_{shellcode_md5.hex()}.bin"
                    with open(shellcode_filename, 'wb') as shellcode_file:
                        shellcode_file.write(shellcode)
                    
                    migrate_output.write(f"\n\tShellcode written to: {shellcode_filename}\n")

        elif command == "MsgSideloadReq":
            sideload_req = sliver_pb2.SideloadReq()
            sideload_req.ParseFromString(request_data)

            session_id = sideload_req.Request.SessionID

            dll = sideload_req.Data
            dll_args = sideload_req.Args
            dll_entrypoint = sideload_req.EntryPoint
            process = sideload_req.ProcessName
            dll_kill = sideload_req.Kill

            with open(self.output_file, 'a') as dll_output:
                dll_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                dll_output.write(f"\tRequested DLL injection into: {process}\n")
                dll_output.write(f"\t\tDLL entrypoint: {dll_entrypoint}\n\t\tDLL args: {dll_args}\n\t\tKill: {dll_kill}\n")

                if len(dll) > 0:
                    dll_md5 = hashlib.md5(dll).digest()
                    dll_filename = f"{self.dump_dir}/{self.sliver_session}_{command}_{dll_md5.hex()}.dll"

                    with open(dll_filename, 'wb') as dll_file:
                        dll_file.write(dll)

                    dll_output.write(f"\nDLL written to: {dll_filename}\n")

        elif command == "MsgSpawnDllReq":
            dll_req = sliver_pb2.SpawnDllReq()
            dll_req.ParseFromString(request_data)

            session_id = dll_req.Request.SessionID

            dll = dll_req.Data
            dll_args = dll_req.Args
            dll_offset = dll_req.Offset
            process = dll_req.ProcessName
            dll_kill = dll_req.Kill

            with open(self.output_file, 'a') as dll_output:
                dll_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                dll_output.write(f"\tRequested DLL injection into: {process}\n")
                dll_output.write(f"\t\tDLL offset: {dll_offset}\n\t\tDLL args: {dll_args}\n\t\tKill: {dll_kill}\n")

                if len(dll) > 0:
                    dll_md5 = hashlib.md5(dll).digest()
                    dll_filename = f"{self.dump_dir}/{self.sliver_session}_{command}_{dll_md5.hex()}.dll"
                    with open(dll_filename, 'wb') as dll_file:
                        dll_file.write(dll)

                    dll_output.write(f"\nDLL written to: {dll_filename}\n")

        elif command == "MsgIfconfigReq":
            ifconfig_req = sliver_pb2.IfconfigReq()
            ifconfig_req.ParseFromString(request_data)

            session_id = ifconfig_req.Request.SessionID

            ifconfig_handler = sliver_pb2.Ifconfig()
            ifconfig_handler.ParseFromString(command_data)

            interfaces = ifconfig_handler.NetInterfaces

            with open(self.output_file, 'a') as ifconfig_output:
                ifconfig_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")

                for iface in interfaces:
                    ifconfig_output.write(f"\n\tInterface: {iface.Name}\t MAC: {iface.MAC}\n")

                    for address in iface.IPAddresses:
                        ifconfig_output.write(f"\t\tAddress: {address}\n")

        elif command == "MsgExecuteReq":
            execute_req = sliver_pb2.ExecuteReq()
            execute_req.ParseFromString(request_data)

            session_id = execute_req.Request.SessionID
            
            path = execute_req.Path

            execute_handler = sliver_pb2.Execute()
            execute_handler.ParseFromString(command_data)

            result = execute_handler.Result
            
            with open(self.output_file, 'a') as execute_output:
                execute_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                execute_output.write(f"\n\tExecuted: {path}\n\n")
                execute_output.write(f"\t{result}\n")

        elif command == "MsgTerminateReq":
            terminate_req = sliver_pb2.TerminateReq()
            terminate_req.ParseFromString(request_data)

            session_id = terminate_req.Request.SessionID

            pid = terminate_req.Pid
            force = terminate_req.Force

            terminate_resp = sliver_pb2.Terminate()
            terminate_resp.ParseFromString(command_data)

            response = str(terminate_resp.Response)

            with open(self.output_file, 'a') as terminate_output:
                terminate_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")

                if len(response) > 0:
                    terminate_output.write(f"\n\tFailed to terminate PID: {pid}\n")
                else:
                    terminate_output.write(f"\n\tTerminated PID: {pid}\tForce: {force}\n")

        elif command == "MsgScreenshotReq":
            screenshot_req = sliver_pb2.ScreenshotReq()
            screenshot_req.ParseFromString(request_data)

            session_id = screenshot_req.Request.SessionID

            screenshot_handler = sliver_pb2.Screenshot()
            screenshot_handler.ParseFromString(command_data)

            response = screenshot_handler.Response

            screenshot_data = screenshot_handler.Data

            with open(self.output_file, 'a') as screenshot_output:
                screenshot_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")

                if len(screenshot_data) > 0:
                    screenshot_md5 = hashlib.md5(screenshot_data).digest()
                    screenshot_file = f"{self.dump_dir}/{self.sliver_session}_{command}_{screenshot_md5.hex()}.png"

                    with open(screenshot_file, 'wb') as dump_file:
                        dump_file.write(screenshot_data)
                    
                    screenshot_output.write(f"\n\tScreenshot written to: {screenshot_file}\n")

                else:
                    screenshot_output.write(f"\n\t{response}\n")  

        elif command == "MsgNetstatReq":
            netstat_req = sliver_pb2.NetstatReq()
            netstat_req.ParseFromString(request_data)

            session_id = netstat_req.Request.SessionID

            netstat_handler = sliver_pb2.Netstat()
            netstat_handler.ParseFromString(command_data)

            entries = netstat_handler.Entries
            
            with open(self.output_file, 'a') as netstat_output:
                netstat_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n\n")

                for entry in entries:
                    netstat_output.write(f"\tLocal Addr: {entry.LocalAddr.Ip}")
                    netstat_output.write(f"\tRemote Addr: {entry.RemoteAddr.Ip}")
                    netstat_output.write(f"\tState: {entry.SkState}")
                    netstat_output.write(f"\tProcess: {entry.Process.Executable} {entry.Process.Pid}")
                    netstat_output.write(f"\tProtocol: {entry.Protocol}\n")

        elif command == "MsgNamedPipesReq":
            pipe_req = sliver_pb2.NamedPipesReq()
            pipe_req.ParseFromString(request_data)

            session_id = pipe_req.Request.SessionID

            pipename = pipe_req.PipeName

            with open(self.output_file, 'a') as pipe_output:
                pipe_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                pipe_output.write(f"\n\tCreated named pipe: {pipename}\n")

        elif command == "MsgTCPPivotReq":
            pivot_req = sliver_pb2.TCPPivotReq()
            pivot_req.ParseFromString(request_data)

            session_id = pivot_req.Request.SessionID

            address = pivot_req.Address

            pivot_resp = sliver_pb2.TCPPivot()
            pivot_resp.ParseFromString(command_data)

            pivot_success = pivot_resp.Success

            with open(self.output_file, 'a') as pivot_output:
                pivot_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                if pivot_success:
                    pivot_output.write(f"\n\tSuccessfully added pivot: {address}\n")
                else:
                    pivot_output.write(f"\n\tFailed to add pivot: {address}\n")
                    pivot_output.write(f"\tResponse: {pivot_resp.Response}")

        elif command == "MsgPivotListReq":
            list_req = sliver_pb2.PivotListReq()
            list_req.ParseFromString(request_data)

            session_id = list_req.Request.SessionID

            list_resp = sliver_pb2.PivotList()
            list_resp.ParseFromString(command_data)

            pivots = list_resp.Entries

            with open(self.output_file, 'a') as list_output:
                list_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")

                for pivot in pivots:
                    list_output.write(f"\n\tPivot type: {pivot.Type}\t{pivot.Remote}\n")

        elif command == "MsgPivotOpen":
            pivot_req = sliver_pb2.PivotOpen()
            pivot_req.ParseFromString(request_data)
            
            pivot_id = pivot_req.PivotID
            pivot_type = pivot_req.PivotType
            pivot_addr = pivot_req.RemoteAddress
            pivot_register = pivot_req.RegisterMsg
            
            try:
                envelope = sliver_pb2.Envelope()
                envelope.ParseFromString(pivot_register)
            except DecodeError:
                return

            msg_data = envelope.Data

            with open(self.output_file, 'a') as pivot_output:
                pivot_output.write(f"\n{request_time}\tPIVOT OPEN ID: {pivot_id}\t Type: {pivot_type}\t Address: {pivot_addr}\n\n")
            
            self.sliver_register(register_proto=msg_data, utc_ts=request_time)

        elif command == "MsgPivotClose":
            pass

        elif command == "MsgPivotData":
            pass

        elif command == "MsgStartServiceReq":
            start_service_req = sliver_pb2.StartServiceReq()
            start_service_req.ParseFromString(request_data)

            session_id = start_service_req.Request.SessionID

            servicename = start_service_req.ServiceName
            service_description = start_service_req.ServiceDescription
            binpath = start_service_req.BinPath
            hostname = start_service_req.Hostname

            with open(self.output_file, 'a') as service_output:
                service_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                service_output.write(f"\n\tStarted service:\n\t\tService name: {servicename}\n")
                service_output.write(f"\t\tDescription: {service_description}\n")
                service_output.write(f"\t\tBinary path: {binpath}\n")
                service_output.write(f"\t\tHostname: {hostname}\n")

        elif command == "MsgStopServiceReq":
            pass

        elif command == "MsgRemoveServiceReq":
            remove_service_req = sliver_pb2.RemoveServiceReq()
            remove_service_req.ParseFromString(request_data)

            session_id = remove_service_req.Request.SessionID
            
            servicename = remove_service_req.ServiceInfo.ServiceName
            hostname = remove_service_req.ServiceInfo.Hostname

            with open(self.output_file, 'a') as service_output:
                service_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                service_output.write(f"\n\tRemoved service:\n\t\tService name: {servicename}\n\t\tHostname: {hostname}\n")

        elif command == "MsgMakeTokenReq":
            make_token_handler_req = sliver_pb2.MakeTokenReq()
            make_token_handler_req.ParseFromString(request_data)

            session_id = make_token_handler_req.Request.SessionID
            
            user_domain = make_token_handler_req.Domain
            user = make_token_handler_req.Username
            password = make_token_handler_req.Password
            
            make_token_handler_resp = sliver_pb2.MakeToken()
            make_token_handler_resp.ParseFromString(command_data)

            response = str(make_token_handler_resp.Response)
            
            with open(self.output_file, 'a') as make_token_output:
                make_token_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                if response:
                    make_token_output.write(f"\n\tFailed to create token:\n\t\tUser: {user_domain}\{user} Password: {password}\n")
                else:
                    make_token_output.write(f"\n\tSuccessfully created token:\n\t\tUser: {user_domain}\{user}\n\t\tPassword: {password}\n")

        elif command == "MsgMakeToken":
            token_req = sliver_pb2.MakeTokenReq()
            token_req.ParseFromString(request_data)

            session_id = token_req.Request.SessionID

            domain = token_req.Domain
            user = token_req.User
            password = token_req.Password

            token_resp = sliver_pb2.MakeToken()
            token_resp.ParseFromString(command_data)

            response = token_resp.Response()

            with open(self.output_file, 'a') as make_token_output:
                make_token_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                if len(str(response)):
                    make_token_output.write(f"\n\tFailed to create token:\n\t\tUser: {domain}\{user} Password: {password}\n")
                else:
                    make_token_output.write(f"\n\tSuccessfully created token:\n\t\tUser: {domain}\{user}\n\t\tPassword: {password}\n")

        elif command == "MsgEnvReq":
            env_req = sliver_pb2.EnvReq()
            env_req.ParseFromString(request_data)

            session_id = env_req.Request.SessionID

            env_resp = sliver_pb2.EnvInfo()
            env_resp.ParseFromString(command_data)

            variables = env_resp.Variables

            with open(self.output_file, 'a') as env_output:
                env_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n\n")

                if len(str(env_resp)) > 0:
                    for env_var in variables:
                        env_output.write(f"\t{env_var.Key}={env_var.Value}\n")

        elif command == "MsgSetEnvReq":
            env_req = sliver_pb2.SetEnvReq()
            env_req.ParseFromString(request_data)

            session_id = env_req.Request.SessionID

            env_key = env_req.Variable.Key
            env_value = env_req.Variable.Value

            with open(self.output_file, 'a') as env_output:
                env_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                env_output.write(f"\n\tSet environment variable: {env_key}={env_value}\n")

        elif command == "MsgExecuteTokenReq":
            exec_token_req = sliver_pb2.ExecuteTokenReq()
            exec_token_req.ParseFromString(request_data)

            session_id = exec_token_req.Request.SessionID

            path = exec_token_req.Path
            args = exec_token_req.Args

            with open(self.output_file, 'a') as exec_token_output:
                exec_token_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                
                if len(args) > 0:
                    exec_token_req.write(f"\n\Execute token: {path} {' '.join([arg for arg in args])}")
                else:
                    exec_token_output.write(f"\n\tExecute token: {path}\n")

        elif command == "MsgRegistryReadReq":
            registry_read_req = sliver_pb2.RegistryReadReq()
            registry_read_req.ParseFromString(request_data)

            session_id = registry_read_req.Request.SessionID

            reg_hive = registry_read_req.Hive
            reg_path = registry_read_req.Path
            reg_key = registry_read_req.Key

            registry_read_handler = sliver_pb2.RegistryRead()
            registry_read_handler.ParseFromString(command_data)

            response = str(registry_read_handler.Response)

            with open(self.output_file, 'a') as reg_output:
                reg_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                reg_output.write(f"\n\tRegistry read: {reg_hive}\\{reg_path}\\{reg_key}\n")

                if len(response) == 0:
                    reg_data = registry_read_handler.Value
                    reg_output.write(f"\n\tData: {reg_data}\n")

                else:
                    reg_output.write(f"\n\t{response}\n")

        elif command == "MsgRegistryWriteReq":
            registry_write_req = sliver_pb2.RegistryWriteReq()
            registry_write_req.ParseFromString(request_data)

            session_id = registry_write_req.Request.SessionID

            reg_hive = registry_write_req.Hive
            reg_path = registry_write_req.Path
            reg_key = registry_write_req.Key

            registry_write_handler = sliver_pb2.RegistryWrite()
            registry_write_handler.ParseFromString(command_data)

            response = str(registry_write_handler.Response)

            with open(self.output_file, 'a') as reg_output:
                reg_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                reg_output.write(f"\n\tRegistry write: {reg_hive}\\{reg_path}\\{reg_key}\n")

                if len(response) == 0:

                    if str(registry_write_req.Type) == "STRING":
                        reg_data = str(registry_write_req.StringValue)
                        reg_output.write(f"\n\tData: {reg_data}")

                    else:
                        reg_data = registry_write_req.ByteValue
                        reg_data_md5 = hashlib.md5(reg_data).digest()
                        screenshot_file = f"{self.dump_dir}/{self.sliver_session}_{command}_{reg_data_md5.hex()}.bin"

                        with open(screenshot_file, 'wb') as dump_file:
                            dump_file.write(reg_data)
                        
                        reg_output.write(f"\tData written to: {screenshot_file}\n")

                else:
                    reg_output.write(f"\n\t{response}\n")

        elif command == "MsgRegistryCreateKeyReq":
            registry_create_req = sliver_pb2.RegistryCreateKeyReq()
            registry_create_req.ParseFromString(request_data)

            session_id = registry_create_req.Request.SessionID

            reg_hive = registry_create_req.Hive
            reg_path = registry_create_req.Path
            reg_key = registry_create_req.Key

            registry_create_handler = sliver_pb2.RegistryCreateKey()
            registry_create_handler.ParseFromString(command_data)

            response = str(registry_create_handler.Response)

            with open(self.output_file, 'a') as reg_output:
                reg_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                reg_output.write(f"\n\tRegistry create: {reg_hive}\\{reg_path}\\{reg_key}\n")

                if len(response) > 0:
                    reg_output.write(f"\t{response}\n")

        elif command == "MsgWGStartPortFwdReq":
            wg_startfwd_req = sliver_pb2.WGPortForwardStartReq()
            wg_startfwd_req.ParseFromString(request_data)

            session_id = wg_startfwd_req.Request.SessionID

            wg_startfwd_resp = sliver_pb2.WGSocksStartReq()
            wg_startfwd_resp.ParseFromString(command_data)

            response = str(wg_startfwd_resp.Response)

            with open(self.output_file, 'a') as wg_output:
                wg_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                if len(response) > 0:
                    wg_output.write(f"\n\t{response}\n")
                else:
                    wg_output.write(f"\n\tStarted WG Listener at: {wg_startfwd_req.RemoteAddress}:{wg_startfwd_req.LocalPort}\n")

        elif command == "MsgWGStopPortFwdReq":
            wg_stopfwd_req = sliver_pb2.WGPortForwardStopReq()
            wg_stopfwd_req.ParseFromString(request_data)

            session_id = wg_stopfwd_req.Request.SessionID

            wg_id = wg_stopfwd_req.ID

            with open(self.output_file, 'a') as wg_output:
                wg_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                wg_output.write(f"\n\tStopped WG listener: {wg_id}\n")

        elif command == "MsgWGStartSocksReq":
            socks_start_req = sliver_pb2.WGSocksStartReq()
            socks_start_req.ParseFromString(request_data)

            session_id = socks_start_req.Request.SessionID

            port = socks_start_req.Port

            with open(self.output_file, 'a') as socks_output:
                socks_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                socks_output.write(f"\n\tStarted SOCKS listener: {port}\n")

        elif command == "MsgWGStopSocksReq":
            socks_stop_req = sliver_pb2.WGSocksStopReq()
            socks_stop_req.ParseFromString(request_data)

            session_id = socks_stop_req.Request.SessionID

            socks_id = socks_stop_req.ID

            with open(self.output_file, 'a') as socks_output:
                socks_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                socks_output.write(f"\n\tStopped SOCKS listener: {socks_id}\n")

        elif command == "MsgWGListForwardersReq":
            pass

        elif command == "MsgWGListSocksReq":
            pass
        
        elif command == "MsgPortfwdReq":
            portfwd_req = sliver_pb2.PortfwdReq()
            portfwd_req.ParseFromString(request_data)

            session_id = portfwd_req.Request.SessionID

            tunnel_id = portfwd_req.TunnelID
            host = portfwd_req.Host
            port = portfwd_req.Port
            proto = portfwd_req.Protocol

            with open(self.output_file, 'a') as portfwd_output:
                portfwd_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                portfwd_output.write(f"\n\tStarted port forward:\n")
                portfwd_output.write(f"\t\tID: {tunnel_id}\t{host}:{port}\t{proto}\n")
        
        elif command == "MsgReconnectIntervalReq":
            interval_req = sliver_pb2.ReconnectIntervalReq()
            interval_req.ParseFromString(request_data)

            session_id = interval_req.Request.SessionID

            interval = interval_req.ReconnectIntervalSeconds

            with open(self.output_file, 'a') as interval_output:
                interval_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                interval_output.write(f"\n\tInterval updated to: {interval} seconds\n")

        elif command == "MsgReconnectInterval":
            pass
        
        elif command == "MsgPollIntervalReq":
            poll_req = sliver_pb2.ReconnectIntervalReq()
            poll_req.ParseFromString(request_data)

            session_id = poll_req.Request.SessionID

            poll_interval = poll_req.PollIntervalSeconds

            with open(self.output_file, 'a') as interval_output:
                interval_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                interval_output.write(f"\tInterval polled to update to: {poll_interval} seconds\n")
            
        elif command == "MsgUnsetEnvReq":
            env_req = sliver_pb2.UnsetEnvReq()
            env_req.ParseFromString(request_data)

            session_id = env_req.Request.SessionID

            env_name = env_req.Name

            with open(self.output_file, 'a') as env_output:
                env_output.write(f"\n{request_time}\tSESSIONID: {session_id}\t TASK ID: {task_id}\t TASK: {command}\n")
                env_output.write(f"\tUnset environment var: {env_name}\n")

