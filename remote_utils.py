import paramiko

def remote_file_hash(host, username, password, remote_path):
    """
    Connect to remote host via SSH and calculate SHA-256 hash of a remote file.
    Returns hash as hex string or None if failed.
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, username=username, password=password, timeout=10)

        sftp = ssh.open_sftp()
        remote_file = sftp.file(remote_path, 'rb')

        import hashlib
        sha256 = hashlib.sha256()
        while True:
            data = remote_file.read(4096)
            if not data:
                break
            sha256.update(data)

        remote_file.close()
        sftp.close()
        ssh.close()
        return sha256.hexdigest()
    except Exception as e:
        return None
