import socket
import os

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5001

def upload_file(filename):
    if not os.path.exists(filename):
        print(f"[-] File '{filename}' does not exist.")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))
        s.sendall(f"UPLOAD\n{filename}\n".encode())
        with open(filename, "rb") as f:
            while chunk := f.read(1024):
                s.sendall(chunk)
        s.sendall(b"EOF")

    print(f"[+] File '{filename}' uploaded successfully.")

def download_file(filename):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))
        s.sendall(f"DOWNLOAD\n{filename}\n".encode())
        with open(filename, "wb") as f:
            while True:
                data = s.recv(1024)
                if data == b"EOF":
                    break
                elif data == b"ERROR":
                    print(f"[-] File '{filename}' not found on server.")
                    f.close()
                    os.remove(filename)
                    return
                f.write(data)

    print(f"[+] File '{filename}' downloaded successfully.")

def main():
    while True:
        print("\n--- File Transfer Client ---")
        print("1. Upload file")
        print("2. Download file")
        print("3. Exit")

        choice = input("Enter choice: ")

        if choice == "1":
            filename = input("Enter file name to upload: ")
            upload_file(filename)
        elif choice == "2":
            filename = input("Enter file name to download: ")
            download_file(filename)
        elif choice == "3":
            print("[+] Exiting client.")
            break
        else:
            print("[-] Invalid choice, try again.")

if __name__ == "__main__":
    main()
