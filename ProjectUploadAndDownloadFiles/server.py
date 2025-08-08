import socket
import threading
import os

FILES_DIR = "server_files"
os.makedirs(FILES_DIR, exist_ok=True)

HOST = "0.0.0.0"
PORT = 5001

def recv_line(conn):
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode().rstrip("\n")

def handle_client(conn, addr):
    print(f"[+] New connection from {addr}")

    try:
        while True:
            command = recv_line(conn).strip().upper()
            if not command:
                break

            filename = recv_line(conn).strip()
            if not filename:
                print(f"[-] No filename provided for {command.lower()}.")
                break

            if command == "UPLOAD":
                filepath = os.path.join(FILES_DIR, filename)
                with open(filepath, "wb") as f:
                    while True:
                        chunk = conn.recv(1024)
                        if chunk == b"EOF":
                            break
                        if not chunk:
                            break
                        f.write(chunk)
                print(f"[+] File '{filename}' uploaded successfully to {filepath}.")

            elif command == "DOWNLOAD":
                filepath = os.path.join(FILES_DIR, filename)
                if os.path.exists(filepath):
                    with open(filepath, "rb") as f:
                        while chunk := f.read(1024):
                            conn.sendall(chunk)
                    conn.sendall(b"EOF")
                    print(f"[+] File '{filename}' sent to client.")
                else:
                    conn.sendall(b"ERROR")
                    print(f"[-] File '{filename}' not found.")

            else:
                print(f"[-] Unknown command: {command}")
                break

    except Exception as e:
        print(f"[!] Error handling client {addr}: {e}")

    finally:
        conn.close()
        print(f"[-] Connection with {addr} closed")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[+] Server listening on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()
