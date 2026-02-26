import socket

HOST = "0.0.0.0"
PORT = 8002

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(1)

print(f"Listening on {HOST}:{PORT}...")

conn, addr = server.accept()
print("STM32 connected from:", addr)

while True:
    try:
        data = conn.recv(1024)
        if data:
            print("STM32:", data.decode('utf-8', errors='ignore'))
    except socket.timeout:
        pass
    except ConnectionResetError:
        print("STM32 disconnected")
        break

