import socket
import ssl
import threading


server_address = ("localhost", 12345)

clients = []


def handle_client(client_socket):
    try:
        while True:
            data = client_socket.recv(1024)
            if not data: 
                break
            print(f"Received: {data.decode()}")

            for client in clients:
                if client != client_socket:
                    try:
                        client.send(data)
                    except:
                        client.remove(client)
    except: 
        clients.remove(client_socket)
    finally:
        print("Client disconnected", client_socket.getpeername())
        clients.remove(client_socket)
        client_socket.close()

server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_socket.bind(server_address)
server_socket.listen(5)
print(f"Server listening on {server_address}")

while True:
    client_socket,client_address = server_socket.accept()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS)

    context.load_cert_chain(certfile="certificates/server-cert.crt", keyfile="certificates/server-key.key")

    ssl_socket = context.wrap_socket(client_socket,server_side=True)

    client_thread = threading.Thread(target=handle_client,args= (ssl_socket,))
    client_thread.start()
    