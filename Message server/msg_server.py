# Name: Yarden Green
# ID: 313925976


import socket
import struct
import uuid
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from pathlib import Path
from Crypto.Util.Padding import unpad
import base64
import threading



msg_server_file = Path("msg.info")
msg_server_key = get_random_bytes(32)
thread_local = threading.local()

# sets current thread session key
def set_session_key(key):  # sets the session key for the current thread
    thread_local.session_key = key

def set_client_id(id):  # sets the client id for the current thread
    thread_local.client_id = id

# gets session key for the current thread
def get_session_key():  # gets the session key for the current thread
    return getattr(thread_local, 'session_key', None)

def get_client_id():  # gets the client id for the current thread
    return getattr(thread_local, 'client_id', None)


# creates msg.info file
def create_msg_server_info(ip, port, name, sid, key, msg_server_file = "msg.info"):  # creates msg.info file
    key = base64.b64encode(key)
    with open(msg_server_file, 'w') as f:
        f.write(f"{ip}:{port}\n")
        f.write(name + '\n')
        f.write(sid + '\n')
        f.write(key.decode() + '\n')



def unpad_and_decrypt(data, key, iv):  # a function to unpad and decrypt
    decipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(decipher.decrypt(data), AES.block_size)



def handle_request_1028(data, client_socket):  # handles request 1028
    unpacked_data = struct.unpack('<16sbHI16s48sB16s16s8s16s48s', data)  # unpack all
    header = unpacked_data[0:4]  # gets the header
    authenticator_iv = unpacked_data[4]  # gets the authenticator iv
    enc_authenticator = unpacked_data[5]  # gets the authenticator
    ticket = unpacked_data[6:]  # gets the ticket
    enc_ticket_data = ticket[-1]
    ticket_iv = ticket[4]  # gets the ticket iv
    dec_ticket_data = unpad_and_decrypt(enc_ticket_data, msg_server_key, ticket_iv)  # decrypts the ticket
    session_key = dec_ticket_data[0:32]  # gets the session key from ticket
    ticket_expiration_time = dec_ticket_data[32:]  # gets the expiration time from ticket
    set_session_key(session_key)  # sets session key for the current thread
    authenticator = unpad_and_decrypt(enc_authenticator,get_session_key(),authenticator_iv)  # decrypts authenticator
    authenticator_client_id = authenticator[1:17].hex()  # get the authenticator client id to compare
    ticket_client_id = ticket[1].hex()  # gets the client id from request
    authenticator_creation_time = authenticator[33:]  # gets the authenticator creation time to compare
    if ticket_expiration_time > authenticator_creation_time and authenticator_client_id == ticket_client_id:  # checks validity
        set_client_id(ticket_client_id)  # sets client id
        code = 1604  # if all went well - set ack
        print("request 1028 handled, TGS validated")
    else:
        code = 1609  # there was a problem
        print("there was a problem validating TGS")

    reply = struct.pack('<H', code)
    client_socket.send(reply)  # sends reply



def handle_request_1029(data, client_socket):  # handles request 1029
    header_size = 23
    header = struct.unpack('<16sBHI', data[:header_size])  # gets the header
    user_id, version, code, payload_size = header
    total_size = len(data)  # calculates the request size
    packed_payload = data[header_size:total_size]  # extracts the payload
    message_size = payload_size - 20
    message_size, message_iv, encrypted_message = struct.unpack(f'<I16s{message_size}s', packed_payload)  # unpack payload
    session_key = get_session_key()  # gets session key
    decrypted_message = unpad_and_decrypt(encrypted_message, session_key, message_iv).decode('utf-8')  # decrypts the message
    print(f"Got a message from client id:{get_client_id()}:\n{decrypted_message}")  # prints the client id and the message got from him
    if decrypted_message:  # if everything went well set ack
        code = 1605  # ack

    else:
        code = 1609  # there was an error
    reply = struct.pack('<H', code)
    client_socket.send(reply)  # sends ack


msg_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

if not msg_server_file.exists():  # if msg server file doesn't exist create it

    server_ip = '127.0.0.1'
    msg_server_port = 1234
    server_name = "message server"
    msg_server_id = str(uuid.uuid4()).replace('-', '')
    msg_server_key = get_random_bytes(32)
    create_msg_server_info(server_ip, msg_server_port, server_name, msg_server_id, msg_server_key)

else:  # if the file exists get the data
    with open(msg_server_file, 'r') as f:
        server_ip_port = f.readline().strip().split(':')
        server_ip = server_ip_port[0]
        msg_server_port = int(server_ip_port[1])
        server_name = f.readline().strip()
        msg_server_id = f.readline().strip()
        msg_server_key = f.readline().strip()
        msg_server_key = base64.b64decode(msg_server_key)



def handle_client(client_socket, client_address):  # handles user requests
    try:
        while True:
            received_request = client_socket.recv(1024)  # receive requests
            if not received_request:
                print(f"Client {client_address} disconnected.")
                break

            request_num = struct.unpack('<H', received_request[17:19])[0]

            if request_num == 1028:
                handle_request_1028(received_request, client_socket)  # sends the request to handle 1028


            if request_num == 1029:
                message_size = struct.unpack('<I', received_request[23:27])[0] + 43  # checks for big messages
                received_size = 1024
                while received_size < message_size:  # if its a big message
                    chunk = client_socket.recv(min(message_size - received_size, 1024))  # get chunks from socket
                    if not chunk:
                        raise RuntimeError("Incomplete message received")
                    received_request += chunk
                    received_size += len(chunk)
                handle_request_1029(received_request, client_socket)  # sends the request to handle 1029

    except ConnectionResetError:  # resets connection
        print(f"Connection reset by client {client_address}.")
    except Exception as e:  # other exceptions
        print(f"An error occurred for client {client_address}: {e}")
    finally:
        client_socket.close()


msg_server.bind((server_ip, int(msg_server_port)))
msg_server.listen()  # listens on socket
print(f"Socket is listening on IP address {server_ip}, on port {msg_server_port}")

# main loop
while True:
    try:
        client_socket, client_address = msg_server.accept()
        print(f"Accepted connection from {client_address}")

        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start() # opens thread for new user

    except Exception as e:
        print(f"An error occurred: {e}")

