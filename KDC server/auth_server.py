# Name: Yarden Green
# ID: 313925976


import base64
import socket
import struct
import uuid
from datetime import datetime, timedelta
import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from pathlib import Path
from Crypto.Util.Padding import pad
import threading


file_write_lock = threading.Lock()

class User:  # defines a user with all the necessary attributes
    def __init__(self, user_id, username, password_hash, last_seen):
        self.user_id = user_id
        self.username = username
        self.password_hash = password_hash
        self.last_seen = last_seen


msg_server_file = Path("../Message server/msg.info")
clients_file = Path("clients")
port_file = Path("port.info")
user_list = []
version = 24

server_ip = '127.0.0.1'
server_port = None
client_socket = None

def load_users_from_file(file_path):  # loads the registered users from the user file
    users = []
    with open(file_path, "r") as f:
        for line in f:
            data = line.strip().split(':')
            if len(data) == 4:
                user_id, username, password_hash, last_seen = data
                client = User(user_id, username, password_hash, last_seen)
                users.append(client)  # appends to the user list
            else:
                print("Invalid data format in line:", line)
    return users

def get_server_key(file_path):  # gets the server key from file
    if file_path.exists():
        with open(file_path, 'r') as f:
            lines = f.readlines()
            key = lines[3].rstrip()
            key = base64.b64decode(key)
            return key
    else:
        print("message server file is missing")


def pad_and_encrypt(data, key, iv):  # a function to pad and encrypt
    data = pad(data, AES.block_size, style='pkcs7')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data


# handles registration for request 1024
def handle_registration(username, user_password):
    try:
        password_hash = hashlib.sha256(user_password.encode('utf-8')).hexdigest()  # creates the hash key
        # searches for a username that is taken
        with open("clients", 'a+', encoding='utf-8') as f:
            f.seek(0)
            if any(username in line for line in f):
                client_socket.send("This username already exists. Please try a different one.".encode('utf-8'))
            else:
                # creates a new user and adds to list
                user_id = str(uuid.uuid4()).replace('-', '')
                user_id = bytes.fromhex(user_id)
                last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S").replace(':', '- ')
                f.write(f"{user_id.hex()}:{username}:{password_hash}:{last_seen}\n")
                new_user = User(user_id.hex(), username, password_hash, last_seen)
                user_list.append(new_user)
                return user_id
    except Exception as e:
        print(f"Error handling registration: {e}")
        return None

# handles request 1024 for registration
def handle_request_1024(data):
    try:
        # unpacks the request
        client_id, version, request_num, received_payload_size, user_name, user_password = struct.unpack(
            '<16sBHI255s255s', data)
        user_name = user_name.decode('utf-8').rstrip("\x00")  # gets username
        user_password = user_password.decode('utf-8').rstrip("\x00")  # gets password
        user_id = handle_registration(user_name, user_password)  # send to registration function
        print(f"registering {user_name} with password {user_password}")
        if user_id:  # if user_id created send ack
            return_code = 1600
            return_payload = user_id
            return_payload_size = len(return_payload)
            return_pack = struct.pack('<BHI16s', version, return_code, return_payload_size, return_payload)

            try:
                client_socket.send(return_pack)
                print(f"Request 1024 handled\nuser: {user_name} created with id: {user_id.hex()}")
            except Exception as e:
                print(f"Error sending the authorization to the client: {e}")

    except struct.error as e:
        print(f"Error processing client request 1024: {e}")



    except Exception as e:
        print(f"An error occurred while handling request 1000: {e}")


def handle_request_1027(data):

    try:
        # unpack the request
        client_id, version, request_num, received_payload_size, server_id, user_nonce = struct.unpack(
            '<16sBHI16sQ', data)
        code = 1603
        user_nonce = user_nonce.to_bytes(8, byteorder='little')  # gets nonce
        client_id = client_id.hex().rstrip("\x00")  # gets client id
        server_id = server_id.decode('utf-8').rstrip("\x00").encode('utf-8')  # gets server id
        creation_time = datetime.now()  # gets creation time
        expiration_time = creation_time + timedelta(minutes=5)  # gets expiration time of 5 minutes from creation time
        creation_time = creation_time.strftime("%H:%M:%S").encode('utf-8')  # formats and encodes
        expiration_time = expiration_time.strftime("%H:%M:%S").encode('utf-8')  # formats and encodes
        user_pack_iv = get_random_bytes(16)  # gets iv for encrypted data pack
        ticket_iv = get_random_bytes(16)  # gets iv for encrypted ticket pack
        session_key = get_random_bytes(32)  # creates a session key for the user and message server
        filtered_users = [user for user in user_list if user.user_id == client_id]  # searches for user
        if not filtered_users:
            print(f"User with id {client_id} not found.")
            return
        current_user = filtered_users[0]
        hash_key = bytes.fromhex(current_user.password_hash)  # gets the user key
        user_data = user_nonce + session_key
        enc_user_data = pad_and_encrypt(user_data, hash_key, user_pack_iv)


        # packs user pack
        user_pack = struct.pack('<16s16s48s', bytes.fromhex(client_id), user_pack_iv, enc_user_data)

        ticket = session_key + expiration_time
        enc_ticket = pad_and_encrypt(ticket, msg_server_key, ticket_iv)

        # packs the ticket
        ticket_pack = struct.pack('<B16s16s8s16s48s', version, bytes.fromhex(client_id), server_id, creation_time
                                  , ticket_iv, enc_ticket)
        payload_size = len(user_pack + ticket_pack)
        header = struct.pack('<BHI', version, code, payload_size)
        payload = user_pack + ticket_pack  # combines payload
        client_socket.send(header + payload)  # sends payload
        print(f"Request 1027 handled, TGS sent to client id: {client_id}")

    except struct.error as e:
        print(f"Error processing client request 1027: {e}")
    except Exception as ex:
        print(f"An unexpected error occurred: {ex}")

# reads port from port file
def read_port():
    global server_port
    if port_file.exists():
        with open(port_file, 'r') as f:
            server_port = int(f.readline())
    else:
        print("there is no port.info file. working on default")
        server_port = 1256


# handles clients requests
def handle_client(client_socket, client_address):
    try:
        while True:
            received_request = client_socket.recv(1024)
            if not received_request:
                print(f"Client {client_address} disconnected.")
                break

            request_num = struct.unpack('<H', received_request[17:19])[0]

            if request_num == 1024:
                handle_request_1024(received_request)


            elif request_num == 1027:
                handle_request_1027(received_request)

            else:
                print(f"Unknown request type: {request_num}")

    except Exception as e:
        print(f"An error occurred while handling client {client_address}: {e}")

    finally:
        client_socket.close()

# main function loops
if __name__ == "__main__":
    msg_server_key = get_server_key(msg_server_file)
    read_port()
    kdc_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    kdc_server.bind((server_ip, server_port))
    kdc_server.listen()
    print(f"Socket is listening on IP address {server_ip}, on port {server_port}")

    try:
        if clients_file.exists():
            user_list = load_users_from_file(clients_file)
        while True:
            client_socket, client_address = kdc_server.accept()
            print(f"Accepted connection from {client_address}")

            # Start a new thread to handle the client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()  # opens thread for new user

    except Exception as e:
        print(f"Error handling requests: {e}")

    finally:
        kdc_server.close()
