# Name: Yarden Green
# ID: 313925976


import socket
import struct
import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import time
from datetime import datetime
import errno
from Crypto.Util.Padding import pad, unpad
from pathlib import Path


server_version = None
server_id = None
creation_time = None
ticket = None
client_iv = None
session_key = None
version = 24
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
msg_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
kdc_ip = '127.0.0.1'
msg_server_ip = '127.0.0.1'
kdc_port = None
msg_server_port = 1234
key_flag = 0
user_flag = 0
ticket_valid_flag = 0
server_info_path = Path("srv.info")
client_info_Path = Path("me.info")


class User:
    def __init__(self, client_id="", username="", password_hash=""):
        self.client_id = client_id
        self.username = username
        self.password_hash = password_hash


def export_data_to_attack(nonce, pack, client_iv):  # for question 2, creates a file for the attack, containing the encrypted pack, nonce and iv
    with open("../attack_data.txt", "w") as file:
        file.truncate()
        file.write(f"{nonce.hex()}\n")
        file.write(f"{pack.hex()}\n")
        file.write(f"{client_iv.hex()}\n")


def get_kdc_port():  # gets the kdc port number from server file
    global kdc_port
    if server_info_path.exists():
        with open(server_info_path, 'r') as f:
            kdc_line = f.readline().rstrip().split(':')
            kdc_port = int(kdc_line[1])
    else:
        kdc_port = 1256
    print(f"connected to kdc port:{kdc_port}")



def check_registration(username, password):  # checks for username valid length
    if 0 < len(username) <= 244 and 0 < len(password) <= 244:
        return True
    else:
        return "Username and password lengths should be between 1 - 254 bytes."


def handle_registration(username, password):  # handles the registration process and creates a request pack for the KDC server
    global version
    if check_registration(username, password): # if username is valid length
        user_name = username[:254].ljust(255, '\0')  # formats 255 characters with null at the end
        user_password = password[:254].ljust(255, '\0')
        request_num = 1024
        client_id = " " * 16
        client_id = bytes.fromhex(client_id)
        payload = user_name.encode('utf-8') + user_password.encode('utf-8')  # creates the payload
        payload_size = len(payload)
        package = struct.pack(f'<16sBHi{payload_size}s', client_id, version, request_num, payload_size, payload)
        return package


# checks for the registered user's name and id
def check_my_info(user):
    global user_flag
    try:
        with open("me.info", "r") as f:
            user_name = f.readline().strip()
            client_id = f.readline().strip()
            user.client_id = client_id
            user.username = user_name
            password = input(f"Hi {user_name}, to log in please type your password: ")
            password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            user.password_hash = password_hash
            user_flag = 1
            return True
    except FileNotFoundError:
        return False
    except Exception as e:
        print(f"An error occurred opening me.info: {e}")


def generate_nonce():  # generates nonce
    nonce = get_random_bytes(8)
    return nonce



def pad_and_encrypt(data, key, iv):  # a function to pad and encrypt
    data = pad(data, AES.block_size, style='pkcs7')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data



def unpad_and_decrypt(data, key, iv):  # a function to unpad and decrypt
    decipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(decipher.decrypt(data), AES.block_size)


user = User()

def handle_request_1024():  # handles request 1024
    global client_socket
    global user_flag
    if not client_info_Path.exists():  # if the user is not registered from before get details
        username = input("Please choose a username: ")
        password = input("Please choose a password: ")
        request_pack = handle_registration(username, password)  # creates the request pack
        try:
            print("Now registering you with KDC")
            client_socket.send(request_pack)  # sends the request to the KDC server
            time.sleep(0.1)
        except BlockingIOError as e:
            if e.errno == errno.WSAEWOULDBLOCK:
                time.sleep(0.1)  # wait if there's a block in the socket
                return False  # exit the function and let the loop continue
            else:
                print(f"Error sending the request to the server: {e}")
                return False  # exit the function and let the loop continue

        while True:
            try:
                message_received = client_socket.recv(1024)  # receive the answer from KDC server
                break
            except BlockingIOError as e:  # if socket is blocked
                if e.errno == errno.WSAEWOULDBLOCK:
                    time.sleep(0.1)
                    continue
                else:
                    print(f"Error receiving the message from the server: {e}")
                    return False  # exit the function and let the loop continue

        try:
            # unpacks the answer from KDC
            version, return_code, return_payload_size, return_payload = struct.unpack('<BHI16s', message_received)
            user_name = username
            user.client_id = return_payload.hex()
            print(f"client id is: {user.client_id}")
            password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            user.username = user_name
            user.password_hash = password_hash
            with open("me.info", "w") as f:
                f.write(f"{user_name}\n{user.client_id}")  # writes details to the file
                user_flag = 1
            return True  # registration went well

        except struct.error:
            print(f"Username {username} already exists")
            return False  # there was an error in the registration process

    else:  # the user already exists , load details
        if user.username == "" and user.client_id == "":
            with open("me.info", "r") as f:
                user.username = f.readline().strip("\n")
                user.client_id = bytes.fromhex(f.readline().strip("\x00"))
                user_flag = 1
                print("user already exists")
        else:
            print("User already logged in")
        return True



def handle_request_1027():  # handles request 1027
    global key_flag
    global server_version
    global server_id
    global creation_time
    global ticket
    global client_iv
    global session_key
    global ticket_valid_flag
    global user_flag

    ticket_valid_flag = 0
    server_id = " " * 16
    nonce = generate_nonce()
    payload = server_id.encode('utf-8') + nonce  # creates the payload for the request
    payload_size = len(payload)
    client_id = user.client_id
    if user_flag == 0 :
        print("first take care of registering, then request ticket")
    try:
        # creates the request pack
        request_pack = struct.pack(f'<16sBHi{payload_size}s', bytes.fromhex(client_id), version, 1027, payload_size,
                                   payload)
        client_socket.send(request_pack)  # sends the request and waits
        time.sleep(0.3)
    except BlockingIOError as e:  # if socket is blocked wait 1 second
        if e.errno == errno.EWOULDBLOCK:
            time.sleep(1)
            return False
        else:
            print(f"Error packing request 1027: {e}")
            return False

    try:
        message_received = client_socket.recv(1024)  # gets the response from KDC
        if message_received:
            unpacked_data = struct.unpack('<BHI16s16s48sB16s16s8s16s48s', message_received)  # unpacks the response
            # Check if response indicates acknowledgment for creating session key
            if unpacked_data[1] == 1603:
                enc_user_pack = unpacked_data[5]  # gets the user pack
                client_iv = unpacked_data[4]  # gets the iv from server
                key = bytes.fromhex(user.password_hash)  # gets the key

                # retry decryption until successful to confirm the password in case of logging in
                while True:
                    try:
                        user_pack = unpad_and_decrypt(enc_user_pack, key, client_iv)
                        server_nonce = user_pack[0:8]
                        session_key = user_pack[8:]
                        break  # decryption is successful
                    except ValueError:
                        # if decryption fails get a new password and retry
                        password = input("Wrong password. Please enter the correct password: ")
                        user.password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
                        key = bytes.fromhex(user.password_hash)

                if server_nonce != nonce:  # comparing our encrypted nonce with the server's encrypted nonce
                    while server_nonce != nonce:  # cant continue if password's not correct
                        password = input("Wrong password. Please enter the correct password: ")
                        user.password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
                        key = bytes.fromhex(user.password_hash)

                        # retry decryption until successful
                        while True:
                            try:

                                user_pack = unpad_and_decrypt(enc_user_pack, key, client_iv)
                                server_nonce = user_pack[0:8]
                                session_key = user_pack[8:]
                                break  # successful decryption
                            except ValueError:
                                # if decryption fails get a new password and retry
                                password = input("Wrong password. Please enter the correct password: ")
                                user.password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
                                key = bytes.fromhex(user.password_hash)

                export_data_to_attack(nonce, enc_user_pack, client_iv)  # exports the data for the attack in question 2
                server_version = unpacked_data[0]  # get server version
                server_id = unpacked_data[8]  # get server id
                ticket = unpacked_data[6:]  # gets the ticket
                creation_time = ticket[3]  # get creation time for ticket
                key_flag = 1  # we got a valid session key from KDC , we can continue with request 1028
                print("got a valid session key and ticket from KDC")
                return True
            else:
                print("there is something wrong, check registration again")
                return True
    except BlockingIOError as e:
        if e.errno == errno.EWOULDBLOCK:  # if socket is blocked wait
            time.sleep(0.1)
            return False
        else:
            print(f"Error receiving the message from the server: {e}")
            return False
    except Exception as e:
        print(f"Error processing response from server: {e}")
        return False

    return False



def handle_request_1028():  # handles request 1028
    global key_flag
    global server_version
    global server_id
    global creation_time
    global ticket
    global client_iv
    global session_key
    global ticket_valid_flag

    client_id = bytes.fromhex(user.client_id)
    if not key_flag == 1:  # if we didn't go through request 1027 dont continue
        print("Cannot proceed with this request, please send request 1027 before.")
        return False
    else:
        global msg_socket
        if ticket:  # if we have a ticket
            server_id = " " * 16
            # gathers the ticket pack
            ticket_pack = struct.pack('<B16s16s8s16s48s', ticket[0], ticket[1], ticket[2], ticket[3], ticket[4],
                                      ticket[5])
            authenticator_iv = get_random_bytes(16)

            # creates authenticator
            authenticator = struct.pack('<B16s16s8s', version, client_id, server_id.encode('utf-8'), creation_time)
            # encrypts authenticator with the session key
            enc_authenticator = pad_and_encrypt(authenticator, session_key, authenticator_iv)
            authenticator_iv = struct.pack('<16s', authenticator_iv)  # packs the authenticator iv
            payload = authenticator_iv + enc_authenticator+ ticket_pack  # prepare the payload
            code = 1028 # request code
            payload_size = len(payload)
            header = struct.pack('<16sBHI', client_id, version, code, payload_size)  # create the header
            msg_socket.send(header + payload)  # sends the header + authenticator + ticket
            time.sleep(0.2)  # wait for server to process
            while True:
                try:

                    reply = msg_socket.recv(1024)
                    if not reply:
                        break
                    reply_code = struct.unpack('<H', reply)[0]  # reply from message server
                    if reply_code == 1604:  # ack
                        ticket_valid_flag = 1
                        print("ticket validated with message server")
                        return True
                    else:  # no ack
                        print("there was an error that wasn't handled before, check registration or request ticket again")
                except BlockingIOError:
                    time.sleep(0.1)
                    continue
                except Exception as e:
                    print(f"An error occurred: {e}")
                    break

        return False

# handles request 1029
def handle_request_1029():
    code = 1029
    global ticket_valid_flag
    if ticket_valid_flag == 0:  # if the current ticket wasn't validated with msg server
        print("please send request 1028 before request 1029")
        return False
    try:
        message_iv = get_random_bytes(16)  # iv for the message
        message = input("Please enter your message for the server: ")  # gets the message
        encrypted_message = pad_and_encrypt(message.encode('utf-8'), session_key, message_iv)  # encrypts the message
        message_size = len(encrypted_message)
        # arranges the request pack
        request_pack = struct.pack(f'<I16s{message_size}s', message_size, message_iv, encrypted_message)
        payload_size = len(request_pack)
        header = struct.pack(f'<16sBHI', bytes.fromhex(user.client_id), version, code, payload_size)
        msg_socket.send(header + request_pack)  # sends to the message server
        time.sleep(0.2)  # wait for server to process
        reply = msg_socket.recv(1024)
        reply_code = struct.unpack('<H', reply)[0]  # reply from server
        if reply_code == 1605:  # ack
            print("message received by message server")
            return True
        else:
            print("there was a problem that wasn't handled before, check registration, or request ticket again, "
                  "or send ticket and authenticator to message server again")
    except BlockingIOError:
        time.sleep(0.1)
    except struct.error as se:
        print(f"Struct packing error: {se}")
    except Exception as e:
        print(f"An error occurred: {e}")
    return False


get_kdc_port()
client_socket.connect((kdc_ip, kdc_port))
client_socket.setblocking(False)
msg_socket.connect((msg_server_ip, msg_server_port))
msg_socket.setblocking(False)


try:
    # check user info and connect to the message server
    if client_info_Path.exists():
        check_my_info(user)


    while True:
        request_num = input("Please enter request number: ")

        if request_num.casefold() == "exit":
            break

        try:
            request_num = int(request_num)
        except ValueError:
            print("Invalid input. Please enter a valid integer for the request number.")
            continue

        if request_num == 1024:
            handle_request_1024()

        elif request_num == 1027:
            print("Requesting ticket from the KDC")
            handle_request_1027()

        elif request_num == 1028:
            print("Validating ticket with message server")
            handle_request_1028()

        elif request_num == 1029:
            print("Sending a message to message server")
            handle_request_1029()


except ConnectionResetError:
    print("Connection lost with the server")

finally:
    print("Connection was terminated")
    msg_socket.close()
