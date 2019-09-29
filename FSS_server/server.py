from Crypto.PublicKey import RSA
from cookiegen import get_unique_cookie as cook
import fmanag as fm
import os
import sockCrypto as sc
import hashlib
import traceback
import sevmanag as dbm
import socket
import base64

GDB = (r"fssGlobal.db", r".shc")
LISTENING_PORT = 954
IP = ''


def main():
    password = input("Enter operation code (a password): ")
    if verify(password):
        # check if database file is exists
        if not dbm.exists(GDB[0]):
            dbm.create(GDB[0])
        # check if key file exists
        if not dbm.exists(sc.FK[0]):
            print(" - Generating RSA keys -")
            sc.gen_key(password)
        # create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_id = (IP, LISTENING_PORT)
        try:
            sock.bind(server_id)
        except Exception:
            print("Server Error: Server operation was aborted. \nError Details:\n", traceback.format_exc())
        # run server
        print("- FSS Server Is Now Running -")
        while True:
            try:
                server(sock, password)  # operate server
            except Exception:
                print("Server Error: Server operation was aborted. \nError Details:\n", traceback.format_exc())


def server(sock, password):
    """
    function will run the FSS server.
    :param sock: socket
    :type sock: socket object
    :param password: server code (password)
    :type password: str
    :return: none
    """
    sock.listen(1)  # listening
    client_soc, client_address = sock.accept()  # connection accepted
    private, public = exchange(client_soc, password)
    print("\nconnected - ", client_address)  # print client id
    request = client_soc.recv(4096)  # get request
    request = sc.decrypt_message(message=request, private=private)
    try:
        operate(client_soc, request, private, public)  # operate
    except Exception:
        print("Server Error: Failed to proceed with the selected operation. \nError Details:\n", traceback.format_exc())
        # try to send an error message to the client
        try:
            message = b'E\x00Failed to proceed with the selected operation\x00'
            message = sc.encrypt_message(message=message, public=public)
            client_soc.sendall(message)
            client_soc.close()
        except Exception:
            pass
    print("\ndisconnected - ", client_address)  # print client id


def exchange(sock, password):
    """
    exchange RSA public keys.
    :param sock: socket
    :type sock: socket object
    :param password: server code (password)
    :type password: str
    :return: key pear (public, private)
    :rtype: RSA key objects
    """
    private, public = sc.read_key(password)  # read key
    public = public.exportKey('PEM')  # export
    sock.sendall(public)  # send
    public = sock.recv(4096)  # receive public key of client
    return private, RSA.import_key(public)


def operate(sock, request, private, public):
    """
    this function will operate the functions which apply to the client's request.
    :param sock: TCP socket
    :type sock: socket object
    :param request: client request
    :type request: byte array
    :param private: private key
    :type private: RSA key object
    :param public: public key
    :type public: RSA key object
    :return: None
    """
    request = request.split(b'\x00')  # split arguments

    # if it's upload request
    if b'U' == request[0]:
        importing(sock, request, private, public)  # import file to storage
    elif request[0] == b'D':
        exporting(sock, request, private, public)  # export file from storage
    else:
        message = b'E\x00illegal user state\x00'  # set message
        sock.sendall(message)  # send
        sock.close()  # close connection
        print("\t-> illegal user state. connection closed.")  # print conversation


def importing(sock, request, private, public):
    """
    this function will import client's file for storage.
    :param sock: TCP socket
    :type sock: socket object
    :param request: client request
    :type request: byte array
    :param private: private key
    :type private: RSA key object
    :param public: public key
    :type public: RSA key object
    :return: None
    """

    size = 0  # file size
    password = ''  # user password
    cookie = ''  # file cookie
    message = b''  # message
    data = b''  # data stream
    create_hash = True

    password = request[1].decode()  # get password
    cookie = cook(GDB[0])  # cook cookie
    directory = fm.create(cookie)  # create storage directory

    dbm.insert(file=GDB[0], path=directory, cookie=cookie)  # insert to database

    message = b'R\x00' + cookie.encode() + b'\x00'  # set message
    message = sc.encrypt_message(message=message, public=public)
    sock.sendall(message)  # send

    print("\t-> importing file data.")  # print conversation

    # load file from client
    while request[1] != b'FIN':
        request = sock.recv(4096)  # receive
        request = sc.decrypt_message(message=request, private=private)
        request = request.split(b'\x00')  # split arguments
        if request[0] == b'F':
            fm.load_encrypted_data(directory=directory, stream=request[1], password=password, create_hash=create_hash)
            create_hash = False
            message = b'R\x00OK\x00'  # set message
            message = sc.encrypt_message(message=message, public=public)
            sock.sendall(message)  # send
        else:
            # print and exit
            print("Server Error: cannot download the file.")
            break
    sock.close()  # close socket


def exporting(sock, request, private, public):
    """
    this will operate the functions which apply to the client's request.
    :param sock: TCP socket
    :type sock: socket object
    :param request: client request
    :type request: byte array
    :param private: private key
    :type private: RSA key object
    :param public: public key
    :type public: RSA key object
    :return: None
    """
    file_path = ''
    directory = ''
    size = 0  # file size
    password = ''  # user password
    cookie = ''  # file cookie
    message = b''  # message
    data = b''  # data stream

    cookie = request[1].decode()  # get cookie

    try:
        directory = dbm.path(GDB[0], cookie)  # get directory path
    except Exception:
        message = b'E\x00Invalid cookie\x00'  # set error message
        message = sc.encrypt_message(message=message, public=public)
        sock.sendall(message)  # send
        sock.close()  # close connection
        print("\t-> server received an invalid cookie.")  # print conversation
        return None

    file_path = str(directory) + "\\" + "F"

    password = request[2].decode()  # get password
    size = os.path.getsize(file_path)  # get file size

    # if file can be decrypted
    if fm.verify(directory, password):
        message = b'S\x00Approved\x00'  # set message
        message = sc.encrypt_message(message=message, public=public)  # encrypt message
        sock.sendall(message)  # send
        print("\t-> client approved - exporting file.")  # print conversation

        # open file
        with open(file_path, "rb") as f:
            for i in range(0, size, 1024):
                data = f.read(1024)
                message = b'F\x00' + base64.b64encode(data) + b'\x00'  # set message and encode data stream in base64
                message = sc.encrypt_message(message=message, public=public)
                sock.sendall(message)  # send
                request = sock.recv(4096)  # receive
                request = sc.decrypt_message(message=request, private=private)  # decrypt message
                request = request.split(b'\x00')  # split arguments
                # in case the file wasn't uploaded successfully
                if b'OK' not in request[1]:
                    # print and exit
                    print("Server Error: cannot upload the file.")
                    break
        message = b'F\x00FIN\x00'  # set end message
        message = sc.encrypt_message(message=message, public=public)
        sock.sendall(message)  # send
        sock.close()  # close socket
        fm.delete_record(GDB[0], cookie)  # delete record
    else:
        message = b'E\x00Invalid password\x00'  # set message
        message = sc.encrypt_message(message=message, public=public)
        sock.sendall(message)  # send
        sock.close()  # close connection
        print("\t-> wrong password. connection was closed.")  # print conversation


def verify(password):
    """
    verification to server operation code (password).
    :param password: password
    :type password: str
    :return: exit code
    :rtype: bool
    """
    password = password.encode()  # encode password
    # if hash file exists
    if dbm.exists(GDB[1]):
        with open(GDB[1], "rb") as h:
            data = h.read()  # read hash
            hash = hashlib.sha384(password).digest()  # create verification hash
        # compare
        if hash == data:
            return True
    else:
        # in case the hash doesn't exists
        with open(GDB[1], "wb") as h:
            # create and save hash
            hash = hashlib.sha384(password).digest()
            h.write(hash)
            print("code was set successfully.")
            return True
    return False


def change_code(new):
    """
    function will change the operation code.
    :param new: new password
    :type new: str
    :return: None
    """
    with open(GDB[1], "wb+") as h:
        new = input("Enter Your new password: ")  # new password
        new = new.encode()
        hash = hashlib.sha384(new).digest()  # create an hash
        h.write(hash)  # write hash to file
        print("code was set successfully.")


if __name__ == '__main__':
    main()
