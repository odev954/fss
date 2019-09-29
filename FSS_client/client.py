from Crypto.PublicKey import RSA
import os
import sockCrypto as sc
import clmanag as dbm
import socket
import base64
import hashlib
import traceback
from Crypto.Cipher import AES

LDB = (r"fssLocal.db", r".vh")

SERVER_IP = "127.0.0.1"
SERVER_PORT = 954


def main():
    password = input("Enter Your Password: ")  # request password from user
    # if password was verified
    if verify(password):
        # check if database exists
        if not dbm.exists(LDB[0]):
            try:
                dbm.create(LDB[0])  # create new
            except Exception:
                print("Client Error: SQL Server cannot create a new database")
                return 0
        if not dbm.exists(sc.FK[0]):
            sc.gen_key(password)
        try:
            client(password)  # run client
        except Exception:
            print("Client Error: Failed to proceed with the selected operation. \nError Details:\n", traceback.format_exc())
    else:
        print("Client Error: Wrong Password")
    return 0


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
    private, public = sc.read_key(password)
    public = public.exportKey('PEM')
    sock.sendall(public)
    public = sock.recv(4096)
    return private, RSA.import_key(public)


def load_decrypt_data(name, stream, password, padding_limit):
    """
    function will load decrypted data stream to a file.
    :param name: file name
    :type name: str
    :param stream: file data stream
    :type stream: bytes
    :param password: decryption password
    :type password: str
    :param padding_limit: original file size (used to remove padding)
    :type padding_limit: int
    :return: updated padding limit
    :rtype: int
    """
    p = 1
    stream = b''
    password = hashlib.sha256(password.encode()).digest()
    vector = hashlib.md5(password).digest()  # create vector in a size of 128-bit (16-bytes) for AES encryption calculations
    dec = AES.new(password, AES.MODE_CBC, vector)  # create decryption module
    try:
        stream = base64.b64decode(stream)
    except Exception:
        stream += b'==='  # add base64 padding
        stream = base64.b64decode(stream)
    if len(stream) % 16 != 0:
        # add padding
        length = 16 - (len(stream) % 16)
        while p < length + 1:
            stream += (chr(p)).encode()  # add padding
            p += 1  # padding count
    stream = dec.decrypt(stream)  # decrypt stream
    if p != 1:
        stream = stream[:-p]
    padding_limit = padding_limit - len(stream)  # update padding limit
    if len(stream.split()) > padding_limit:
        stream = stream[:padding_limit]  # remove padding
    with open(name, "ab+") as f:
        f.write(stream)  # write encrypted stream to file
    return padding_limit


def download(password):
    """
    downloads a requested file from server.
    :return: None
    """
    size = 0  # file size
    f_list = dbm.list_files(LDB[0])
    if len(f_list) != 0:
        # print file list
        print("\nFile List:\n|\tName\t\tDate")
        for stored in f_list:
            print("|\t" + stored[0] + "\t" + stored[1])
        name = input("\nPlease choose one of the files above: ")  # user choice
        new_path = input("Please enter the location where you want the file to be saved: ")  # get location
        while True:
            try:
                cookie = dbm.get_cookie(LDB[0], name)   # get cookie and password from database
                break
            except Exception:
                name = input("Client Error: Record not found. please try again: ")  # if file not found
        # set request and connect
        message = b'D\x00' + cookie.encode() + b'\x00' + password.encode() + b'\x00'
        sock, private, public = connect(password)
        # if connected
        if sock:
            # send and receive
            message = sc.encrypt_message(message=message, public=public)  # encrypt message
            sock.sendall(message)
            response = sock.recv(4096)
            response = sc.decrypt_message(message=response, private=private)  # decrypt message
            response = response.split(b'\x00')
            # if request was approved
            if response[0] in b'S' and response[1] in b'Approved':
                # size = int(response[2].decode())  # save size
                padding_limit = int(dbm.get_size(LDB[0], name))
                # run for the size of the file
                while response[1] != b'FIN':
                    response = sock.recv(4096)  # receive
                    response = sc.decrypt_message(message=response, private=private)
                    response = response.split(b'\x00')  # split arguments
                    # if we got file data
                    if response[0] == b'F':
                        # load(new_path + '/' + name, response[1])  # insert stream to file
                        padding_limit = load_decrypt_data(name=(new_path + '/' + name), stream=response[1], password=password, padding_limit=padding_limit)
                        # padding_limit = padding_limit - len(response[1])
                        message = b'D\x00OK'  # set message
                        message = sc.encrypt_message(message=message, public=public)
                        sock.sendall(message)  # send
                    else:
                        break
                dbm.remove(LDB[0], cookie)  # remove from record
                print("File was downloaded successfully.")
            elif response[0] == b'E':  # if response is an error message
                print("Server Error: " + response[1].decode())
            else:
                print("Server Error: invalid server response. Server message:\n", response)  # in case there is un-recognized response code
            sock.close()  # close socket
    else:
        print("Information: file list is empty. there are no files stored in the server.")  # in case the file list is empty


def upload(password):
    """
    uploads a requested file from server.
    :return: None
    """
    data = b''  # data stream
    size = 0  # file size
    path = input("enter the file path you wish to upload: ")  # enter path
    size = 0
    while True:
        # if the file exists
        if dbm.exists(path):
            # open file
            size = os.path.getsize(path)  # get file size
            with open(path, "rb") as f:
                sock, private, public = connect(password)  # connect
                # if connected
                if sock:
                    # password = dbm.password_gen()  # generate password
                    message = b'U\x00' + password.encode() + b'\x00'  # set request
                    message = sc.encrypt_message(message=message, public=public)  # encrypt message
                    # send and receive
                    sock.sendall(message)
                    response = sock.recv(4096)
                    response = sc.decrypt_message(message=response, private=private)  # decrypt message
                    response = response.split(b'\x00')  # split arguments
                    # if response is valid
                    if response[0] is b'R':
                        cookie = response[1].decode()  # get cookie
                        # upload file
                        for i in range(0, size, 1024):
                            data = f.read(1024)  # read file stream
                            message = b'F\x00' + base64.b64encode(data) + b'\x00'  # set request and encode file stream to base64
                            message = sc.encrypt_message(message=message, public=public)
                            # send and receive
                            sock.sendall(message)
                            response = sock.recv(4096)
                            response = sc.decrypt_message(message=response, private=private)
                            response = response.split(b'\x00')  # split arguments
                            # if message wasn't approved by server
                            if b'OK' not in response[1]:
                                print("Server Error: cannot upload the file.")
                                break
                        message = b'F\x00FIN\x00'  # set end message
                        message = sc.encrypt_message(message=message, public=public)
                        sock.sendall(message)  # send
                        sock.close()  # close connection
                        dbm.insert(file=LDB[0], path=path, cookie=cookie, f_size=size)  # insert record
                        print("File was uploaded successfully.")
                    elif response[0] == b'E':  # if response is an error message
                        print("Server Error: " + response[1].decode())
                    else:
                        print("Server Error: invalid server response. Server message:\n", response)  # in case there is un-recognized response code
            break
        else:
            path = input("file does not exists!\nenter the file path again: ")  # new path


def connect(password):
    """
    establishing connection with the server.
    :return: socket and a key pear (public, private) if connected successfully (None if not)
    :rtype: socket object, RSA key objects
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP socket
    server_id = (SERVER_IP, SERVER_PORT)  # server id
    try:
        sock.connect(server_id)  # connect
        private, public = exchange(sock, password)  # exchange keys
        return sock, private, public
    except Exception:
        print("Client Error: Server Connection Was Failed.")
        return None, None, None


def client(password):
    """
    operating the client.
    :return: None
    """
    while True:
        op = input("please choose:\n[1] download\n[2] upload\n[3] change password\n[4] exit\nyour choice: ")  # choose operation
        if '1' in op:
            download(password)  # download file
        elif '2' in op:
            upload(password)  # upload file
        elif '3' in op:
            change_pass()  # change password
        elif '4' in op:
            break  # exit
        else:
            print("Client Error: This Operation Does Not Exist")  # default case


def change_pass():
    """
    change password operation
    :return: exit code
    :rtype: None
    """
    # check if there are file stored on the server
    if len(dbm.list_files(LDB[0])) == 0:
        with open(LDB[1], "wb+") as h:
            new = input("Enter Your new password: ")  # new password
            new = new.encode()
            hash = hashlib.sha384(new).digest()  # create an hash
            h.write(hash)  # write hash to file
            print("password was set successfully")
    else:
        print("Information: files are still stored on the server. please download them first in order to continue.")


def verify(password):
    """
    function verify client's password.
    :param password: password
    :return: exit code
    :rtype: bool
    """
    password = password.encode()  # encode password
    # if hash file exists
    if dbm.exists(LDB[1]):
        with open(LDB[1], "rb") as h:
            data = h.read()  # read hash
            hash = hashlib.sha384(password).digest()  # create verification hash
        # compare
        if hash == data:
            return True
    else:
        # in case the hash doesn't exists
        with open(LDB[1], "wb") as h:
            password = input("Please enter a password to set: ")  # enter a new password
            # create and save hash
            password = password.encode()
            hash = hashlib.sha384(password).digest()
            h.write(hash)
            print("password was set successfully")
            return True
    return False


if __name__ == '__main__':
    main()
