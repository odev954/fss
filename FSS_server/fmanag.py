# from filelock import FileLock
import os
import base64
from shutil import rmtree as deldir
from sevmanag import path
from sevmanag import remove
import hashlib

from Crypto.Cipher import AES


def create(cookie):
    """
    create a file storage directory.
    :param cookie: file cookie
    :type cookie: str
    :return:
    """
    name = "F-" + cookie
    os.mkdir("F-" + cookie)  # create
    return name


def insert(directory, stream):
    """
    appends a base64 stream to the file.
    :param directory: directory name
    :type directory: str
    :param stream: base64 encoded stream
    :type stream: bytearray
    :return: none
    """
    f = open(directory + "/F", "ab+")
    try:
        stream = base64.b64decode(stream)
    except Exception:
        stream += b'==='
        stream = base64.b64decode(stream)
    f.write(stream)
    f.close()


def delete_record(db_file, cookie):
    """
    deletes the directory and the record in the database.
    :param db_file: database file path
    :type db_file: str
    :param cookie: cookie
    :type cookie: str
    :return: None
    """
    p = path(db_file, cookie)  # get path
    deldir(p)  # delete
    remove(db_file, cookie)  # remove


def key_procedure(directory,  password, create):
    """
    function will generate the key for the encryption and store it as an hash in a file.
    :param directory: directory path
    :type directory: str
    :param password: password for encryption
    :type password: str
    :param create: hash file creation flag
    :type create: bool
    :return: key
    :rtype: bytes
    """
    # encode and  create key
    password = password.encode()
    password = hashlib.sha256(password).digest()
    # if creation flag is operated
    if create:
        # create hash file
        with open(directory + '\H', "wb") as h:
            hash = hashlib.sha384(password).digest()
            h.write(hash)
    return password


def verify(directory, password):
    """
    function will verify the given password.
    :param directory: directory path
    :type directory: str
    :param password: password for encryption
    :type password: str
    :return: verification result
    :rtype: bool
    """
    password = key_procedure(directory,  password, False)  # get key
    with open(directory + '\H', "rb") as h:
        hash = hashlib.sha384(password).digest()  # create hash
        data = h.read()  # read hash
    # compare
    if data == hash:
        return True
    return False


def load_encrypted_data(directory, stream, password, create_hash):
    """
    function will load an encrypted data stream to a file.
    :param directory: saved directory
    :type directory: str
    :param stream: file data stream
    :type stream: bytes
    :param password: encryption key
    :type password: str
    :param create_hash: hash creation flag
    :type create_hash: bool
    :return: None
    """
    p = 1  # padding counter
    length = 0  # stream length

    password = key_procedure(directory,  password, create_hash)  # get key and write
    vector = hashlib.md5(password).digest()  # create vector in a size of 128-bit (16-bytes) for AES encryption calculations
    enc = AES.new(password, AES.MODE_CBC, vector)  # create encryption module

    # decode BASE-64 format
    try:
        stream = base64.b64decode(stream)
    except Exception:
        stream += b'==='
        stream = base64.b64decode(stream)

    if len(stream) % 16 != 0:
        # add padding
        length = 16 - (len(stream) % 16)
        while p < length + 1:
            stream += (chr(p)).encode()
            p += 1
    stream = enc.encrypt(stream)  # encrypt stream

    with open(directory + "/F", "ab+") as f:
        f.write(stream)  # write encrypted stream to file
