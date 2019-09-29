from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
import hashlib
import ast

FK = (".pk",)


def gen_key(password):
    """
    generates private RSA key.
    :param password: password
    :type password: str
    :return: None
    """
    private = RSA.generate(2048)  # generate
    private = private.exportKey('PEM')  # export
    password = hashlib.sha256(password.encode()).digest()  # get pass phrase
    vector = hashlib.md5(password).digest()  # create vector
    enc = AES.new(password, AES.MODE_CBC, vector)  # create encryption module
    if len(private) % 16 != 0:
        # add padding
        length = 16 - (len(private) % 16)
        private += bytes([length])*length
    with open(FK[0], "wb") as f:
        f.write(enc.encrypt(private))  # write the encrypted key to the file


def read_key(password):
    """
    reads private RSA key from file.
    :param password: password
    :type password: str
    :return: key pear (public, private)
    :rtype: RSA key objects
    """
    password = hashlib.sha256(password.encode()).digest()  # get key and write
    vector = hashlib.md5(password).digest()  # create vector
    dec = AES.new(password, AES.MODE_CBC, vector)  # create decryption module
    # read
    with open(FK[0], "rb") as f:
        private = f.read()
        private = dec.decrypt(private)  # decrypt
        private = private[:-private[-1]]  # remove padding

    private = RSA.import_key(private)  # import private key
    public = private.publickey()  # set public key
    return private, public


def encrypt_message(message, public):
    """
    encrypts a message with public key.
    :param message: message to encrypt
    :type message: bytes
    :param public: public key
    :type public: RSA key object
    :return: encrypted message
    :rtype: bytes
    """
    stream = []  # message stream
    i = 0  # byte counter
    while i < len(message):
        i += 214  # increase by max length
        stream.append(message[i - 214:i:1])  # add to segment stream
    stream.append(message[i:-1:1])  # add last segment
    enc = PKCS1_OAEP.new(public)  # set encryption model
    for i in range(len(stream)):
        stream[i] = enc.encrypt(stream[i])  # encrypt stream
    return b''.join(stream)


def decrypt_message(message, private):
    """
    decrypts a message with public key.
    :param message: message to decrypt
    :type message: bytes
    :param private: private key
    :type private: RSA key object
    :return: decrypted message
    :rtype: bytes
    """
    stream = []  # message stream
    i = 0  # byte counter
    while i < len(message):
        i += 256  # increase by max length
        stream.append(message[i - 256:i:1])  # add to segment stream
    dec = PKCS1_OAEP.new(private)  # set decryption model
    for i in range(len(stream)):
        stream[i] = dec.decrypt(ast.literal_eval(str(stream[i])))  # decrypt stream
    return b''.join(stream)
