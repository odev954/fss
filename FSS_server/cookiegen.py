from sevmanag import path as search
import os


def gen():
    """
    generates a cookie in the size of 48 bytes.
    :return: cookie
    :rtype: str
    """
    stream = os.urandom(16)  # get random stream of bytes
    cookie = []  # cookie stream
    for byte in stream:
        # convert to integers and insert to the cookie stream
        if int(byte) < 10:
            cookie.append('00' + str(int(byte)))
        elif int(byte) < 100:
            cookie.append('0' + str(int(byte)))
        else:
            cookie.append(str(int(byte)))
    return ''.join(cookie)  # join to a string


def check(file, cookie):
    """
    checks if a cookie exists in the database.
    :param cookie: given cookie
    :type cookie: str
    :param file: database file path
    :type file: str
    :return: statement
    :rtype: bool
    """
    return search(file, cookie)


def get_unique_cookie(file):
    """
    generates a unique cookie.
    :param file: database file path
    :type file: str
    :return: unique cookie
    :rtype: str
    """
    cookie = gen()  # generate
    while not check(file, cookie):
        cookie = gen()  # generate again if used already
    return cookie
