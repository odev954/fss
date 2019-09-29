import os
import sqlite3 as sql
import datetime


def create(file):
    """
    creates a new FSS local database with a cookie table.
    :param file: database file path
    :type file: str
    :return: None
    """
    con = None
    cursor = None
    create_table = """  
    CREATE TABLE IF NOT EXISTS cookies(
    cookie text NOT NULL UNIQUE,
    name text NOT NULL,
    size text NOT NULL,
    date text NOT NULL
    );
    """  # command
    try:
        # open connection
        con = sql.connect(file)
        cursor = con.cursor()
        cursor.execute(create_table)  # execute SQL command
    except sql.Error:
        raise Exception("SqlConnectionError")  # raise exception
    finally:
        # close connection
        cursor.close()
        con.close()


def exists(file):
    """
    checks if the database file exists.
    :param file: database file path
    :type file: str
    :return: check result
    :rtype: bool
    """
    return os.path.isfile(file)


def insert(file, path, f_size, cookie):
    """
    inserts new line to the table.
    :param file: database file path
    :type file: str
    :param path: the saved file path
    :type path: str
    :param cookie: server's cookie
    :type cookie: str
    :param f_size: original file size
    :type: int
    :return: None
    """
    # open connection
    con = sql.connect(file)
    cursor = con.cursor()

    ins = "INSERT INTO cookies(cookie, name, size, date) " \
          "VALUES(?, ?, ?, ?);"  # command
    cursor.execute(ins, (cookie, path, f_size, str(datetime.datetime.now())[:16:]))  # execute SQL command
    con.commit()  # updating database
    # close connection
    cursor.close()
    con.close()


def remove(file, cookie):
    """
    deletes a line from the table.
    :param file: database file path
    :type file: str
    :param cookie: server's cookie
    :type cookie: str
    :return: None
    """
    # open connection
    con = sql.connect(file)
    cursor = con.cursor()

    dlt = "DELETE FROM cookies WHERE cookie=?;"  # command
    cursor.execute(dlt, (cookie,))  # execute SQL command
    con.commit()  # updating database
    # close connection
    cursor.close()
    con.close()


def search(file, name):
    """
    searching for a file in the database.
    :param file: database file path
    :type file: str
    :param name: requested file name
    :type name: str
    :return: results
    :rtype: list
    """
    # open connection
    con = sql.connect(file)
    cursor = con.cursor()

    que = "SELECT name,date FROM cookies WHERE name=?;"  # command
    cursor.execute(que, (name,))  # execute SQL command

    res = cursor.fetchall()  # extracting data
    # close connection
    cursor.close()
    con.close()
    return res


def list_files(file):
    """
    listing all the saved files.
    :param file: database file path
    :type file: str
    :return: all the saved file names and dates
    :rtype: list
    """
    # open connection
    con = sql.connect(file)
    cursor = con.cursor()

    lst = "SELECT name,date FROM cookies ORDER BY date;"  # command
    cursor.execute(lst)  # execute SQL command

    rows = cursor.fetchall()  # extracting data
    # close connection
    cursor.close()
    con.close()
    return rows


def clean(file):
    """
    deletes all from database.
    :param file: database file path
    :type file: str
    :return: None
    """
    # open connection
    con = sql.connect(file)
    cursor = con.cursor()

    dlt = "DELETE FROM cookies;"  # command
    cursor.execute(dlt)  # execute SQL command
    con.commit()  # updating database
    # close connection
    cursor.close()
    con.close()


def get_cookie(file, name):
    """
    searching for a file in the database and returning the cookie.
    :param file: database file path
    :type file: str
    :param name: requested file name
    :type name: str
    :return: cookie
    :rtype: str
    """
    # open connection
    con = sql.connect(file)
    cursor = con.cursor()

    que = "SELECT cookie FROM cookies WHERE name=?;"  # command
    cursor.execute(que, (name,))  # execute SQL command

    res = cursor.fetchall()  # extracting data
    # close connection
    cursor.close()
    con.close()
    return res[0][0]


def get_size(file, name):
    # open connection
    con = sql.connect(file)
    cursor = con.cursor()

    que = "SELECT size FROM cookies WHERE name=?;"  # command
    cursor.execute(que, (name,))  # execute SQL command

    res = cursor.fetchall()  # extracting data
    # close connection
    cursor.close()
    con.close()
    return res[0][0]


def password_gen():
    """
    password generating function.
    :return: password
    :rtype: str
    """
    stream = os.urandom(32)  # get random byte stream
    password = []
    for byte in stream:
        password.append(chr(int(byte) % 94 + 32))  # insert
    return ''.join(password)



