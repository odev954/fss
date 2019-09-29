import os
import sqlite3 as sql
import datetime


def create(file):
    """
    creates a new FSS local database with a stored file table.
    :param file: database file path
    :type file: str
    :return: None
    """
    con = None
    cursor = None
    create_table = """  
    CREATE TABLE IF NOT EXISTS stored(
    cookie text NOT NULL UNIQUE,
    path text NOT NULL UNIQUE,
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


def insert(file, path, cookie):
    """
    inserts new line to the table.
    :param file: database file path
    :type file: str
    :param path: the stored file path
    :type path: str
    :param cookie: server's cookie
    :type cookie: str
    :return: None
    """
    # open connection
    con = sql.connect(file)
    cursor = con.cursor()

    ins = "INSERT INTO stored(cookie, path, date) " \
          "VALUES(?, ?, ?);"  # command
    cursor.execute(ins, (cookie, path, datetime.date.today()))  # execute SQL command
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

    dlt = "DELETE FROM stored WHERE cookie=?;"  # command
    cursor.execute(dlt, (cookie,))  # execute SQL command
    con.commit()  # updating database
    # close connection
    cursor.close()
    con.close()


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

    dlt = "DELETE FROM stored;"  # command
    cursor.execute(dlt)  # execute SQL command
    con.commit()  # updating database
    # close connection
    cursor.close()
    con.close()


def path(file, cookie):
    """
    searching for a file in the database and returning the cookie.
    :param file: database file path
    :type file: str
    :param cookie: requested file name
    :type cookie: str
    :return: cookie (or true statement if result is empty)
    :rtype: str (or bool statement if result is empty)
    """
    # open connection
    con = sql.connect(file)
    cursor = con.cursor()

    que = "SELECT path FROM stored WHERE cookie=?;"  # command
    cursor.execute(que, (cookie,))  # execute SQL command

    res = cursor.fetchall()  # extracting data
    # close connection
    cursor.close()
    con.close()
    if len(res) == 0:
        return True
    return res[0][0]

