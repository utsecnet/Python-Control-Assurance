import mysql.connector

class dbConn:

    def __init__(me,host,user,password,db):
        me.host = host
        me.user = user
        me.passwd = password
        me.db = db
        me.insert_id = -1

    def doSel(me,query):
        #me.insert_id = -1
        #me.numrows = -1
        db = mysql.connector.connect(
                host=me.host,
                user=me.user,
                passwd=me.passwd,
                database=me.db
        )
        curs = db.cursor()
        curs.execute(query)
        res = curs.fetchall()
        db.close()
        return res

    def doExec(me,query):
        #me.numrows = -1
        db = mysql.connector.connect(
                host=me.host,
                user=me.user,
                passwd=me.passwd,
                database=me.db
        )
        curs = db.cursor()
        curs.execute(query)
        db.commit()
        me.insert_id = curs.lastrowid