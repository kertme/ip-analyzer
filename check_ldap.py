from ldap3 import Server, Connection

def test(ip):
    s = Server(ip, connect_timeout=1)
    conn = None
    try:
        conn = Connection(s, auto_bind=True, receive_timeout=1)
    except:
        pass
    finally:
        return conn
