import socket


def test(ip, port):
    a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    a_socket.settimeout(1)
    location = (ip, int(port))
    result_of_check = 1
    try:
        result_of_check = a_socket.connect_ex(location)
    except Exception as e:
        #print(file=sys.stderr)
        #result_of_check = 1
        pass
    finally:
        return result_of_check

