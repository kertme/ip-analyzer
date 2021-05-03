import ntplib
import sys
c = ntplib.NTPClient()


def test(ip):
    ntp_resp = None
    try:
        ntp_resp = c.request(ip)
    except Exception as e:
        pass
        #print(f'ntp exception:{e}', file=sys.stderr)
    finally:
        return ntp_resp

