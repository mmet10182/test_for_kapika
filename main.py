import nmap
from datetime import datetime


def nmap_scan(ip_range: str = None, port_range: str = '1-65535'):
    if ip_range is None:
        return print('Err: set dst_ip')
    nm = nmap.PortScanner()
    result = nm.scan(ip_range, port_range).get('scan')
    return result


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print(datetime.now())
    dstips = '192.168.10.1-254'
    result = nmap_scan(ip_range=dstips)
    print('hosts: {} \n'.format(result.keys()))
    for k, v in result.items():
        #print('key: {}  value: {}'.format(k, v))
        print('-'*100)
        for k1, v1 in v.items():
            print('key: {}  value: {}'.format(k1, v1))
    print(datetime.now())