import nmap
from datetime import datetime
import time


class KapikaScan:

    def __init__(self, dst_ip=None, port_range='1-65535', timeout='300'):
        self.dst_ip = dst_ip
        self.port_range = port_range
        self.timeout = timeout
        self.result_scan = None
        self.elapsed_time = None

    def scan(self):
        if self.dst_ip is None:
            return 'Err: set dst_ip'
        nm = nmap.PortScanner()
        args = '--host-timeout ' + str(self.timeout)
        start_time = time.time()
        self.result_scan = nm.scan(self.dst_ip, self.port_range, arguments=args).get('scan')
        end_time = time.time()
        self.elapsed_time = end_time - start_time

        return self.result_scan


class KapikaNetDevie:

    def __init__(self):
        self.detection_time = None
        self._scan_total_time = None
        self._result_scan = None
        self.udp_ports = self._udp_ports()
        self.tcp_ports = self._tcp_ports()
        self.vendor = self._vendor()
        self.mac_addr = self._mac_addr()
        self.ip_addr = self._ip_addr()
        self.elapsed_time = self._elapsed_time()

    def _elapsed_time(self):
        """if self._scan_total_time >= 300:
            return 'scanning takes more than five minutes'"""
        return self._scan_total_time

    def _ip_addr(self):
        pass

    def _mac_addr(self):
        pass

    def _vendor(self):
        pass

    def _tcp_ports(self):
        pass

    def _udp_ports(self):
        pass


if __name__ == '__main__':
    s = KapikaNetDevie()
    s.dst_ip = '192.168.10.253'
    s.scan()
    print(s.elapsed_time, s.result_scan)
    """scan = KapikaScan()
    scan.dst_ip = '192.168.10.253'
    scan.scan()
    print(scan.result_scan, scan.elapsed_time)"""

    """
    dstip = '192.168.10.'
    print('Start time: ', datetime.now(), '\n')
    for i in range(1, 254):
        start_time = time.time()
        dstip = dstip + str(i)
        result = nmap_scan(dst_ip=dstip)
        if result:
            print('Start: {}{}{}{}'.format(dstip, '-' * 10, datetime.now(), '-' * 10))
            for k, v in result.items():
                for k1, v1 in v.items():
                    print('key: {}  value: {}'.format(k1, v1))
            print('End: {}{}{}{}'.format(dstip, '-' * 10, datetime.now(), '-' * 10))
            end_time = time.time()
            total_time = end_time - start_time
            print('Total time: {} \n'.format(total_time))
            if total_time >= 300:
                print('Scaning more five minutes \n')
        dstip = '192.168.10.'
    print('End time: ', datetime.now())
    """
