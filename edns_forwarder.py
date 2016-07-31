import asyncio
import struct
import socket
import dns.message
import dns.edns

import hashlib

"""
EDNS_OPTION_CODE_FWDR Format

|0 1 2 3 4 5 6 7 | 0 1 2 3 4 5 6 7 | 0 1 2 3 4 5 6 7 | 0 1 2 3 4 5 6 7 |
|                            IPv4 Address                              |
|__________________________________|___________________________________|
|           Port Number            |              Protocol             |
|__________________________________|___________________________________|

"""

""" Host details - IP address, Port and Protocol """
EDNS_OPTION_CODE_HOST = 14

""" Tree of forwarder IP address """
EDNS_OPTION_CODE_FWDR = 15

""" Query ID """
EDNS_OPTION_CODE_QUERY_ID = 16

""" Host MAC """
EDNS_OPTION_CODE_HOST_MAC = 17

class Edns (dns.edns.Option):
    def __init__ (self, ip = "", local_ip = 0, port = 0, proto = 0, option = 0, data = b'',
                  query_id = 0, mac = 0):
        super (Edns, self).__init__(option)
        if len (ip):
            self.ip = socket.inet_aton (ip)
        #because its hardcoded below, for now.
        self.local_ip = socket.inet_pton (socket.AF_INET, '127.0.0.1')
        self.port = port
        self.proto = proto
        self.data = data
        self.option = option
        self.query_id = query_id
        self.host_mac = mac

    def _get_hash (self, option):
        hash_string = ''
        if option == EDNS_OPTION_CODE_HOST_MAC:
            hash_len = 6
            for i in range (0, 6):
                hash_string += str (self.host_mac[i])
        elif option == EDNS_OPTION_CODE_HOST:
            ip = self.ip + self.local_ip
            hash_len = 4
            for i in range (0, len(ip)):
                hash_string += str (ip[i])
        return hashlib.sha256 (hash_string.encode('utf-8')).hexdigest()[:hash_len]

    def to_wire (self, file):
        if (self.option == EDNS_OPTION_CODE_HOST):
            self.data += struct.pack ("!s", (self._get_hash (EDNS_OPTION_CODE_HOST)).encode('utf-8'))
            self.data += struct.pack ("!HH", self.port, self.proto)
            print ("Port {0} proto {1}".format (self.port, self.proto))
        elif (self.option == EDNS_OPTION_CODE_FWDR):
            self.data += self.ip
            self.data += struct.pack ("!HH", self.port, self.proto)
        elif (self.option == EDNS_OPTION_CODE_QUERY_ID):
            self.data += struct.pack ("!L", self.query_id)
            print ("Query id {0}".format (self.query_id))
        elif (self.option == EDNS_OPTION_CODE_HOST_MAC):
            self.data += struct.pack ("!s", (self._get_hash (EDNS_OPTION_CODE_HOST_MAC)).encode('utf-8'))

        file.write (self.data)

    def from_wire (cls, otype, wire, current, olen):
        return

class EdnsForwarderServer (asyncio.DatagramProtocol):
    def __init__ (self, loop, remote_ip_string, remote_port):
        self.loop = loop
        self.remote_ip_string = remote_ip_string
        self.remote_port = remote_port

    def connection_made (self, transport):
        print ('Connection Made')
        self.transport = transport
        return

    def datagram_received (self, data, addr):
        print ('Datagram Received from Client {0}'.format (addr))
        self.c_addr = addr
        found_host_edns = False
        found_frwdr_ends = False
        found_query_ends = False
        found_host_mac_edns = False

        """ Read the DNS message received """
        dns_message = dns.message.from_wire (data)

        edns_options = []

        """ Get Forwarder ENDS if present in the query """
        for options in dns_message.options:
            if (options.otype == EDNS_OPTION_CODE_HOST):
                found_host_edns = True
                edns_options.append (options)
            elif (options.otype == EDNS_OPTION_CODE_FWDR):
                if (len (options.data) % 8 != 0):
                    print ("Wrong formatted ENDS Forwarder")
                    return
                found_frwdr_ends = True
                edns_obj = Edns (ip=addr[0], port=addr[1], option=EDNS_OPTION_CODE_FWDR,
                                 data=options.data)
                edns_options.append (edns_obj)
            elif (options.otype == EDNS_OPTION_CODE_QUERY_ID):
                found_query_ends = True
                edns_options.append (options)
            elif (options.otype == EDNS_OPTION_CODE_HOST_MAC):
                found_host_mac_edns = True
                edns_options.append (options)

        """ Add Host ENDS """
        if (found_host_edns == False):
            print ("Adding host edns. Port {0}".format (addr[1]))
            edns_obj = Edns (ip=addr[0], port=int(addr[1]), option=EDNS_OPTION_CODE_HOST)
            edns_options.insert (0, edns_obj)

            if (found_query_ends == False):
                edns_obj = Edns (option=EDNS_OPTION_CODE_QUERY_ID, query_id=dns_message.id)
                edns_options.append (edns_obj)

            #if (found_host_mac_edns == False):
            #    edns_obj = Edns (option=EDNS_OPTION_CODE_HOST_MAC, mac= )
            #    edns_options.append (edns_obj)

        elif (found_frwdr_ends == False):
            edns_obj = Edns (ip=addr[0], port=addr[1], option=EDNS_OPTION_CODE_FWDR)
            edns_options.append (edns_obj)

        dns_message.use_edns (options=edns_options)

        """ Forward to next server """
        self.loop.create_task (self.loop.create_datagram_endpoint (
            lambda: EdnsForwarderClient (self.callback, dns_message),
            remote_addr = (self.remote_ip_string, self.remote_port))
        )
        return

    def error_received (self, exec):
        print ('Error Received')
        return

    def connection_lost (self, exec):
        print ('Connection Lost')
        return

    def callback (self, data):
        self.transport.sendto (data.to_wire (), self.c_addr)
        return


class EdnsForwarderClient (asyncio.DatagramProtocol):
    def __init__(self, callback, data):
        self.data = data
        self.callback = callback

    def connection_made (self, transport):
        print ('Connection Made to Server')
        transport.sendto (self.data.to_wire())
        return

    def datagram_received (self, data, addr):
        print ('Datagram Received from Server')
        response = dns.message.from_wire (data)
        for rr in response.answer:
            print ('{0}\n'.format(rr.to_text()))
        self.callback (response)
        return

    def error_received (self, exec):
        print ('Error Received')
        return

    def connection_lost (self, exec):
        print ('Connection Lost')
        return

def main ():
    import argparse
    parser = argparse.ArgumentParser ('EDNSForwarder')
    parser.add_argument ('port', type = int, help = 'Port number to listen on')
    parser.add_argument ('remote_ip', type = str, help = 'DNS Server or next hop forwarder IP')
    parser.add_argument ('remote_port', type = int, help = 'DNS Server or next hop forwarder port')
    args = parser.parse_args ()

    loop = asyncio.get_event_loop ()
    loop.create_task (loop.create_datagram_endpoint (
        lambda : EdnsForwarderServer (loop, args.remote_ip, args.remote_port),
        local_addr = ('127.0.0.1', args.port)))
    loop.run_forever ()
    #transport.close ()
    loop.close ()

if __name__ == '__main__':
    main ();
