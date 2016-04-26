import asyncio
import struct
import socket
import dns.message
import dns.edns

""" Host details - IP address, Port and Protocol """
EDNS_OPTION_CODE_HOST = 14

""" Tree of forwarder IP address """
EDNS_OPTION_CODE_FWDR = 15

class Edns (dns.edns.Option):
    def __init__ (self,ip, port = 0, option = 0, data = b''):
        super (Edns, self).__init__(option)
        self.ip = socket.inet_aton (ip)
        self.port = port
        self.data = data

    def to_wire (self, file):
        self.data += self.ip
        if (self.port != 0):
            self.data += struct.pack ("!H", self.port)
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
        self.host_addr = addr
        found_host_edns = False
        found_frwdr_ends = False

        """ Read the DNS message received """
        dns_message = dns.message.from_wire (data)

        edns_options = []

        """ Get Forwarder ENDS if present in the query """
        for options in dns_message.options:
            if (options.otype == EDNS_OPTION_CODE_HOST):
                found_host_edns = True
                edns_options.append (options)
            elif (options.otype == EDNS_OPTION_CODE_FWDR):
                found_frwdr_ends = True
                edns_obj = Edns (addr[0], addr[1], EDNS_OPTION_CODE_FWDR,
                                 options.data)
                edns_options.append (edns_obj)

        """ Add Host ENDS """
        if (found_host_edns == False):
            edns_obj = Edns (addr[0], addr[1], EDNS_OPTION_CODE_HOST)
            edns_options.insert (0, edns_obj)
        elif (found_frwdr_ends == False):
            edns_obj = Edns (addr[0], addr[1], EDNS_OPTION_CODE_FWDR)
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
        self.transport.sendto (data.to_wire (), self.host_addr)
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
    transport.close ()
    loop.close ()

if __name__ == '__main__':
    main ();
