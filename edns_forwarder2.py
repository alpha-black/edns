import asyncio
import struct
import socket
import dns.message
import dns.edns

class Edns (dns.edns.Option):
    def __init__ (self, ip = 0, option = 0):
        super(Edns, self).__init__(option)
        """ Currently only IPv4 """
        self.ip = ip

    def to_wire (self, file):
        print ('EDNS to wire')
        data = socket.inet_pton (socket.AF_INET, self.ip)
        file.write (data)

    def from_wire (cls, otype, wire, current, olen):
        return

class EdnsForwarderServer (asyncio.DatagramProtocol):
    def __init__ (self, loop, option = 0):
        self.loop = loop
        self.option = option

    def connection_made (self, transport):
        print ('Connection Made')
        self.transport = transport
        return

    def datagram_received (self, data, addr):
        print ('Datagram Received from Client {0}'.format (addr))
        self.host_addr = addr

        """ New EDNS options field from the incoming address """
        dns_message = dns.message.from_wire (data)
        edns_obj = Edns (addr[0], self.option)

        """ Get ENDS present in the query """
        edns_options = []
        edns_options.append (edns_obj)
        for obj in dns_message.options:
            edns_options.append (obj)

        dns_message.use_edns (options=edns_options)

        """ Forward to public server """
        self.loop.create_task (self.loop.create_datagram_endpoint (
            lambda: EdnsForwarderClient (self.callback, dns_message),
            #remote_addr = ('8.8.8.8', 53))
            remote_addr = ('130.233.224.141', 53))
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
            #string = 'Answer = ' + response.name.to_text()
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
    option = 0

    loop = asyncio.get_event_loop ()
    loop.create_task (loop.create_datagram_endpoint (
        lambda : EdnsForwarderServer (loop, option),
        local_addr = ('127.0.0.1', 5354)))
    loop.run_forever ()
    transport.close ()
    loop.close ()

if __name__ == '__main__':
    main ();
