import asyncio
import struct
import socket
import dns.message
import dns.edns
import dns.zone

import time

""" Host details - IP address, Port and Protocol """
EDNS_OPTION_CODE_HOST = 14

""" Tree of forwarder IP address """
EDNS_OPTION_CODE_FWDR = 15

"""
 Max 3 queries in 100 seconds from a host
"""
MAX_QUERIES_TIMEOUT = 100
MAX_QUERIES = 3

class EdnsServer (asyncio.DatagramProtocol):
    def __init__(self, loop, zone):
        self.loop = loop
        self.zone = zone
        """ DB for storing EDNS, nothing to do with the db file. Change naming """
        self.client_edns_db = dict ()
        self.no_service = False

    def connection_made (self, transport):
        print ('Connection Made to Server')
        self.transport = transport
        return

    def datagram_received (self, data, addr):
        print ('Datagram Received Server')
        dns_query = dns.message.from_wire (data)
        self.process_dns_query (dns_query, addr)
        return

    def error_received (self, exec):
        print ('Error Received')
        return

    def connection_lost (self, exec):
        print ('Connection Lost')
        return

    def process_dns_query (self, dns_query, addr):

        self.process_edns (dns_query)

        if (self.no_service == True):
            self.no_service = False
            print ("Deny service!")
            return

        for question in dns_query.question:
            print (question)
            name, rdtype, rdclass = question.name, question.rdtype, question.rdclass
            break

        """ Make response """
        response = dns.message.make_response (dns_query, recursion_available=True)
        rrset = self.zone.get_rrset (name, rdtype)
        print (rrset, name, rdtype)

        response.set_rcode (dns.rcode.NOERROR)
        response.answer.append(rrset)

        """ Copy EDNS back in the response """


        """ Send response """
        self.transport.sendto (response.to_wire (), addr)
        return


    def process_edns (self, dns_query):

        #print ("Query id {0}".format(dns_query.id))

        """ Handle EDNS """
        for options in dns_query.options:
            if (options.otype == EDNS_OPTION_CODE_HOST or
                options.otype == EDNS_OPTION_CODE_FWDR):

                data_len = len (options.data)
                if (data_len % 8 != 0):
                    print ("Wrong formatted ENDS options")
                    return

                if (options.otype == EDNS_OPTION_CODE_HOST):
                    #if (len (options.data) / 8 != 1)
                    #    print ("Wrong formatted ENDS Host")
                    #    return
                    host_ip_string = socket.inet_ntoa (options.data [:4])
                    (host_ip, host_port, host_proto) = struct.unpack ("!LHH", options.data)

                    print ("Host details")
                    print ('IP {0} port {1} proto {2}'.format (host_ip_string,
                                                               host_port, host_proto))
                else:
                    forwarder_list = []
                    num_frwdrs = (int) (len (options.data) / 8)
                    for i in range (0, num_frwdrs):
                        ip_string = socket.inet_ntoa (options.data [8*i:8*i+4])
                        (ip, port, proto) = struct.unpack ("!LHH", options.data [8*i:8*(i+1)])
                        forwarder_list.append([ip, port, proto, ip_string])

                    print ("Forwarder details")
                    for (ip, port, proto, ip_string) in forwarder_list:
                        print ('IP {0} port {1} proto {2}'.format (ip_string, port, proto))

        """ Generate key for client_edns_db """
        """
        key_obj = hashlib.new ('sha256')
        key_obj.update (str (host_ip) + str (dns_query.id))
        key = key_obj.hexdigest()[:32]
        """
        client_db_val = []

        """ If no entry for the host exists """
        if (self.client_edns_db.get (host_ip) == None):
            """ Key = Host IP
                Val =  Number of queries, Time stamp, Host Port, Host Proto,
                       All Forwarder details (IP, Port, Proto)
            """
            client_db_val.append (1)
            client_db_val.append (time.time())
            client_db_val.append (host_port)
            client_db_val.append (host_proto)

            for forwarder_val in forwarder_list:
                for val in forwarder_val:
                    client_db_val.append (val)
            client_db_entry = {host_ip: client_db_val}
            self.client_edns_db.update (client_db_entry)
        else:
            db_entry = self.client_edns_db[host_ip]
            """ If the number of queries < MAX_QUERIES, update number of queries
                and servie the request """
            if (db_entry[0] < MAX_QUERIES):
                db_entry[0] += 1
                client_db_entry = {host_ip: db_entry}
                self.client_edns_db.update (client_db_entry)
            else:
                """ If the time out has not expired, deny service """
                time_recvd = time.time ()
                if (time_recvd - db_entry[1] < MAX_QUERIES_TIMEOUT):
                    self.client_edns_db.pop (host_ip)
                    self.no_service = True
                    return
                else:
                    """ Set time stamp to current value and queries to 1 and service
                        the request
                    """
                    db_entry[0] = 1
                    db_entry[1] = time_recvd
                    client_db_entry = {host_ip: db_entry}
                    self.client_edns_db.update (client_db_entry)
        return


def main ():
    import argparse
    parser = argparse.ArgumentParser ('EDNS Server')
    parser.add_argument ('port', type = int, help = 'Port number to listen on')
    args = parser.parse_args ()

    try:
        zone = dns.zone.from_file('db.mydomain.com', 'mydomain.com', relativize=False)
    except Exception:
        print ("Error reading zone file.")
        return

    loop = asyncio.get_event_loop ()
    loop.create_task (loop.create_datagram_endpoint (
        lambda : EdnsServer (loop, zone),
        local_addr = ('127.0.0.1', args.port)))
    loop.run_forever ()
    transport.close ()
    loop.close ()

if __name__ == '__main__':
    main ();
