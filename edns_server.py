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

MAX_QUERIES_TIMEOUT = 1000000
MAX_QUERIES = 3

class RateLimiting ():
    def __init__ (self):
        self.host_list = dict ()
        self.forwarder_list = dict()

    """ host_list = {host_ip : [time_stamp, port, proto, query_id,
                                count]} """

    """ forwarder_list = {xor ip: [[time stamp, count, question],
                   [ip, port, proto], [ip, port, proto], ..]} """

    def process_edns_host (self, host_ip, host_port, host_proto):
        return self.lookup_and_add_host (host_ip, [time.time(), host_port,
                                         host_proto])

    def process_edns_forwarder_list (self, forwarder_list):
        return True

    def add_to_host_list (self, host_ip, host_details):
        self.host_list.update ({host_ip : host_details})

    def lookup_host (self, host_ip):
        return self.host_list.get (host_ip)

    def lookup_and_add_host (self, host_ip, host_details):
        """ If entry does not exist """
        if not self.lookup_host (host_ip):
            # Count = 1, New entry
            host_details.append (1)
            self.add_to_host_list (host_ip, host_details)
            return True
        else:
            host_list_entry = self.host_list[host_ip]
            
            if host_list_entry[3] < MAX_QUERIES:
                """ If the number of queries < MAX_QUERIES, update number of queries
                and servie the request """
                host_list_entry[3] += 1
                return True
            else:
                """ If mx queries exceeds and time not expired """
                time_recvd = time.time ()
                if (time_recvd - host_list_entry[0] < MAX_QUERIES_TIMEOUT):
                    return False
                else:
                    """ Reset query count and time """
                    host_list_entry[3] = 1
                    host_list_entry[0] = time.time()
                    return True
        return True

    def add_to_forwarder_list (self, key, value):
        self.forwarder_list.update ({key : value})

    def lookup_forwarder (self, key):
        return self.forwarder_list.get (key)

    def lookup_and_add_forwarder (self, key, value):
        if not self.lookup_forwarder (key):
            self.add_to_forwarder_list (key, value)
            return True
        else:
            forwarder_entry = self.forwarder_list[key]
            if forwarder_entry[0][1] < MAX_QUERIES:
                forwarder_entry[0][1] += 1
                return True
            else:
                if (time.time() - forwarder_entry[0][0] < MAX_QUERIES_TIMEOUT):
                    return False
                else:
                    forwarder_entry[0][0] = time.time()
                    forwarder_entry[0][1] = 1
                    return True
        return True


class EdnsServer (asyncio.DatagramProtocol):
    def __init__(self, loop, zone):
        self.loop = loop
        self.zone = zone
        self.rate_limit = RateLimiting ()

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

        if not self.process_edns (dns_query):
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
        question = dns_query.question[0]

        for options in dns_query.options:
            if (options.otype != EDNS_OPTION_CODE_HOST and
                options.otype != EDNS_OPTION_CODE_FWDR):
                continue

            data_len = len (options.data)
            if (data_len % 8 != 0):
                print ("Wrong formatted ENDS options")
                return

            if (options.otype == EDNS_OPTION_CODE_HOST):
                (host_ip, host_port, host_proto) = struct.unpack ("!LHH", options.data)
                self.rate_limit.process_edns_host (host_ip, host_port, host_proto)
                #if not self.db.lookup_and_add_host (host_ip, [time.time(), host_port,
                #                                    host_proto, dns_query.id]):
                #    return False
            elif (options.otype == EDNS_OPTION_CODE_FWDR):
                forwarder_list = []
                #key = 0
                #num_frwdrs = (int) (len (options.data) / 8)
                for i in range (0, num_frwdrs):
                    (ip, port, proto) = struct.unpack ("!LHH", options.data [8*i:8*(i+1)])
                    #key ^= ip
                    forwarder_list.append([ip, port, proto])
                self.rate_limit.process_edns_forwarder_list (forwarder_list)
                #Add time and tries
                #forwarder_list.insert (0, [time.time (), 1, question])
                #if not self.db.lookup_and_add_forwarder (key, forwarder_list):
                #    return False
        return True


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
