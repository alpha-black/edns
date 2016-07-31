import asyncio
import struct
import socket
import dns.message
import dns.edns
import dns.zone

import time
import hashlib
import collections

""" Host details - IP address, Port and Protocol """
EDNS_OPTION_CODE_HOST = 14
""" Tree of forwarder IP address """
EDNS_OPTION_CODE_FWDR = 15
ENDS_OPTION_CODE_QUERY_ID = 16
ENDS_OPTION_CODE_HOST_MAC = 17

MAX_QUERIES_TIMEOUT = 1000000
MAX_QUERIES = 3

HOST_IP_LIST = 0
FORWARDER_LIST = 1
HOST_MAC_LIST = 2
HOST_FRWDR_LIST = 3

class RateLimiting ():
    def __init__ (self):
        self.host_ip_list = dict ()
        self.forwarder_list = dict()
        self.host_mac_list = dict()
        self.host_frwdr_list = dict()

    def _add_to_dict (self, list_id, key, value):
        if (list_id == HOST_IP_LIST):
            self.host_ip_list.update ({key : value})
        elif (list_id == FORWARDER_LIST):
            self.forwarder_list.update ({key : value})
        elif (list_id == HOST_MAC_LIST):
            self.host_mac_list.update ({key : value})
        elif (list_id == HOST_FRWDR_LIST):
            self.host_frwdr_list.update ({key : value})

    def _lookup_dict (self, list_id, key):
        if (list_id == HOST_IP_LIST):
            return self.host_ip_list.get (key)
        elif (list_id == FORWARDER_LIST):
            return self.forwarder_list.get (key)
        elif (list_id == HOST_MAC_LIST):
            return self.host_mac_list.get (key)
        elif (list_id == HOST_FRWDR_LIST):
            return self.host_frwdr_list.get (key)

    def _cmp_query_ids (self, id1, id2):
        return id1 == id2

    def  _cmp_query_question (self, question1, question2):
        return question1 == question2

    def _cmp_host_port (self, port1, port2):
        return port1 == port2

    def _cmp_host_proto (self, proto1, proto2):
        return proto1 == proto2


    #def _get_host_mac_hash (self, host_mac):
    #    mac = ''
    #    for i in range (0, 6):
    #        mac += str (host_mac[i])
    #    return hashlib.sha256 (mac.encode('utf-8')).hexdigest()[:10]


    def _get_forwarder_list_key (self, forwarder_list):
        forwarder_ip_key = 0
        for ip, port, proto in forwarder_list:
            forwarder_ip_key ^= ip
        return forwarder_ip_key

    def _rl_host_ip (self, host_details):
        """ host_details = host_ip, host_port, host_proto """
        host_ip_entry = self._lookup_dict (HOST_IP_LIST, host_details[0])
        current_request_time = time.time()
        # First entry
        if not host_ip_entry:
            self._add_to_dict (HOST_IP_LIST, host_details[0], [current_request_time, 1])
            return True
        else:
            # Within permitted query count
            if (host_ip_entry[1] <= MAX_QUERIES):
                host_ip_entry[1] += 1
                return True
            # Timeout has not expired and query count exceeds
            elif (current_request_time - host_ip_entry[0] <= MAX_QUERIES_TIMEOUT):
                print ("No service, ip list")
                return False
            # Only left possiblility, query count exceeded but in acceptable time
            else:
                host_ip_entry[0] = current_request_time
                host_ip_entry[1] = 1
                return True
        return True

    def _rl_forwarder_tree (self, host_details, forwarder_list, query_id, question):
        """ forwarder_list = [[ip, port, proto], [], ..] """
        forwarder_ip_key = self._get_forwarder_list_key (forwarder_list)
        forwrder_entry = self._lookup_dict (FORWARDER_LIST, forwarder_ip_key)
        current_request_time = time.time()

        """ forwrder_entry = [time, count, query_id, question, host_port, host proto """
        if not forwrder_entry:
            self._add_to_dict (FORWARDER_LIST, forwarder_ip_key, [current_request_time, 1,
                               query_id, question, host_details[1], host_details[2]])
        else:
            if (forwrder_entry[1] <= MAX_QUERIES):
                forwrder_entry[1] += 1
                return True
            elif (current_request_time - forwrder_entry[0] <= MAX_QUERIES_TIMEOUT):
                # True implies similarity
                if (((self._cmp_query_ids (forwrder_entry[2], query_id) == True) and
                     (self._cmp_query_question (forwrder_entry[3], question) == True)) or
                    ((self._cmp_host_port (forwrder_entry[4], host_details[1]) == True) and
                     (self._cmp_host_proto (forwrder_entry[5], host_details[2]) == True))):
                    print ("No service, forwarder tree")
                    return False
            else:
                forwrder_entry[0] = current_request_time
                forwrder_entry[1] = 1

        return True

    def _rl_host_mac (self, host_details, host_mac):
        current_request_time = time.time()
        #host_mac_hash = self._get_host_mac_hash (host_mac)
        host_mac_entry = _lookup_dict (HOST_MAC_LIST, host_mac)
        if not host_mac_entry:
            self._add_to_dict (HOST_MAC_LIST, host_mac, [current_request_time,
                               host_details[0]])
            return True
        elif ((host_mac_entry[2] != host_details[0]) and
              (current_request_time - host_mac_entry[0] < MAX_QUERIES_TIMEOUT)):
            """ If IP is different within the timeout, replace IP and do not service """
            host_mac_entry[1] = host_details[0]
            host_mac_entry[0] = current_request_time
            return False
        else:
            """ New IP after timeout, replace and service """
            host_mac_entry[1] = host_details[0]
            return True

    def _rl_same_ip_diff_forwarder (self, host_details, forwarder_list):
        # Circular queue as value for the different forwarders
        forwarder_key_list = collections.deque (maxlen = 5)
        entry_found = False
        ret = False

        # Get ip key from the list of forwarders
        forwarder_ip_key = self._get_forwarder_list_key (forwarder_list)
        forwarder_key_list.appendleft (forwarder_ip_key)

        # lookup entry with host ip as key
        host_forwarder_entry = self._lookup_dict (HOST_FRWDR_LIST, host_details[0])

        if not host_forwarder_entry:
            self._add_to_dict (HOST_FRWDR_LIST, host_details[0], forwarder_key_list)
            return True
        else:
            for entry in host_forwarder_entry:
                if entry == forwarder_ip_key:
                    entry_found = True
                    return True
            if (entry_found == False):
                if (len (host_forwarder_entry) < host_forwarder_entry.maxlen):
                    ret = True
            host_forwarder_entry.appendleft (forwarder_ip_key)
            return ret

    def process_edns (self, host_details, forwarder_list, query_id, question, host_mac):
        ret = True
        """ IP spoofing. Consider only host IP """
        if len (host_details):
            ret &= self._rl_host_ip (host_details)
            print ("RL host IP returns {0}".format (ret))

        """ Same forwarder list and similary query - question, query id """
        if (len (host_details) and len (forwarder_list) and query_id):
            ret &= self._rl_forwarder_tree (host_details, forwarder_list, query_id, question)
            print ("FRWDR List returns {0}".format (ret))

        """ Same MAC different ID """
        if (len (host_details) and len (host_mac)):
            ret &= self._rl_host_mac (host_details, host_mac)
            print ("Host MAC returns {0}".format (ret))

        """ Same (subnet) IP but (too many) different forwarder list """
        if (len (host_details) and len (forwarder_list)):
            ret &= self._rl_same_ip_diff_forwarder (host_details, forwarder_list)
            print ("Same IP diff forwarders returns {0}".format (ret))

        return ret

    def process_edns_forwarder_list (self, forwarder_list):
        return True

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
        forwarder_list = []
        host_details = []
        query_id = 0
        host_ip = host_port = host_proto = 0
        host_mac = ''

        for options in dns_query.options:
            if (options.otype == EDNS_OPTION_CODE_HOST):
                (host_ip, host_port, host_proto) = struct.unpack ("!sHH", options.data)
                host_details = [host_ip, host_port, host_proto]
                print ("Host details Hash of IP {0}, Port {1}, Proto {2}".format (host_ip, host_port, host_proto))

            elif (options.otype == EDNS_OPTION_CODE_FWDR):
                data_len = len (options.data)
                if (data_len % 8 != 0):
                    print ("Wrong formatted ENDS options")
                    return

                print ("Forwarder details - Ip, port, proto")
                num_frwdrs = (int) (data_len / 8)
                for i in range (0, num_frwdrs):
                    (ip, port, proto) = struct.unpack ("!LHH", options.data [8*i:8*(i+1)])
                    forwarder_list.append ([ip, port, proto])
                    print ("{0}, {1}, {2}".format (ip, port, proto))
            elif (options.otype == ENDS_OPTION_CODE_QUERY_ID):
                query_id = int(struct.unpack ("!L", options.data)[0])
                print ("Query Id {0}".format (query_id))
            elif (options.otype == ENDS_OPTION_CODE_HOST_MAC):
                host_mac = strcut.unpack ("!s", options.data)
                print ("Host MAC {0}".format (host_mac))

        return self.rate_limit.process_edns (host_details, forwarder_list,
                                             query_id, question, host_mac)

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
