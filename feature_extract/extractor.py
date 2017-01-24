#!/usr/bin/env python

'''
Feature Extractor for Bigtree project
    by maziazy@gmail.com

DO NOT use scapy. It's really handy but way too slow.

TODO:
  * Should judge whether a packet is SSL by signature,
    but not TCP port 443
  * We should use ndpi libary to identify the flow, but not the ndpiReader

'''

from dpkt import ssl
from subprocess import call
from os import devnull
import warnings
import mpkt
import json
import sys
import csv
from scapy.all import *
from subprocess import call
import MySQLdb

_PRECEDING_PACKETS_NUM = 5
_NDPI_TEMPNAME = 'ndpi_out.json'

cons = {}                   # set of connections
features = {}               # set of features
fo_writer = None
flow_count = 0
packet_count = 0

# Flow features
class Feature(mpkt.FiveTuple):
    def __init__(self, src, dst, sport, dport, proto='TCP'):
        super(Feature, self).__init__(src, dst, sport, dport, proto)

        self.packets_size = []                      # Preceding packets byte count
        self.talk_size = {'A': 0, 'B':0, 'A+B': 0}  # APPR talk byte count
        self.talk_pkt = {'A': 0, 'B':0, 'A+B': 0}   # APPR talk packet count

        self.objs = {                               # Extraction objectives
            'APPR': False,
            'preceding': False
        }

    @classmethod
    def from5tuple(cls, tuple):
        return cls(tuple.src, tuple.dst, tuple.sport, tuple.dport, tuple.proto)

    ''' Check whether all extraction objectives are completed'''
    def complete(self):
        for key, objective in self.objs.iteritems():
            if not objective: return False
        return True

    ''' Convert features into 5 tuple '''
    def to5tuple(self):
        return mpkt.FiveTuple(self.src, self.dst, self.sport, self.dport, self.proto)

    ''' Convert features into list '''
    def toList(self):
        list = []
        list.append(self.src)
        list.append(self.sport)
        list.append(self.dst)
        list.append(self.dport)
        list.append(self.proto)
        for i in range(0, _PRECEDING_PACKETS_NUM):
            list.append(self.packets_size[i])
        list.append(self.talk_pkt['A'])
        list.append(self.talk_pkt['B'])
        list.append(self.talk_pkt['A+B'])
        list.append(self.talk_size['A'])
        list.append(self.talk_size['B'])
        list.append(self.talk_size['A+B'])
	print list
        return list


    def toSQL(self):
	ps=list()
        SQL_src=self.src
        SQL_srcport=self.sport
	src=SQL_src+":"+str(SQL_srcport)
        SQL_dst=self.dst
        SQL_dstport=self.dport
	dst=SQL_dst+":"+str(SQL_dstport)
        SQL_proto=self.proto
        for i in range(0, _PRECEDING_PACKETS_NUM):
            ps.append(self.packets_size[i])
        p1=self.talk_pkt['A']
        p2=self.talk_pkt['B']
        p3=self.talk_pkt['A+B']
        p4=self.talk_size['A']
        p5=self.talk_size['B']
        p6=self.talk_size['A+B']
	#connect MySQL database
	conn = MySQLdb.connect(host='localhost',user='root',passwd='123',db='sonicwall')
        cur = conn.cursor()
        sql_data = [SQL_proto, src, dst, ps[0], ps[1], ps[2], ps[3], ps[4], p1, p2, p3, p4, p5, p6]
	sql_data = [str(i) for i in sql_data]
	print sql_data 
        cur.execute('insert into flow_fe(protocol, src, dst, packet_1_size, packet_2_size, packet_3_size, packet_4_size, packet_5_size, packet_count_A, packet_count_b, packet_count_A_B, byte_count_A, byte_count_B, byte_count_A_B) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',sql_data)
        #cursor.executemany('insert into package(appname, appcat, protocol, src, dst) values(%s,%s,%s,%s,%s)', appname, appcat, protocol, src, dst)
        conn.commit()
        cur.close()
        conn.close()
	
        return list

def packetIn(buf):
    global fo_writer, cons, feature, flow_count, packet_count
    # print "PACKETIN"
    # packet_count = packet_count + 1
    try: pkt = mpkt.Packet(buf)
    except mpkt.PacketError: return
    
    ts = buf.time 
    name = pkt.get5tuple().toString()
    name_rev = pkt.get5tuple().reversal().toString()


    if name not in cons and pkt.isFlags('SYN'):
        cons[name] = mpkt.Connection.from5tuple(ts, pkt.get5tuple())
        features[name] = Feature.from5tuple(pkt.get5tuple())

    # reverse 5-tuple if this is a reversal packet
    if name not in cons and name_rev in cons:
        name, name_rev = name_rev, name

    # Process the packet
    if name in cons:
        con     = cons[name]
        feature = features[name]

        # Update connection information and strip SSL handshake
        alters = con.next(pkt) # update state

        # Feature extraction

	# ***************************************************************************
        # "SSL" Talk A start need to initiated
	if con.l5_proto == 'SSL' and ( alters['APPR'] == 1 or alters['APPR'] == 2 ) and alters['SSL'] == mpkt.SSLState.EXCHANGE_MESS : 
	    con.count['byte'] = pkt.len
	    con.count['data'] = 1
  
        # Talk A complete
        if alters['APPR'] == 3 or alters['APPR'] == 4:
            feature.talk_size['A'] = con.count['byte'] - pkt.len
            feature.talk_pkt['A'] = con.count['data'] - 1
            
        # Talk B complete
        elif alters['APPR'] == 5:
            feature.talk_size['B'] = con.count['byte'] - feature.talk_size['A'] - pkt.len
            feature.talk_pkt['B'] = con.count['data'] - feature.talk_pkt['A'] - 1
            feature.talk_size['A+B'] = con.count['byte'] - pkt.len
            feature.talk_pkt['A+B'] = con.count['data'] - 1
            feature.objs['APPR'] = True

        # Cpature preceding packet byte count
        if pkt.len > 0 and len(feature.packets_size) < _PRECEDING_PACKETS_NUM and \
            (con.l5_proto != 'SSL' or con.state['SSL'] == mpkt.SSLState.EXCHANGE_MESS ):
            feature.packets_size.append(pkt.len)
            # Captured all preceding packets
            if len(feature.packets_size) == _PRECEDING_PACKETS_NUM:
                feature.objs['preceding'] = True

	# ***************************************************************************

        # Write to csv file
        if feature.complete():
	    #feature.toSQL()
            result = feature.toList()                     # Features
            fo_writer.writerow(result)
            del cons[name]
            del features[name]

def main():
    global packet_count
    # Check for arguments
    if len(sys.argv) == 2:
	file_in = sys.argv[1]
        file_out = 'essence.csv'
    elif len(sys.argv) == 3:
	file_in = sys.argv[1]
        file_out = sys.argv[2]
    else:
        print "Usage: ", sys.argv[0], "[interface_name/pcap_file]", "[output.csv]"
        return

    global fo_writer
    # Open files for input and output
    try:
        FNULL = open(devnull, 'w')   # File of nowhere
        fo = open(file_out, 'w')
        fo_writer = csv.writer(fo)
    except IOError as (errno, strerror):
        print "I/O error({0}): {1}".format(errno, strerror)
        return

    # Prepare csv (header)
    csv_header = ['src_ip']
    csv_header.append('src_port')
    csv_header.append('dst_ip')
    csv_header.append('dst_port')
    csv_header.append('protocol')
    for i in xrange(1, _PRECEDING_PACKETS_NUM+1):
        csv_header.append('packet '+str(i)+' size')
    csv_header.append('packet count A')
    csv_header.append('packet count B')
    csv_header.append('packet count A+B')
    csv_header.append('byte count A')
    csv_header.append('byte count B')
    csv_header.append('byte count A+B')
    fo_writer.writerow(csv_header)

    if file_in.find(".pcap") == -1 : sniff(iface=file_in, prn=packetIn, store=0, filter="tcp" )
    else : sniff(offline=file_in, prn=packetIn)
    fo.close()

if __name__ == "__main__":
    main()
