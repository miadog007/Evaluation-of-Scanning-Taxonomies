#!/usr/bin/python
###dont work!/usr/bin/env python

#----------------------------------------------------------------#
# Prints out some useful fields as a CSV
# (c) 2019 Barry Irwin
#
#----------------------------------------------------------------#
import dpkt
# NB needs version 1.9.0 or greater 
#if not (float(dpkt.__version__[0:3])>=1.9) :
#	print('ERROR: dpkt version >1.9.0 is required')
#	sys.exit(2)
import time
import datetime
import sys
import socket

#sanity checking
#if int(len(sys.argv)) < 3:
 #   print(sys.argv[0] , 'requires two arguments <in> <out>')
  #  sys.exit(-1)

infile = '/data/anon_196.21.146.cap'
outfile = 'check.csv'

#If compressed do gzip stuff  otherwise read normal
#if (str(infile)[-3:]=='.gz'):
 #   import gzip
  #  f=gzip.open(infile, 'rb')
#elif (str(sys.argv[1])[-4:]=='.bz2'):
 #   print('.bz2 is not currently supported only .gz')
  #  sys.exit(-1)
#else:
    # open the file plain
f = open(infile,'rb')

#print 'DEBUG: file data: ', f

pcap = dpkt.pcap.Reader(f)

#iterate over the file
import csv

with open(outfile, mode='w') as pcap_file:
    pcap_writer = csv.writer(pcap_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)



    for ts, buf in pcap:
        print(ts, len(buf))
        packet=[]
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        
        srcip=ip.src
        dstip=ip.dst
        ttl=ip.ttl
        ptime=str(datetime.datetime.utcfromtimestamp(ts))
     
        #print(ptime,socket.inet_ntoa(srcip),socket.inet_ntoa(dstip),ttl,ip.len,ip.p,end='')  
        
        packet.append(ptime)
        packet.append(socket.inet_ntoa(srcip))
        packet.append(socket.inet_ntoa(dstip))
        packet.append(ttl)
        packet.append(ip.len)
        packet.append(ip.p)
        
        #packet.append((ptime,socket.inet_ntoa(srcip),socket.inet_ntoa(dstip),ttl,ip.len,ip.p))
        
       
        
        if ip.p==6:
            tcp = ip.data
            try:
                sport=tcp.sport
                dport=tcp.dport
            except:
                sport=-1
                dport=-1
            #print(sport,dport,end='\n')
            packet.append(sport)
            packet.append(dport)
        elif  ip.p==17:
            udp = ip.data
            try:
                sport=udp.sport
                dport=udp.dport
            except:
                sport=-1
                dport=-1
            packet.append(sport)
            packet.append(dport)
        elif  ip.p==1:
            icmp=ip.data
            try:
                t=icmp.type
                c=icmp.code
            except:
                t=-1
                c=-1
            packet.append(t) #icmp.type)
            packet.append(c) #icmp.code)
        else:
            proto=ip.data
            packet.append(0)
            packet.append(0)
        

        
        pcap_writer.writerow(packet)
        
        #clean up to avoid possible problems
        del ip
        sport=-1
        dport=-1
        ttl=-1
        del ptime
        
        
