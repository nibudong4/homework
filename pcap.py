#!/usr/bin/python
# -*- coding: UTF-8 -*-
import sys
import string
import struct

def handlepcap(string_pcap,pkt_offset):
    pcap_header={}
    pcap_header['caplen'] = string_pcap[pkt_offset + 8:pkt_offset + 12]
    print len(pcap_header['caplen'])
    cap_len = struct.unpack('I', pcap_header['caplen'])[0]
#    cap_len=cap_len[0]

    ip_header={}
    ip_header['v_l']=string_pcap[pkt_offset+16+14:pkt_offset+16+14+1]
    v_l=struct.unpack('B',ip_header['v_l'])[0]
    ip_len=v_l&0x0f
    ip_len*=4

    tcp_header={}
    tcp_header['l_baoliu']=string_pcap[pkt_offset+16+14+ip_len+12:pkt_offset+16+14+ip_len+13]
    l_baoliu=struct.unpack('B',tcp_header['l_baoliu'])[0]
#    l_baoliu=l_baoliu[0]
    tcp_len=l_baoliu&0xf0
    tcp_len=tcp_len>>4
    tcp_len*=4

    tcpdata_len=cap_len-14-ip_len-tcp_len
    print cap_len,ip_len,tcp_len,tcpdata_len
    return (cap_len,ip_len,tcp_len,tcpdata_len)


def file_entropy(name):
    fpcap=open(name,"rb")
    string_pcap = fpcap.read()
    pkt_offset = 24
    pcap_num=0
    while (len(string_pcap) > 24):
       print "---------包"+str(pcap_num)+"----------"
       (cap_len, ip_len, tcp_len, tcpdata_len)=handlepcap(string_pcap,pkt_offset)
       pkt_offset += 16 + cap_len
       pcap_num += 1


if __name__=="__main__":
#    name=raw_input("请输入：");
#    fpcap=open(name,'rb')
 #   entropy_arrary=filetobuffer(name)
    entropy_arrary=file_entropy("jmll.pcap")







