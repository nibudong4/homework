#!/usr/bin/python
# -*- coding: UTF-8 -*-

import sys
import string
import struct
import math

def handlepcap(string_pcap,pkt_offset):
    pcap_header={}
    pcap_header['caplen'] = string_pcap[pkt_offset + 8:pkt_offset + 12]
    cap_len = struct.unpack('I', pcap_header['caplen'])[0]

    ip_header={}
    ip_header['v_l']=string_pcap[pkt_offset+16+14:pkt_offset+16+14+1]
    v_l=struct.unpack('B',ip_header['v_l'])[0]
    ip_len=v_l&0x0f
    ip_len*=4
    ip_header['ip_proto']=string_pcap[pkt_offset+16+14+9:pkt_offset+16+14+10]
    ip_proto=struct.unpack('B',ip_header['ip_proto'])[0]
    if(ip_proto!=6):
        ip_len=-1

    tcp_header={}
    tcp_header['l_baoliu']=string_pcap[pkt_offset+16+14+ip_len+12:pkt_offset+16+14+ip_len+13]
    l_baoliu=struct.unpack('B',tcp_header['l_baoliu'])[0]
    tcp_len=l_baoliu&0xf0
    tcp_len=tcp_len>>4
    tcp_len*=4

    tcpdata_len=cap_len-14-ip_len-tcp_len
    return (cap_len,ip_len,tcp_len,tcpdata_len)

def frency_calc(string_tcpdata,tcpdata_len):
    byte_count = []
    byte_count = [0] * 256
    length = 0
    for i in range(0, tcpdata_len):
        tcpdata_byte = struct.unpack('B', string_tcpdata[i])[0]
#        print "tcpdata_byte"+str(tcpdata_byte)
        byte_count[tcpdata_byte]+=1
    return byte_count



def tcpdata_entropy_calc(string_tcpdata,tcpdata_len):
    entropy=0.0
    byte_count = frency_calc(string_tcpdata, tcpdata_len)
    for i in range(0, 256):
        if (byte_count[i] != 0):
 #           print ("byte_count:%2.5f" % byte_count[i])
            count =float(byte_count[i])  / float(tcpdata_len)
 #           print ("count:%2.5f"%count)
            entropy += -count * math.log(count,2)
#            print ("log2:%2.5f"%math.log(count,2))
#            print ("entropy:%2.5f"%entropy)
    return entropy

def file_entropy(name):
    fpcap=open(name,"rb")
    string_pcap = fpcap.read()
    pkt_offset = 24
    pcap_num=1
    entropy_arrary={}
    jmb_i=0
    while (len(string_pcap) != pkt_offset):
        print "---------包"+str(pcap_num)+"----------"
        (cap_len, ip_len, tcp_len, tcpdata_len)=handlepcap(string_pcap,pkt_offset)

        if (tcpdata_len == 0):
            print "此包没有tcp数据部分\n"
            entropy_arrary[pcap_num] = -1
        elif (ip_len == -1):
            print "此包不是tcp包\n"
            entropy_arrary[pcap_num] = -2
        else:
            string_tcpdata = string_pcap[
                             pkt_offset + 16 + 14 + ip_len + tcp_len:pkt_offset + 16 + 14 + ip_len + tcp_len + tcpdata_len]
            entropy = tcpdata_entropy_calc(string_tcpdata, tcpdata_len)

            entropy_arrary[pcap_num] = entropy
            if (entropy > 7.1317):
                print ("此包熵值为%2.5f:是加密包"%(entropy))
                jmb_i += 1
            else:
                print ("此包熵值为%2.5f:不是加密包" % (entropy))
        pcap_num += 1
        pkt_offset += 16 + cap_len

    return entropy_arrary


if __name__=="__main__":
#    name=raw_input("请输入：");
#    fpcap=open(name,'rb')
 #   entropy_arrary=filetobuffer(name)
    entropy_arrary=file_entropy("jmll.pcap")