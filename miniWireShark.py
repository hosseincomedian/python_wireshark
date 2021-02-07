
import socket
from struct import *
import sys


def ethernet_head(raw_data):
    dest, src ,protocol= unpack('! 6s 6s H' ,raw_data[:14])
    data = raw_data[14:]
    dest_mac =''
    for i in range(0,5):
        dest_mac += str(hex(dest[i])).replace('0x','')+':'
    dest_mac+= str(hex(dest[5])).replace('0x','')
    src_mac =''
    for i in range(0,5):
        src_mac+=str(hex(src[i])).replace('0x','')+':' 
    src_mac+=str(hex(src[5])).replace('0x','')
    proto = socket.htons(protocol)
    return(dest_mac,src_mac,proto,data)

def get_ip(addr):
    return '.'.join(map(str, addr))
'''
def access_bit(data, num):
    base = int(num // 8)
    shift = int(num % 8)
    return (data[base] & (1<<shift)) >> shift
'''
def ipv4_head(raw_data):
    version_header_length = raw_data[0]   #version and header_length
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    
    tos, total_length, identi, ipof, ttl, protocol,HeaderChecksum, src, des = unpack('! 1x B 2s 2s 2s B B 2s 4s 4s', raw_data[0:20])
    total_length= ''.join(map(str,total_length))  #tabdil 2byte be int motanazer
    total_length= int(total_length)  
    identi= ''.join(map(str,identi))  
    s=[]
    for i in ipof:
        s.append(i)
    IPFpags= s[1]
    offset= s[0]
    data = raw_data[header_length:]
    src = get_ip(src)
    des = get_ip(des)
    return version, header_length, tos, total_length,identi, ttl, protocol, src, des, IPFpags, offset, HeaderChecksum,  data


def tcp_head(raw_data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags, window_size, Ckecksum, Urgent_Pointer = unpack('! H H L L H H 2s H', raw_data[:20])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    data = raw_data[offset:]
    print('\n\n')
    for i in data:
        print(i)
    print('\n\n')
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window_size, Ckecksum,Urgent_Pointer, data

def icmp_head(raw_data):
    typee, code, Checksum = unpack('! B B 2s', raw_data[:4])
    typee= ''.join(map(str,typee))
    code= ''.join(map(str,code)) 
    Checksum= ''.join(map(str,Checksum)) 
    data = raw_data[4:]
    return typee,code,Checksum,data

def udp_head(raw_data):
    src_port, dest_port,length, Checksum = unpack('! H H H 2s', raw_data[:8])
    data = raw_data[8:]
    return src_port, dest_port, length, Checksum,data


s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
while True:
        raw_data, addr = s.recvfrom(65535)
        eth = ethernet_head(raw_data)
        print('$'*25+'__New-Packet__'+'$'*25)
        print('\n- Ethernet Frame:')
        print('\tDestination MAC: {}, Source MAC: {}, Protocol: {}'.format(eth[0], eth[1], eth[2]))
        ipv4 = ipv4_head(eth[3])
        print( '\n- ' + 'IP Packet:')
        print('\t\t - ' + 'Version: {}, Header Length: {}, TOS:{}'.format(ipv4[0], ipv4[1], ipv4[2]))
        print('\t\t - ' + 'Total length: {}, Identification: {}, TTL: {} '.format(ipv4[3],ipv4[4],ipv4[5] ))
        print('\t\t - ' + 'IPFpags: {}, offset: {}, HeaderChecksum: {}'.format(ipv4[9],ipv4[10],ipv4[11]))
        print('\t\t - ' + 'Protocol: {}, Source: {}, dest:{}'.format(ipv4[6], ipv4[7], ipv4[8]))   
        
        if ipv4[6] == 1:
            icmp = icmp_head(ipv4[12])
            print('\t- ' + 'ICMP Packet:')
            print('\t\t -' + 'Type: {}, Code: {}, Checksum:{},'.format(icmp[0], icmp[1], icmp[2]))
            print('\t\t -' + 'ICMP Data:')
            print(format_multi_line('\t\t\t', icmp[3]))
        
        elif ipv4[6] == 6:
            tcp = tcp_head(ipv4[12])
            print('- ' + 'TCP Segment:')
            print('\t' + 'Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))
            print('\t' + 'Sequence: {}, Acknowledgment: {}'.format(tcp[2], tcp[3]))
            print('\t' + 'Flags:')
            print('\t' + 'URG: {}, ACK: {}, PSH:{}'.format(tcp[4], tcp[5], tcp[6]))
            print('\t' + 'RST: {}, SYN: {}, FIN:{}'.format(tcp[7], tcp[8], tcp[9]))
            print('\t' + 'window size: {}, Chacksum: {}, Urgent_Pointer: {} '.format(tcp[10], tcp[11], tcp[12]))
            if len(tcp[13]) > 0:
                print('TCP Data:')
                print(tcp[13])
        
        elif ipv4[6] == 17:
            UDP = udp_head(ipv4[12])
            print('- ' + 'UDP Segment:')
            print('\t' + 'Source Port: {}, Destination Port: {}'.format(UDP[0], UDP[1]))
            print('\t' + 'Length: {}, Chacksum: {}'.format(UDP[2], UDP[3]))
            if len(UDP[4]) > 0:
                print('UDP Data:')
                print(UDP[4])


