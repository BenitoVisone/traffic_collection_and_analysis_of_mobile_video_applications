#!/usr/bin/env python
# coding: utf-8

# In[1]:


from scapy.all import *
import os
import time
import csv


# In[2]:


def get_conversations(file):
    f = open(file, "r")
    for _ in range(5):
            next(f)

    #Reading IP Source Address and Source Port
    out = False
    i = 0
    conversations = []

    while out == False:

        src_ip = ""
        src_port = ""
        dst_ip = ""
        dst_port = ""
        left_frames_string = ""
        left_bytes_string = ""
        right_frames_string = ""
        right_bytes_string = ""
        total_frames = 0
        total_bytes = 0
        val = " "
        while(val!=":"):
            val = f.read(1)
            if(val == "="):
                out = True
                break
            src_ip +=val
        src_ip = src_ip.replace(":","")
        val = ""
        if out == True:
            break
        while(val!=" "):
            val = f.read(1)
            src_port +=val
        src_port = src_port.replace(" ","")
        while(f.read(1)!=">"):
            continue
        f.read(1)
        val = " "
        while(val!=":"):
            val = f.read(1)
            dst_ip +=val
        dst_ip = dst_ip.replace(":","")
        val = ""
        while(val!=" "):
            val = f.read(1)
            dst_port +=val
        dst_port = dst_port.replace(" ","")
        while True:
            val = f.read(1)
            if (val != " "):
                break
        while(val!=" "):
            left_frames_string +=val
            val = f.read(1)
        while True:
            val = f.read(1)
            if (val != " "):
                break

        while(val!=" "):
            left_bytes_string +=val
            val = f.read(1)

        while True:
            val = f.read(1)
            if (val != " "):
                break

        while(val!=" "):
            right_frames_string +=val
            val = f.read(1)

        while True:
            val = f.read(1)
            if (val != " "):
                break

        while(val!=" "):
            right_bytes_string +=val
            val = f.read(1)

        total_frames = int(left_frames_string) + int(right_frames_string)
        total_bytes = int(left_bytes_string) + int(right_bytes_string)
        row = src_ip,src_port,dst_ip,dst_port,left_frames_string,left_bytes_string,right_frames_string,right_bytes_string,total_frames,total_bytes,"N\D","N\D","N\D","N\D"
        conversations.append(row)
        next(f)
    return conversations
    
        
                    


# In[3]:


captures = ["visone_4g1","visone_4g2","visone_wifi1","visone_wifi2","russo_4g1","russo_4g2","russo_wifi1","russo_wifi2"]

j = 0
for j in range(len(captures)):
    x = "tshark -r "+captures[j] + ".pcap -qz conv,tcp > tcp_conversations_"+captures[j]+".txt"
    y = "tshark -r "+captures[j] + ".pcap -qz conv,udp > udp_conversations_"+captures[j]+".txt"
    subprocess.call(x, shell=True)
    subprocess.call(y, shell=True)
    while not os.path.exists("tcp_conversations_"+captures[j]+".txt"):
            time.sleep(1)
    while not os.path.exists("udp_conversations_"+captures[j]+".txt"):
            time.sleep(1)
    udp_conversations = get_conversations("udp_conversations_"+captures[j]+".txt")
    tcp_conversations = get_conversations("tcp_conversations_"+captures[j]+".txt")
    #We have got rows of the CSV file
    i = 0
    with open('tcp_conversations_'+captures[j]+'.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["SRC_IP", "SRC_PORT", "DST_IP","DST_PORT","LEFT_FRAMES","LEFT_BYTES","RIGHT_FRAMES","RIGHT_BYTES","TOTAL_FRAMES","TOTAL_BYTES","SNI","DNS","HTTP"])
        for i in range(len(tcp_conversations)):
            writer.writerow(tcp_conversations[i])
            i+=1
    with open('udp_conversations_'+captures[j]+'.csv', 'w', newline='') as file3:
        writer = csv.writer(file3)
        writer.writerow(["SRC_IP", "SRC_PORT", "DST_IP","DST_PORT","LEFT_FRAMES","LEFT_BYTES","RIGHT_FRAMES","RIGHT_BYTES","TOTAL_FRAMES","TOTAL_BYTES","SNI","DNS","HTTP"])
        for i in range(len(udp_conversations)):
            writer.writerow(udp_conversations[i])
            i+=1
            
    #SNI -Extractions        
    x = "tshark -r "+captures[j] + ".pcap -T fields -E separator=, -E quote=d  -e frame.time_epoch -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e tcp.dstport -e tls.handshake.extensions_server_name -E header=y,separator=/t -Y 'ssl.handshake.extensions_server_name' >sni_extraction_"+captures[j]+".csv"
    subprocess.call(x, shell=True)
    while not os.path.exists("sni_extraction_"+captures[j]+".csv"):
            time.sleep(1)
    #HTTP -Extractions        
    x = "tshark -r "+captures[j] + ".pcap -T fields -E separator=, -E quote=d  -e frame.time_epoch -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e tcp.dstport -e http.host -E header=y,separator=/t -Y 'http' >http_extraction_"+captures[j]+".csv"
    subprocess.call(x, shell=True)
    while not os.path.exists("http_extraction_"+captures[j]+".csv"):
            time.sleep(1)
    #DNS -Extractions        
    x = "tshark -r "+captures[j] + ".pcap -T fields -E separator=, -E quote=d -e frame.time_epoch -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e tcp.dstport -e dns.a -e dns.qry.name -Y '(dns.flags.response == 1 )'>dns_extraction_"+captures[j]+".csv"
    subprocess.call(x, shell=True)
    while not os.path.exists("dns_extraction_"+captures[j]+".csv"):
            time.sleep(1)
            
    sni_extractions = []
    with open("sni_extraction_"+captures[j]+".csv", newline="", encoding="ISO-8859-1") as filecsv:
        lettore = csv.reader(filecsv,delimiter=",")
        try:
            while(next(lettore)):
                sni_extractions.append(next(lettore))
        except StopIteration as e:
            print(e)
    http_extractions = []
    with open("http_extraction_"+captures[j]+".csv", newline="", encoding="ISO-8859-1") as filecsv:
        lettore = csv.reader(filecsv,delimiter=",")
        try:
            while(next(lettore)):
                http_extractions.append(next(lettore))
        except StopIteration as e:
            print(e)
    dns_extractions = []
    with open("dns_extraction_"+captures[j]+".csv", newline="", encoding="ISO-8859-1") as filecsv:
        lettore = csv.reader(filecsv,delimiter=",")
        try:
            while(next(lettore)):
                dns_extractions.append(next(lettore))
        except StopIteration as e:
            print(e)
            
    
    read_conversations = []
    with open("tcp_conversations_"+captures[j]+".csv", newline="", encoding="ISO-8859-1") as filecsv2:
        lettore2 = csv.reader(filecsv2,delimiter=",")
        try:
            while(next(lettore2)):
                read_conversations.append(next(lettore2))
        except StopIteration as e:
            print(e)
            
    read_conversations2 = []
    with open("udp_conversations_"+captures[j]+".csv", newline="", encoding="ISO-8859-1") as filecsv3:
        lettore3 = csv.reader(filecsv3,delimiter=",")
        try:
            while(next(lettore3)):
                read_conversations2.append(next(lettore3))
        except StopIteration as e:
            print(e)
            
    #Matching TCP and SNI
    for s in range(len(read_conversations)):
        for z in range(len(sni_extractions)):
            if read_conversations[s][2] == sni_extractions[z][2] and read_conversations[s][0] == sni_extractions[z][1] and read_conversations[s][1] == sni_extractions[z][4] and read_conversations[s][3] == sni_extractions[z][5]:
                read_conversations[s][10] = sni_extractions[z][6]
    #Matching UDP and HTTP
    for k in range(len(read_conversations2)):
        for l in range(len(http_extractions)):
            if read_conversations2[k][2] == http_extractions[l][2]:
                read_conversations2[k][12] = http_extractions[l][6]  
    #Matching TCP and HTTP
    for v in range(len(read_conversations)):
        for w in range(len(http_extractions)):
            if read_conversations[v][2] == http_extractions[w][2]:
                read_conversations[v][12] = http_extractions[w][6]
    #Matching TCP and DNS
    for a in range(len(read_conversations)):
        for b in range(len(dns_extractions)):
            if read_conversations[a][2] == dns_extractions[b][7]:
                read_conversations[a][11] = dns_extractions[b][8]
    #Matching UDP and DNS
    for g in range(len(read_conversations2)):
        for h in range(len(dns_extractions)):
            if read_conversations2[g][2] == dns_extractions[h][7]:
                read_conversations2[g][11] = dns_extractions[h][8]
    i = 0
    
    with open('tcp_conversations_result_'+captures[j]+'.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["SRC_IP", "SRC_PORT", "DST_IP","DST_PORT","LEFT_FRAMES","LEFT_BYTES","RIGHT_FRAMES","RIGHT_BYTES","TOTAL_FRAMES","TOTAL_BYTES","SNI","DNS","HTTP"])
        for i in range(len(read_conversations)):
            writer.writerow(read_conversations[i])
            i+=1
    i = 0
    with open('udp_conversations_result_'+captures[j]+'.csv', 'w', newline='') as file_udp:
        writer = csv.writer(file_udp)
        writer.writerow(["SRC_IP", "SRC_PORT", "DST_IP","DST_PORT","LEFT_FRAMES","LEFT_BYTES","RIGHT_FRAMES","RIGHT_BYTES","TOTAL_FRAMES","TOTAL_BYTES","SNI","DNS","HTTP"])
        for i in range(len(read_conversations2)):
            writer.writerow(read_conversations2[i])
            i+=1
    


# In[ ]:




