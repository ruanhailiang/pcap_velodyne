try:
    import scapy.all as scapy
except ImportError:
    import scapy
import re


def parse_http_pcap(pcap_path):
    fp = scapy.PcapReader(pcap_path)
    p = fp.read_packet()
    # print(p.payload.payload.fields_desc)

    for f in p.payload.payload.fields_desc:
        fvalue = p.payload.getfieldval(f.name)
        reprval = f.i2repr(p.payload, fvalue)  # 转换成十进制字符串
        for f2 in p.payload.payload.payload.fields_desc:  # payload向下解析一层
            # print f2.name
            if f2.name == "load" or f2.name == "data":
                fvalue = p.payload.getfieldval(f2.name)
                reprval = f2.i2repr(p.payload, fvalue)
                print(reprval)
                print(fvalue)
                print(str(reprval, 'utf8'))
                refind = re.compile(r'[A-Fa-f0-9]{32}')  # 根据自己的需求设置正则
                temp = refind.findall(reprval)
                print(temp)
                # stringlist.extend(temp)




    # # packet.show()
    # raw_data = packet['Raw']
    # # print(raw_data)
    # if 'UDP' in packet:
    #     print(packet.summary())
    #     s = repr(packet)
    #     # print(s)
    #     print(packet['UDP'].sport)

    # packets = scapy.rdpcap(pcap_path, 100)
    # for p in packets:
    #     print("----")
    #     p.show()
    #     # 判断是否包含某一层，用haslayer
    #     if p.haslayer("IP"):
    #         src_ip = p["IP"].src
    #         dst_ip = p["IP"].dst
    #         print("sip: %s" % src_ip)
    #         print("dip: %s" % dst_ip)
    #     if p.haslayer("UDP"):
    #         s = repr(p)
    #         print(s)
    #         print(p['UDP'].sport)
    #         print("ok")
    #     if p.haslayer("TCP"):
    #         print("ok")
    #         # 获取某一层的原始负载用.payload.original
    #         raw_http = p["TCP"].payload.original
    #         sport = p["TCP"].sport
    #         dport = p["TCP"].dport
    #         print("sport: %s" % sport)
    #         print("dport: %s" % dport)
    #         print("raw_http:\n%s" % raw_http)
    #     if p.haslayer("HTTPRequest"):
    #         host = p["HTTPRequest"].Host
    #         uri = p["HTTPRequest"].Path
    #         # 直接获取提取好的字典形式的http数据用fields
    #         http_fields = p["HTTPRequest"].fields
    #         http_payload = p["HTTPRequest"].payload.fields
    #         print("host: %s" % host)
    #         print("uri: %s" % uri)
    #         print("http_fields:\n%s" % http_fields)
    #         print("http_payload:\n%s" % http_payload)


parse_http_pcap("d:\\test.pcap")


# https://www.cnblogs.com/v5captain/p/6435140.html
# https://www.pianshen.com/article/4431618646/