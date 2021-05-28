import os
import time
import sys
import math
import re
import struct
import argparse
import logging
import pynmea2

from coordtransform import wgs84_to_gcj02
from ext_path.path import get_ext_files


logger = logging.getLogger(__name__)
logger.setLevel(level=logging.INFO)
# 文件日志处理器
localtime = str(time.strftime("%Y-%m-%d_%H_%M_%S", time.localtime()))
log_path = os.path.join(os.getcwd(), 'logs')
if not os.path.exists(log_path):
    os.makedirs(log_path)
handler = logging.FileHandler(log_path + "\\log_%s.txt" % (localtime,))
formatter = logging.Formatter("%(asctime)s - %(levelname)s: %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
# 打印日志处理器
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logger.addHandler(console)


class PcapHeader(object):
    """
    pcap file header size 24 bytes.
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    0 |                          Magic Number                         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    4 |          Major Version        |         Minor Version         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    8 |                           Reserved1                           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   12 |                           Reserved2                           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   16 |                            SnapLen                            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   20 | FCS |f|                   LinkType                            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    def __init__(self, byte_data):
        self.magic_number = byte_data[0: 4]
        self.version_major = byte_data[4: 6]
        self.version_minor = byte_data[6: 8]
        self.thiszone = byte_data[8: 12]
        self.sigfigs = byte_data[12: 16]
        self.snaplen = byte_data[16: 20]
        self.linktype = byte_data[20: 24]
    BYTE_SIZE = 24


class PacketHeader(object):
    """
    pcap file packet header size 16 bytes.
                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    0 |                      Timestamp (Seconds)                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    4 |            Timestamp (Microseconds or nanoseconds)            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    8 |                    Captured Packet Length                     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   12 |                    Original Packet Length                     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   16 /                                                               /
      /                          Packet Data                          /
      /                        variable length                        /
      +---------------------------------------------------------------+
    """
    def __init__(self, byte_data):
        self.gmt_time = byte_data[0: 4]
        self.micro_time = byte_data[4: 8]
        self.captured_length = struct.unpack('I', byte_data[8: 12])[0]
        self.original_length = struct.unpack('I', byte_data[12: 16])[0]
    BYTE_SIZE = 16


class GprmcMessage(object):
    """ Pre-NMEA Version 2.3 Message Format"""
    def __init__(self, byte_data):
        gprmc = byte_data.split()[0]  # filter out gprmc message, remaining are zeros
        gprmc = gprmc.decode('ascii').split(',')
        if len(gprmc) != 12:
            raise Exception("数据解析异常")
        self.type_0 = gprmc[0]
        self.time_1 = gprmc[1]
        self.status_2 = gprmc[2]
        self.lat_3 = gprmc[3]
        self.lat_ori_4 = gprmc[4]
        self.long_5 = gprmc[5]
        self.long_ori_6 = gprmc[6]
        self.speed_ground_7 = gprmc[7]  # Speed over the ground (knots)
        self.track_made_good_8 = gprmc[8]  # Track made good (degrees True)
        self.date_9 = gprmc[9]  # 230394 23rd of March 1994
        self.magnetic_variation_10 = gprmc[10]
        self.magnetic_variation_unit_11 = gprmc[11].split('*')[0]
        self.singularity_12 = gprmc[11].split('*')[1]


def get_lon_dir(lon):
    """获取经纬度所在ori
    经纬度范围：-180 ~ 180
    负坐标代表西半球，正坐标代表东半球.
    """
    d = "E"
    if lon < 0:
        d = "W"
    return d


def get_lat_dir(lat):
    """获取经纬度所在ori
    经纬度范围：-90 ~ 90
    负坐标代表南半球，正坐标代表北半球
    """
    d = "N"
    if lat < 0:
        d = "S"
    return d


def lon_lat_to_dm(lon, lat):
    """
    Converts a geographic co-ordinate given in "degrees/minutes" dddmm.mmmm
    format (eg, "12319.943281" = 123 degrees, 19.943281 minutes) to a signed
    decimal (python float) format
    经度: dddmm.mmmmmm(度分)格式(前面的0也将被传输)
    纬度: ddmm.mmmmmm(度分)格式(前面的0也将被传输)
    """
    # 纬度
    a1 = math.floor(lon)
    b1 = (lon - a1) * 60.0
    c1 = str(round(a1 * 100.0 + b1, 6))
    a, b = c1.split(".")
    new_lon = '.'.join([a.rjust(5, '0'), b.ljust(6, '0')])

    # 纬度
    a2 = math.floor(lat)
    b2 = (lat - a2) * 60.0
    c2 = str(round(a2 * 100.0 + b2, 6))
    a, b = c2.split(".")
    new_lat = '.'.join([a.rjust(4, '0'), b.ljust(6, '0')])
    return new_lon, new_lat


def get_pre_and_gprmc_bytes(packet_data):
    """
    :param packet_data:
    :return: gprmc bytes
    """
    # udp_header = packet_data[:42]  # 01 UDP header Number of Bytes 42.
    # unused = packet_data[42: 240]  # 02 unused (null bytes) Number of Bytes 198.
    # timestamp = packet_data[240: 244]  # 03 Timestamp (µs) Number of Bytes 4.
    # per_second_status = packet_data[244: 245]  # 04 Pulse Per Second status Number of Bytes 1.
    # unused2 = packet_data[245: 248]  # 05 unused Number of Bytes 3.
    pre_gprmc = packet_data[:248]
    # The GPRMC sentence is terminated with CR/LF and padded to end of payload with null bytes
    gprmc = packet_data[248:]  # 06 NMEA GPRMC sentence
    return pre_gprmc, gprmc


def wgs84_to_gcj02_dm(gprmc_bytes):
    gprmc = gprmc_bytes.split()[0]  # filter out gprmc message, remaining are zeros
    rmc = pynmea2.parse(gprmc.decode('ascii'), check=True)
    gcj_lng, gcj_lat = wgs84_to_gcj02(rmc.longitude, rmc.latitude)
    new_lon, new_lat = lon_lat_to_dm(gcj_lng, gcj_lat)

    return new_lon, get_lon_dir(gcj_lng), new_lat, get_lat_dir(gcj_lat)


def calc_new_gprmc_bytes(gprmc_bytes):
    rmc = GprmcMessage(gprmc_bytes)
    if rmc.type_0 != "$GPRMC":
        raise Exception("数据解析异常")
    lon, lon_dir, lat, lat_dir = wgs84_to_gcj02_dm(gprmc_bytes)
    rmc_data = (rmc.time_1, rmc.status_2, lat, lat_dir, lon, lon_dir, rmc.speed_ground_7, rmc.track_made_good_8,
                rmc.date_9, rmc.magnetic_variation_10, rmc.magnetic_variation_unit_11)
    sentence = pynmea2.RMC('GP', 'RMC', rmc_data)
    gprmc_str = str(sentence) + '\r\n'
    gprmc_str_bytes = bytes(gprmc_str, 'ascii')

    return gprmc_str_bytes + bytes(306-len(gprmc_str_bytes))


def encoding_pcap_file(in_pcap_file, out_pcap_file):
    pcap_fp = open(in_pcap_file, 'rb')
    data = pcap_fp.read()
    out_fp = open(out_pcap_file, 'wb')
    # pcap文件头解析
    # pcap_header = PcapHeader(data[0: PcapHeader.BYTE_SIZE])
    out_fp.write(data[0: PcapHeader.BYTE_SIZE])
    # pcap文件的数据包解析
    i = PcapHeader.BYTE_SIZE
    packet_num = 0
    while i < len(data):
        # 数据包头各个字段
        packet_header = PacketHeader(data[i: i+PacketHeader.BYTE_SIZE])
        out_fp.write(data[i: i+PacketHeader.BYTE_SIZE])
        # 求出此包的包长len
        packet_len = packet_header.original_length
        # 获取packet数据记录
        packet_data = data[i + PacketHeader.BYTE_SIZE: i + PacketHeader.BYTE_SIZE + packet_len]
        if packet_len != 554:
            out_fp.write(packet_data)
        else:
            pre_bytes, gprmc_bytes = get_pre_and_gprmc_bytes(packet_data)
            out_fp.write(pre_bytes)
            if len(gprmc_bytes) != 306:
                logger.error("文件%s解析异常" % (in_pcap_file,))
                raise Exception("数据解析异常")
            new_gprmc_bytes = calc_new_gprmc_bytes(gprmc_bytes)
            out_fp.write(new_gprmc_bytes)
            packet_num += 1
        # 写入此包数据
        i = i + packet_len + 16

    print("一共有%s条记录" % (packet_num,))
    out_fp.close()
    pcap_fp.close()


def main(args):
    pcap_files = get_ext_files(args.in_path, "PCAP")
    count = len(pcap_files)
    for index, pcap_file in enumerate(pcap_files):
        logger.info("转换文件开始 %s / %s [ %s ]" % (index, count, pcap_file))
        out_pcap_file = os.path.join(args.out_path, pcap_file[len(args.in_path)+1:])
        out_pcap_path = os.path.dirname(out_pcap_file)
        if not os.path.exists(out_pcap_path):
            os.makedirs(out_pcap_path)
        encoding_pcap_file(pcap_file, out_pcap_file)
        logger.info("转换文件完毕 %s / %s [ %s ]" % (index, count, pcap_file))
    input("程序运行完毕！请按回车键结束...")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='NCOM文件的WGS84坐标转换火星坐标工具')
    parser.add_argument('-i', '--input_file_path', help='转换前ncom文件目录', dest='in_path', type=str)
    parser.add_argument('-o', '--out_file_path', help='转换后ncom文件目录', dest='out_path', type=str)
    args = parser.parse_args()

    if not any(vars(args).values()):
        msg = "程序参数不正确，未运行"
        print("*" * 15 + "**" * len(msg) + "*" * 15)
        print("*" * 15 + msg + "*" * 15)
        print("*" * 15 + "**" * len(msg) + "*" * 15)
        parser.print_help()
        print("*" * 15 + "**" * len(msg) + "*" * 15)
        print("*" * 15 + "**" * len(msg) + "*" * 15)
        sys.exit(1)
    if not os.path.exists(args.in_path) or not os.path.exists(args.out_path):
        msg = "输入或输出路径不正确，未运行"
        print("*" * 15 + "**" * len(msg) + "*" * 15)
        print("*" * 15 + msg + "*" * 15)
        print("*" * 15 + "**" * len(msg) + "*" * 15)
        sys.exit(1)
    main(args)
