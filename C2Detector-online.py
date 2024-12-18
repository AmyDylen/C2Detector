from scapy.all import *
from scapy.all import PcapReader, TCP, IP, UDP, ICMP, DNS, DNSQR
import time
from datetime import datetime
import numpy as np
import os
import threading
os.environ["PATH"] += os.pathsep + 'C:/Program Files/Graphviz/bin'
import pickle
import logging
import psutil
from scapy.all import sniff
import pyfiglet

# Data normalization operation (block length)
def log_with_sign(nums):
    signs = np.sign(nums)
    nums = np.abs(nums)
    nums[nums < 2] = 2  # Replace all zeros with 1 to avoid log10(0)
    nums[nums > 1000000] = 1000000
    first = np.log10(nums)
    min_val = np.log10(1)
    max_val = np.log10(1000000)
    second = (first - min_val) / (max_val - min_val)
    third = second * signs
    return third

#数据归一化操作(数据块时间)
def log_with_time(nums):
    # 使用numpy的log10函数对绝对值取对数，然后乘以原始符号
    # np.sign(nums) 返回每个元素的符号，对正数为1，负数为-1，0为0
    # np.abs(nums) 计算每个元素的绝对值
    # np.log10() 对给定值取以10为底的对数
    # 结果是原始符号乘以绝对值的对数

    # 第一步，取对数变换
    nums = np.abs(nums)
    nums[nums < 2] = 2  # Replace all zeros with 1 to avoid log10(0)
    nums[nums > 100000] = 100000
    first = np.log10(nums)
    min_val = np.log10(1)  #最小值一般为2个字节
    max_val = np.log10(100000)  #最大值这里取100000，一般需要计算所有样本中的最大值才能确定
    # 对绝对值进行最大-最小归一化
    second = (first - min_val) / (max_val - min_val)
    
    # 第二步，计算最大值和最小值
    #min_val = np.min(first)
    #max_val = np.max(first)
    # min_val = np.log10(0.0000001)  #时间间隔最小值
    # max_val = np.log10(1000)  #最大时间间隔这里取1000
    # # 对绝对值进行最大-最小归一化
    # second = (first - min_val) / (max_val - min_val)
    return second


def dynamic_pooling(lst, m):  
    """  
    Map a variable-length list to a fixed length m using dynamic pooling  
    :param lst: Input variable-length list  
    :param m: Target fixed length  
    :return: List after dynamic pooling  
    """  
    if len(lst) > m:  
        lst = lst[:m]
    # Calculate the length of subsequences  
    min_len = min(len(lst), m)  
    subseq_len = max(1, min_len // m)
    # Initialize result list  
    result = [0] * m
    # Dynamic pooling  
    for i in range(m):  
        if i < len(lst):  
            subseq = lst[i:i + subseq_len]  
            result[i] = np.mean(subseq) if subseq_len > 1 else subseq[0]
    return result

def remove_extension(filename):
    if filename.endswith(".pcap"):
        return filename[:-5]
    elif filename.endswith(".pcapng"):
        return filename[:-7]
    else:
        return filename

def log_warning(message):
    # Create logger object
    logger = logging.getLogger('warning_logger')
    logger.setLevel(logging.WARNING)
    # Create file handler and set log file name
    file_handler = logging.FileHandler('detect.log')
    # Create formatter and set format
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    # Add file handler to logger object
    logger.addHandler(file_handler)
    # Output warning message
    logger.warning(message)
    # Close handlers
    for handler in logger.handlers:
        handler.close()

    # Clear handlers
    logger.handlers.clear()

    
def format_tuple(src_ip, src_port, dst_ip, dst_port):
    """
    Format quintuple for desired output
    """
    return f"{src_ip}:{src_port} <---> {dst_ip}:{dst_port}"

def extract_sessions_features(key,pcap_name):
    iii = 0
    j = 0  
    packet_time=[] # Packet delay sequence
    packet_length=[] # Packet length sequence, positive and negative sign represent direction
    x=[]
    attack_flag=0
    i=0
    count=0
    timetotal = 0   
             
    for packet in flows[key]:
        payload_data=0
        if packet.haslayer(IP): # Only detect packets above IP layer, extract IP address, payload part, timestamp
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ts = int(packet.time * 1000) #用毫秒来计算
        else:
            continue
        
        if packet.haslayer(TCP): # Detect TCP packets
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            # 遍历所有的协议层
            while packet:
                # 获取当前协议层的名称
                layer_name = packet.__class__.__name__
                # 如果是TCP层，计算载荷长度
                if layer_name == "TCP":
                    # 检查是否存在载荷，并计算其长度
                    payload_data = int(len(packet.payload))
                    #print(f"Tcp_payload_length: {payload_data}")
                # 跳到下一层协议
                packet = packet.payload
        else:
            continue
                                  

        if payload_data > 1: # Only extract packets with payload, some keep-alive ack packets have a length of 1, here a shortcut is taken, treating keep-alive packets this way, keep-alive packets are also removed
            if count == 0:
                packet_time.append(0) # The time of the first packet is 0
                time_flag = ts
                time_begin= ts
                direction_flag = src_ip
            else:
                packet_time.append(int(ts - time_flag))
                time_flag = ts
                timetotal = int(ts - time_begin)
                   
            if src_ip == direction_flag:
                packet_length.append(payload_data)
            else:
                packet_length.append(-payload_data)
            count +=1     

    if count > 6: # If there are more than 3 valid payload packets in a session, perform detection on this session. Actually, many sessions are empty
        j +=1
        packet_length_new=[] # Packet length sequence, positive and negative sign represent direction
        packet_time_new=[] # Packet delay sequence

        # Simple segmentation and recombination, to restore the upper layer interaction process as much as possible. Actually, we only need to restore the file size, so the disorder does not affect the size, retransmission occurs in very high latency networks, and retransmission is not considered in this detection. So no consideration of other complex situations.
        i = 0
        while i < len(packet_length):
            temp_packet_length = packet_length[i]
            temp_packet_time   = packet_time[i]
            if temp_packet_length > 0:
                while i < len(packet_length) - 1 and packet_length[i+1] > 0 and packet_time[i+1] < 3000: # Merge consecutive positive direction packets and consider that the time interval of adjacent packets is within 3 seconds as packets belonging to segmented reassembly
                    temp_packet_length += packet_length[i+1]
                    temp_packet_time  += packet_time[i+1]
                    i += 1
            else:
                while i < len(packet_length) - 1 and packet_length[i+1] < 0 and packet_time[i+1] < 3000: # Merge consecutive reverse direction packets and consider that the time interval of adjacent packets is within 3 seconds
                    temp_packet_length += packet_length[i+1]
                    temp_packet_time  += packet_time[i+1]
                    i += 1
            packet_length_new.append(temp_packet_length)
            packet_time_new.append(temp_packet_time)
            i += 1
            
        m = 30 #THE same as the setting of the trainnig modle
        packet_length = dynamic_pooling(log_with_sign(packet_length_new), m)
        packet_time = dynamic_pooling(np.sign(packet_length_new)*log_with_time(packet_time_new), m)
        x.append(packet_length + packet_time)

        with open(os.path.join(os.getcwd(), "decision_tcp.pkl"), 'rb') as f:
            loaded_decisionclf = pickle.load(f)

        predictions = loaded_decisionclf.predict(x)
        if predictions == 1:
            if timetotal > 50000 and len(packet_length_new) > 5:
                #print(f"{pcap_name} suspected vulnerability exploitation process, but the session duration is too short or the number of interactions within the session is less than 3.")
                log_warning(f"{pcap_name} suspected vulnerability exploitation traffic")

                formatted_tuple = format_tuple(src_ip, src_port, dst_ip, dst_port)
                print(f"    Suspected remote control session found: {formatted_tuple}")
                print("    Suspected vulnerability exploitation session traffic file:", pcap_name)
                j +=1
                attack_flag = 1 
                    
    return iii, j, attack_flag

# Create an empty dictionary to store packets for each TCP flow
flows = {}
# Dictionary to store session start times
flow_start_times = {}
# Define a callback function to handle captured packets
sum_sessions = 0

def save_flow(key):
    global sum_sessions
    if key in flows:
        if len(flows[key]) > 5: # Only save flows with more than 5 packets
            current_timestamp = time.time()
            current_datetime = datetime.fromtimestamp(current_timestamp)
            current_dir = os.getcwd()
            temp_folder_name = "temp"
            if not os.path.exists(os.path.join(current_dir, temp_folder_name)):
                os.makedirs(os.path.join(current_dir, temp_folder_name))
                print(f"Temporary folder created: {temp_folder_name}")
            temp_dir = os.path.join(current_dir, temp_folder_name)
            file_name = "{}_{}.pcap".format(key, current_datetime.strftime("%Y-%m-%d-%H-%M-%S-%f")).replace(" ", "")
            iii, j, attack_flag = extract_sessions_features(key,file_name)
            if attack_flag == 1:
                sum_sessions += 1
            file_path = os.path.join(temp_dir, file_name)
            wrpcap(file_path, flows[key], append=False)
            print(sum_sessions, f"Session data file saved: {file_name}")
                
        del flows[key]
        del flow_start_times[key]

    
def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_addr = packet[IP].src
        dst_addr = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        key = (src_addr, dst_addr, src_port, dst_port)
        reverse_key = (dst_addr, src_addr, dst_port, src_port)

        if key in flows:
            flows[key].append(packet)
            if 'F' in packet[TCP].flags and 'A' in packet[TCP].flags or 'R' in packet[TCP].flags:
                save_flow(key)
        elif reverse_key in flows:
            flows[reverse_key].append(packet)
            if 'F' in packet[TCP].flags and 'A' in packet[TCP].flags or 'R' in packet[TCP].flags:
                save_flow(reverse_key)
        else:
            flows[key] = [packet]
            flow_start_times[key] = time.time()
            threading.Timer(180, save_flow, args=[key]).start()  # Timed save of flows to avoid memory overflow

        if len(flows) > 10000:
            oldest_key = min(flow_start_times, key=flow_start_times.get)
            save_flow(oldest_key)

def list_network_interfaces():
    interfaces = []
    for interface, addrs in psutil.net_if_addrs().items():
        status = "Up" if psutil.net_if_stats()[interface].isup else "Down"
        interfaces.append((interface, status))
    return interfaces

def main():
    # Output title in artistic font
    font_name = "slant"
    ascii_banner = pyfiglet.figlet_format("C2Detector", font=font_name)
    print("======++++++++++++++++++++++++++++++++++++++++++++++++======")
    print(ascii_banner)
    print("======+++++++++++++++++++++ C2Detector v2.2 +++++++++++++++++++++======")
    
    interfaces = list_network_interfaces()
    
    if not interfaces:
        print("No networkinterfaces found.")
        exit(1)
    
    print("Available network interfaces:")
    for index, (interface, status) in enumerate(interfaces):
        print(f"{index+1}. {interface} - {status}")
    
    choice = int(input("Enter the number of the interface you want to monitor: "))
    selected_interface = interfaces[choice - 1][0]
    #print(selected_interface)
    print("======+++++  C2Detector system is monitoring real-time traffic on the network card  +++++======")
    
    sniff(iface=selected_interface, prn=packet_callback)

if __name__ == "__main__":
    main()
