from scapy.all import rdpcap

# 元のPCAPファイルパス
original_pcap_path = 'SendaiCTF2024-Network.pcapng'

# 抽出条件
src_ip = '192.168.0.4'
dst_ip = '10.1.101.128'

# 元のPCAPファイルを読み込み
packets = rdpcap(original_pcap_path)

# フィルタ条件に一致するパケットを抽出
filtered_packets = [pkt for pkt in packets if pkt.haslayer('IP') and
                    pkt['IP'].src == src_ip and pkt['IP'].dst == dst_ip]

# 抽出したパケットをテキスト形式で保存
output_text_path = 'filtered_packets.txt'
with open(output_text_path, 'w') as f:
    for pkt in filtered_packets:
        f.write(pkt.summary() + '\n')  # 各パケットの概要を出力
        f.write(str(pkt.show(dump=True)) + '\n')  # パケットの詳細情報を出力
        f.write('=' * 80 + '\n')  # 区切り線

print(f"Filtered packet details saved to: {output_text_path}")
