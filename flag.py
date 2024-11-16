from scapy.all import rdpcap

# 元のPCAPファイルパス
original_pcap_path = 'filtered_packets.pcap'

# PCAPファイルを読み込み
packets = rdpcap(original_pcap_path)

# ICMPエコーリクエストのデータを格納するリスト
icmp_data = []

# ICMPパケットを解析
for pkt in packets:
    if pkt.haslayer('ICMP'):  # ICMP層があるか確認
        icmp_layer = pkt['ICMP']
        if icmp_layer.type == 8:  # エコーリクエストのみ
            seq = icmp_layer.seq  # シーケンス番号
            raw_data = bytes(pkt['Raw'].load).decode('utf-8') if pkt.haslayer('Raw') else ''  # データ部分
            icmp_data.append((seq, raw_data))  # シーケンス番号とデータを保存

# シーケンス番号順に並べ替え
sorted_data = sorted(icmp_data, key=lambda x: x[0])

# フラグを復元
flag = ''.join(data[1] for data in sorted_data)

# 結果を出力
print(f"Recovered flag: {flag}")
