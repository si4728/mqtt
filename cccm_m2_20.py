# txt파일을 읽어 pub/sub 를 id/sequence별 1개 파일오 묶는 작업. 
import json
from collections import defaultdict
import configparser
import pandas as pd
import argparse
import sys

config = configparser.ConfigParser()
#LOG_FILE = "cccm_rpc1015.txt"
INCOMPLETE_LOG_FILE = "incomplete_sequences.json"

def filter_invalid_sequences(file_path, invalid_sequences):
    all_line = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            all_line.append(line)
    f.close()  

    filtered_lines = []
    for line in all_line:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        if "sequence" in entry:
            if entry["sequence"] not in invalid_sequences:
                filtered_lines.append(line)
        else:
            filtered_lines.append(line)
    

    if len(filtered_lines) > 0:
        BAK_FILE = file_path + ".bak"
        with open(BAK_FILE, "w", encoding="utf-8") as f:
            for line in all_line:
                f.write(line)
        f.close()
        print(f"Filtered out {len(all_line) - len(filtered_lines)} invalid entries.")

        with open(file_path, "w", encoding="utf-8") as f:
                for line in filtered_lines:
                    f.writelines(line)
        f.close()
        print(f"Filtered log file saved to {file_path}. Please re-run the script.")

   # return filtered_lines

def validation_pair(file_path, remove_option):
    pair_counts = defaultdict(lambda: {"pub": 0, "sub": 0})
    total_sequences = set()

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            if "tcp_ping" in entry:
                continue

            if "sequence" in entry and "direction" in entry:
                seq = entry["sequence"]
                direction = entry["direction"]
                total_sequences.add(seq)
                
                if direction == "pub":
                    pair_counts[seq]["pub"] += 1
                elif direction == "sub":
                    pair_counts[seq]["sub"] += 1
                incomplete_sequences = []

    for seq, counts in pair_counts.items():
        pub_count = counts["pub"]
        sub_count = counts["sub"]
        
        # pub과 sub이 모두 1회씩만 나타나지 않은 경우 (불완전하거나 중복된 세트)
        if pub_count != 1 or sub_count != 1:
            status = f"pub: {pub_count}, sub: {sub_count}"
            incomplete_sequences.append((seq, status))
    if incomplete_sequences:
        print("\n=======================================================")
        print(f"Warning: Incomplete or duplicated pub/sub pairs found from {file_path}")
        print(f"Total unique sequences found: {len(total_sequences)}")
        print(f"Sequences with invalid pairs ({len(incomplete_sequences)} total):")
        
        for seq, status in incomplete_sequences:
            print(f"  - Sequence {seq}: {status}")    
 
        print("=======================================================\n")
        return incomplete_sequences
    else:
        print("All sequences have valid pub/sub pairs.")
        return None
    

def merge_pub_sub_log_to_list(file_path, output_path):
    sequence_dict = defaultdict(dict)
    pending_sub_ping = None  # sequence 없는 tcp_ping 값을 저장

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            if "tcp_ping" in entry:
                pending_sub_ping = entry["tcp_ping"]
                continue

            # sequence가 있는 pub/sub 로그
            if "sequence" in entry:
                seq = entry["sequence"]
                seq_entry = sequence_dict[seq]
                direction = entry.get("direction")

                # 공통 키 그대로 저장
                for k in ["id", "sequence", "compress_method", "encryption_type", "pub_ping", "sub_ping"]:
                    if k in entry:
                        seq_entry[k] = entry[k]

                # sub 로그이면 pending_sub_ping 덮어쓰기
                if direction == "sub" and pending_sub_ping is not None:
                    entry["sub_ping"] = pending_sub_ping

                # 나머지 키 정리 (_pub/_sub 접미사)
                for k, v in entry.items():
                    if k not in ["id", "sequence", "compress_method", "encryption_type", "pub_ping", "sub_ping", "direction"]:
                        if direction == "pub":
                            seq_entry[f"{k}_pub"] = v
                        elif direction == "sub":
                            seq_entry[f"{k}_sub"] = v
                        else:
                            seq_entry[k] = v

    if seq_entry["sub_ping"] < 0:
        print(seq_entry)
        if pending_sub_ping is not None:
            seq_entry["sub_ping"] = pending_sub_ping 
        else:
            seq_entry["sub_ping"] = seq_entry["pub_ping"] 
    if seq_entry["hash_time_pub"]==0.0 and seq_entry["hash_time_sub"]==0.0:
        seq_entry["hash_mode"]="None"
    else:
        seq_entry["hash_mode"]="hash"


    result = [sequence_dict[k] for k in sorted(sequence_dict.keys())]

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=4)

    return True

def data_calc_step(data_file):        

    # Read the JSON data from output.txt
    with open("output.txt", "r") as f:
        data = json.load(f)

    # Process each record to compute calc_time, round_trip_time, and total_time
    for record in data:
        compress_time_pub = record.get("compress_time_pub", 0) or 0
        encryption_time_pub = record.get("encryption_time_pub", 0) or 0
        hash_time_pub = record.get("hash_time_pub", 0) or 0
        hash_time_sub = record.get("hash_time_sub", 0) or 0
        hash_time = hash_time_pub + hash_time_sub
        decryption_time_sub = record.get("decryption_time_sub", 0) or 0
        decompress_time_sub = record.get("decompress_time_sub", 0) or 0
        publish_time_pub = record.get("publish_time_pub", 0) or 0
        subscribe_time_sub = record.get("subscribe_time_sub", 0) or 0
        sequence = record.get("sequence", -1)

        calc_time = (
            compress_time_pub +
            encryption_time_pub +
            hash_time_pub +
            hash_time_sub +
            decryption_time_sub +
            decompress_time_sub
        )

        round_trip_time = (subscribe_time_sub - publish_time_pub)
        print(f"{sequence}, {round_trip_time}, === {calc_time}")
        total_time = calc_time + round_trip_time

        # Add computed values to the record
        record["calc_time"] = calc_time
        record["round_trip_time"] = round_trip_time
        record["total_time"] = total_time
        record["data_size_pub"] = record.get("size_sub", 0) or 0

    # Save the updated data back to a new log file and a CSV file
    df = pd.DataFrame(data)
    CSV_FILE = data_file.split(".")[0] + ".csv"
    df.to_csv(CSV_FILE, index=False)

    print(f"Updated data saved to {data_file} and  {CSV_FILE}.")

def main():
    parser = argparse.ArgumentParser(description="txt data file")
    parser.add_argument('--data', required=True, help='Path to data_log.txt')
    parser.add_argument('--mismatch', default='n', help='mismatched data remove[y] or not[n/default]')
    args = parser.parse_args()
    data_log_file = args.data
    mismatch_option = args.mismatch

    if not data_log_file:
        print("Error: --data argument is missing. Please provide the path to data_log.txt.")
        sys.exit(1)
    if not mismatch_option:
        print("if have mismatched data, does not remove it.")
        mismatch_option = 'n'

    print(f"Data log file path provided: {data_log_file}")
    
    test = validation_pair(data_log_file, mismatch_option)
    if test != None:
        if mismatch_option.lower() == 'y':
            print("Remove mismatched data and reprocess the log file.")
            filter_invalid_sequences(data_log_file, [seq for seq, _ in test])
        else:
            print("Mismatched data found. Please set --mismatch to 'y' to remove them and reprocess.")  
            exit(1)

    merge_pub_sub_log_to_list(data_log_file, "output.txt")
    data_calc_step(data_log_file)


if __name__ == "__main__":
    main()

