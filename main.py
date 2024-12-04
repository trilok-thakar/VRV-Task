import re
import csv
from collections import defaultdict

def count_requests_per_ip(log_file_path):
    ip_count = defaultdict(int)
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')

    with open(log_file_path, 'r') as file:
        for line in file:
            ip_match = ip_pattern.search(line)
            if ip_match:
                ip_address = ip_match.group(0)
                ip_count[ip_address] += 1

    sorted_ip_count = sorted(ip_count.items(), key=lambda item: item[1], reverse=True)

    return sorted_ip_count

def most_frequently_accessed_endpoint(log_file_path):
    endpoint_count = defaultdict(int)
    endpoint_pattern = re.compile(r'\"[A-Z]+\s+(/[^ ]*)\s+HTTP/')

    with open(log_file_path, 'r') as file:
        for line in file:
            endpoint_match = endpoint_pattern.search(line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_count[endpoint] += 1

    if endpoint_count:
        most_accessed_endpoint = max(endpoint_count.items(), key=lambda item: item[1])
        return most_accessed_endpoint
    else:
        return None

def detect_suspicious_activity(log_file_path, threshold=5):  
    failed_login_count = defaultdict(int)
    failed_login_pattern = re.compile(
        r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[.*\] ".*" 401 .*"Invalid credentials"'
    )

    with open(log_file_path, 'r') as file:
        for line in file:
            failed_login_match = failed_login_pattern.search(line)
            if failed_login_match:
                ip_address = failed_login_match.group('ip') 
                failed_login_count[ip_address] += 1

  
    flagged_ips = {ip: count for ip, count in failed_login_count.items() if count >= threshold}

    return flagged_ips

def display_suspicious_activity(flagged_ips):
    if flagged_ips:
        print("Suspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        print("--------------------------------------------------")
        for ip, count in flagged_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

def save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity, filename='log_analysis_results.csv'):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts:
            writer.writerow([ip, count])
        writer.writerow([]) 

        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        if most_accessed_endpoint:
            writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        writer.writerow([]) 

        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def print_results(ip_counts, most_accessed_endpoint, suspicious_activity):
    print(f"{'IP Address':<20} {'Request Count':<15}")
    print('-' * 35)
    for ip, count in ip_counts:
        print(f"{ip:<20} {count:<15}")

    print(f"\nMost Frequently Accessed Endpoint:")
    if most_accessed_endpoint:
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    else:
        print("No endpoints found.")

    print(f"\n{'Suspicious Activity Detected:':<30}")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<20}")
    print('-' * 50)
    if suspicious_activity:
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20} {count:<20}")
    else:
        print("No suspicious activity detected.")

if __name__ == "__main__":
    log_file_path = 'D:\VRV\sample.log'
    threshold = 5 

    flagged_ips = detect_suspicious_activity(log_file_path, threshold)
    display_suspicious_activity(flagged_ips)
    ip_counts = count_requests_per_ip(log_file_path)

    most_accessed_endpoint = most_frequently_accessed_endpoint(log_file_path)

    suspicious_activity = detect_suspicious_activity(log_file_path, threshold=10)

    save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity)