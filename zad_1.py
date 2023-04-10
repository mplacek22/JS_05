import re


def parse_logs(ssh_file):
    logs_list = []

    with open(ssh_file) as file:
        for line in file:
            line = line.strip()
            log_entry = {}

            if re.match(r'^\w{3} \d{1,2} \d{2}:\d{2}:\d{2} \S+ sshd\[\d+\]:', line):
                fields = line.split()
                log_entry['timestamp'] = fields[0] + ' ' + fields[1] + ' ' + fields[2]
                log_entry['hostname'] = fields[3]
                log_entry['process'] = fields[4]
                log_entry['message'] = ' '.join(fields[5:])
                logs_list.append(log_entry)
    return logs_list




if __name__ == '__main__':
    parsed_logs = parse_logs('SSH.log')
    for log in parsed_logs:
        print(log)
