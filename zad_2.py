import re
from enum import Enum


def parse_log_line(line):
    line_stripped = line.strip()
    log_entry = {}

    if re.match(r'^\w{3}\s? \d{1,2} \d{2}:\d{2}:\d{2} \S+ sshd\[\d+\]:', line_stripped):
        fields = line_stripped.split()
        log_entry['timestamp'] = fields[0] + ' ' + fields[1] + ' ' + fields[2]
        log_entry['hostname'] = fields[3]
        log_entry['process'] = fields[4]
        log_entry['message'] = ' '.join(fields[5:])
        return log_entry

    raise ValueError("Invalid data format")


def parse_log_file(ssh_file_name):
    logs_list = []

    with open(ssh_file_name) as file:
        for line in file:
            logs_list.append(parse_log_line(line))
    return logs_list


def get_ipv4s_from_log(lines):
    ipv4_regex = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    ipv4_list = []

    for line in lines:
        ipv4_address = re.search(ipv4_regex, line)
        if ipv4_address:
            ipv4_list.append(ipv4_address.group(0))
    return ipv4_list


def get_lines_from_file(file_name):
    with open(file_name) as file:
        return file.readlines()


def get_user_from_log(log_line):
    pattern = r'user=([^\s]+)'
    user = re.search(pattern, log_line)
    if user:
        return user.group(1)
    return None


def get_message_type(message):
    patterns_dict = {
        MessageType.ACCEPTED_PASSWORD: r'^Accepted password',
        MessageType.FAILED_PASSWORD: r'^Failed password',
        MessageType.CONNECTION_CLOSED: r'^Connection closed',
        MessageType.INVALID_USERNAME: r'^Invalid user',
        MessageType.BREAK_IN_ATTEMPT: r'POSSIBLE BREAK-IN ATTEMPT!$'
    }
    for mess_type, pattern in patterns_dict.items():
        match = re.search(pattern, message)
        if match:
            return mess_type
    return MessageType.OTHER


class MessageType(Enum):
    OTHER = 0
    ACCEPTED_PASSWORD = 1
    FAILED_PASSWORD = 2
    CONNECTION_CLOSED = 3
    INVALID_USERNAME = 4
    BREAK_IN_ATTEMPT = 5


if __name__ == '__main__':
    parsed_logs = parse_log_file('SSH.log')
    lines = get_lines_from_file('SSH.log')
    for log in parsed_logs:
        print(log['message'])
        print(get_message_type(log['message']))
