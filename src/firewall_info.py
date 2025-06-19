import re
from analyzer_utils import execute_command

def get_ufw_state(rules):
    command = "ufw status"
    result_command = execute_command(command)
    if len(result_command) > 0:
        rules['ufw_state'] = []

        for temp_row in result_command:
            rules['ufw_state'].append(temp_row)

def get_firewall_ports(rules):
    command = "firewall-cmd --list-ports"
    result_command = execute_command(command)
    if len(result_command) > 0:
        rules['firewall_ports'] = []

        for temp_row in result_command:
            rules['firewall_ports'].append(temp_row)

def get_firewall_information(rules: dict):
    command = "firewall-cmd --get-zones"
    result_command = execute_command(command)
    if len(result_command) > 0:
        rules['firewall_rules'] = {}

        zones = result_command[0]
        for zone in zones.split(" "):
            if zone not in rules['firewall_rules']:
                rules['firewall_rules'][zone] = []

            command = f"firewall-cmd --zone={zone} --list-all"
            result_command = execute_command(command)
            for temp_row in result_command:
                if temp_row == "" or temp_row == zone:
                    continue

                rules['firewall_rules'][zone].append(temp_row)

def get_iptables_information(rules: dict):
    command = ['iptables','-L','-v','-n']
    result_command = execute_command(command)
    type_rule = "unknown"

    if len(result_command) > 0:
        rules['iptables'] = {}

        for tr in result_command:
            temp_row = tr.strip()
            if temp_row.startswith("Chain "):
                temp_type = re.match(r'Chain (.*) \(', temp_row)
                type_rule = temp_type.group(1)
                continue
            elif temp_row.startswith("pkts"):
                continue
            elif temp_row == "":
                continue

            if type_rule not in rules['iptables']:
                rules['iptables'][type_rule] = []

            rules['iptables'][type_rule].append(re.sub(' +', ' ', temp_row))

def get_fw_information():
    rules = {}
    get_ufw_state(rules)
    get_firewall_ports(rules)
    get_firewall_information(rules)
    get_iptables_information(rules)

    return rules