import re
import json
from analyzer_utils import execute_command

def get_docker_information():
    docker_info = []
    result_array = []
    try:
        result_array = execute_command(['docker','ps','--format','json'])
    finally:
        if "command not found" not in "".join(result_array) and "docker: not found" not in "".join(result_array):
            for line in result_array:
                try:
                    json_line = json.loads(line)
                    docker_info.append({"name": json_line["Names"]})
                except TypeError:
                    pass
                except json.decoder.JSONDecodeError:
                    print("docker: error list containers")

    return docker_info

def get_sessions_information():
    regexp = r"^(.*) pts.*([\d]{4}.*) - .*$"
    session = {}
    sessions_info = execute_command(['last','--time-format','iso','-w'])
    if len(sessions_info) == 0:
        sessions_info = execute_command(['last','-w'])
        regexp = r"^(.*) pts.*([\w]{3}.*) - .*$"
    for line in sessions_info:
        search_obj = re.search(regexp, line)
        if search_obj:
            login = search_obj.group(1)
            date = search_obj.group(2)
            if login not in session:
                session[login] = {"last_login": date}
    return session
