import os
import json
import pwd
from analyzer_utils import check_service
from analyzer_utils import check_process
from analyzer_utils import execute_command

def check_patroni(result_dict: dict):
    status = check_service(result_dict, "patroni")
    files_config = ['/etc/patroni/postgresql.yml', '/etc/patroni/patroni.yml']
    file_config = None
    for file_c in files_config:
        if os.path.exists(file_c):
            file_config = file_c
            break

    if status == "active" and file_config is not None:
        patroni_info = {}
        print(f"Patroni config {file_config}")
        result_command = execute_command(['patronictl','-c',file_config,'list','-f','json'])
        try:
            patroni_info = json.loads(result_command[0])
            if isinstance(patroni_info, list) and len(patroni_info) > 3:
                patroni_info = patroni_info[:3]
        except json.decoder.JSONDecodeError:
            print(f"Error read patroni config: {result_command}")
        except IndexError:
            print(f"Error result_command: {result_command}")
        result_dict['patroni_cluster'] = patroni_info

def get_data_from_postgresql(query):
    final_query = ['psql','-U','postgres','-qAtc',f'{query};']
    final_result = execute_command(final_query)
    if len(final_result) > 10:
        final_result = final_result[:10]
    return final_result

def get_postgresql_information(is_debug=False):
    if is_debug:
        print("postgresql: info collect")

    postgresql_info = {}
    attributes = ["config_file", "max_connections", "data_directory", "wal_level"]

    try:
        postgresql_user = pwd.getpwnam("postgres")
    except KeyError:
        postgresql_user = -1

    if os.getuid() == 0 and postgresql_user != -1:
        # Get configure
        for attr in attributes:
            result = get_data_from_postgresql(f"SHOW {attr}")
            try:
                result = result[0]
            except IndexError:
                result = ""
            postgresql_info[attr] = "".join(result)

        # Get list db (ограниченное количество)
        query = """SELECT pg_database.datname as "database_name", pg_size_pretty(pg_database_size(pg_database.datname)) AS size_in_mb FROM pg_database ORDER by size_in_mb DESC LIMIT 5;"""
        result = get_data_from_postgresql(query)
        for r in result:
            split_r = r.split("|")
            if len(split_r) == 2:
                dbname = split_r[0].strip()
                size = split_r[1]
                if "databases" not in postgresql_info:
                    postgresql_info['databases'] = {}

                postgresql_info['databases'][dbname] = {"size": size}

        # Get version
        result = get_data_from_postgresql('SHOW server_version;')
        postgresql_info["version"] = "".join(result).strip()
        try:
            pg_version = int("".join(result).strip().split(".")[0])
        except ValueError:
            pg_version = 0
            
        # Получаем информацию о pg_hba с ограниченным размером
        if pg_version >= 10:
            result = get_data_from_postgresql('select * from pg_hba_file_rules LIMIT 5;')
            for r in result:
                if 'pg_hba' not in postgresql_info:
                    postgresql_info['pg_hba'] = []

                postgresql_info['pg_hba'].append(r)

        # Get slot (важно для репликации)
        result = get_data_from_postgresql('select array_agg(slot_name) from pg_replication_slots;')
        postgresql_info['slot_name'] = "".join(result)

        # Get extension (с ограничением)
        result = get_data_from_postgresql('SELECT * FROM pg_extension LIMIT 5;')
        for r in result:
            split_r = r.split("|")
            if len(split_r) > 0:
                try:
                    ext_name = split_r[1].strip()
                except IndexError:
                    print(split_r)
                    ext_name = 0
                if 'extension' not in postgresql_info:
                    postgresql_info['extension'] = []

                postgresql_info['extension'].append(ext_name)

        # Get pgbouncer
        check_service(postgresql_info, "pgbouncer")
        # Get patroni
        check_patroni(postgresql_info)
        # Get walsender
        check_process(postgresql_info, "walsender")
        # Get walreceiver
        check_process(postgresql_info, "walreceiver")

    elif postgresql_user == -1:
        if is_debug:
            print("postgresql: not found")
    elif os.getuid() != 0:
        print("postgresql: current user is not root")

    if is_debug:
        print("postgresql: info collected")
    return postgresql_info