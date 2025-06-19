import os
import psutil
from analyzer_utils import execute_command

def device_linux_statistics():
    all_devices = {}
    devices = execute_command(['lsblk','-Sr','-o','NAME'])
    for i in range(1, len(devices)):
        device = devices[i]
        device_name = f"/dev/{device.strip()}"
        all_devices[device_name] = get_new_disk_structure()
    return all_devices

def partition_statistics(all_devices: dict):
    partitions = psutil.disk_partitions()
    for part in partitions:
        disk = psutil.disk_usage(part.mountpoint)
        device = get_device(all_devices, part.device)
        part_stat = statistics_usage(disk, part.device)
        all_devices[device]['partitions'].append(part_stat)
    calculate_device_information(all_devices)
    return all_devices

def statistics_usage(point, point_name):
    total = round(point.total / 1024 ** 3)
    used = round(point.used / 1024 ** 3)
    return {"device": point_name, "total": total, "used": used}

def get_device(all_devices, point):
    for d in all_devices.keys():
        if d in point or d == point:
            return d
    all_devices[point] = get_new_disk_structure()
    return point

def get_new_disk_structure():
    return  {"partitions": [], "total": 0, "used": 0}

def calculate_device_information(devices: dict):
    for device, info in devices.items():
        total = 0
        used = 0
        for part in info['partitions']:
            total += part['total']
            used += part['used']
        devices[device]['total'] = total
        devices[device]['used'] = used