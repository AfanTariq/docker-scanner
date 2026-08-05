# monitoring.py — Real time container resource monitoring (Windows fixed)

from collections import deque
from datetime import datetime


def get_container_stats(client, container_name):
    try:
        container = client.containers.get(container_name)

        if container.status != 'running':
            return None, f"Container {container_name} is not running"

        stats = container.stats(stream=False)

        cpu_percent  = calculate_cpu_percent(stats)
        mem_stats    = stats.get('memory_stats', {})
        mem_usage_mb = mem_stats.get('usage', 0) / 1024 / 1024
        mem_limit    = mem_stats.get('limit', 1)
        mem_limit_mb = mem_limit / 1024 / 1024
        mem_percent  = (mem_usage_mb / mem_limit_mb * 100) if mem_limit_mb > 0 else 0

        net_rx = 0
        net_tx = 0
        networks = stats.get('networks', {})
        if networks:
            for net_data in networks.values():
                net_rx += net_data.get('rx_bytes', 0)
                net_tx += net_data.get('tx_bytes', 0)

        blkio     = stats.get('blkio_stats', {})
        io_stats  = blkio.get('io_service_bytes_recursive', []) or []
        disk_read = sum(s.get('value', 0) for s in io_stats if s.get('op') == 'read')
        disk_write = sum(s.get('value', 0) for s in io_stats if s.get('op') == 'write')

        return {
            'cpu_percent':  round(cpu_percent, 2),
            'mem_usage_mb': round(mem_usage_mb, 2),
            'mem_limit_mb': round(mem_limit_mb, 2),
            'mem_percent':  round(mem_percent, 2),
            'net_rx_mb':    round(net_rx / 1024 / 1024, 3),
            'net_tx_mb':    round(net_tx / 1024 / 1024, 3),
            'disk_read_mb': round(disk_read / 1024 / 1024, 3),
            'disk_write_mb':round(disk_write / 1024 / 1024, 3),
            'timestamp':    datetime.now().strftime('%H:%M:%S'),
            'status':       container.status
        }, None

    except Exception as e:
        return None, f"Stats error: {str(e)}"


def calculate_cpu_percent(stats):
    try:
        cpu_stats     = stats.get('cpu_stats', {})
        precpu_stats  = stats.get('precpu_stats', {})

        cpu_usage     = cpu_stats.get('cpu_usage', {})
        precpu_usage  = precpu_stats.get('cpu_usage', {})

        cpu_total     = cpu_usage.get('total_usage', 0)
        precpu_total  = precpu_usage.get('total_usage', 0)
        cpu_delta     = cpu_total - precpu_total

        system_cpu    = cpu_stats.get('system_cpu_usage', 0)
        presystem_cpu = precpu_stats.get('system_cpu_usage', 0)
        system_delta  = system_cpu - presystem_cpu

        num_cpus = cpu_stats.get('online_cpus', 1)
        if num_cpus == 0:
            percpu = cpu_usage.get('percpu_usage', [1])
            num_cpus = len(percpu) if percpu else 1

        if system_delta > 0 and cpu_delta >= 0:
            return (cpu_delta / system_delta) * num_cpus * 100.0
        return 0.0
    except Exception:
        return 0.0


def init_metrics_buffer(max_points=20):
    return {
        'timestamps':   deque(maxlen=max_points),
        'cpu':          deque(maxlen=max_points),
        'mem':          deque(maxlen=max_points),
        'net_rx':       deque(maxlen=max_points),
        'net_tx':       deque(maxlen=max_points),
        'disk_read':    deque(maxlen=max_points),
        'disk_write':   deque(maxlen=max_points),
    }


def append_metrics(buffer, stats):
    buffer['timestamps'].append(stats['timestamp'])
    buffer['cpu'].append(stats['cpu_percent'])
    buffer['mem'].append(stats['mem_percent'])
    buffer['net_rx'].append(stats['net_rx_mb'])
    buffer['net_tx'].append(stats['net_tx_mb'])
    buffer['disk_read'].append(stats['disk_read_mb'])
    buffer['disk_write'].append(stats['disk_write_mb'])
    return buffer


def get_all_running_containers(client):
    try:
        containers = []
        for c in client.containers.list():
            containers.append({
                'name':   c.name,
                'image':  c.image.tags[0] if c.image.tags else 'unknown',
                'status': c.status,
                'id':     c.short_id
            })
        return containers, None
    except Exception as e:
        return [], str(e)