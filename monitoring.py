# monitoring.py — Real time container resource monitoring

import time
from collections import deque
from datetime import datetime


def get_container_stats(client, container_name):
    try:
        container = client.containers.get(container_name)
        stats = container.stats(stream=False)

        cpu_percent = calculate_cpu_percent(stats)
        mem_usage_mb = stats['memory_stats'].get('usage', 0) / 1024 / 1024
        mem_limit_mb = stats['memory_stats'].get('limit', 1) / 1024 / 1024
        mem_percent = (mem_usage_mb / mem_limit_mb * 100) if mem_limit_mb > 0 else 0

        net_rx = 0
        net_tx = 0
        if 'networks' in stats:
            for net_data in stats['networks'].values():
                net_rx += net_data.get('rx_bytes', 0)
                net_tx += net_data.get('tx_bytes', 0)

        return {
            'cpu_percent': round(cpu_percent, 2),
            'mem_usage_mb': round(mem_usage_mb, 2),
            'mem_limit_mb': round(mem_limit_mb, 2),
            'mem_percent': round(mem_percent, 2),
            'net_rx_mb': round(net_rx / 1024 / 1024, 3),
            'net_tx_mb': round(net_tx / 1024 / 1024, 3),
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }, None

    except Exception as e:
        return None, str(e)


def calculate_cpu_percent(stats):
    try:
        cpu_delta = (
            stats['cpu_stats']['cpu_usage']['total_usage'] -
            stats['precpu_stats']['cpu_usage']['total_usage']
        )
        system_delta = (
            stats['cpu_stats']['system_cpu_usage'] -
            stats['precpu_stats']['system_cpu_usage']
        )
        num_cpus = stats['cpu_stats'].get('online_cpus', 1)

        if system_delta > 0 and cpu_delta > 0:
            return (cpu_delta / system_delta) * num_cpus * 100.0
        return 0.0
    except (KeyError, ZeroDivisionError):
        return 0.0


def detect_image_drift(client, tracked_images):
    drift_results = []
    for img_name in tracked_images:
        try:
            image = client.images.get(img_name)
            current_id = image.short_id
            drift_results.append({
                'image': img_name,
                'current_id': current_id,
                'status': 'tracked'
            })
        except Exception as e:
            drift_results.append({
                'image': img_name,
                'current_id': None,
                'status': 'not_found',
                'error': str(e)
            })
    return drift_results


def init_metrics_buffer(max_points=30):
    return {
        'timestamps': deque(maxlen=max_points),
        'cpu': deque(maxlen=max_points),
        'mem': deque(maxlen=max_points)
    }


def append_metrics(buffer, stats):
    buffer['timestamps'].append(stats['timestamp'])
    buffer['cpu'].append(stats['cpu_percent'])
    buffer['mem'].append(stats['mem_percent'])
    return buffer