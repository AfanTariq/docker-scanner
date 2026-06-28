# trends.py — Risk trend analysis across scan history

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io


def generate_risk_trend_chart(history):
    if not history or len(history) < 2:
        return None, "Need at least 2 scans in history to show a trend"

    sorted_history = sorted(history, key=lambda x: x.get('id', 0))

    timestamps = [h.get('timestamp', '')[5:16] for h in sorted_history]
    scores = [h.get('risk_score', 0) for h in sorted_history]
    targets = [h.get('target', 'Unknown') for h in sorted_history]

    fig, ax = plt.subplots(figsize=(10, 4.5))

    ax.plot(
        range(len(scores)), scores,
        marker='o', linewidth=2, markersize=7,
        color='#D85A30', markerfacecolor='#D85A30'
    )

    ax.fill_between(
        range(len(scores)), scores,
        alpha=0.1, color='#D85A30'
    )

    ax.axhspan(0, 40, color='#639922', alpha=0.08)
    ax.axhspan(40, 70, color='#EF9F27', alpha=0.08)
    ax.axhspan(70, 100, color='#E24B4A', alpha=0.08)

    ax.set_ylim(0, 105)
    ax.set_ylabel('Risk score', fontsize=10)
    ax.set_xlabel('Scan number', fontsize=10)
    ax.set_xticks(range(len(scores)))
    ax.set_xticklabels([str(i+1) for i in range(len(scores))], fontsize=9)
    ax.grid(True, alpha=0.2)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    for i, (score, target) in enumerate(zip(scores, targets)):
        ax.annotate(
            target[:15],
            (i, score),
            textcoords="offset points",
            xytext=(0, 12),
            ha='center',
            fontsize=7,
            color='#555555'
        )

    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=120, bbox_inches='tight')
    buf.seek(0)
    plt.close(fig)

    return buf, None


def generate_severity_breakdown_chart(history):
    if not history:
        return None, "No history available"

    sorted_history = sorted(history, key=lambda x: x.get('id', 0))

    critical_vals = [h['counts'].get('Critical', 0) for h in sorted_history]
    high_vals     = [h['counts'].get('High', 0) for h in sorted_history]
    medium_vals   = [h['counts'].get('Medium', 0) for h in sorted_history]
    low_vals      = [h['counts'].get('Low', 0) for h in sorted_history]

    x = range(len(sorted_history))

    fig, ax = plt.subplots(figsize=(10, 4.5))

    ax.bar(x, critical_vals, label='Critical', color='#A32D2D')
    ax.bar(x, high_vals, bottom=critical_vals, label='High', color='#BA7517')
    ax.bar(
        x, medium_vals,
        bottom=[c+h for c,h in zip(critical_vals, high_vals)],
        label='Medium', color='#185FA5'
    )
    ax.bar(
        x, low_vals,
        bottom=[c+h+m for c,h,m in zip(critical_vals, high_vals, medium_vals)],
        label='Low', color='#3B6D11'
    )

    ax.set_xlabel('Scan number', fontsize=10)
    ax.set_ylabel('Number of findings', fontsize=10)
    ax.set_xticks(list(x))
    ax.set_xticklabels([str(i+1) for i in x], fontsize=9)
    ax.legend(loc='upper right', fontsize=9, frameon=False)
    ax.grid(True, alpha=0.15, axis='y')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=120, bbox_inches='tight')
    buf.seek(0)
    plt.close(fig)

    return buf, None


def calculate_trend_stats(history):
    if not history or len(history) < 2:
        return None

    sorted_history = sorted(history, key=lambda x: x.get('id', 0))
    scores = [h.get('risk_score', 0) for h in sorted_history]

    first_score = scores[0]
    last_score = scores[-1]
    change = last_score - first_score
    avg_score = sum(scores) / len(scores)
    best_score = min(scores)
    worst_score = max(scores)

    trend = "improving" if change < 0 else "worsening" if change > 0 else "stable"

    return {
        'first_score': first_score,
        'last_score': last_score,
        'change': change,
        'avg_score': round(avg_score, 1),
        'best_score': best_score,
        'worst_score': worst_score,
        'trend': trend,
        'total_scans': len(history)
    }