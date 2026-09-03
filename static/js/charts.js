function renderExecutiveChart(threatCount, normalCount) {
    const ctx = document.getElementById('executiveChart');
    if (!ctx) return;

    new Chart(ctx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['Threat Alerts', 'Normal Traffic'],
            datasets: [{
                label: 'Event Distribution',
                data: [threatCount, normalCount],
                backgroundColor: ['#ef4444', '#3b82f6'],
                borderColor: '#1e293b',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: {
                y: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } },
                x: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } }
            }
        }
    });
}

function renderStatisticsChart(threatDataJSON) {
    const ctx = document.getElementById('statisticsChart');
    if (!ctx) return;

    const labels = Object.keys(threatDataJSON);
    const counts = Object.values(threatDataJSON);

    new Chart(ctx.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: counts,
                backgroundColor: ['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6'],
                borderColor: '#1e293b',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#94a3b8' } }
            }
        }
    });
}