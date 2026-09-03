document.addEventListener("DOMContentLoaded", () => {
    const socket = io();

    socket.on('connect', () => {
        console.log('[SIEM] Live WebSocket pipeline connected.');
    });

    socket.on('new_incident', (data) => {
        const stream = document.getElementById('stream');
        if (!stream) return;

        const row = document.createElement('tr');
        const isThreat = data.threat_type !== "Normal Traffic";

        row.innerHTML = `
            <td>${data.timestamp}</td>
            <td><strong>${data.source_ip}</strong></td>
            <td class="${isThreat ? 'threat-high' : ''}">${data.threat_type}</td>
            <td>${data.confidence}</td>
            <td>${data.explanation}</td>
            <td>
                <span class="badge ${data.enforcement.includes('BLOCKED') ? 'badge-blocked' : 'badge-monitored'}">
                    ${data.enforcement}
                </span>
            </td>
        `;

        stream.insertBefore(row, stream.firstChild);
    });
});