document.addEventListener('DOMContentLoaded', () => {
    // Elements
    const btnStart = document.getElementById('btn-start');
    const btnStop = document.getElementById('btn-stop');
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');
    const interfaceName = document.getElementById('interface-name');
    const actionMessage = document.getElementById('action-message');
    const statsGridIngress = document.getElementById('stats-grid-ingress');
    const statsGridEgress = document.getElementById('stats-grid-egress');
    const statsGridDrops = document.getElementById('stats-grid-drops');

    // State
    let isRunning = false;
    let pollInterval = null;
    let trafficChart = null;
    const chartData = {
        labels: [],
        datasets: []
    };
    const MAX_DATA_POINTS = 30;
    let previousStats = {};

    // Initialize Chart
    const ctx = document.getElementById('traffic-chart').getContext('2d');
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: chartData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 0 },
            scales: {
                x: {
                    display: true,
                    title: { display: true, text: 'Time', color: '#8b949e' },
                    ticks: { color: '#8b949e' },
                    grid: { color: '#30363d' }
                },
                y: {
                    beginAtZero: true,
                    title: { display: true, text: 'Drops / sec', color: '#8b949e' },
                    ticks: { color: '#8b949e' },
                    grid: { color: '#30363d' }
                }
            },
            plugins: {
                legend: { labels: { color: '#f0f6fc' } }
            }
        }
    });

    // Initial Status Check
    checkStatus();

    // Attach actions to global scope for the onclick attributes
    window.startFilter = startFilter;
    window.stopFilter = stopFilter;

    function setLoading(isLoading) {
        btnStart.disabled = isLoading || isRunning;
        btnStop.disabled = isLoading || !isRunning;
    }

    function showMessage(msg, isError = false) {
        actionMessage.textContent = msg;
        actionMessage.className = `message ${isError ? 'error' : 'success'}`;
        setTimeout(() => {
            actionMessage.textContent = '';
        }, 3000);
    }

    function updateUI(status) {
        isRunning = status.is_running;
        interfaceName.textContent = status.device;

        if (isRunning) {
            statusDot.className = 'dot active';
            statusText.textContent = 'ACTIVE (FILTERING)';
            statusText.style.color = 'var(--success)';
            btnStart.disabled = true;
            btnStop.disabled = false;

            // Start polling if not already
            if (!pollInterval) {
                pollInterval = setInterval(checkStatus, 1500); // Poll every 1.5s
            }

            renderStats(status.stats);
        } else {
            statusDot.className = 'dot inactive';
            statusText.textContent = 'OFFLINE';
            statusText.style.color = '';
            btnStart.disabled = false;
            btnStop.disabled = true;

            // Stop polling
            if (pollInterval) {
                clearInterval(pollInterval);
                pollInterval = null;
            }

            const emptyHtml = `
                <div class="stat-card empty-state">
                    <p>Waiting for filter activation...</p>
                </div>
            `;
            statsGridIngress.innerHTML = emptyHtml;
            statsGridEgress.innerHTML = emptyHtml;
            statsGridDrops.innerHTML = emptyHtml;
        }
    }

    function renderStatsGroup(statsGroup, container, labelClass, labelText) {
        if (!statsGroup || Object.keys(statsGroup).length === 0) {
            container.innerHTML = `
                <div class="stat-card empty-state">
                    <p>No traffic recorded.</p>
                </div>
            `;
            return;
        }

        let html = '';
        const sortedKeys = Object.keys(statsGroup).sort();

        for (const proto of sortedKeys) {
            const count = statsGroup[proto];
            const formatted = new Intl.NumberFormat().format(count);

            html += `
                <div class="stat-card">
                    <div class="stat-value ${labelClass}">${formatted}</div>
                    <div class="stat-label">${proto} ${labelText}</div>
                </div>
            `;
        }

        container.innerHTML = html;
    }

    function renderStats(stats) {
        if (!stats) return;

        renderStatsGroup(stats.ingress, statsGridIngress, 'text-success', 'Ingress');
        renderStatsGroup(stats.egress, statsGridEgress, 'text-info', 'Egress');
        renderStatsGroup(stats.drops, statsGridDrops, 'text-danger', 'Drops');

        updateChart(stats);
    }

    function updateChart(stats) {
        if (!stats) return;

        const now = new Date();
        const timeLabel = now.getHours() + ':' + String(now.getMinutes()).padStart(2, '0') + ':' + String(now.getSeconds()).padStart(2, '0');

        chartData.labels.push(timeLabel);
        if (chartData.labels.length > MAX_DATA_POINTS) {
            chartData.labels.shift();
        }

        // Process ingress
        const inKeys = Object.keys(stats.ingress || {}).sort();
        inKeys.forEach((proto, index) => {
            const labelName = `[IN] ${proto}`;
            let datasetParams = trafficChart.data.datasets.find(d => d.label === labelName);

            if (!datasetParams) {
                const colors = ['#238636', '#2ea043', '#1e6823'];
                datasetParams = {
                    label: labelName,
                    data: [],
                    borderColor: colors[index % colors.length],
                    backgroundColor: colors[index % colors.length] + '33',
                    fill: false,
                    tension: 0.4
                };
                trafficChart.data.datasets.push(datasetParams);
            }

            const currentTotal = stats.ingress[proto] || 0;
            const prevTotal = previousStats?.ingress?.[proto] || 0;
            const count = Math.max(0, currentTotal - prevTotal);
            datasetParams.data.push(count);

            if (datasetParams.data.length > MAX_DATA_POINTS) {
                datasetParams.data.shift();
            }
        });

        // Process egress
        const outKeys = Object.keys(stats.egress || {}).sort();
        outKeys.forEach((proto, index) => {
            const labelName = `[OUT] ${proto}`;
            let datasetParams = trafficChart.data.datasets.find(d => d.label === labelName);

            if (!datasetParams) {
                const colors = ['#58a6ff', '#3182ce', '#1f6feb'];
                datasetParams = {
                    label: labelName,
                    data: [],
                    borderColor: colors[index % colors.length],
                    backgroundColor: colors[index % colors.length] + '33',
                    fill: false,
                    tension: 0.4
                };
                trafficChart.data.datasets.push(datasetParams);
            }

            const currentTotal = stats.egress[proto] || 0;
            const prevTotal = previousStats?.egress?.[proto] || 0;
            const count = Math.max(0, currentTotal - prevTotal);
            datasetParams.data.push(count);

            if (datasetParams.data.length > MAX_DATA_POINTS) {
                datasetParams.data.shift();
            }
        });

        // Process drops
        const dropKeys = Object.keys(stats.drops || {}).sort();
        dropKeys.forEach((proto, index) => {
            const labelName = `[DROP] ${proto}`;
            let datasetParams = trafficChart.data.datasets.find(d => d.label === labelName);

            if (!datasetParams) {
                const colors = ['#da3633', '#b32624', '#ff7b72'];
                datasetParams = {
                    label: labelName,
                    data: [],
                    borderColor: colors[index % colors.length],
                    backgroundColor: colors[index % colors.length] + '33',
                    fill: true,
                    tension: 0.4
                };
                trafficChart.data.datasets.push(datasetParams);
            }

            const currentTotal = stats.drops[proto] || 0;
            const prevTotal = previousStats?.drops?.[proto] || 0;
            const count = Math.max(0, currentTotal - prevTotal);
            datasetParams.data.push(count);

            if (datasetParams.data.length > MAX_DATA_POINTS) {
                datasetParams.data.shift();
            }
        });

        previousStats = JSON.parse(JSON.stringify(stats));
        trafficChart.update();
    }

    // API Calls
    async function checkStatus() {
        try {
            const res = await fetch('/api/status');
            const data = await res.json();
            updateUI(data);
        } catch (e) {
            console.error('Failed to fetch status', e);
            statusText.textContent = 'SERVER DISCONNECTED';
            statusDot.className = 'dot inactive';
            statusDot.style.backgroundColor = 'var(--danger)';
        }
    }

    async function startFilter() {
        setLoading(true);
        actionMessage.textContent = 'Compiling and attaching XDP program...';
        actionMessage.className = 'message';

        try {
            const res = await fetch('/api/start', { method: 'POST' });
            const data = await res.json();

            if (data.success) {
                showMessage('Shield Activated!', false);
                checkStatus();
            } else {
                showMessage(data.message || 'Failed to start.', true);
                setLoading(false);
            }
        } catch (e) {
            showMessage('Network error while starting filter.', true);
            setLoading(false);
        }
    }

    async function stopFilter() {
        setLoading(true);
        actionMessage.textContent = 'Detaching XDP program...';
        actionMessage.className = 'message';

        try {
            const res = await fetch('/api/stop', { method: 'POST' });
            const data = await res.json();

            if (data.success) {
                showMessage('Shield Deactivated.', false);
                checkStatus();
            } else {
                showMessage(data.message || 'Failed to stop.', true);
                setLoading(false);
            }
        } catch (e) {
            showMessage('Network error while stopping filter.', true);
            setLoading(false);
        }
    }
});
