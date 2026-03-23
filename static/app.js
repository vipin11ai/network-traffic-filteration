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
    const attackBanner = document.getElementById('attack-banner');
    const attackBannerText = document.getElementById('attack-banner-text');

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
        isRunning = status.status === 'running';
        interfaceName.textContent = status.interface;

        if (isRunning) {
            statusDot.className = 'dot active';
            
            // Handle Attack Status
            const attackStatus = status.attack_status || "NORMAL";
            if (attackStatus !== "NORMAL") {
                statusText.textContent = `UNDER ATTACK: ${attackStatus}`;
                statusText.style.color = 'var(--danger)';
                statusDot.style.backgroundColor = 'var(--danger)';
                statusDot.classList.add('pulse');
                
                // Show Banner
                attackBanner.classList.remove('hidden');
                attackBannerText.textContent = `CRITICAL: ${attackStatus} DETECTED! FILTER IS IN EFFECT.`;
            } else {
                statusText.textContent = 'ACTIVE (FILTERING)';
                statusText.style.color = 'var(--success)';
                statusDot.style.backgroundColor = 'var(--success)';
                statusDot.classList.remove('pulse');
                
                // Hide Banner
                attackBanner.classList.add('hidden');
            }
            
            btnStart.disabled = true;
            btnStop.disabled = false;

            // Start polling if not already
            if (!pollInterval) {
                pollInterval = setInterval(checkStatus, 1000); // Poll every 1s
            }

            renderStats(status.stats);
        } else {
            statusDot.className = 'dot inactive';
            statusText.textContent = 'OFFLINE';
            statusText.style.color = '';
            statusDot.style.backgroundColor = '';
            statusDot.classList.remove('pulse');
            btnStart.disabled = false;
            btnStop.disabled = true;

            // Stop polling
            if (pollInterval) {
                clearInterval(pollInterval);
                pollInterval = null;
            }

            attackBanner.classList.add('hidden');

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

    function renderStatsGroup(statsGroup, ppsGroup, container, labelClass, labelText) {
        if (!statsGroup || Object.keys(statsGroup).length === 0) {
            container.innerHTML = `
                <div class="stat-card empty-state">
                    <p>No traffic recorded.</p>
                </div>
            `;
            return;
        }

        let html = '';
        const sortedKeys = Object.keys(statsGroup).sort((a, b) => (ppsGroup?.[b] || 0) - (ppsGroup?.[a] || 0));

        for (const proto of sortedKeys) {
            const count = statsGroup[proto];
            const pps = ppsGroup?.[proto] || 0;
            const formattedTotal = new Intl.NumberFormat().format(count);
            const formattedPPS = new Intl.NumberFormat().format(pps);

            html += `
                <div class="stat-card">
                    <div class="stat-value ${labelClass}">${formattedPPS} <small>pps</small></div>
                    <div class="stat-label">${proto}</div>
                    <div class="stat-total">Total: ${formattedTotal}</div>
                </div>
            `;
        }

        container.innerHTML = html;
    }

    function renderStats(stats) {
        if (!stats) return;

        const pps = stats.pps || { ingress: {}, egress: {}, drops: {} };

        renderStatsGroup(stats.ingress, pps.ingress, statsGridIngress, 'text-success', 'Ingress');
        renderStatsGroup(stats.egress, pps.egress, statsGridEgress, 'text-info', 'Egress');
        renderStatsGroup(stats.drops, pps.drops, statsGridDrops, 'text-danger', 'Drops');

        updateChart(stats);
    }

    function updateChart(stats) {
        if (!stats || !stats.pps) return;

        const now = new Date();
        const timeLabel = now.getHours() + ':' + String(now.getMinutes()).padStart(2, '0') + ':' + String(now.getSeconds()).padStart(2, '0');

        chartData.labels.push(timeLabel);
        if (chartData.labels.length > MAX_DATA_POINTS) {
            chartData.labels.shift();
        }

        const pps = stats.pps;

        // Process ingress
        const inKeys = Object.keys(pps.ingress || {}).sort();
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

            const val = pps.ingress[proto] || 0;
            datasetParams.data.push(val);

            if (datasetParams.data.length > MAX_DATA_POINTS) {
                datasetParams.data.shift();
            }
        });

        // Process egress
        const outKeys = Object.keys(pps.egress || {}).sort();
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

            const val = pps.egress[proto] || 0;
            datasetParams.data.push(val);

            if (datasetParams.data.length > MAX_DATA_POINTS) {
                datasetParams.data.shift();
            }
        });

        // Process drops
        const dropKeys = Object.keys(pps.drops || {}).sort();
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

            const val = pps.drops[proto] || 0;
            datasetParams.data.push(val);

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

            if (data.status === 'running') {
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

            if (data.status === 'stopped') {
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
