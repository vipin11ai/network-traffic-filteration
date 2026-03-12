"use client";

import { useEffect, useState, useRef } from "react";
import { Sidebar } from "@/components/Sidebar";
import { StatCard } from "@/components/StatCard";
import { LiveChart } from "@/components/LiveChart";
import { Play, Square, Menu, ShieldAlert } from "lucide-react";

export default function Dashboard() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [statusText, setStatusText] = useState("Filter is offline");
  const [interfaceName, setInterfaceName] = useState("auto");

  // Use previous stats for delta calculation
  const prevStatsRef = useRef<any>(null);

  // Chart Data State
  const [chartData, setChartData] = useState<any>({
    labels: [],
    datasets: []
  });

  // Latest Stats State for Cards
  const [latestStats, setLatestStats] = useState<{
    ingress: Record<string, number>;
    egress: Record<string, number>;
    drops: Record<string, number>;
  }>({
    ingress: {},
    egress: {},
    drops: {}
  });

  // Fetch status on load
  useEffect(() => {
    fetch("http://localhost:5000/api/status")
      .then(res => res.json())
      .then(data => {
        setIsRunning(data.status === "running");
        setStatusText(data.status === "running" ? "Filter is ACTIVE" : "Filter is offline");
        setInterfaceName(data.interface || "auto");
      })
      .catch(err => console.error("Error fetching status", err));
  }, []);

  // Set up polling when running
  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (isRunning) {
      interval = setInterval(() => {
        fetch("http://localhost:5000/api/status")
          .then(res => res.json())
          .then(data => {
            if (data.status !== "running") {
              setIsRunning(false);
              setStatusText("Filter is offline");
              return;
            }

            if (data.stats) {
              setLatestStats(data.stats);
              updateChart(data.stats);
            }
          })
          .catch(err => console.error(err));
      }, 1000);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isRunning, chartData]);

  const updateChart = (stats: any) => {
    const MAX_POINTS = 30;
    const now = new Date();
    const timeLabel = `${now.getHours()}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;

    setChartData((prev: any) => {
      const newLabels = [...prev.labels, timeLabel];
      if (newLabels.length > MAX_POINTS) newLabels.shift();

      const newDatasets = [...prev.datasets];

      const processCategory = (category: string, labelPrefix: string, colors: string[], isFill: boolean) => {
        const keys = Object.keys(stats[category] || {}).sort();
        keys.forEach((proto, index) => {
          const labelName = `[${labelPrefix}] ${proto}`;
          let dataset = newDatasets.find(d => d.label === labelName);

          if (!dataset) {
            dataset = {
              label: labelName,
              data: [],
              borderColor: colors[index % colors.length],
              backgroundColor: colors[index % colors.length] + '33',
              fill: isFill,
              tension: 0.4
            };
            newDatasets.push(dataset);
          }

          const currentTotal = stats[category][proto] || 0;
          const prevTotal = prevStatsRef.current?.[category]?.[proto] || 0;
          const diff = Math.max(0, currentTotal - prevTotal);

          const newData = [...dataset.data, diff];
          if (newData.length > MAX_POINTS) newData.shift();
          dataset.data = newData;
        });
      };

      processCategory("ingress", "IN", ['#10B981', '#34D399', '#059669'], false);
      processCategory("egress", "OUT", ['#35C9FF', '#3B6CFF', '#2A55E6'], false);
      processCategory("drops", "DROP", ['#FF8A3D', '#EF4444', '#DC2626'], true);

      return { labels: newLabels, datasets: newDatasets };
    });

    prevStatsRef.current = JSON.parse(JSON.stringify(stats));
  };

  const handleToggle = async () => {
    try {
      if (isRunning) {
        setStatusText("Stopping filter...");
        const res = await fetch("http://localhost:5000/api/stop", { method: "POST" });
        const data = await res.json();
        if (data.status === "stopped") {
          setIsRunning(false);
          setStatusText("Filter stopped successfully");
        } else {
          setStatusText("Failed to stop filter");
        }
      } else {
        setStatusText("Starting filter...");
        const res = await fetch("http://localhost:5000/api/start", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ interface: interfaceName })
        });
        const data = await res.json();
        if (data.status === "running") {
          setIsRunning(true);
          setStatusText("Filter is ACTIVE");
          setChartData({ labels: [], datasets: [] });
          prevStatsRef.current = null;
        } else {
          setStatusText("Failed to start filter");
        }
      }
    } catch (err) {
      setStatusText("Error communicating with backend");
    }
  };

  return (
    <div className="flex height-screen bg-[var(--background)] transition-colors duration-200">
      <Sidebar isOpen={sidebarOpen} toggle={() => setSidebarOpen(!sidebarOpen)} />

      <div className="flex-1 flex flex-col h-screen overflow-hidden">
        {/* Header */}
        <header className="h-16 flex shrink-0 items-center justify-between px-4 sm:px-6 lg:px-8 bg-[var(--panel)] border-b border-[var(--border)]">
          <div className="flex items-center gap-4">
            <button onClick={() => setSidebarOpen(true)} className="p-2 -ml-2 rounded-md lg:hidden hover:bg-gray-100 dark:hover:bg-gray-800">
              <Menu className="h-5 w-5 text-gray-500" />
            </button>
            <h1 className="text-xl font-bold text-[var(--foreground)] hidden sm:block">Traffic Analytics</h1>
          </div>

          <div className="flex items-center gap-4">
            <div className="hidden sm:flex items-center gap-2 text-sm text-[var(--foreground)] font-medium">
              <span className="text-gray-500">Interface:</span>
              <input
                type="text"
                value={interfaceName}
                onChange={(e) => setInterfaceName(e.target.value)}
                disabled={isRunning}
                className="bg-[var(--background)] border border-[var(--border)] rounded px-3 py-1.5 w-24 text-[var(--foreground)] disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-primary-500"
              />
            </div>
            <button
              onClick={handleToggle}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-white transition-all shadow-[var(--shadow-softGlow)] ${isRunning
                ? "bg-red-500 hover:bg-red-600"
                : "bg-primary-500 hover:bg-primary-600"
                }`}
            >
              {isRunning ? <><Square className="h-4 w-4" /> Stop Shield</> : <><Play className="h-4 w-4" /> Activate Shield</>}
            </button>
          </div>
        </header>

        {/* Main Content */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8">
          <div className="max-w-[1600px] mx-auto space-y-6">

            {/* Status Banner */}
            <div className={`p-4 rounded-xl border flex items-center gap-3 ${isRunning
              ? "bg-secondary-50 dark:bg-secondary-900/20 border-secondary-200 dark:border-secondary-900/50 text-secondary-700 dark:text-secondary-400"
              : "bg-gray-50 dark:bg-gray-800/50 border-gray-200 dark:border-gray-800 text-gray-600 dark:text-gray-400"
              }`}>
              <div className={`h-3 w-3 rounded-full ${isRunning ? "bg-secondary-500 animate-pulse" : "bg-gray-400"}`} />
              <span className="font-medium">{statusText}</span>
            </div>

            {/* Desktop Layout: 3 Columns - Main Analytics / Insight Panel */}
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">

              {/* Left/Middle: Charts & Primary Stats */}
              <div className="xl:col-span-2 space-y-6">
                <LiveChart data={chartData} />

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                  {/* Render Ingress */}
                  {Object.keys(latestStats.ingress).length > 0 ? (
                    Object.entries(latestStats.ingress).map(([proto, count]) => (
                      <StatCard key={`in-${proto}`} title="Allowed Ingress" value={count} protocol={proto} type="ingress" />
                    ))
                  ) : (
                    <div className="bg-[var(--panel)] border border-[var(--border)] rounded-xl p-5 shadow-[var(--shadow-card)] flex items-center justify-center text-gray-400 text-sm h-[132px]">
                      Waiting for ingress...
                    </div>
                  )}

                  {/* Render Egress */}
                  {Object.keys(latestStats.egress).length > 0 ? (
                    Object.entries(latestStats.egress).map(([proto, count]) => (
                      <StatCard key={`out-${proto}`} title="Monitored Egress" value={count} protocol={proto} type="egress" />
                    ))
                  ) : (
                    <div className="bg-[var(--panel)] border border-[var(--border)] rounded-xl p-5 shadow-[var(--shadow-card)] flex items-center justify-center text-gray-400 text-sm h-[132px]">
                      Waiting for egress...
                    </div>
                  )}
                </div>
              </div>

              {/* Right: Insights Panel / Threat Blocks */}
              <div className="space-y-6">
                <div className="bg-[var(--panel)] border border-[var(--border)] rounded-xl p-5 shadow-[var(--shadow-card)]">
                  <h3 className="text-lg font-semibold mb-4 text-[var(--foreground)]">Threat Insights</h3>
                  <div className="space-y-4">
                    {Object.keys(latestStats.drops).length > 0 ? (
                      Object.entries(latestStats.drops).map(([proto, count]) => (
                        <div key={`drop-${proto}`} className="p-4 bg-red-50 dark:bg-red-900/10 border border-red-100 dark:border-red-900/30 rounded-lg">
                          <div className="flex justify-between items-center mb-1">
                            <span className="font-medium text-red-700 dark:text-red-400">Dropped {proto}</span>
                            <span className="text-xs font-bold bg-red-100 dark:bg-red-900/50 text-red-600 dark:text-red-300 px-2 py-1 rounded-full flex items-center gap-1">
                              <ShieldAlert className="w-3 h-3" /> Threat
                            </span>
                          </div>
                          <div className="text-2xl font-bold text-red-600 dark:text-red-500 mt-2">
                            {new Intl.NumberFormat().format(count)}
                          </div>
                          <p className="text-xs text-red-500/80 mt-1">Malicious packets blocked by firewall</p>
                        </div>
                      ))
                    ) : (
                      <div className="text-center p-8 text-gray-400 text-sm border border-dashed border-[var(--border)] rounded-lg">
                        Shield is active. No threats detected.
                      </div>
                    )}
                  </div>
                </div>

                <div className="bg-[var(--panel)] border border-[var(--border)] rounded-xl p-5 shadow-[var(--shadow-card)]">
                  <h3 className="text-sm font-semibold mb-4 text-gray-500 uppercase tracking-wider">Active Kernel Rules</h3>
                  <ul className="space-y-3 text-sm text-[var(--foreground)]">
                    <li className="flex items-start gap-2">
                      <div className="mt-1.5 h-1.5 w-1.5 rounded-full bg-secondary-500 shrink-0" />
                      <span>Allow inbound ICMP Echo (Pings) and log traffic</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <div className="mt-1.5 h-1.5 w-1.5 rounded-full bg-red-500 shrink-0" />
                      <span>Drop UDP connectionless floods unconditionally</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <div className="mt-1.5 h-1.5 w-1.5 rounded-full bg-red-500 shrink-0" />
                      <span>Intercept and drop TCP SYN Floods targeting Port 80</span>
                    </li>
                  </ul>
                </div>
              </div>

            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
