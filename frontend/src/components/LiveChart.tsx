"use client";

import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend,
    Filler
} from 'chart.js';
import { Line } from 'react-chartjs-2';
import { useTheme } from 'next-themes';

ChartJS.register(
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend,
    Filler
);

interface LiveChartProps {
    data: any;
}

export function LiveChart({ data }: LiveChartProps) {
    const { theme } = useTheme();

    const options = {
        responsive: true,
        maintainAspectRatio: false,
        animation: {
            duration: 0
        },
        scales: {
            x: {
                grid: {
                    color: theme === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)',
                },
                ticks: {
                    color: theme === 'dark' ? '#94a3b8' : '#64748b'
                }
            },
            y: {
                beginAtZero: true,
                grid: {
                    color: theme === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)'
                },
                ticks: {
                    color: theme === 'dark' ? '#94a3b8' : '#64748b'
                }
            }
        },
        plugins: {
            legend: {
                labels: {
                    color: theme === 'dark' ? '#cbd5e1' : '#475569'
                }
            }
        }
    };

    return (
        <div className="bg-[var(--panel)] border border-[var(--border)] rounded-xl p-5 shadow-[var(--shadow-card)] flex flex-col">
            <h3 className="text-lg font-semibold mb-4 text-[var(--foreground)]">Real-time Traffic Activity</h3>
            <div className="flex-1 w-full min-h-[300px] relative">
                <Line options={options} data={data} />
            </div>
        </div>
    );
}
