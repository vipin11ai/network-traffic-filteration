import { ArrowUpRight, ArrowDownRight, ShieldAlert } from "lucide-react";

interface StatCardProps {
    title: string;
    value: number;
    type: "ingress" | "egress" | "drop";
    protocol: string;
}

export function StatCard({ title, value, type, protocol }: StatCardProps) {
    // Determine styling based on type
    const isIngress = type === "ingress";
    const isEgress = type === "egress";
    const isDrop = type === "drop";

    let colorClasses = "";
    let Icon = null;

    if (isIngress) {
        colorClasses = "text-secondary-500 dark:text-secondary-400"; // Traffic Green
        Icon = ArrowDownRight;
    } else if (isEgress) {
        colorClasses = "text-accent-cyan dark:text-accent-cyan"; // Cyan
        Icon = ArrowUpRight;
    } else {
        colorClasses = "text-red-500 dark:text-red-400"; // Danger Drop
        Icon = ShieldAlert;
    }

    return (
        <div className="bg-[var(--panel)] border border-[var(--border)] rounded-xl p-5 shadow-[var(--shadow-card)] flex flex-col justify-between">
            <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">{title}</h3>
                <div className={`p-2 rounded-lg bg-opacity-10 dark:bg-opacity-20 ${isIngress ? "bg-secondary-500 text-secondary-600 dark:text-secondary-400" :
                        isEgress ? "bg-accent-cyan text-accent-cyan" :
                            "bg-red-500 text-red-600 dark:text-red-400"
                    }`}>
                    <Icon className="h-4 w-4" />
                </div>
            </div>
            <div>
                <div className={`text-3xl font-bold ${colorClasses}`}>
                    {new Intl.NumberFormat().format(value)}
                </div>
                <p className="text-xs text-gray-400 mt-1 uppercase tracking-wider">{protocol} Traffic</p>
            </div>
        </div>
    );
}
