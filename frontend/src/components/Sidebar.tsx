import { Shield, Activity, Settings, Menu, X } from "lucide-react";
import { ThemeSwitch } from "./ThemeSwitch";

export function Sidebar({ isOpen, toggle }: { isOpen: boolean; toggle: () => void }) {
    return (
        <>
            {/* Mobile Backdrop */}
            {isOpen && (
                <div
                    className="fixed inset-0 z-40 bg-black/50 lg:hidden"
                    onClick={toggle}
                />
            )}

            {/* Sidebar Navigation */}
            <div className={`
        fixed inset-y-0 left-0 z-50 w-64 bg-[var(--panel)] border-r border-[var(--border)] transform transition-transform duration-300 ease-in-out
        lg:relative lg:translate-x-0
        ${isOpen ? "translate-x-0" : "-translate-x-full"}
      `}>
                <div className="flex h-16 items-center justify-between px-6 border-b border-[var(--border)]">
                    <div className="flex items-center gap-2">
                        <Shield className="h-6 w-6 text-primary-500" />
                        <span className="font-bold text-lg text-[var(--foreground)] font-[family-name:var(--font-heading)]">Kawach</span>
                    </div>
                    <button onClick={toggle} className="lg:hidden p-1 rounded-md text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800">
                        <X className="h-5 w-5" />
                    </button>
                </div>

                <nav className="p-4 space-y-2">
                    <a href="#" className="flex items-center gap-3 px-3 py-2 rounded-md bg-primary-50 dark:bg-primary-900/30 text-primary-600 dark:text-primary-400 font-medium">
                        <Activity className="h-5 w-5" />
                        Dashboard
                    </a>
                    <a href="#" className="flex items-center gap-3 px-3 py-2 rounded-md text-gray-500 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors">
                        <Settings className="h-5 w-5" />
                        Settings
                    </a>
                </nav>

                <div className="absolute bottom-0 w-full p-6 border-t border-[var(--border)] flex items-center justify-between">
                    <span className="text-sm text-gray-500 font-medium">Appearance</span>
                    <ThemeSwitch />
                </div>
            </div>
        </>
    );
}
