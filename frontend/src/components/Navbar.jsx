import React, { useMemo } from 'react';
import { NAVIGATION_ITEMS, VIEWS } from '../constants/views';
import './Navbar.css';

const Navbar = ({
    currentView,
    onNavigate,
    collapsed,
    onToggleCollapse,
    searchQuery,
    onSearchChange,
    theme,
    onToggleTheme,
    criticalAlertsCount = 0
}) => {
    const filteredNavItems = useMemo(() => {
        if (!searchQuery) return NAVIGATION_ITEMS;
        return NAVIGATION_ITEMS.filter(item =>
            item.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
            item.description.toLowerCase().includes(searchQuery.toLowerCase())
        );
    }, [searchQuery]);

    return (
        <aside
            className={`shell-nav ${collapsed ? 'sidebar-collapsed' : ''}`}
            role="navigation"
            aria-label="Main navigation"
        >
            <div className={`nav-header ${collapsed ? 'collapsed' : ''}`}>
                <div className="nav-brand">
                    <span className="brand-icon" title="DevOps Shield">🛡️</span>
                    {!collapsed && <span className="brand-text">DEVOPS SHIELD</span>}
                </div>
            </div>

            {/* Search */}
            {!collapsed && (
                <div className="nav-search">
                    <input
                        id="nav-search"
                        type="text"
                        placeholder="Search (Ctrl+K)..."
                        value={searchQuery}
                        onChange={(e) => onSearchChange(e.target.value)}
                        aria-label="Search navigation items"
                    />
                    <span className="search-icon">🔍</span>
                </div>
            )}

            {/* Navigation Items */}
            <nav className="nav-items">
                {filteredNavItems.map((item) => (
                    <button
                        key={item.id}
                        type="button"
                        className={`nav-link ${item.id === currentView ? 'active' : ''}`}
                        onClick={() => onNavigate(item.id)}
                        aria-label={`${item.label} - ${item.description}`}
                        aria-current={item.id === currentView ? 'page' : undefined}
                        title={`${item.label} (${item.shortcut})`}
                    >
                        <span className="nav-icon" aria-hidden="true">{item.icon}</span>
                        {!collapsed && (
                            <span className="nav-text">
                                <span className="nav-label">{item.label}</span>
                                <span className="nav-description">{item.description}</span>
                            </span>
                        )}
                        {item.id === VIEWS.ALERTS && criticalAlertsCount > 0 && (
                            <span className="nav-badge" aria-label={`${criticalAlertsCount} critical alerts`}>
                                {criticalAlertsCount}
                            </span>
                        )}
                    </button>
                ))}
            </nav>

            {/* Footer */}
            <div className="nav-footer">
                {!collapsed && (
                    <div className="footer-info">
                        <span className="muted">v1.2.0 · {new Date().getFullYear()}</span>
                    </div>
                )}
                <div className="footer-actions">
                    <button
                        className="footer-btn"
                        onClick={onToggleTheme}
                        aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
                        title={`Toggle theme`}
                        style={collapsed ? { margin: '0 auto' } : {}}
                    >
                        <span className="theme-icon">{theme === 'dark' ? '☀️' : '🌙'}</span>
                    </button>
                </div>
            </div>
        </aside>
    );
};

export default Navbar;
