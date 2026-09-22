import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { 
  LayoutDashboard, Activity, List, Search, Server, 
  AlertTriangle, GitBranch, FileText, Settings, 
  ChevronLeft, ChevronRight, Shield, Zap
} from 'lucide-react';
import { cn } from '../utils/helpers';

interface SidebarProps {
  isCollapsed: boolean;
  onToggle: () => void;
}

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard, roles: ['admin', 'analyst', 'viewer'] },
  { name: 'Threat Overview', href: '/threat-overview', icon: Activity, roles: ['admin', 'analyst', 'viewer'] },
  { name: 'Incidents', href: '/incidents', icon: AlertTriangle, roles: ['admin', 'analyst', 'viewer'] },
  { name: 'Events', href: '/events', icon: List, roles: ['admin', 'analyst', 'viewer'] },
  { name: 'Investigation', href: '/investigation', icon: Search, roles: ['admin', 'analyst'] },
  { name: 'IP Analysis', href: '/ip-analysis', icon: Server, roles: ['admin', 'analyst'] },
  { name: 'Services', href: '/services', icon: Server, roles: ['admin'] },
  { name: 'Alerts', href: '/alerts', icon: Zap, roles: ['admin', 'analyst'] },
  { name: 'MITRE ATT&CK', href: '/mitre', icon: GitBranch, roles: ['admin', 'analyst', 'viewer'] },
  { name: 'Reports', href: '/reports', icon: FileText, roles: ['admin'] },
  { name: 'Settings', href: '/settings', icon: Settings, roles: ['admin'] },
];

export function Sidebar({ isCollapsed, onToggle }: SidebarProps) {
  const location = useLocation();
  const { user } = useAuth();

  return (
    <aside
      className={cn(
        'fixed left-0 top-0 z-40 h-full bg-white border-r border-gray-200 transition-all duration-300',
        isCollapsed ? 'w-16' : 'w-64'
      )}
    >
      <div className="flex flex-col h-full">
        <div className={cn('flex items-center justify-between h-16 px-4 border-b border-gray-200', isCollapsed && 'justify-center')}>
          {!isCollapsed && (
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-primary-600 flex items-center justify-center">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <span className="font-bold text-lg text-gray-900">HoneyTrap</span>
            </div>
          )}
          <button
            onClick={onToggle}
            className={cn(
              'p-1.5 rounded-lg text-gray-500 hover:text-gray-700 hover:bg-gray-100 transition-colors',
              isCollapsed && 'mx-auto'
            )}
            aria-label={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {isCollapsed ? <ChevronRight className="w-5 h-5" /> : <ChevronLeft className="w-5 h-5" />}
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1" role="navigation" aria-label="Main navigation">
          {navigation
            .filter(item => !user || item.roles.includes(user.role))
            .map((item) => {
              const isActive = location.pathname === item.href || 
                (item.href !== '/' && location.pathname.startsWith(item.href));
              
              return (
                <NavLink
                  key={item.name}
                  to={item.href}
                  className={cn(
                    'sidebar-link',
                    isActive && 'sidebar-link-active',
                    isCollapsed && 'justify-center px-2'
                  )}
                  title={isCollapsed ? item.name : undefined}
                  aria-current={isActive ? 'page' : undefined}
                >
                  <item.icon className="w-5 h-5 flex-shrink-0" aria-hidden="true" />
                  {!isCollapsed && <span>{item.name}</span>}
                </NavLink>
              );
            })}
        </nav>

        <div className={cn('p-4 border-t border-gray-200', isCollapsed && 'hidden')}>
          <div className="text-xs text-gray-500 text-center">
            HoneyTrap v2.0.0
          </div>
        </div>
      </div>
    </aside>
  );
}

import { useAuth } from '../context/AuthContext';