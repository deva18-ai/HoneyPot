import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { 
  Server, Shield, AlertTriangle, Activity, 
  Settings, Loader2, ChevronUp, ChevronDown,
  ToggleLeft, ToggleRight, Wifi, WifiOff
} from 'lucide-react';
import { cn, formatRelativeTime, getRiskLevelBadge } from '../utils/helpers';
import type { PaginatedResponse } from '../types';

interface ServiceStatus {
  name: string;
  port: number;
  status: 'active' | 'inactive';
  events_24h: number;
  alerts_24h: number;
  connections: number;
}

export function Services() {
  const [services, setServices] = useState<ServiceStatus[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [sessionStats] = await Promise.all([
        api.getSessionStats(24),
      ]);
      setStats(sessionStats);
      
      const serviceList: ServiceStatus[] = [
        { name: 'SSH', port: 2222, status: 'active', events_24h: 0, alerts_24h: 0, connections: 0 },
        { name: 'FTP', port: 2121, status: 'active', events_24h: 0, alerts_24h: 0, connections: 0 },
        { name: 'Telnet', port: 2323, status: 'active', events_24h: 0, alerts_24h: 0, connections: 0 },
        { name: 'Database', port: 9090, status: 'active', events_24h: 0, alerts_24h: 0, connections: 0 },
        { name: 'HTTP Honeypot', port: 8081, status: 'inactive', events_24h: 0, alerts_24h: 0, connections: 0 },
      ];
      
      if (sessionStats?.by_service) {
        serviceList.forEach(s => {
          const stat = sessionStats.by_service[s.name.toUpperCase()] || sessionStats.by_service[s.name];
          if (stat) {
            s.events_24h = stat;
          }
        });
      }
      
      setServices(serviceList);
    } catch (error) {
      console.error('Failed to fetch services:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  const toggleService = async (service: ServiceStatus) => {
    // Would call API to toggle service
    console.log('Toggle service:', service.name, service.status);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Services</h1>
          <p className="text-gray-500">Manage and monitor honeypot services</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {services.map((service, index) => (
          <div key={service.name} className="card">
            <div className="card-body">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className={cn('w-12 h-12 rounded-xl flex items-center justify-center',
                    service.status === 'active' ? 'bg-success-100' : 'bg-gray-100'
                  )}>
                    <Server className={cn('w-6 h-6', service.status === 'active' ? 'text-success-600' : 'text-gray-400')} />
                  </div>
                  <div>
                    <h3 className="font-semibold text-lg">{service.name}</h3>
                    <p className="text-sm text-gray-500">Port {service.port}</p>
                  </div>
                </div>
                <button
                  onClick={() => toggleService(service)}
                  className={cn('relative w-12 h-7 rounded-full transition-colors',
                    service.status === 'active' ? 'bg-success-500' : 'bg-gray-300'
                  )}
                  role="switch"
                  aria-checked={service.status === 'active'}
                >
                  <span className={cn('absolute top-0.5 w-6 h-6 rounded-full bg-white shadow-md transition-transform',
                    service.status === 'active' ? 'translate-x-5' : 'translate-x-0.5'
                  )} />
                </button>
              </div>

              <div className="grid grid-cols-3 gap-4 mb-4">
                <div className="text-center p-3 bg-gray-50 rounded-lg">
                  <p className="text-2xl font-bold text-gray-900">{service.events_24h}</p>
                  <p className="text-xs text-gray-500">Events (24h)</p>
                </div>
                <div className="text-center p-3 bg-gray-50 rounded-lg">
                  <p className="text-2xl font-bold text-danger-600">{service.alerts_24h}</p>
                  <p className="text-xs text-gray-500">Alerts (24h)</p>
                </div>
                <div className="text-center p-3 bg-gray-50 rounded-lg">
                  <p className="text-2xl font-bold text-primary-600">{service.connections}</p>
                  <p className="text-xs text-gray-500">Active Connections</p>
                </div>
              </div>

              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-500">Status</span>
                  <span className={cn('font-medium', service.status === 'active' ? 'text-success-600' : 'text-gray-500')}>
                    {service.status === 'active' ? 'Running' : 'Stopped'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Last Activity</span>
                  <span className="font-mono text-gray-900">
                    {service.events_24h > 0 ? 'Active' : 'No recent activity'}
                  </span>
                </div>
              </div>

              <div className="pt-4 border-t border-gray-200 flex gap-2">
                <button className="btn-secondary flex-1 text-sm">
                  <Settings className="w-4 h-4 mr-1" />
                  Configure
                </button>
                <button className="btn-ghost flex-1 text-sm" onClick={() => console.log('View logs:', service.name)}>
                  Logs
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="card">
        <div className="card-header">
          <h2 className="text-lg font-semibold text-gray-900">Service Configuration</h2>
        </div>
        <div className="card-body">
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Service</th>
                  <th>Port</th>
                  <th>Protocol</th>
                  <th>Banner</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {[
                  { name: 'SSH', port: 2222, protocol: 'TCP', banner: 'SSH-2.0-OpenSSH_8.9-HoneyTrap', status: 'active' },
                  { name: 'FTP', port: 2121, protocol: 'TCP', banner: '220 HoneyTrap FTP Service', status: 'active' },
                  { name: 'Telnet', port: 2323, protocol: 'TCP', banner: 'Welcome to HoneyTrap Telnet', status: 'active' },
                  { name: 'Database', port: 9090, protocol: 'TCP', banner: 'PostgreSQL 15.2 HoneyTrap Database', status: 'active' },
                  { name: 'HTTP Honeypot', port: 8081, protocol: 'TCP', banner: 'Custom HTTP responses', status: 'inactive' },
                ].map((svc, i) => (
                  <tr key={i}>
                    <td className="font-medium">{svc.name}</td>
                    <td className="font-mono">{svc.port}</td>
                    <td><span className="px-2 py-0.5 text-xs rounded bg-gray-100">{svc.protocol}</span></td>
                    <td className="font-mono text-sm max-w-xs truncate">{svc.banner}</td>
                    <td>
                      <span className={cn('px-2 py-0.5 text-xs rounded-full',
                        svc.status === 'active' ? 'bg-success-100 text-success-700' : 'bg-gray-100 text-gray-700'
                      )}>
                        {svc.status}
                      </span>
                    </td>
                    <td>
                      <button className="btn-ghost text-sm">Edit</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}