import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { 
  Search, Filter, ChevronLeft, ChevronRight, 
  Bell, Check, X, Download, Loader2, 
  ChevronUp, ChevronDown, AlertTriangle, Clock
} from 'lucide-react';
import { cn, formatRelativeTime, getRiskLevelBadge } from '../utils/helpers';
import type { Alert, PaginatedResponse } from '../types';

const ALERT_TYPES = ['all', 'BRUTE_FORCE', 'MULTI_SERVICE_SCAN', 'HONEYTOKEN_TRIGGERED', 'EXPLOIT_ATTEMPT', 'ANOMALY_SPIKE', 'PORT_SCAN', 'WEB_RECON', 'CREDENTIAL_ABUSE'];

export function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [stats, setStats] = useState<any>(null);
  const [pagination, setPagination] = useState({ page: 1, page_size: 50, total: 0, total_pages: 0 });
  const [filters, setFilters] = useState({
    alert_type: 'all',
    acknowledged: 'all',
    start_time: '',
    end_time: '',
  });
  const [sortConfig, setSortConfig] = useState<{ key: string; direction: 'asc' | 'desc' }>({ key: 'created_at', direction: 'desc' });
  const [selectedIds, setSelectedIds] = useState<number[]>([]);

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [alertsResponse, statsData] = await Promise.all([
        api.getAlerts({
          page: pagination.page,
          page_size: pagination.page_size,
          alert_type: filters.alert_type !== 'all' ? filters.alert_type : undefined,
          acknowledged: filters.acknowledged === 'all' ? undefined : filters.acknowledged === 'true',
          start_time: filters.start_time || undefined,
          end_time: filters.end_time || undefined,
        }),
        api.getAlertStats(24),
      ]);
      setAlerts(alertsResponse.items);
      setStats(statsData);
      setPagination(prev => ({ ...prev, total: alertsResponse.total, total_pages: alertsResponse.total_pages }));
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [pagination.page, filters]);

  const handleSort = (key: string) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc',
    }));
  };

  const handleAcknowledge = async (id: number) => {
    try {
      await api.acknowledgeAlert(id);
      fetchData();
    } catch (error) {
      console.error('Failed to acknowledge alert:', error);
    }
  };

  const handleUnacknowledge = async (id: number) => {
    try {
      await api.unacknowledgeAlert(id);
      fetchData();
    } catch (error) {
      console.error('Failed to unacknowledge alert:', error);
    }
  };

  const handleBulkAcknowledge = async () => {
    if (selectedIds.length === 0) return;
    try {
      await api.bulkAcknowledgeAlerts(selectedIds);
      setSelectedIds([]);
      fetchData();
    } catch (error) {
      console.error('Failed to bulk acknowledge:', error);
    }
  };

  const columns = [
    { key: 'created_at', label: 'Time', sortable: true },
    { key: 'alert_type', label: 'Type', sortable: true },
    { key: 'message', label: 'Message', sortable: false },
    { key: 'acknowledged', label: 'Status', sortable: true },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Alerts</h1>
          <p className="text-gray-500">Monitor and manage security alerts</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="btn-secondary">
            <Download className="w-4 h-4 mr-2" />
            Export CSV
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-500">Total Alerts (24h)</p>
                <p className="text-3xl font-bold text-gray-900">{stats?.total_alerts || 0}</p>
              </div>
              <Bell className="w-8 h-8 text-primary-500" />
            </div>
          </div>
        </div>
        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-500">Acknowledged</p>
                <p className="text-3xl font-bold text-success-600">{stats?.acknowledged_stats?.true || 0}</p>
              </div>
              <Check className="w-8 h-8 text-success-500" />
            </div>
          </div>
        </div>
        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-500">Unacknowledged</p>
                <p className="text-3xl font-bold text-danger-600">{stats?.acknowledged_stats?.false || 0}</p>
              </div>
              <X className="w-8 h-8 text-danger-500" />
            </div>
          </div>
        </div>
        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-500">Critical Alerts</p>
                <p className="text-3xl font-bold text-danger-600">{stats?.recent_critical?.length || 0}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-danger-500" />
            </div>
          </div>
        </div>
      </div>

      {selectedIds.length > 0 && (
        <div className="card bg-primary-50 border-primary-200">
          <div className="card-body flex items-center justify-between">
            <span className="text-sm font-medium text-primary-800">
              {selectedIds.length} alert(s) selected
            </span>
            <div className="flex items-center gap-2">
              <button onClick={handleBulkAcknowledge} className="btn-primary text-sm">
                <Check className="w-4 h-4 mr-1" />
                Acknowledge Selected
              </button>
              <button onClick={() => setSelectedIds([])} className="btn-ghost text-sm">Clear</button>
            </div>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-body">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 mb-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search alerts..."
                className="input pl-10"
              />
            </div>
            <select
              value={filters.alert_type}
              onChange={(e) => setFilters(prev => ({ ...prev, alert_type: e.target.value }))}
              className="input"
            >
              {ALERT_TYPES.map(t => <option key={t} value={t}>{t === 'all' ? 'All Types' : t.replace('_', ' ')}</option>)}
            </select>
            <select
              value={filters.acknowledged}
              onChange={(e) => setFilters(prev => ({ ...prev, acknowledged: e.target.value }))}
              className="input"
            >
              <option value="all">All Status</option>
              <option value="true">Acknowledged</option>
              <option value="false">Unacknowledged</option>
            </select>
          </div>

          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th className="w-10">
                    <input
                      type="checkbox"
                      checked={selectedIds.length === alerts.length && alerts.length > 0}
                      onChange={() => setSelectedIds(selectedIds.length === alerts.length ? [] : alerts.map(a => a.id))}
                      className="w-4 h-4 rounded border-gray-300"
                    />
                  </th>
                  {columns.map(col => (
                    <th
                      key={col.key}
                      className={cn('cursor-pointer', col.sortable && 'hover:bg-gray-50')}
                      onClick={() => col.sortable && handleSort(col.key)}
                    >
                      <div className="flex items-center gap-1">
                        {col.label}
                        {sortConfig.key === col.key && (
                          sortConfig.direction === 'asc' ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />
                        )}
                      </div>
                    </th>
                  ))}
                  <th className="w-20">Actions</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr>
                    <td colSpan={columns.length + 2} className="text-center py-8">
                      <Loader2 className="w-6 h-6 animate-spin text-primary-600 mx-auto" />
                    </td>
                  </tr>
                ) : alerts.length === 0 ? (
                  <tr>
                    <td colSpan={columns.length + 2} className="text-center py-8 text-gray-400">
                      No alerts found
                    </td>
                  </tr>
                ) : (
                  alerts.map(alert => (
                    <tr key={alert.id} className={alert.acknowledged ? 'bg-gray-50' : ''}>
                      <td>
                        <input
                          type="checkbox"
                          checked={selectedIds.includes(alert.id)}
                          onChange={() => setSelectedIds(prev => prev.includes(alert.id) 
                            ? prev.filter(x => x !== alert.id) 
                            : [...prev, alert.id]
                          )}
                          className="w-4 h-4 rounded border-gray-300"
                        />
                      </td>
                      <td className="whitespace-nowrap text-sm">
                        <div>{formatRelativeTime(alert.created_at)}</div>
                        <div className="text-xs text-gray-500">{new Date(alert.created_at).toLocaleDateString()}</div>
                      </td>
                      <td>
                        <span className="px-2 py-0.5 text-xs rounded bg-gray-100 text-gray-700 font-mono">
                          {alert.alert_type}
                        </span>
                      </td>
                      <td className="max-w-md truncate">{alert.message}</td>
                      <td>
                        <span className={cn('px-2 py-0.5 text-xs rounded-full',
                          alert.acknowledged ? 'bg-success-100 text-success-700' : 'bg-warning-100 text-warning-700'
                        )}>
                          {alert.acknowledged ? 'Acknowledged' : 'Unacknowledged'}
                        </span>
                      </td>
                      <td>
                        <div className="flex items-center gap-1">
                          {!alert.acknowledged ? (
                            <button
                              onClick={() => handleAcknowledge(alert.id)}
                              className="p-1.5 text-success-600 hover:bg-success-100 rounded"
                              aria-label="Acknowledge"
                            >
                              <Check className="w-4 h-4" />
                            </button>
                          ) : (
                            <button
                              onClick={() => handleUnacknowledge(alert.id)}
                              className="p-1.5 text-gray-500 hover:bg-gray-100 rounded"
                              aria-label="Unacknowledge"
                            >
                              <X className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between mt-4">
            <p className="text-sm text-gray-500">
              Showing {((pagination.page - 1) * pagination.page_size) + 1} to {Math.min(pagination.page * pagination.page_size, pagination.total)} of {pagination.total}
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPagination(prev => ({ ...prev, page: prev.page - 1 }))}
                disabled={pagination.page === 1 || isLoading}
                className="btn-secondary"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="px-3 text-sm text-gray-600">
                Page {pagination.page} of {pagination.total_pages}
              </span>
              <button
                onClick={() => setPagination(prev => ({ ...prev, page: prev.page + 1 }))}
                disabled={pagination.page === pagination.total_pages || isLoading}
                className="btn-secondary"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {stats?.recent_critical && stats.recent_critical.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h2 className="text-lg font-semibold text-gray-900">Recent Critical Alerts</h2>
          </div>
          <div className="card-body">
            <div className="space-y-3">
              {stats.recent_critical.slice(0, 5).map((alert: any, i: number) => (
                <div key={i} className="p-3 bg-danger-50 rounded-lg border border-danger-100">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <AlertTriangle className="w-5 h-5 text-danger-500" />
                      <div>
                        <p className="font-medium">{alert.alert_type}</p>
                        <p className="text-sm text-gray-500">{alert.message}</p>
                      </div>
                    </div>
                    <span className="text-sm text-gray-500">{formatRelativeTime(alert.created_at)}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}