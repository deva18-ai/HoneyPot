import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../services/api';
import { 
  Search, Filter, ChevronLeft, ChevronRight, 
  Download, Loader2, ChevronUp, ChevronDown, 
  Shield, AlertTriangle, Globe, Lock
} from 'lucide-react';
import { cn, formatRelativeTime, getRiskLevelBadge, formatThreatScore } from '../utils/helpers';
import type { IPStats, PaginatedResponse } from '../types';

export function IPAnalysis() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [ipStats, setIpStats] = useState<IPStats[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [pagination, setPagination] = useState({ page: 1, page_size: 50, total: 0, total_pages: 0 });
  const [filters, setFilters] = useState({
    min_score: '',
    is_blocked: '',
    country: '',
  });
  const [sortConfig, setSortConfig] = useState<{ key: string; direction: 'asc' | 'desc' }>({ key: 'threat_score', direction: 'desc' });
  const [selectedIP, setSelectedIP] = useState<IPStats | null>(null);
  const [ipEvents, setIpEvents] = useState<any[]>([]);
  const [ipDetailLoading, setIpDetailLoading] = useState(false);

  const fetchIPStats = async () => {
    setIsLoading(true);
    try {
      const params = {
        page: pagination.page,
        page_size: pagination.page_size,
        min_score: filters.min_score || undefined,
        is_blocked: filters.is_blocked === 'all' ? undefined : filters.is_blocked === 'true',
        country: filters.country || undefined,
      };
      const response = await api.getIPStats(params);
      setIpStats(response.items);
      setPagination(prev => ({ ...prev, total: response.total, total_pages: response.total_pages }));
    } catch (error) {
      console.error('Failed to fetch IP stats:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchIPStats();
  }, [pagination.page, filters]);

  const handleIPClick = async (ip: IPStats) => {
    setSelectedIP(ip);
    setIpDetailLoading(true);
    try {
      const events = await api.getIPEvents(ip.source_ip, 200);
      setIpEvents(events.events || []);
    } catch (error) {
      console.error('Failed to fetch IP events:', error);
    } finally {
      setIpDetailLoading(false);
    }
  };

  const handleSort = (key: string) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc',
    }));
  };

  const handleBlock = async (ip: string, block: boolean) => {
    try {
      if (block) {
        await api.blockIP(ip);
      } else {
        await api.unblockIP(ip);
      }
      fetchIPStats();
    } catch (error) {
      console.error('Failed to block/unblock IP:', error);
    }
  };

  const columns = [
    { key: 'source_ip', label: 'IP Address', sortable: true },
    { key: 'country', label: 'Country', sortable: true },
    { key: 'asn', label: 'ASN', sortable: true },
    { key: 'total_events', label: 'Total Events', sortable: true },
    { key: 'failed_logins', label: 'Failed Logins', sortable: true },
    { key: 'services_hit', label: 'Services', sortable: true },
    { key: 'threat_score', label: 'Threat Score', sortable: true },
    { key: 'reputation_score', label: 'Reputation', sortable: true },
    { key: 'last_seen', label: 'Last Seen', sortable: true },
    { key: 'is_blocked', label: 'Status', sortable: true },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">IP Analysis</h1>
          <p className="text-gray-500">Analyze source IP addresses and threat profiles</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="btn-secondary">
            <Download className="w-4 h-4 mr-2" />
            Export CSV
          </button>
        </div>
      </div>

      {selectedIP && (
        <div className="card">
          <div className="card-header flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">IP Detail: {selectedIP.source_ip}</h2>
            <button onClick={() => setSelectedIP(null)} className="btn-ghost">
              <ChevronLeft className="w-4 h-4 mr-1" />
              Close
            </button>
          </div>
          <div className="card-body">
            {ipDetailLoading ? (
              <div className="flex justify-center py-8">
                <Loader2 className="w-6 h-6 animate-spin text-primary-600" />
              </div>
            ) : (
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <p className="text-sm text-gray-500">Total Events</p>
                    <p className="font-mono text-2xl font-bold">{selectedIP.total_events}</p>
                  </div>
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <p className="text-sm text-gray-500">Failed Logins</p>
                    <p className="font-mono text-2xl font-bold text-danger-600">{selectedIP.failed_logins}</p>
                  </div>
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <p className="text-sm text-gray-500">Services Hit</p>
                    <p className="font-mono text-2xl font-bold">{selectedIP.services_hit}</p>
                  </div>
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <p className="text-sm text-gray-500">Threat Score</p>
                    <p className={cn('font-mono text-2xl font-bold', formatThreatScore(selectedIP.threat_score).color)}>
                      {selectedIP.threat_score}
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h3 className="text-lg font-semibold mb-3">IP Information</h3>
                    <div className="space-y-2">
                      <div className="flex justify-between p-2 bg-gray-50 rounded">
                        <span className="text-gray-500">Country</span>
                        <span className="font-mono">{selectedIP.country || 'Unknown'}</span>
                      </div>
                      <div className="flex justify-between p-2 bg-gray-50 rounded">
                        <span className="text-gray-500">ASN</span>
                        <span className="font-mono">{selectedIP.asn || 'Unknown'}</span>
                      </div>
                      <div className="flex justify-between p-2 bg-gray-50 rounded">
                        <span className="text-gray-500">ISP</span>
                        <span className="font-mono">{selectedIP.isp || 'Unknown'}</span>
                      </div>
                      <div className="flex justify-between p-2 bg-gray-50 rounded">
                        <span className="text-gray-500">Reputation Score</span>
                        <span className="font-mono">{selectedIP.reputation_score}/100</span>
                      </div>
                      <div className="flex justify-between p-2 bg-gray-50 rounded">
                        <span className="text-gray-500">First Seen</span>
                        <span className="font-mono">{formatRelativeTime(selectedIP.first_seen)}</span>
                      </div>
                      <div className="flex justify-between p-2 bg-gray-50 rounded">
                        <span className="text-gray-500">Last Seen</span>
                        <span className="font-mono">{formatRelativeTime(selectedIP.last_seen)}</span>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-lg font-semibold mb-3">Recent Events ({ipEvents.length})</h3>
                    <div className="table-container max-h-96 overflow-y-auto">
                      <table className="table text-sm">
                        <thead className="sticky top-0 bg-white">
                          <tr>
                            <th>Time</th>
                            <th>Service</th>
                            <th>Event Type</th>
                            <th>Severity</th>
                            <th>Score</th>
                            <th>Classification</th>
                          </tr>
                        </thead>
                        <tbody>
                          {ipEvents.slice(0, 50).map((event: any, i: number) => (
                            <tr key={i}>
                              <td className="whitespace-nowrap">{formatRelativeTime(event.timestamp)}</td>
                              <td><span className="px-2 py-0.5 text-xs rounded bg-gray-100">{event.service}</span></td>
                              <td className="max-w-xs truncate">{event.event_type}</td>
                              <td><span className={cn('px-2 py-0.5 text-xs rounded', 
                                event.severity === 'CRITICAL' && 'bg-danger-100 text-danger-700',
                                event.severity === 'HIGH' && 'bg-danger-100 text-danger-600',
                                event.severity === 'MEDIUM' && 'bg-warning-100 text-warning-700',
                                event.severity === 'LOW' && 'bg-success-100 text-success-700'
                              )}>{event.severity}</span></td>
                              <td><span className={cn('font-mono', formatThreatScore(event.threat_score).color)}>{event.threat_score}</span></td>
                              <td className="max-w-xs truncate">{event.classification || '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              </div>
            )}
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
                placeholder="Search IPs..."
                className="input pl-10"
                onChange={(e) => setSearchParams({ q: e.target.value })}
              />
            </div>
            <input
              type="text"
              placeholder="Min Score..."
              value={filters.min_score}
              onChange={(e) => setFilters(prev => ({ ...prev, min_score: e.target.value }))}
              className="input"
            />
            <select
              value={filters.is_blocked}
              onChange={(e) => setFilters(prev => ({ ...prev, is_blocked: e.target.value }))}
              className="input"
            >
              <option value="all">All Status</option>
              <option value="true">Blocked</option>
              <option value="false">Active</option>
            </select>
            <input
              type="text"
              placeholder="Country..."
              value={filters.country}
              onChange={(e) => setFilters(prev => ({ ...prev, country: e.target.value }))}
              className="input"
            />
          </div>

          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
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
                  <th className="w-12">Actions</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr>
                    <td colSpan={columns.length + 1} className="text-center py-8">
                      <Loader2 className="w-6 h-6 animate-spin text-primary-600 mx-auto" />
                    </td>
                  </tr>
                ) : ipStats.length === 0 ? (
                  <tr>
                    <td colSpan={columns.length + 1} className="text-center py-8 text-gray-400">
                      No IP data found
                    </td>
                  </tr>
                ) : (
                  ipStats.map(ip => (
                    <tr key={ip.source_ip} onClick={() => handleIPClick(ip)} className="cursor-pointer hover:bg-gray-50">
                      <td className="font-mono font-medium">{ip.source_ip}</td>
                      <td>
                        <span className="flex items-center gap-1">
                          <Globe className="w-3 h-3 text-gray-400" />
                          {ip.country || 'Unknown'}
                        </span>
                      </td>
                      <td className="font-mono text-sm">{ip.asn || 'Unknown'}</td>
                      <td>{ip.total_events}</td>
                      <td className="text-danger-600 font-medium">{ip.failed_logins}</td>
                      <td>{ip.services_hit}</td>
                      <td>
                        <span className={cn('font-mono font-medium', formatThreatScore(ip.threat_score).color)}>
                          {ip.threat_score}
                        </span>
                      </td>
                      <td>
                        <span className={cn('font-mono', 
                          ip.reputation_score >= 70 && 'text-danger-600',
                          ip.reputation_score >= 40 && 'text-warning-600',
                          ip.reputation_score < 40 && 'text-success-600'
                        )}>
                          {ip.reputation_score}
                        </span>
                      </td>
                      <td className="whitespace-nowrap text-sm">
                        {formatRelativeTime(ip.last_seen)}
                      </td>
                      <td>
                        <span className={cn('px-2 py-0.5 text-xs rounded-full',
                          ip.is_blocked ? 'bg-danger-100 text-danger-700' : 'bg-success-100 text-success-700'
                        )}>
                          {ip.is_blocked ? 'Blocked' : 'Active'}
                        </span>
                      </td>
                      <td>
                        <button
                          onClick={(e) => { e.stopPropagation(); handleBlock(ip.source_ip, !ip.is_blocked); }}
                          className={cn('p-1.5 rounded', 
                            ip.is_blocked ? 'text-success-600 hover:bg-success-100' : 'text-danger-600 hover:bg-danger-100'
                          )}
                          aria-label={ip.is_blocked ? 'Unblock IP' : 'Block IP'}
                        >
                          {ip.is_blocked ? <Lock className="w-4 h-4" /> : <Shield className="w-4 h-4" />}
                        </button>
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
    </div>
  );
}