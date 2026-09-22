import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { 
  Search, Filter, ChevronLeft, ChevronRight, 
  Eye, Download, Loader2, ChevronUp, ChevronDown
} from 'lucide-react';
import { cn, formatRelativeTime, getSeverityBadge, formatThreatScore } from '../utils/helpers';
import type { Event, PaginatedResponse } from '../types';

const SEVERITY_OPTIONS = ['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const SERVICE_OPTIONS = ['all', 'SSH', 'FTP', 'TELNET', 'DB', 'HTTP', 'HTTPS'];

export function Events() {
  const [events, setEvents] = useState<Event[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [pagination, setPagination] = useState({ page: 1, page_size: 50, total: 0, total_pages: 0 });
  const [filters, setFilters] = useState({
    severity: 'all',
    service: 'all',
    event_type: '',
    source_ip: '',
    classification: '',
    start_time: '',
    end_time: '',
    min_score: '',
    max_score: '',
  });
  const [searchQuery, setSearchQuery] = useState('');
  const [sortConfig, setSortConfig] = useState<{ key: string; direction: 'asc' | 'desc' }>({ key: 'timestamp', direction: 'desc' });

  const fetchEvents = async () => {
    setIsLoading(true);
    try {
      const params = {
        page: pagination.page,
        page_size: pagination.page_size,
        severity: filters.severity !== 'all' ? filters.severity : undefined,
        service: filters.service !== 'all' ? filters.service : undefined,
        event_type: filters.event_type || undefined,
        source_ip: filters.source_ip || undefined,
        classification: filters.classification || undefined,
        start_time: filters.start_time || undefined,
        end_time: filters.end_time || undefined,
        min_score: filters.min_score || undefined,
        max_score: filters.max_score || undefined,
      };
      const response = await api.getEvents(params);
      setEvents(response.items);
      setPagination(prev => ({ ...prev, total: response.total, total_pages: response.total_pages }));
    } catch (error) {
      console.error('Failed to fetch events:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [pagination.page, filters]);

  const handleSort = (key: string) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc',
    }));
  };

  const columns = [
    { key: 'timestamp', label: 'Time', sortable: true },
    { key: 'source_ip', label: 'Source IP', sortable: true },
    { key: 'service', label: 'Service', sortable: true },
    { key: 'event_type', label: 'Event Type', sortable: true },
    { key: 'username', label: 'Username', sortable: false },
    { key: 'severity', label: 'Severity', sortable: true },
    { key: 'threat_score', label: 'Score', sortable: true },
    { key: 'classification', label: 'Classification', sortable: true },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Events</h1>
          <p className="text-gray-500">Live event feed and historical analysis</p>
        </div>
        <button className="btn-secondary">
          <Download className="w-4 h-4 mr-2" />
          Export CSV
        </button>
      </div>

      <div className="card">
        <div className="card-body">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4 mb-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search events..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="input pl-10"
              />
            </div>
            <select
              value={filters.severity}
              onChange={(e) => setFilters(prev => ({ ...prev, severity: e.target.value }))}
              className="input"
            >
              {SEVERITY_OPTIONS.map(s => <option key={s} value={s}>{s === 'all' ? 'All Severity' : s}</option>)}
            </select>
            <select
              value={filters.service}
              onChange={(e) => setFilters(prev => ({ ...prev, service: e.target.value }))}
              className="input"
            >
              {SERVICE_OPTIONS.map(s => <option key={s} value={s}>{s === 'all' ? 'All Services' : s}</option>)}
            </select>
            <input
              type="text"
              placeholder="Event Type..."
              value={filters.event_type}
              onChange={(e) => setFilters(prev => ({ ...prev, event_type: e.target.value }))}
              className="input"
            />
            <input
              type="text"
              placeholder="Source IP..."
              value={filters.source_ip}
              onChange={(e) => setFilters(prev => ({ ...prev, source_ip: e.target.value }))}
              className="input"
            />
            <input
              type="text"
              placeholder="Classification..."
              value={filters.classification}
              onChange={(e) => setFilters(prev => ({ ...prev, classification: e.target.value }))}
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
                ) : events.length === 0 ? (
                  <tr>
                    <td colSpan={columns.length + 1} className="text-center py-8 text-gray-400">
                      No events found
                    </td>
                  </tr>
                ) : (
                  events.map(event => (
                    <tr key={event.id} className="hover:bg-gray-50">
                      <td className="whitespace-nowrap text-sm">
                        <div>{formatRelativeTime(event.timestamp)}</div>
                        <div className="text-xs text-gray-500">{new Date(event.timestamp).toLocaleDateString()}</div>
                      </td>
                      <td className="font-mono text-sm">{event.source_ip}</td>
                      <td>
                        <span className="px-2 py-0.5 text-xs rounded bg-gray-100 text-gray-700">
                          {event.service}
                        </span>
                      </td>
                      <td className="max-w-xs truncate">{event.event_type}</td>
                      <td className="text-sm">{event.username || '-'}</td>
                      <td>
                        <span className={getSeverityBadge(event.severity)}>
                          {event.severity}
                        </span>
                      </td>
                      <td>
                        <span className={cn('font-mono', formatThreatScore(event.threat_score).color)}>
                          {event.threat_score}
                        </span>
                      </td>
                      <td className="max-w-xs truncate">{event.classification || '-'}</td>
                      <td>
                        <button className="p-1.5 text-gray-400 hover:text-gray-600" aria-label="View details">
                          <Eye className="w-4 h-4" />
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