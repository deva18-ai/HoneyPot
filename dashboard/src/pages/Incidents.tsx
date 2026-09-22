import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { 
  Search, Filter, ChevronLeft, ChevronRight, 
  MoreVertical, Edit, Eye, AlertTriangle, 
  Loader2, Download, Calendar, Clock
} from 'lucide-react';
import { cn, formatRelativeTime, getRiskLevelBadge, getStatusBadge, formatThreatScore } from '../utils/helpers';
import type { Incident, PaginatedResponse } from '../types';

const STATUS_OPTIONS = ['all', 'open', 'in_progress', 'acknowledged', 'resolved', 'closed', 'false_positive'];
const RISK_OPTIONS = ['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export function Incidents() {
  const navigate = useNavigate();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [pagination, setPagination] = useState({ page: 1, page_size: 20, total: 0, total_pages: 0 });
  const [filters, setFilters] = useState({
    status: 'all',
    risk_level: 'all',
    classification: '',
    source_ip: '',
    start_time: '',
    end_time: '',
  });
  const [searchQuery, setSearchQuery] = useState('');
  const [sortConfig, setSortConfig] = useState<{ key: string; direction: 'asc' | 'desc' }>({ key: 'first_seen', direction: 'desc' });
  const [selectedIds, setSelectedIds] = useState<number[]>([]);

  const fetchIncidents = async () => {
    setIsLoading(true);
    try {
      const params = {
        page: pagination.page,
        page_size: pagination.page_size,
        status: filters.status !== 'all' ? filters.status : undefined,
        risk_level: filters.risk_level !== 'all' ? filters.risk_level : undefined,
        classification: filters.classification || undefined,
        source_ip: filters.source_ip || undefined,
        start_time: filters.start_time || undefined,
        end_time: filters.end_time || undefined,
      };
      const response = await api.getIncidents(params);
      setIncidents(response.items);
      setPagination(prev => ({ ...prev, total: response.total, total_pages: response.total_pages }));
    } catch (error) {
      console.error('Failed to fetch incidents:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [pagination.page, filters]);

  const handleSort = (key: string) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc',
    }));
  };

  const handleRowClick = (incident: Incident) => {
    navigate(`/incidents/${incident.id}`);
  };

  const toggleSelect = (id: number) => {
    setSelectedIds(prev => prev.includes(id) 
      ? prev.filter(x => x !== id) 
      : [...prev, id]
    );
  };

  const toggleSelectAll = () => {
    if (selectedIds.length === incidents.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(incidents.map(i => i.id));
    }
  };

  const handleBulkAction = async (action: 'acknowledge' | 'resolve' | 'close') => {
    // Implementation would call bulk update API
    console.log('Bulk action:', action, selectedIds);
  };

  const columns = [
    { key: 'incident_id', label: 'Incident ID', sortable: true },
    { key: 'classification', label: 'Classification', sortable: true },
    { key: 'risk_level', label: 'Risk', sortable: true },
    { key: 'threat_score', label: 'Score', sortable: true },
    { key: 'source_ip', label: 'Source IP', sortable: true },
    { key: 'target_service', label: 'Target', sortable: true },
    { key: 'first_seen', label: 'First Seen', sortable: true },
    { key: 'status', label: 'Status', sortable: true },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Incidents</h1>
          <p className="text-gray-500">Track and manage security incidents</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="btn-secondary">
            <Download className="w-4 h-4 mr-2" />
            Export CSV
          </button>
        </div>
      </div>

      <div className="card">
        <div className="card-body">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 mb-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search incidents..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="input pl-10"
              />
            </div>
            <select
              value={filters.status}
              onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value }))}
              className="input"
            >
              {STATUS_OPTIONS.map(s => <option key={s} value={s}>{s === 'all' ? 'All Status' : s.replace('_', ' ').toUpperCase()}</option>)}
            </select>
            <select
              value={filters.risk_level}
              onChange={(e) => setFilters(prev => ({ ...prev, risk_level: e.target.value }))}
              className="input"
            >
              {RISK_OPTIONS.map(r => <option key={r} value={r}>{r === 'all' ? 'All Risk Levels' : r}</option>)}
            </select>
            <input
              type="text"
              placeholder="Classification..."
              value={filters.classification}
              onChange={(e) => setFilters(prev => ({ ...prev, classification: e.target.value }))}
              className="input"
            />
            <input
              type="text"
              placeholder="Source IP..."
              value={filters.source_ip}
              onChange={(e) => setFilters(prev => ({ ...prev, source_ip: e.target.value }))}
              className="input"
            />
          </div>

          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th className="w-10">
                    <input
                      type="checkbox"
                      checked={selectedIds.length === incidents.length && incidents.length > 0}
                      onChange={toggleSelectAll}
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
                  <th className="w-12">Actions</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr>
                    <td colSpan={columns.length + 2} className="text-center py-8">
                      <Loader2 className="w-6 h-6 animate-spin text-primary-600 mx-auto" />
                    </td>
                  </tr>
                ) : incidents.length === 0 ? (
                  <tr>
                    <td colSpan={columns.length + 2} className="text-center py-8 text-gray-400">
                      No incidents found
                    </td>
                  </tr>
                ) : (
                  incidents.map(incident => (
                    <tr key={incident.id} onClick={() => handleRowClick(incident)} className="cursor-pointer">
                      <td>
                        <input
                          type="checkbox"
                          checked={selectedIds.includes(incident.id)}
                          onChange={() => toggleSelect(incident.id)}
                          onClick={(e) => e.stopPropagation()}
                          className="w-4 h-4 rounded border-gray-300"
                        />
                      </td>
                      <td className="font-mono font-medium">{incident.incident_id}</td>
                      <td className="max-w-xs truncate">{incident.classification}</td>
                      <td>
                        <span className={getRiskLevelBadge(incident.risk_level)}>
                          {incident.risk_level}
                        </span>
                      </td>
                      <td>
                        <span className={cn('font-mono', formatThreatScore(incident.threat_score).color)}>
                          {incident.threat_score}
                        </span>
                      </td>
                      <td className="font-mono">{incident.source_ip}</td>
                      <td>{incident.target_service || '-'}</td>
                      <td className="whitespace-nowrap">
                        <div className="text-sm">{formatRelativeTime(incident.first_seen)}</div>
                        <div className="text-xs text-gray-500">{new Date(incident.first_seen).toLocaleDateString()}</div>
                      </td>
                      <td>
                        <span className={getStatusBadge(incident.status)}>
                          {incident.status.replace('_', ' ')}
                        </span>
                      </td>
                      <td>
                        <div className="flex items-center gap-1">
                          <button
                            onClick={(e) => { e.stopPropagation(); handleRowClick(incident); }}
                            className="p-1.5 text-gray-400 hover:text-gray-600"
                            aria-label="View details"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {selectedIds.length > 0 && (
            <div className="mt-4 p-3 bg-primary-50 border border-primary-200 rounded-lg flex items-center justify-between">
              <span className="text-sm font-medium text-primary-800">
                {selectedIds.length} incident(s) selected
              </span>
              <div className="flex items-center gap-2">
                <button onClick={() => handleBulkAction('acknowledge')} className="btn-secondary text-sm">Acknowledge</button>
                <button onClick={() => handleBulkAction('resolve')} className="btn-primary text-sm">Resolve</button>
                <button onClick={() => setSelectedIds([])} className="btn-ghost text-sm">Clear</button>
              </div>
            </div>
          )}

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

import { ChevronUp, ChevronDown } from 'lucide-react';