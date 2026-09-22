import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { 
  Search, ChevronRight, Shield, Target, 
  Loader2, ChevronUp, ChevronDown, Eye
} from 'lucide-react';
import { cn, formatRelativeTime } from '../utils/helpers';
import type { MitreTechnique, PaginatedResponse } from '../types';

const TACTICS = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

export function MITRE() {
  const [techniques, setTechniques] = useState<MitreTechnique[]>([]);
  const [matrix, setMatrix] = useState<any>({});
  const [coverage, setCoverage] = useState<any>(null);
  const [tactics, setTactics] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [pagination, setPagination] = useState({ page: 1, page_size: 50, total: 0, total_pages: 0 });
  const [filters, setFilters] = useState({
    tactic: '',
    search: '',
    is_subtechnique: '',
  });
  const [sortConfig, setSortConfig] = useState<{ key: string; direction: 'asc' | 'desc' }>({ key: 'technique_id', direction: 'asc' });
  const [activeTab, setActiveTab] = useState<'matrix' | 'list' | 'coverage'>('matrix');
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(null);

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [techniquesResponse, matrixData, coverageData, tacticsData] = await Promise.all([
        api.getMitreTechniques({
          page: pagination.page,
          page_size: pagination.page_size,
          tactic: filters.tactic || undefined,
          search: filters.search || undefined,
          is_subtechnique: filters.is_subtechnique === 'all' ? undefined : filters.is_subtechnique === 'true',
        }),
        api.getMitreMatrix(),
        api.getMitreCoverage(),
        api.getMitreTactics(),
      ]);
      setTechniques(techniquesResponse.items);
      setMatrix(matrixData.matrix || {});
      setCoverage(coverageData);
      setTactics(tacticsData.tactics || []);
      setPagination(prev => ({ ...prev, total: techniquesResponse.total, total_pages: techniquesResponse.total_pages }));
    } catch (error) {
      console.error('Failed to fetch MITRE data:', error);
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

  const tacticColors: Record<string, string> = {
    'Reconnaissance': 'bg-blue-100 text-blue-700',
    'Resource Development': 'bg-indigo-100 text-indigo-700',
    'Initial Access': 'bg-red-100 text-red-700',
    'Execution': 'bg-orange-100 text-orange-700',
    'Persistence': 'bg-amber-100 text-amber-700',
    'Privilege Escalation': 'bg-yellow-100 text-yellow-700',
    'Defense Evasion': 'bg-green-100 text-green-700',
    'Credential Access': 'bg-emerald-100 text-emerald-700',
    'Discovery': 'bg-teal-100 text-teal-700',
    'Lateral Movement': 'bg-cyan-100 text-cyan-700',
    'Collection': 'bg-sky-100 text-sky-700',
    'Command and Control': 'bg-purple-100 text-purple-700',
    'Exfiltration': 'bg-pink-100 text-pink-700',
    'Impact': 'bg-rose-100 text-rose-700',
  };

  if (activeTab === 'matrix') {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">MITRE ATT&CK Matrix</h1>
            <p className="text-gray-500">Tactics, techniques, and procedures mapped to detections</p>
          </div>
          <div className="flex items-center gap-2">
            <select
              value={filters.tactic}
              onChange={(e) => setFilters(prev => ({ ...prev, tactic: e.target.value }))}
              className="input w-auto"
            >
              <option value="">All Tactics</option>
              {TACTICS.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
        </div>

        <div className="card">
          <div className="card-body overflow-x-auto">
            {isLoading ? (
              <div className="flex justify-center py-12">
                <Loader2 className="w-8 h-8 animate-spin text-primary-600" />
              </div>
            ) : (
              <div className="grid grid-cols-[auto_minmax(0,1fr)] gap-1">
                <div className="sticky left-0 bg-white z-10">
                  <div className="p-3 bg-gray-50 border-b border-r border-gray-200 font-semibold text-sm">Tactic</div>
                  {TACTICS.map(tactic => (
                    <div key={tactic} className="px-3 py-2 border-b border-gray-100 min-h-[120px]">
                      <span className={cn('px-2 py-1 rounded text-xs font-medium whitespace-nowrap', tacticColors[tactic] || 'bg-gray-100 text-gray-700')}>
                        {tactic}
                      </span>
                    </div>
                  ))}
                </div>
                <div className="grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-1">
                  {TACTICS.map(tactic => {
                    const techs = matrix[tactic] || [];
                    return (
                      <div key={tactic} className="min-h-[120px]">
                        {techs.map((tech: any) => (
                          <div
                            key={tech.technique_id}
                            className={cn('p-2 border-b border-gray-100 hover:bg-gray-50 cursor-pointer transition-colors', tech.is_subtechnique && 'ml-4 border-l-2 border-primary-200 pl-6')}
                            onClick={() => setSelectedTechnique(tech)}
                          >
                            <div className="font-mono text-xs font-medium text-gray-900">{tech.technique_id}</div>
                            <div className="text-xs text-gray-600 truncate">{tech.name}</div>
                            {tech.is_subtechnique && tech.parent_technique && (
                              <div className="text-xs text-gray-400">↳ {tech.parent_technique}</div>
                            )}
                          </div>
                        ))}
                        {techs.length === 0 && (
                          <div className="p-4 text-center text-gray-400 text-xs">No techniques</div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  if (activeTab === 'list') {
    return (
      <div className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Techniques List</h1>
            <p className="text-gray-500">Browse and search all MITRE ATT&CK techniques</p>
          </div>
        </div>

        <div className="card">
          <div className="card-body">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search techniques..."
                  value={filters.search}
                  onChange={(e) => setFilters(prev => ({ ...prev, search: e.target.value }))}
                  className="input pl-10"
                />
              </div>
              <select
                value={filters.tactic}
                onChange={(e) => setFilters(prev => ({ ...prev, tactic: e.target.value }))}
                className="input"
              >
                <option value="">All Tactics</option>
                {TACTICS.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
              <select
                value={filters.is_subtechnique}
                onChange={(e) => setFilters(prev => ({ ...prev, is_subtechnique: e.target.value }))}
                className="input"
              >
                <option value="all">All</option>
                <option value="false">Parent Techniques</option>
                <option value="true">Sub-techniques</option>
              </select>
            </div>

            <div className="table-container">
              <table className="table">
                <thead>
                  <tr>
                    {[
                      { key: 'technique_id', label: 'ID', sortable: true },
                      { key: 'name', label: 'Name', sortable: true },
                      { key: 'tactic', label: 'Tactic', sortable: true },
                      { key: 'platform', label: 'Platform', sortable: false },
                      { key: 'is_subtechnique', label: 'Type', sortable: true },
                    ].map(col => (
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
                      <td colSpan={6} className="text-center py-8">
                        <Loader2 className="w-6 h-6 animate-spin text-primary-600 mx-auto" />
                      </td>
                    </tr>
                  ) : techniques.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="text-center py-8 text-gray-400">No techniques found</td>
                    </tr>
                  ) : (
                    techniques.map(tech => (
                      <tr key={tech.id} onClick={() => setSelectedTechnique(tech)} className="cursor-pointer hover:bg-gray-50">
                        <td className="font-mono font-medium">{tech.technique_id}</td>
                        <td className="max-w-xs truncate">{tech.name}</td>
                        <td>
                          <span className={cn('px-2 py-0.5 text-xs rounded', tacticColors[tech.tactic] || 'bg-gray-100 text-gray-700')}>
                            {tech.tactic}
                          </span>
                        </td>
                        <td className="text-sm text-gray-500">{tech.platform || 'Multi-platform'}</td>
                        <td>
                          <span className={cn('px-2 py-0.5 text-xs rounded',
                            tech.is_subtechnique ? 'bg-purple-100 text-purple-700' : 'bg-gray-100 text-gray-700'
                          )}>
                            {tech.is_subtechnique ? 'Sub-technique' : 'Parent'}
                          </span>
                        </td>
                        <td>
                          <button className="p-1.5 text-gray-400 hover:text-gray-600" onClick={(e) => { e.stopPropagation(); setSelectedTechnique(tech); }}>
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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">MITRE ATT&CK Coverage</h1>
          <p className="text-gray-500">Detection coverage analysis against MITRE ATT&CK framework</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="card">
          <div className="card-body text-center">
            <p className="text-sm text-gray-500">Techniques Covered</p>
            <p className="text-4xl font-bold text-primary-600">{coverage?.covered_techniques || 0}</p>
          </div>
        </div>
        <div className="card">
          <div className="card-body text-center">
            <p className="text-sm text-gray-500">Total Techniques</p>
            <p className="text-4xl font-bold text-gray-900">{coverage?.total_techniques || 0}</p>
          </div>
        </div>
        <div className="card">
          <div className="card-body text-center">
            <p className="text-sm text-gray-500">Coverage</p>
            <p className="text-4xl font-bold text-success-600">{coverage?.coverage_percent || 0}%</p>
          </div>
        </div>
        <div className="card">
          <div className="card-body text-center">
            <p className="text-sm text-gray-500">Detected Techniques</p>
            <p className="text-4xl font-bold text-warning-600">{coverage?.detected?.length || 0}</p>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2 className="text-lg font-semibold text-gray-900">Coverage by Tactic</h2>
        </div>
        <div className="card-body">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {TACTICS.map(tactic => {
              const tacticTechs = matrix[tactic] || [];
              const detectedInTactic = tacticTechs.filter((t: any) => 
                coverage?.detected?.includes(t.technique_id)
              ).length;
              const totalInTactic = tacticTechs.length;
              const pct = totalInTactic > 0 ? Math.round((detectedInTactic / totalInTactic) * 100) : 0;
              return (
                <div key={tactic} className="p-4 bg-gray-50 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <span className={cn('px-2 py-1 rounded text-xs font-medium', tacticColors[tactic] || 'bg-gray-100 text-gray-700')}>
                      {tactic}
                    </span>
                    <span className="font-bold text-lg">{pct}%</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div className={cn('h-2 rounded-full transition-all', tacticColors[tactic]?.replace('bg-', 'bg-').replace('text-', ''))} style={{ width: `${pct}%` }} />
                  </div>
                  <p className="text-xs text-gray-500 mt-1">{detectedInTactic} / {totalInTactic} techniques</p>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2 className="text-lg font-semibold text-gray-900">Detected Techniques</h2>
        </div>
        <div className="card-body">
          {coverage?.detected && coverage.detected.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {coverage.detected.map((tech: string, i: number) => (
                <span key={i} className="px-3 py-1 bg-primary-50 text-primary-700 rounded-full text-sm font-mono">
                  {tech}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-gray-500 text-center py-8">No techniques detected yet</p>
          )}
        </div>
      </div>
    </div>
  );
}