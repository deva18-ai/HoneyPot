import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { 
  Shield, AlertTriangle, Users, Activity, Zap, 
  Server, TrendingUp, Target, Download, Loader2,
  RefreshCw, ChevronRight
} from 'lucide-react';
import { 
  Chart as ChartJS, 
  CategoryScale, 
  LinearScale, 
  PointElement, 
  LineElement, 
  BarElement, 
  Title, 
  Tooltip, 
  Legend, 
  ArcElement,
  Filler
} from 'chart.js';
import { Line, Bar, Doughnut } from 'react-chartjs-2';
import { cn, formatRelativeTime, getRiskLevelBadge, formatThreatScore } from '../utils/helpers';
import type { ThreatOverview } from '../types';

ChartJS.register(
  CategoryScale, LinearScale, PointElement, LineElement, 
  BarElement, Title, Tooltip, Legend, ArcElement, Filler
);

const KPI_CARDS = [
  { name: 'Total Events', key: 'total_events', icon: Activity, color: 'bg-primary-500', description: 'All captured events' },
  { name: 'High Severity', key: 'high_severity_events', icon: AlertTriangle, color: 'bg-danger-500', description: 'Critical & High severity' },
  { name: 'Unique IPs', key: 'unique_ips', icon: Users, color: 'bg-success-500', description: 'Distinct source addresses' },
  { name: 'Active Incidents', key: 'active_incidents', icon: Shield, color: 'bg-warning-500', description: 'Open & in-progress' },
  { name: 'Critical Incidents', key: 'critical_incidents', icon: AlertTriangle, color: 'bg-danger-600', description: 'Immediate attention needed' },
  { name: 'Alerts Generated', key: 'alerts_generated', icon: Zap, color: 'bg-purple-500', description: 'Detection alerts fired' },
];

export function ThreatOverview() {
  const [overview, setOverview] = useState<ThreatOverview | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [timeRange, setTimeRange] = useState(24);
  const [refreshing, setRefreshing] = useState(false);

  const fetchData = async () => {
    try {
      const data = await api.getThreatOverview(timeRange);
      setOverview(data);
    } catch (error) {
      console.error('Failed to fetch threat overview:', error);
    } finally {
      setIsLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [timeRange]);

  const handleRefresh = async () => {
    setRefreshing(true);
    await fetchData();
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
    },
    scales: {
      x: { grid: { display: false } },
      y: { grid: { color: '#f1f5f9' }, beginAtZero: true },
    },
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Threat Overview</h1>
          <p className="text-gray-500">Real-time security posture and threat landscape</p>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(Number(e.target.value))}
            className="input w-auto"
          >
            <option value={1}>Last Hour</option>
            <option value={6}>Last 6 Hours</option>
            <option value={24}>Last 24 Hours</option>
            <option value={168}>Last 7 Days</option>
            <option value={720}>Last 30 Days</option>
          </select>
          <button onClick={handleRefresh} disabled={refreshing} className="btn-secondary">
            <RefreshCw className={cn('w-4 h-4', refreshing && 'animate-spin')} />
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {KPI_CARDS.map((card) => (
          <div key={card.key} className="card">
            <div className="card-body">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-500">{card.name}</p>
                  <p className="text-3xl font-bold text-gray-900 mt-1">
                    {overview?.kpis[card.key as keyof typeof overview.kpis] || 0}
                  </p>
                  <p className="text-xs text-gray-500 mt-1">{card.description}</p>
                </div>
                <div className={cn('w-12 h-12 rounded-xl flex items-center justify-center', card.color)}>
                  <card.icon className="w-6 h-6 text-white" />
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 card">
          <div className="card-header">
            <h2 className="text-lg font-semibold text-gray-900">Attack Trend</h2>
          </div>
          <div className="card-body">
            <div className="h-80">
              {overview && (
                <Line
                  data={{
                    labels: overview.kpis.attack_trend?.map((d: any) => new Date(d.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })) || [],
                    datasets: [
                      {
                        label: 'Total Events',
                        data: overview.kpis.attack_trend?.map((d: any) => d.count) || [],
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                      },
                      {
                        label: 'High Severity',
                        data: overview.kpis.attack_trend?.map((d: any) => d.high_severity) || [],
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                      },
                    ],
                  }}
                  options={chartOptions}
                />
              )}
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h2 className="text-lg font-semibold text-gray-900">Attack Distribution</h2>
          </div>
          <div className="card-body">
            <div className="h-80 flex items-center justify-center">
              {overview?.attack_distribution && Object.keys(overview.attack_distribution).length > 0 ? (
                <Doughnut
                  data={{
                    labels: Object.keys(overview.attack_distribution),
                    datasets: [{
                      data: Object.values(overview.attack_distribution),
                      backgroundColor: [
                        '#ef4444', '#f97316', '#f59e0b', '#22c55e', 
                        '#06b6d4', '#3b82f6', '#8b5cf6', '#ec4899'
                      ],
                      borderWidth: 0,
                    }],
                  }}
                  options={{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                      legend: {
                        position: 'bottom',
                        labels: { usePointStyle: true, padding: 16, font: { size: 11 } },
                      },
                    },
                  }}
                />
              ) : (
                <div className="text-gray-400 text-sm">No attack data</div>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <div className="card-header flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">Top Attackers</h2>
            <button className="btn-ghost text-sm">
              View All
              <ChevronRight className="w-4 h-4 ml-1" />
            </button>
          </div>
          <div className="card-body">
            <div className="table-container">
              <table className="table">
                <thead>
                  <tr>
                    <th>Rank</th>
                    <th>IP Address</th>
                    <th>Events</th>
                    <th>Max Score</th>
                    <th>Risk Level</th>
                  </tr>
                </thead>
                <tbody>
                  {overview?.top_attackers.slice(0, 10).map((attacker, i) => (
                    <tr key={i}>
                      <td className="font-medium text-gray-500">#{i + 1}</td>
                      <td className="font-mono">{attacker.ip}</td>
                      <td>{attacker.event_count}</td>
                      <td>
                        <span className={cn('font-mono', formatThreatScore(attacker.max_threat_score).color)}>
                          {attacker.max_threat_score}
                        </span>
                      </td>
                      <td>
                        <span className={getRiskLevelBadge(
                          attacker.max_threat_score >= 90 ? 'CRITICAL' :
                          attacker.max_threat_score >= 70 ? 'HIGH' :
                          attacker.max_threat_score >= 40 ? 'MEDIUM' : 'LOW'
                        )}>
                          {attacker.max_threat_score >= 90 ? 'Critical' :
                           attacker.max_threat_score >= 70 ? 'High' :
                           attacker.max_threat_score >= 40 ? 'Medium' : 'Low'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">Recent Incidents</h2>
            <button className="btn-ghost text-sm">
              View All
              <ChevronRight className="w-4 h-4 ml-1" />
            </button>
          </div>
          <div className="card-body">
            <div className="space-y-3">
              {overview?.recent_incidents.slice(0, 10).map((incident, i) => (
                <div key={i} className="flex items-center justify-between p-3 rounded-lg hover:bg-gray-50">
                  <div className="flex items-center gap-3">
                    <span className={cn('w-2.5 h-2.5 rounded-full', 
                      incident.risk_level === 'CRITICAL' && 'bg-danger-500',
                      incident.risk_level === 'HIGH' && 'bg-danger-400',
                      incident.risk_level === 'MEDIUM' && 'bg-warning-500',
                      incident.risk_level === 'LOW' && 'bg-success-500'
                    )} />
                    <div>
                      <p className="text-sm font-medium text-gray-900">{incident.incident_id}</p>
                      <p className="text-xs text-gray-500">{incident.classification}</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className={getRiskLevelBadge(incident.risk_level)}>
                      {incident.risk_level}
                    </span>
                    <p className="text-xs text-gray-500 mt-1">{formatRelativeTime(incident.first_seen)}</p>
                  </div>
                </div>
              ))}
              {(!overview?.recent_incidents || overview.recent_incidents.length === 0) && (
                <div className="text-center py-8 text-gray-400">
                  No recent incidents
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2 className="text-lg font-semibold text-gray-900">Honeypot Services Status</h2>
        </div>
        <div className="card-body">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
            {[
              { name: 'SSH', port: 2222, status: 'active', events: overview?.kpis?.total_events || 0 },
              { name: 'FTP', port: 2121, status: 'active', events: 0 },
              { name: 'Telnet', port: 2323, status: 'active', events: 0 },
              { name: 'Database', port: 9090, status: 'active', events: 0 },
              { name: 'HTTP', port: 8081, status: 'inactive', events: 0 },
            ].map((svc, i) => (
              <div key={i} className={cn('p-4 rounded-lg border transition-colors', 
                svc.status === 'active' ? 'border-success-200 bg-success-50' : 'border-gray-200 bg-gray-50'
              )}>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Server className={cn('w-5 h-5', svc.status === 'active' ? 'text-success-500' : 'text-gray-400')} />
                    <span className="font-medium">{svc.name}</span>
                  </div>
                  <span className={cn('px-2 py-0.5 text-xs rounded-full',
                    svc.status === 'active' ? 'bg-success-100 text-success-700' : 'bg-gray-100 text-gray-700'
                  )}>
                    {svc.status}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div>
                    <span className="text-gray-500">Port</span>
                    <p className="font-mono">{svc.port}</p>
                  </div>
                  <div>
                    <span className="text-gray-500">Events</span>
                    <p className="font-mono">{svc.events}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}