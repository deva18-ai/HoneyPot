import React, { useEffect, useState } from 'react';
import { useWebSocket } from '../context/WebSocketContext';
import { api } from '../services/api';
import { 
  Shield, Activity, AlertTriangle, Users, TrendingUp, 
  Server, BarChart2, Target, Zap, Loader2, RefreshCw
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
import type { DashboardStats, ThreatOverview } from '../types';

ChartJS.register(
  CategoryScale, LinearScale, PointElement, LineElement, 
  BarElement, Title, Tooltip, Legend, ArcElement, Filler
);

const STAT_CARDS = [
  { name: 'Total Events', key: 'total_events', icon: Activity, color: 'bg-primary-500', trend: '+12%' },
  { name: 'High Severity', key: 'high_severity', icon: AlertTriangle, color: 'bg-danger-500', trend: '+5%' },
  { name: 'Alerts', key: 'alerts', icon: Zap, color: 'bg-warning-500', trend: '+8%' },
  { name: 'Unique IPs', key: 'unique_ips', icon: Users, color: 'bg-success-500', trend: '+3%' },
];

const RISK_CARDS = [
  { level: 'Critical', key: 'critical_incidents', color: 'danger', icon: Shield },
  { level: 'High', key: 'high_incidents', color: 'danger', icon: AlertTriangle },
  { level: 'Medium', key: 'medium_incidents', color: 'warning', icon: Activity },
  { level: 'Low', key: 'low_incidents', color: 'success', icon: Target },
];

export function Dashboard() {
  const { lastEvent, lastAlert, connectionStatus, eventCount, alertCount } = useWebSocket();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [threatOverview, setThreatOverview] = useState<ThreatOverview | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [timeRange, setTimeRange] = useState(24);
  const [refreshing, setRefreshing] = useState(false);

  const fetchData = async () => {
    try {
      const [statsData, threatData] = await Promise.all([
        api.getDashboardStats(timeRange),
        api.getThreatOverview(timeRange),
      ]);
      setStats(statsData);
      setThreatOverview(threatData);
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [timeRange]);

  useEffect(() => {
    if (lastEvent && stats) {
      setStats(prev => prev ? {
        ...prev,
        total_incidents: prev.total_incidents + 1,
        events_last_hour: prev.events_last_hour + 1,
      } : null);
    }
  }, [lastEvent]);

  const handleRefresh = async () => {
    setRefreshing(true);
    await fetchData();
    setRefreshing(false);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-primary-600" />
      </div>
    );
  }

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

  const attackTrendData = stats?.attack_trend || [];
  const chartLabels = attackTrendData.map(d => new Date(d.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }));
  const chartValues = attackTrendData.map(d => d.count);
  const highValues = attackTrendData.map(d => d.high_severity);

  const serviceHeatmapData = stats?.service_heatmap || [];
  const services = ['ssh', 'ftp', 'telnet', 'db', 'http'];
  const hours = Array.from({ length: 24 }, (_, i) => i);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
          <p className="text-gray-500">Real-time threat monitoring and system overview</p>
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

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {STAT_CARDS.map((card) => (
          <div key={card.key} className="card">
            <div className="card-body">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-500">{card.name}</p>
                  <p className="text-3xl font-bold text-gray-900 mt-1">
                    {threatOverview?.kpis[card.key as keyof typeof threatOverview.kpis] || stats?.[card.key as keyof typeof stats] || 0}
                  </p>
                </div>
                <div className={cn('w-12 h-12 rounded-xl flex items-center justify-center', card.color)}>
                  <card.icon className="w-6 h-6 text-white" />
                </div>
              </div>
              <p className="mt-3 text-xs text-success-600">{card.trend} vs last period</p>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {RISK_CARDS.map((card) => (
          <div key={card.key} className="card">
            <div className="card-body">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-500">{card.level} Incidents</p>
                  <p className="text-3xl font-bold text-gray-900 mt-1">
                    {stats?.[card.key as keyof typeof stats] || 0}
                  </p>
                </div>
                <div className={cn('w-12 h-12 rounded-xl flex items-center justify-center', `bg-${card.color}-100`)}>
                  <card.icon className={cn('w-6 h-6', `text-${card.color}-600`)} />
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
            <div className="h-72">
              {attackTrendData.length > 0 ? (
                <Line
                  data={{
                    labels: chartLabels,
                    datasets: [
                      {
                        label: 'Total Events',
                        data: chartValues,
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                      },
                      {
                        label: 'High Severity',
                        data: highValues,
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
              ) : (
                <div className="h-full flex items-center justify-center text-gray-400">
                  No data available for selected time range
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h2 className="text-lg font-semibold text-gray-900">Attack Distribution</h2>
          </div>
          <div className="card-body">
            <div className="h-72 flex items-center justify-center">
              {threatOverview?.attack_distribution && Object.keys(threatOverview.attack_distribution).length > 0 ? (
                <Doughnut
                  data={{
                    labels: Object.keys(threatOverview.attack_distribution),
                    datasets: [{
                      data: Object.values(threatOverview.attack_distribution),
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
            <span className={cn('px-2 py-0.5 text-xs rounded', connectionStatus === 'connected' ? 'bg-success-100 text-success-700' : 'bg-gray-100 text-gray-500')}>
              {connectionStatus === 'connected' ? 'Live' : 'Offline'}
            </span>
          </div>
          <div className="card-body">
            <div className="table-container">
              <table className="table">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Events</th>
                    <th>Max Score</th>
                    <th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {threatOverview?.top_attackers.slice(0, 10).map((attacker, i) => (
                    <tr key={i}>
                      <td className="font-mono text-sm">{attacker.ip}</td>
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
          <div className="card-header">
            <h2 className="text-lg font-semibold text-gray-900">Recent Incidents</h2>
          </div>
          <div className="card-body">
            <div className="space-y-3">
              {threatOverview?.recent_incidents.slice(0, 5).map((incident, i) => (
                <div key={i} className="flex items-center justify-between p-3 rounded-lg hover:bg-gray-50">
                  <div className="flex items-center gap-3">
                    <span className={cn('w-2 h-2 rounded-full', 
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
              {(!threatOverview?.recent_incidents || threatOverview.recent_incidents.length === 0) && (
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
          <h2 className="text-lg font-semibold text-gray-900">Service Heatmap (Last 24h)</h2>
        </div>
        <div className="card-body overflow-x-auto">
          <table className="table text-xs">
            <thead>
              <tr>
                <th className="w-16">Hour</th>
                {services.map(s => (
                  <th key={s} className="text-center capitalize">{s.toUpperCase()}</th>
                ))}
                <th className="text-center">Total</th>
              </tr>
            </thead>
            <tbody>
              {hours.map(hour => {
                const row = serviceHeatmapData.find(r => r.hour === hour);
                const total = services.reduce((sum, s) => sum + (row?.[s] || 0), 0);
                return (
                  <tr key={hour}>
                    <td className="font-medium text-gray-600">{hour.toString().padStart(2, '0')}:00</td>
                    {services.map(s => (
                      <td key={s} className="text-center">
                        {row?.[s] > 0 ? (
                          <span className={cn('inline-block px-2 py-0.5 rounded text-xs',
                            row[s] > 10 && 'bg-danger-100 text-danger-700',
                            row[s] > 5 && row[s] <= 10 && 'bg-warning-100 text-warning-700',
                            row[s] <= 5 && 'bg-gray-100 text-gray-700'
                          )}>
                            {row[s]}
                          </span>
                        ) : '-'}
                      </td>
                    ))}
                    <td className="text-center font-medium">{total}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}