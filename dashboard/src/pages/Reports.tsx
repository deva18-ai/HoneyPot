import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { 
  FileText, Download, Calendar, Loader2, 
  ChevronLeft, ChevronRight, Eye, Trash2,
  Clock, BarChart2
} from 'lucide-react';
import { cn, formatRelativeTime, formatDate } from '../utils/helpers';

interface ReportFile {
  filename: string;
  size: number;
  created: string;
}

export function Reports() {
  const [reports, setReports] = useState<ReportFile[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isGenerating, setIsGenerating] = useState(false);
  const [dateRange, setDateRange] = useState({ start: '', end: '' });
  const [reportType, setReportType] = useState<'events' | 'incidents'>('events');

  const fetchReports = async () => {
    setIsLoading(true);
    try {
      const response = await api.listReports();
      setReports(response.reports || []);
    } catch (error) {
      console.error('Failed to fetch reports:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const generateReport = async (type: 'events' | 'incidents') => {
    setIsGenerating(true);
    try {
      let blob: Blob;
      if (type === 'events') {
        blob = await api.exportEventsCSV({
          start_time: dateRange.start || undefined,
          end_time: dateRange.end || undefined,
        });
      } else {
        blob = await api.exportIncidentsCSV({
          start_time: dateRange.start || undefined,
          end_time: dateRange.end || undefined,
        });
      }
      
      const filename = `${type}_report_${new Date().toISOString().slice(0, 10)}.csv`;
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      
      fetchReports();
    } catch (error) {
      console.error('Failed to generate report:', error);
    } finally {
      setIsGenerating(false);
    }
  };

  const downloadReport = async (filename: string) => {
    // In a real implementation, this would fetch the file
    console.log('Download report:', filename);
  };

  const deleteReport = async (filename: string) => {
    if (!confirm(`Delete ${filename}?`)) return;
    console.log('Delete report:', filename);
    fetchReports();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Reports</h1>
          <p className="text-gray-500">Generate and manage security reports</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 card">
          <div className="card-header">
            <h2 className="text-lg font-semibold text-gray-900">Generate Report</h2>
          </div>
          <div className="card-body space-y-6">
            <div>
              <h3 className="font-medium mb-3">Report Type</h3>
              <div className="grid grid-cols-2 gap-4">
                {[
                  { value: 'events', label: 'Events Report', desc: 'All honeypot events with classifications', icon: BarChart2 },
                  { value: 'incidents', label: 'Incidents Report', desc: 'Security incidents with timeline and evidence', icon: FileText },
                ].map(r => (
                  <button
                    key={r.value}
                    onClick={() => setReportType(r.value as any)}
                    className={cn('p-4 rounded-lg border-2 text-left transition-colors',
                      reportType === r.value ? 'border-primary-500 bg-primary-50' : 'border-gray-200 hover:border-gray-300'
                    )}
                  >
                    <div className="flex items-center gap-3">
                      <r.icon className={cn('w-6 h-6', reportType === r.value ? 'text-primary-600' : 'text-gray-400')} />
                      <div>
                        <p className="font-medium">{r.label}</p>
                        <p className="text-sm text-gray-500">{r.desc}</p>
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            <div className="border-t border-gray-200 pt-6">
              <h3 className="font-medium mb-3">Date Range</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="label">Start Date</label>
                  <input
                    type="datetime-local"
                    value={dateRange.start}
                    onChange={(e) => setDateRange(prev => ({ ...prev, start: e.target.value }))}
                    className="input"
                  />
                </div>
                <div>
                  <label className="label">End Date</label>
                  <input
                    type="datetime-local"
                    value={dateRange.end}
                    onChange={(e) => setDateRange(prev => ({ ...prev, end: e.target.value }))}
                    className="input"
                  />
                </div>
              </div>
              <p className="text-sm text-gray-500 mt-2">Leave empty for all time</p>
            </div>

            <div className="flex gap-3 pt-4 border-t border-gray-200">
              <button
                onClick={() => generateReport(reportType)}
                disabled={isGenerating}
                className="btn-primary flex-1"
              >
                {isGenerating ? (
                  <span className="flex items-center justify-center gap-2">
                    <Loader2 className="w-5 h-5 animate-spin" />
                    Generating...
                  </span>
                ) : (
                  <span className="flex items-center justify-center gap-2">
                    <Download className="w-5 h-5" />
                    Generate & Download
                  </span>
                )}
              </button>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h2 className="text-lg font-semibold text-gray-900">Quick Actions</h2>
          </div>
          <div className="card-body space-y-3">
            <button className="btn-secondary w-full justify-start gap-3" onClick={() => generateReport('events')}>
              <BarChart2 className="w-5 h-5" />
              <span>Events CSV (Last 24h)</span>
            </button>
            <button className="btn-secondary w-full justify-start gap-3" onClick={() => generateReport('incidents')}>
              <FileText className="w-5 h-5" />
              <span>Incidents CSV (Last 24h)</span>
            </button>
            <button className="btn-secondary w-full justify-start gap-3">
              <BarChart2 className="w-5 h-5" />
              <span>Events CSV (Last 7 Days)</span>
            </button>
            <button className="btn-secondary w-full justify-start gap-3">
              <FileText className="w-5 h-5" />
              <span>Incidents CSV (Last 7 Days)</span>
            </button>
            <button className="btn-secondary w-full justify-start gap-3">
              <Clock className="w-5 h-5" />
              <span>Events CSV (Last 30 Days)</span>
            </button>
            <button className="btn-secondary w-full justify-start gap-3">
              <FileText className="w-5 h-5" />
              <span>Incidents CSV (Last 30 Days)</span>
            </button>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-900">Generated Reports</h2>
          <span className="text-sm text-gray-500">{reports.length} files</span>
        </div>
        <div className="card-body">
          {isLoading ? (
            <div className="flex justify-center py-8">
              <Loader2 className="w-8 h-8 animate-spin text-primary-600" />
            </div>
          ) : reports.length === 0 ? (
            <div className="text-center py-12">
              <FileText className="w-12 h-12 text-gray-300 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900">No reports generated</h3>
              <p className="text-gray-500 mt-1">Generate your first report using the panel on the left</p>
            </div>
          ) : (
            <div className="table-container">
              <table className="table">
                <thead>
                  <tr>
                    <th>Filename</th>
                    <th>Size</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {reports.map((report, i) => (
                    <tr key={i}>
                      <td className="font-mono text-sm">{report.filename}</td>
                      <td className="text-sm text-gray-500">{(report.size / 1024).toFixed(1)} KB</td>
                      <td className="whitespace-nowrap text-sm">
                        <div>{formatRelativeTime(report.created)}</div>
                        <div className="text-xs text-gray-500">{formatDate(report.created)}</div>
                      </td>
                      <td>
                        <div className="flex items-center gap-2">
                          <button className="p-1.5 text-gray-400 hover:text-gray-600" aria-label="Download">
                            <Download className="w-4 h-4" />
                          </button>
                          <button className="p-1.5 text-gray-400 hover:text-gray-600" aria-label="View">
                            <Eye className="w-4 h-4" />
                          </button>
                          <button className="p-1.5 text-danger-500 hover:text-danger-600" onClick={() => deleteReport(report.filename)} aria-label="Delete">
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}