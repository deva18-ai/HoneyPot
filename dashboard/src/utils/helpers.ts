import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(dateString: string): string {
  const date = new Date(dateString);
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export function formatRelativeTime(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffSecs < 60) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return formatDate(dateString);
}

export function getRiskLevelColor(riskLevel: string): string {
  switch (riskLevel) {
    case 'CRITICAL': return 'text-danger-600 bg-danger-50 border-danger-200';
    case 'HIGH': return 'text-danger-700 bg-danger-50 border-danger-200';
    case 'MEDIUM': return 'text-warning-700 bg-warning-50 border-warning-200';
    case 'LOW': return 'text-success-700 bg-success-50 border-success-200';
    default: return 'text-gray-600 bg-gray-100 border-gray-200';
  }
}

export function getRiskLevelBadge(riskLevel: string): string {
  switch (riskLevel) {
    case 'CRITICAL': return 'badge-critical';
    case 'HIGH': return 'badge-high';
    case 'MEDIUM': return 'badge-medium';
    case 'LOW': return 'badge-low';
    default: return 'badge';
  }
}

export function getStatusBadge(status: string): string {
  switch (status) {
    case 'open': return 'badge-open';
    case 'in_progress': return 'badge-in-progress';
    case 'acknowledged': return 'badge-warning';
    case 'resolved': return 'badge-resolved';
    case 'closed': return 'badge-gray';
    case 'false_positive': return 'badge-gray';
    default: return 'badge';
  }
}

export function getSeverityBadge(severity: string): string {
  switch (severity) {
    case 'CRITICAL': return 'badge-critical';
    case 'HIGH': return 'badge-high';
    case 'MEDIUM': return 'badge-medium';
    case 'LOW': return 'badge-low';
    default: return 'badge';
  }
}

export function truncateText(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength) + '...';
}

export function downloadBlob(blob: Blob, filename: string): void {
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
}

export function getTimeRangeOptions() {
  return [
    { label: 'Last Hour', value: 1 },
    { label: 'Last 6 Hours', value: 6 },
    { label: 'Last 24 Hours', value: 24 },
    { label: 'Last 7 Days', value: 168 },
    { label: 'Last 30 Days', value: 720 },
  ];
}

export function formatThreatScore(score: number): { color: string; label: string } {
  if (score >= 90) return { color: 'text-danger-600', label: 'Critical' };
  if (score >= 70) return { color: 'text-danger-600', label: 'High' };
  if (score >= 40) return { color: 'text-warning-600', label: 'Medium' };
  return { color: 'text-success-600', label: 'Low' };
}