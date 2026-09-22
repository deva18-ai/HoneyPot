import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { 
  User, Shield, Bell, Server, Database, 
  Save, Loader2, CheckCircle, AlertCircle,
  Key, ToggleLeft, ToggleRight, Eye, EyeOff
} from 'lucide-react';
import { cn } from '../utils/helpers';
import { useAuth } from '../context/AuthContext';
import type { User as UserType } from '../types';

export function Settings() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<'profile' | 'security' | 'notifications' | 'services' | 'system'>('profile');
  const [isSaving, setIsSaving] = useState(false);
  const [saveStatus, setSaveStatus] = useState<'idle' | 'success' | 'error'>('idle');
  
  // Profile
  const [profile, setProfile] = useState({
    username: user?.username || '',
    email: user?.email || '',
    role: user?.role || 'viewer',
  });
  
  // Security
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPasswords, setShowPasswords] = useState(false);
  
  // Notifications
  const [notifications, setNotifications] = useState({
    email_alerts: true,
    telegram_alerts: false,
    webhook_url: '',
    alert_threshold: 'HIGH',
  });
  
  // Services
  const [services, setServices] = useState([
    { name: 'SSH', port: 2222, enabled: true, banner: 'SSH-2.0-OpenSSH_8.9-HoneyTrap' },
    { name: 'FTP', port: 2121, enabled: true, banner: '220 HoneyTrap FTP Service' },
    { name: 'Telnet', port: 2323, enabled: true, banner: 'Welcome to HoneyTrap Telnet' },
    { name: 'Database', port: 9090, enabled: true, banner: 'PostgreSQL 15.2 HoneyTrap Database' },
    { name: 'HTTP Honeypot', port: 8081, enabled: false, banner: 'Custom HTTP responses' },
  ]);
  
  // System
  const [systemSettings, setSystemSettings] = useState({
    log_retention_days: 30,
    max_events_per_ip: 1000,
    brute_force_threshold: 5,
    brute_force_window: 60,
    scan_threshold: 3,
    scan_window: 30,
    auto_incident_creation: true,
    incident_correlation_window: 60,
  });

  const handleSave = async (section: string) => {
    setIsSaving(true);
    setSaveStatus('idle');
    try {
      // In real implementation, would call API
      await new Promise(resolve => setTimeout(resolve, 1000));
      setSaveStatus('success');
      setTimeout(() => setSaveStatus('idle'), 3000);
    } catch (error) {
      setSaveStatus('error');
    } finally {
      setIsSaving(false);
    }
  };

  const tabs = [
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'services', label: 'Services', icon: Server },
    { id: 'system', label: 'System', icon: Database },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
          <p className="text-gray-500">Configure your account and system preferences</p>
        </div>
      </div>

      <div className="card">
        <div className="card-header border-b">
          <div className="flex flex-wrap gap-1">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={cn(
                  'flex items-center gap-2 px-4 py-2.5 text-sm font-medium rounded-lg transition-colors',
                  activeTab === tab.id
                    ? 'bg-primary-100 text-primary-700'
                    : 'text-gray-500 hover:text-gray-700 hover:bg-gray-50'
                )}
              >
                <tab.icon className="w-4 h-4" />
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        <div className="card-body">
          {saveStatus === 'success' && (
            <div className="mb-6 p-3 bg-success-50 border border-success-200 rounded-lg flex items-center gap-2 text-success-700">
              <CheckCircle className="w-5 h-5" />
              Settings saved successfully
            </div>
          )}

          {activeTab === 'profile' && (
            <form className="space-y-6 max-w-2xl">
              <div className="flex items-center gap-6">
                <div className="w-20 h-20 rounded-full bg-primary-100 flex items-center justify-center">
                  <User className="w-10 h-10 text-primary-600" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold">{profile.username}</h3>
                  <p className="text-gray-500">{profile.role} • {profile.email || 'No email'}</p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="label">Username</label>
                  <input
                    type="text"
                    value={profile.username}
                    onChange={(e) => setProfile(prev => ({ ...prev, username: e.target.value }))}
                    className="input"
                    disabled
                  />
                  <p className="text-xs text-gray-500 mt-1">Username cannot be changed</p>
                </div>
                <div>
                  <label className="label">Email</label>
                  <input
                    type="email"
                    value={profile.email}
                    onChange={(e) => setProfile(prev => ({ ...prev, email: e.target.value }))}
                    className="input"
                    placeholder="Enter email address"
                  />
                </div>
                <div>
                  <label className="label">Role</label>
                  <select
                    value={profile.role}
                    onChange={(e) => setProfile(prev => ({ ...prev, role: e.target.value as any }))}
                    className="input"
                    disabled={user?.role !== 'admin'}
                  >
                    <option value="admin">Administrator</option>
                    <option value="analyst">Analyst</option>
                    <option value="viewer">Viewer</option>
                  </select>
                  {user?.role !== 'admin' && <p className="text-xs text-gray-500 mt-1">Only admins can change roles</p>}
                </div>
              </div>

              <div className="flex justify-end pt-4 border-t border-gray-200">
                <button type="button" onClick={() => handleSave('profile')} disabled={isSaving} className="btn-primary">
                  {isSaving ? <Loader2 className="w-5 h-5 animate-spin" /> : <Save className="w-5 h-5 mr-1" />}
                  Save Profile
                </button>
              </div>
            </form>
          )}

          {activeTab === 'security' && (
            <form className="space-y-6 max-w-2xl">
              <h3 className="text-lg font-semibold">Change Password</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="label">Current Password</label>
                  <div className="relative">
                    <input
                      type={showPasswords ? 'text' : 'password'}
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      className="input pr-10"
                      placeholder="Enter current password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPasswords(!showPasswords)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400"
                    >
                      {showPasswords ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                    </button>
                  </div>
                </div>
                <div>
                  <label className="label">New Password</label>
                  <div className="relative">
                    <input
                      type={showPasswords ? 'text' : 'password'}
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      className="input pr-10"
                      placeholder="Enter new password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPasswords(!showPasswords)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400"
                    >
                      {showPasswords ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                    </button>
                  </div>
                </div>
                <div>
                  <label className="label">Confirm New Password</label>
                  <div className="relative">
                    <input
                      type={showPasswords ? 'text' : 'password'}
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      className="input pr-10"
                      placeholder="Confirm new password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPasswords(!showPasswords)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400"
                    >
                      {showPasswords ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                    </button>
                  </div>
                </div>
              </div>
              <p className="text-sm text-gray-500">Password must be at least 8 characters</p>

              <div className="pt-4 border-t border-gray-200">
                <h3 className="text-lg font-semibold mb-4">API Access</h3>
                <div className="space-y-3">
                  <div className="p-4 bg-gray-50 rounded-lg flex items-center justify-between">
                    <div>
                      <p className="font-medium">API Key</p>
                      <p className="text-sm text-gray-500">Generate an API key for programmatic access</p>
                    </div>
                    <button className="btn-secondary">
                      <Key className="w-4 h-4 mr-1" />
                      Generate Key
                    </button>
                  </div>
                  <p className="text-sm text-gray-500">No API keys generated yet</p>
                </div>
              </div>

              <div className="flex justify-end pt-4 border-t border-gray-200">
                <button type="button" onClick={() => handleSave('security')} disabled={isSaving} className="btn-primary">
                  {isSaving ? <Loader2 className="w-5 h-5 animate-spin" /> : <Save className="w-5 h-5 mr-1" />}
                  Update Security
                </button>
              </div>
            </form>
          )}

          {activeTab === 'notifications' && (
            <form className="space-y-6 max-w-2xl">
              <h3 className="text-lg font-semibold">Alert Notifications</h3>
              
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                  <div>
                    <p className="font-medium">Email Alerts</p>
                    <p className="text-sm text-gray-500">Receive email notifications for critical alerts</p>
                  </div>
                  <button
                    onClick={() => setNotifications(prev => ({ ...prev, email_alerts: !prev.email_alerts }))}
                    className={cn('relative w-12 h-7 rounded-full transition-colors',
                      notifications.email_alerts ? 'bg-primary-500' : 'bg-gray-300'
                    )}
                    role="switch"
                    aria-checked={notifications.email_alerts}
                  >
                    <span className={cn('absolute top-0.5 w-6 h-6 rounded-full bg-white shadow-md transition-transform',
                      notifications.email_alerts ? 'translate-x-5' : 'translate-x-0.5'
                    )} />
                  </button>
                </div>

                <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                  <div>
                    <p className="font-medium">Telegram Alerts</p>
                    <p className="text-sm text-gray-500">Send alerts to Telegram chat</p>
                  </div>
                  <button
                    onClick={() => setNotifications(prev => ({ ...prev, telegram_alerts: !prev.telegram_alerts }))}
                    className={cn('relative w-12 h-7 rounded-full transition-colors',
                      notifications.telegram_alerts ? 'bg-primary-500' : 'bg-gray-300'
                    )}
                    role="switch"
                    aria-checked={notifications.telegram_alerts}
                  >
                    <span className={cn('absolute top-0.5 w-6 h-6 rounded-full bg-white shadow-md transition-transform',
                      notifications.telegram_alerts ? 'translate-x-5' : 'translate-x-0.5'
                    )} />
                  </button>
                </div>

                <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                  <div>
                    <p className="font-medium">Webhook Alerts</p>
                    <p className="text-sm text-gray-500">Send alerts to custom webhook endpoint</p>
                  </div>
                  <input
                    type="url"
                    value={notifications.webhook_url}
                    onChange={(e) => setNotifications(prev => ({ ...prev, webhook_url: e.target.value }))}
                    className="input w-64"
                    placeholder="https://example.com/webhook"
                  />
                </div>
              </div>

              <div className="pt-4 border-t border-gray-200">
                <h3 className="text-lg font-semibold mb-4">Alert Threshold</h3>
                <select
                  value={notifications.alert_threshold}
                  onChange={(e) => setNotifications(prev => ({ ...prev, alert_threshold: e.target.value }))}
                  className="input w-48"
                >
                  <option value="LOW">Low - All alerts</option>
                  <option value="MEDIUM">Medium - Medium and above</option>
                  <option value="HIGH">High - High and Critical only</option>
                  <option value="CRITICAL">Critical - Critical only</option>
                </select>
                <p className="text-sm text-gray-500 mt-1">Minimum severity level to trigger notifications</p>
              </div>

              <div className="flex justify-end pt-4 border-t border-gray-200">
                <button type="button" onClick={() => handleSave('notifications')} disabled={isSaving} className="btn-primary">
                  {isSaving ? <Loader2 className="w-5 h-5 animate-spin" /> : <Save className="w-5 h-5 mr-1" />}
                  Save Notifications
                </button>
              </div>
            </form>
          )}

          {activeTab === 'services' && (
            <div className="max-w-4xl">
              <h3 className="text-lg font-semibold mb-4">Honeypot Services Configuration</h3>
              <div className="space-y-4">
                {services.map((service, index) => (
                  <div key={index} className="p-4 bg-gray-50 rounded-lg border border-gray-200">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-3">
                        <Server className="w-6 h-6 text-gray-500" />
                        <div>
                          <p className="font-medium">{service.name}</p>
                          <p className="text-sm text-gray-500">Port {service.port}</p>
                        </div>
                      </div>
                      <button
                        onClick={() => setServices(prev => prev.map((s, i) => i === index ? { ...s, enabled: !s.enabled } : s))}
                        className={cn('relative w-12 h-7 rounded-full transition-colors',
                          service.enabled ? 'bg-success-500' : 'bg-gray-300'
                        )}
                        role="switch"
                        aria-checked={service.enabled}
                      >
                        <span className={cn('absolute top-0.5 w-6 h-6 rounded-full bg-white shadow-md transition-transform',
                          service.enabled ? 'translate-x-5' : 'translate-x-0.5'
                        )} />
                      </button>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <label className="label">Banner / Response</label>
                        <textarea
                          value={service.banner}
                          onChange={(e) => setServices(prev => prev.map((s, i) => i === index ? { ...s, banner: e.target.value } : s))}
                          className="input font-mono text-sm min-h-[80px]"
                          rows={3}
                        />
                      </div>
                      <div>
                        <label className="label">Port</label>
                        <input
                          type="number"
                          value={service.port}
                          onChange={(e) => setServices(prev => prev.map((s, i) => i === index ? { ...s, port: Number(e.target.value) } : s))}
                          className="input"
                          disabled
                        />
                        <p className="text-xs text-gray-500 mt-1">Port changes require service restart</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
              
              <div className="flex justify-end pt-4 border-t border-gray-200">
                <button type="button" onClick={() => handleSave('services')} disabled={isSaving} className="btn-primary">
                  {isSaving ? <Loader2 className="w-5 h-5 animate-spin" /> : <Save className="w-5 h-5 mr-1" />}
                  Save Service Configuration
                </button>
              </div>
            </div>
          )}

          {activeTab === 'system' && (
            <form className="space-y-6 max-w-2xl">
              <h3 className="text-lg font-semibold">Detection Thresholds</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="label">Brute Force Threshold</label>
                  <input
                    type="number"
                    value={systemSettings.brute_force_threshold}
                    onChange={(e) => setSystemSettings(prev => ({ ...prev, brute_force_threshold: Number(e.target.value) }))}
                    className="input"
                    min="1"
                    max="100"
                  />
                  <p className="text-xs text-gray-500 mt-1">Failed attempts before triggering alert</p>
                </div>
                <div>
                  <label className="label">Brute Force Window (seconds)</label>
                  <input
                    type="number"
                    value={systemSettings.brute_force_window}
                    onChange={(e) => setSystemSettings(prev => ({ ...prev, brute_force_window: Number(e.target.value) }))}
                    className="input"
                    min="10"
                    max="3600"
                  />
                  <p className="text-xs text-gray-500 mt-1">Time window for brute force detection</p>
                </div>
                <div>
                  <label className="label">Port Scan Threshold</label>
                  <input
                    type="number"
                    value={systemSettings.scan_threshold}
                    onChange={(e) => setSystemSettings(prev => ({ ...prev, scan_threshold: Number(e.target.value) }))}
                    className="input"
                    min="1"
                    max="50"
                  />
                  <p className="text-xs text-gray-500 mt-1">Unique ports before triggering scan alert</p>
                </div>
                <div>
                  <label className="label">Scan Window (seconds)</label>
                  <input
                    type="number"
                    value={systemSettings.scan_window}
                    onChange={(e) => setSystemSettings(prev => ({ ...prev, scan_window: Number(e.target.value) }))}
                    className="input"
                    min="10"
                    max="3600"
                  />
                  <p className="text-xs text-gray-500 mt-1">Time window for scan detection</p>
                </div>
              </div>

              <div className="pt-4 border-t border-gray-200">
                <h3 className="text-lg font-semibold mb-4">Data Retention & Limits</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <label className="label">Log Retention (days)</label>
                    <input
                      type="number"
                      value={systemSettings.log_retention_days}
                      onChange={(e) => setSystemSettings(prev => ({ ...prev, log_retention_days: Number(e.target.value) }))}
                      className="input"
                      min="1"
                      max="365"
                    />
                  </div>
                  <div>
                    <label className="label">Max Events Per IP</label>
                    <input
                      type="number"
                      value={systemSettings.max_events_per_ip}
                      onChange={(e) => setSystemSettings(prev => ({ ...prev, max_events_per_ip: Number(e.target.value) }))}
                      className="input"
                      min="100"
                      max="10000"
                    />
                  </div>
                </div>
              </div>

              <div className="pt-4 border-t border-gray-200">
                <h3 className="text-lg font-semibold mb-4">Incident Management</h3>
                <div className="space-y-4">
                  <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                    <div>
                      <p className="font-medium">Auto Incident Creation</p>
                      <p className="text-sm text-gray-500">Automatically create incidents from high-severity alerts</p>
                    </div>
                    <button
                      onClick={() => setSystemSettings(prev => ({ ...prev, auto_incident_creation: !prev.auto_incident_creation }))}
                      className={cn('relative w-12 h-7 rounded-full transition-colors',
                        systemSettings.auto_incident_creation ? 'bg-primary-500' : 'bg-gray-300'
                      )}
                    >
                      <span className={cn('absolute top-0.5 w-6 h-6 rounded-full bg-white shadow-md transition-transform',
                        systemSettings.auto_incident_creation ? 'translate-x-5' : 'translate-x-0.5'
                      )} />
                    </button>
                  </div>

                  <div>
                    <label className="label">Incident Correlation Window (minutes)</label>
                    <input
                      type="number"
                      value={systemSettings.incident_correlation_window}
                      onChange={(e) => setSystemSettings(prev => ({ ...prev, incident_correlation_window: Number(e.target.value) }))}
                      className="input w-48"
                      min="5"
                      max="1440"
                    />
                    <p className="text-xs text-gray-500 mt-1">Group related events into single incident</p>
                  </div>
                </div>
              </div>

              <div className="flex justify-end pt-4 border-t border-gray-200">
                <button type="button" onClick={() => handleSave('system')} disabled={isSaving} className="btn-primary">
                  {isSaving ? <Loader2 className="w-5 h-5 animate-spin" /> : <Save className="w-5 h-5 mr-1" />}
                  Save System Settings
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}