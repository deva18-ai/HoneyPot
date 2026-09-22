import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { 
  ChevronRight, ChevronDown, Shield, AlertTriangle, 
  Clock, Target, GitBranch, FileText, Download,
  Eye, Copy, Loader2, AlertCircle, CheckCircle
} from 'lucide-react';
import { cn, formatRelativeTime, formatDate, getRiskLevelBadge, getStatusBadge, formatThreatScore } from '../utils/helpers';
import type { Incident, IncidentEvent } from '../types';

const BEHAVIOR_STAGES = [
  { key: 'initial_access', label: 'Initial Access', icon: AlertTriangle, color: 'text-danger-500' },
  { key: 'reconnaissance', label: 'Reconnaissance', icon: Shield, color: 'text-warning-500' },
  { key: 'credential_access', label: 'Credential Access', icon: Target, color: 'text-primary-500' },
  { key: 'execution', label: 'Execution', icon: AlertCircle, color: 'text-purple-500' },
  { key: 'persistence', label: 'Persistence', icon: CheckCircle, color: 'text-green-500' },
  { key: 'lateral_movement', label: 'Lateral Movement', icon: GitBranch, color: 'text-orange-500' },
  { key: 'collection', label: 'Collection', icon: FileText, color: 'text-blue-500' },
  { key: 'exfiltration', label: 'Exfiltration', icon: Download, color: 'text-red-500' },
  { key: 'command_and_control', label: 'C2', icon: Shield, color: 'text-indigo-500' },
];

export function Investigation() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [timeline, setTimeline] = useState<IncidentEvent[]>([]);
  const [evidence, setEvidence] = useState<any[]>([]);
  const [mitreTechniques, setMitreTechniques] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'timeline' | 'behavior' | 'evidence' | 'mitre'>('overview');
  const [expandedEvents, setExpandedEvents] = useState<Set<number>>(new Set());

  const fetchIncidentData = async () => {
    if (!id) return;
    setIsLoading(true);
    try {
      const [incidentData, timelineData, evidenceData, mitreData] = await Promise.all([
        api.getIncident(Number(id)),
        api.getIncidentTimeline(Number(id)),
        api.getIncidentEvidence(Number(id)),
        api.getIncidentMitre(Number(id)),
      ]);
      setIncident(incidentData);
      setTimeline(timelineData.timeline || []);
      setEvidence(evidenceData.evidence || []);
      setMitreTechniques(mitreData.techniques || []);
    } catch (error) {
      console.error('Failed to fetch incident:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidentData();
  }, [id]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-primary-600" />
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="text-center py-12">
        <AlertCircle className="w-12 h-12 text-gray-300 mx-auto mb-4" />
        <h2 className="text-xl font-semibold text-gray-900">Incident not found</h2>
        <button onClick={() => navigate('/incidents')} className="btn-primary mt-4">
          Back to Incidents
        </button>
      </div>
    );
  }

  const formatStage = (stage?: string) => {
    const found = BEHAVIOR_STAGES.find(s => s.key === stage);
    return found ? found.label : stage || 'Unknown';
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-4">
          <button onClick={() => navigate('/incidents')} className="btn-ghost">
            <ChevronLeft className="w-4 h-4 mr-1" />
            Back
          </button>
          <div>
            <h1 className="text-2xl font-bold text-gray-900">{incident.incident_id}</h1>
            <p className="text-gray-500">{incident.classification}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className={getStatusBadge(incident.status)}>
            {incident.status.replace('_', ' ')}
          </span>
          <span className={getRiskLevelBadge(incident.risk_level)}>
            {incident.risk_level}
          </span>
          <span className={cn('px-3 py-1 rounded-full text-sm font-mono', formatThreatScore(incident.threat_score).color)}>
            Score: {incident.threat_score}/100
          </span>
        </div>
      </div>

      <div className="card">
        <div className="card-header border-b">
          <div className="flex flex-wrap gap-2">
            {['overview', 'timeline', 'behavior', 'evidence', 'mitre'].map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab as any)}
                className={cn(
                  'px-4 py-2 text-sm font-medium rounded-lg transition-colors',
                  activeTab === tab
                    ? 'bg-primary-100 text-primary-700'
                    : 'text-gray-500 hover:text-gray-700 hover:bg-gray-50'
                )}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            ))}
          </div>
        </div>

        <div className="card-body">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="p-4 bg-gray-50 rounded-lg">
                  <p className="text-sm text-gray-500">Source IP</p>
                  <p className="font-mono text-lg font-medium">{incident.source_ip}</p>
                </div>
                <div className="p-4 bg-gray-50 rounded-lg">
                  <p className="text-sm text-gray-500">Target Service</p>
                  <p className="font-medium">{incident.target_service || 'N/A'}</p>
                </div>
                <div className="p-4 bg-gray-50 rounded-lg">
                  <p className="text-sm text-gray-500">Duration</p>
                  <p className="font-medium">{Math.floor(incident.duration_seconds / 60)}m {incident.duration_seconds % 60}s</p>
                </div>
                <div className="p-4 bg-gray-50 rounded-lg">
                  <p className="text-sm text-gray-500">Events / Alerts</p>
                  <p className="font-medium">{incident.event_count} / {incident.alert_count}</p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h3 className="text-lg font-semibold mb-3">Timeline</h3>
                  <div className="space-y-2">
                    <div className="flex items-center gap-3 p-3 bg-gray-50 rounded-lg">
                      <Clock className="w-5 h-5 text-gray-400" />
                      <div>
                        <p className="font-medium">First Seen</p>
                        <p className="text-sm text-gray-500">{formatDate(incident.first_seen)}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3 p-3 bg-gray-50 rounded-lg">
                      <Clock className="w-5 h-5 text-gray-400" />
                      <div>
                        <p className="font-medium">Last Seen</p>
                        <p className="text-sm text-gray-500">{formatDate(incident.last_seen)}</p>
                      </div>
                    </div>
                    {incident.closed_at && (
                      <div className="flex items-center gap-3 p-3 bg-gray-50 rounded-lg">
                        <CheckCircle className="w-5 h-5 text-success-500" />
                        <div>
                          <p className="font-medium">Closed</p>
                          <p className="text-sm text-gray-500">{formatDate(incident.closed_at)}</p>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                <div>
                  <h3 className="text-lg font-semibold mb-3">MITRE ATT&CK Techniques</h3>
                  {incident.mitre_techniques ? (
                    <div className="flex flex-wrap gap-2">
                      {incident.mitre_techniques.split(',').map((tech, i) => (
                        <span key={i} className="px-3 py-1 bg-primary-50 text-primary-700 rounded-full text-sm font-mono">
                          {tech.trim()}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-gray-500">No techniques mapped</p>
                  )}
                </div>
              </div>

              {incident.tags && (
                <div>
                  <h3 className="text-lg font-semibold mb-3">Tags</h3>
                  <div className="flex flex-wrap gap-2">
                    {incident.tags.split(',').map((tag, i) => (
                      <span key={i} className="px-3 py-1 bg-gray-100 text-gray-700 rounded-full text-sm">
                        {tag.trim()}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'timeline' && (
            <div className="space-y-4">
              {timeline.length === 0 ? (
                <div className="text-center py-12 text-gray-400">No timeline data available</div>
              ) : (
                <div className="relative pl-4 border-l-2 border-gray-200">
                  {timeline.map((item, index) => (
                    <div key={item.sequence} className="relative pb-6">
                      <div className="absolute left-[-6px] top-1 w-3 h-3 rounded-full border-2 border-white"
                        style={{ backgroundColor: item.is_key_event ? '#ef4444' : '#3b82f6' }} />
                      <div className="bg-gray-50 rounded-lg p-4 ml-4">
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="font-mono text-sm text-gray-500">{item.sequence}.</span>
                              <span className="font-medium">{item.event_type}</span>
                              <span className={cn('px-2 py-0.5 text-xs rounded', 
                                item.behavior_stage && BEHAVIOR_STAGES.find(s => s.key === item.behavior_stage)?.color || 'bg-gray-100 text-gray-700'
                              )}>
                                {item.behavior_stage ? formatStage(item.behavior_stage) : 'Unknown'}
                              </span>
                              {item.is_key_event && <span className="px-2 py-0.5 text-xs rounded bg-danger-100 text-danger-700">Key Event</span>}
                            </div>
                            <p className="text-sm text-gray-500 mb-2">
                              {new Date(item.timestamp).toLocaleString()}
                            </p>
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs text-gray-600">
                              <span>Service: <span className="font-mono">{item.service}</span></span>
                              <span>IP: <span className="font-mono">{item.source_ip}</span></span>
                              <span>Severity: <span className="font-mono">{item.severity}</span></span>
                              <span>Score: <span className="font-mono">{item.threat_score}</span></span>
                            </div>
                          </div>
                          <button
                            onClick={() => setExpandedEvents(prev => 
                              prev.has(item.event_id) 
                                ? new Set([...prev].filter(x => x !== item.event_id))
                                : new Set([...prev, item.event_id])
                            )}
                            className="p-1 text-gray-400 hover:text-gray-600"
                          >
                            {expandedEvents.has(item.event_id) ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                          </button>
                        </div>
                        {expandedEvents.has(item.event_id) && (
                          <div className="mt-4 p-4 bg-white rounded border border-gray-200 space-y-2">
                            {item.username && <div className="flex gap-4 text-sm"><span className="text-gray-500">Username:</span> <span className="font-mono">{item.username}</span></div>}
                            {item.request_path && <div className="flex gap-4 text-sm"><span className="text-gray-500">Path:</span> <span className="font-mono truncate max-w-xs">{item.request_path}</span></div>}
                            {item.payload && <div className="flex gap-4 text-sm"><span className="text-gray-500">Payload:</span> <span className="font-mono truncate max-w-xs">{item.payload}</span></div>}
                            {item.result && <div className="flex gap-4 text-sm"><span className="text-gray-500">Result:</span> <span>{item.result}</span></div>}
                            {item.classification && <div className="flex gap-4 text-sm"><span className="text-gray-500">Classification:</span> <span>{item.classification}</span></div>}
                            {item.mitre_techniques && <div className="flex gap-4 text-sm"><span className="text-gray-500">MITRE:</span> <span>{item.mitre_techniques}</span></div>}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'behavior' && (
            <div className="space-y-4">
              <p className="text-gray-500 mb-4">Attack behavior analysis based on event sequencing and classification</p>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {BEHAVIOR_STAGES.map(stage => {
                  const stageEvents = timeline.filter(e => e.behavior_stage === stage.key);
                  const hasEvents = stageEvents.length > 0;
                  const keyEvents = stageEvents.filter(e => e.is_key_event).length;
                  return (
                    <div key={stage.key} className={cn(
                      'p-4 rounded-lg border transition-colors',
                      hasEvents ? 'border-primary-200 bg-primary-50' : 'border-gray-200 bg-gray-50'
                    )}>
                      <div className="flex items-center gap-3 mb-3">
                        <div className={cn('w-10 h-10 rounded-lg flex items-center justify-center', hasEvents ? 'bg-primary-100' : 'bg-gray-100')}>
                          <stage.icon className={cn('w-5 h-5', hasEvents ? stage.color : 'text-gray-400')} />
                        </div>
                        <div>
                          <p className="font-medium">{stage.label}</p>
                          <p className="text-sm text-gray-500">{stageEvents.length} events ({keyEvents} key)</p>
                        </div>
                      </div>
                      {hasEvents && (
                        <div className="space-y-1 ml-10">
                          {stageEvents.slice(0, 3).map(e => (
                            <div key={e.event_id} className="text-sm text-gray-600 flex items-center gap-2">
                              <span className="w-1.5 h-1.5 rounded-full bg-primary-500" />
                              {e.event_type} - {formatRelativeTime(e.timestamp)}
                            </div>
                          ))}
                          {stageEvents.length > 3 && (
                            <div className="text-sm text-gray-500">+{stageEvents.length - 3} more</div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {activeTab === 'evidence' && (
            <div>
              {evidence.length === 0 ? (
                <div className="text-center py-12">
                  <FileText className="w-12 h-12 text-gray-300 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-gray-900">No evidence collected</h3>
                  <p className="text-gray-500 mt-1">Add evidence to this investigation</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {evidence.map(e => (
                    <div key={e.id} className="p-4 bg-gray-50 rounded-lg border border-gray-200">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <h4 className="font-medium">{e.title}</h4>
                            <span className="px-2 py-0.5 text-xs rounded bg-gray-200 text-gray-700">{e.evidence_type}</span>
                          </div>
                          {e.description && <p className="text-sm text-gray-500">{e.description}</p>}
                          <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                            <span>{formatRelativeTime(e.created_at)}</span>
                            {e.size_bytes && <span>{(e.size_bytes / 1024).toFixed(1)} KB</span>}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          {e.content && (
                            <button className="btn-secondary text-sm">
                              <Eye className="w-4 h-4 mr-1" /> View
                            </button>
                          )}
                          <button className="btn-ghost text-sm">
                            <Download className="w-4 h-4 mr-1" /> Export
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'mitre' && (
            <div>
              {mitreTechniques.length === 0 ? (
                <div className="text-center py-12">
                  <GitBranch className="w-12 h-12 text-gray-300 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-gray-900">No MITRE techniques mapped</h3>
                  <p className="text-gray-500 mt-1">Techniques will appear when events are classified</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {mitreTechniques.map(tech => (
                    <div key={tech.technique_id} className="p-4 bg-gray-50 rounded-lg border border-gray-200">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <span className="px-3 py-1 bg-primary-100 text-primary-700 rounded-full text-sm font-mono font-medium">
                              {tech.technique_id}
                            </span>
                            <span className="px-2 py-1 bg-gray-200 text-gray-700 rounded text-sm capitalize">{tech.tactic}</span>
                            {tech.is_subtechnique && (
                              <span className="px-2 py-1 bg-purple-100 text-purple-700 rounded text-sm">Sub-technique</span>
                            )}
                          </div>
                          <h4 className="font-medium text-lg">{tech.name}</h4>
                          {tech.description && <p className="text-sm text-gray-500 mt-1">{tech.description}</p>}
                        </div>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 pt-4 border-t border-gray-200">
                        {tech.detection && (
                          <div>
                            <p className="text-sm font-medium text-gray-900 mb-1">Detection</p>
                            <p className="text-sm text-gray-600">{tech.detection}</p>
                          </div>
                        )}
                        {tech.mitigation && (
                          <div>
                            <p className="text-sm font-medium text-gray-900 mb-1">Mitigation</p>
                            <p className="text-sm text-gray-600">{tech.mitigation}</p>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}