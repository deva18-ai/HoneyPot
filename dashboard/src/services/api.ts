import axios, { AxiosInstance, InternalAxiosRequestConfig } from 'axios';
import type { 
  User, Token, Event, Session, Alert, IPStats, 
  Incident, IncidentEvent, IncidentNote, IncidentEvidence,
  MitreTechnique, PaginatedResponse, DashboardStats, ThreatOverview 
} from '../types';

const API_BASE_URL = '/api/v1';

class ApiService {
  private client: AxiosInstance;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        'Content-Type': 'application/json',
      },
      withCredentials: false,
    });

    this.client.interceptors.request.use(
      (config: InternalAxiosRequestConfig) => {
        if (this.accessToken && config.headers) {
          config.headers.Authorization = `Bearer ${this.accessToken}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    this.client.interceptors.response.use(
      (response) => response,
      async (error) => {
        const originalRequest = error.config;
        
        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;
          
          try {
            await this.refreshAccessToken();
            if (this.accessToken && originalRequest.headers) {
              originalRequest.headers.Authorization = `Bearer ${this.accessToken}`;
            }
            return this.client(originalRequest);
          } catch (refreshError) {
            this.clearTokens();
            window.location.href = '/login';
            return Promise.reject(refreshError);
          }
        }
        
        return Promise.reject(error);
      }
    );
  }

  setTokens(access: string, refresh: string) {
    this.accessToken = access;
    this.refreshToken = refresh;
    localStorage.setItem('access_token', access);
    localStorage.setItem('refresh_token', refresh);
  }

  clearTokens() {
    this.accessToken = null;
    this.refreshToken = null;
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
  }

  loadTokens() {
    this.accessToken = localStorage.getItem('access_token');
    this.refreshToken = localStorage.getItem('refresh_token');
  }

  isAuthenticated(): boolean {
    return !!this.accessToken;
  }

  async login(username: string, password: string): Promise<Token> {
    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password);
    
    const response = await this.client.post<Token>('/auth/login', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    
    this.setTokens(response.data.access_token, response.data.refresh_token);
    return response.data;
  }

  async refreshAccessToken(): Promise<void> {
    if (!this.refreshToken) throw new Error('No refresh token');
    
    const response = await this.client.post<Token>('/auth/refresh', {
      refresh_token: this.refreshToken,
    });
    
    this.setTokens(response.data.access_token, response.data.refresh_token);
  }

  async logout(): Promise<void> {
    if (this.refreshToken) {
      try {
        await this.client.post('/auth/logout', { refresh_token: this.refreshToken });
      } catch {
        // Ignore logout errors
      }
    }
    this.clearTokens();
  }

  async getCurrentUser(): Promise<User> {
    const response = await this.client.get<User>('/auth/me');
    return response.data;
  }

  async getDashboardStats(hours: number = 24): Promise<DashboardStats> {
    const response = await this.client.get<DashboardStats>('/dashboard/stats', {
      params: { hours },
    });
    return response.data;
  }

  async getThreatOverview(hours: number = 24): Promise<ThreatOverview> {
    const response = await this.client.get<ThreatOverview>('/dashboard/threat-overview', {
      params: { hours },
    });
    return response.data;
  }

  async getEvents(params: {
    page?: number;
    page_size?: number;
    source_ip?: string;
    service?: string;
    event_type?: string;
    severity?: string;
    classification?: string;
    start_time?: string;
    end_time?: string;
    min_score?: number;
    max_score?: number;
  } = {}): Promise<PaginatedResponse<Event>> {
    const response = await this.client.get<PaginatedResponse<Event>>('/events', { params });
    return response.data;
  }

  async getEvent(id: number): Promise<Event> {
    const response = await this.client.get<Event>(`/events/${id}`);
    return response.data;
  }

  async getEventStats(hours: number = 24): Promise<any> {
    const response = await this.client.get('/events/stats/summary', { params: { hours } });
    return response.data;
  }

  async getEventTrend(hours: number = 24, interval: number = 60): Promise<any> {
    const response = await this.client.get('/events/stats/trend', { params: { hours, interval_minutes: interval } });
    return response.data;
  }

  async getIncidents(params: {
    page?: number;
    page_size?: number;
    status?: string;
    risk_level?: string;
    classification?: string;
    source_ip?: string;
    assignee_id?: number;
    start_time?: string;
    end_time?: string;
    min_score?: number;
    max_score?: number;
  } = {}): Promise<PaginatedResponse<Incident>> {
    const response = await this.client.get<PaginatedResponse<Incident>>('/incidents', { params });
    return response.data;
  }

  async getIncident(id: number): Promise<Incident> {
    const response = await this.client.get<Incident>(`/incidents/${id}`);
    return response.data;
  }

  async getIncidentTimeline(id: number): Promise<any> {
    const response = await this.client.get(`/incidents/${id}/timeline`);
    return response.data;
  }

  async getIncidentEvidence(id: number): Promise<any> {
    const response = await this.client.get(`/incidents/${id}/evidence`);
    return response.data;
  }

  async getIncidentMitre(id: number): Promise<any> {
    const response = await this.client.get(`/incidents/${id}/mitre`);
    return response.data;
  }

  async updateIncident(id: number, data: Partial<Incident>): Promise<Incident> {
    const response = await this.client.patch<Incident>(`/incidents/${id}`, data);
    return response.data;
  }

  async addIncidentNote(incidentId: number, content: string, isInternal: boolean = true): Promise<IncidentNote> {
    const response = await this.client.post<IncidentNote>(`/incidents/${incidentId}/notes`, {
      content,
      is_internal: isInternal,
    });
    return response.data;
  }

  async addIncidentEvidence(incidentId: number, data: Partial<IncidentEvidence>): Promise<IncidentEvidence> {
    const response = await this.client.post<IncidentEvidence>(`/incidents/${incidentId}/evidence`, data);
    return response.data;
  }

  async getIncidentStats(hours: number = 24): Promise<any> {
    const response = await this.client.get('/incidents/stats/summary', { params: { hours } });
    return response.data;
  }

  async getIPStats(params: {
    page?: number;
    page_size?: number;
    min_score?: number;
    is_blocked?: boolean;
    country?: string;
  } = {}): Promise<PaginatedResponse<IPStats>> {
    const response = await this.client.get<PaginatedResponse<IPStats>>('/ip-stats', { params });
    return response.data;
  }

  async getIPStatsDetail(ip: string): Promise<IPStats> {
    const response = await this.client.get<IPStats>(`/ip-stats/${ip}`);
    return response.data;
  }

  async blockIP(ip: string): Promise<void> {
    await this.client.post(`/ip-stats/${ip}/block`);
  }

  async unblockIP(ip: string): Promise<void> {
    await this.client.post(`/ip-stats/${ip}/unblock`);
  }

  async getAlerts(params: {
    page?: number;
    page_size?: number;
    alert_type?: string;
    acknowledged?: boolean;
    start_time?: string;
    end_time?: string;
  } = {}): Promise<PaginatedResponse<Alert>> {
    const response = await this.client.get<PaginatedResponse<Alert>>('/alerts', { params });
    return response.data;
  }

  async getAlertStats(hours: number = 24): Promise<any> {
    const response = await this.client.get('/alerts/stats/summary', { params: { hours } });
    return response.data;
  }

  async acknowledgeAlert(id: number): Promise<void> {
    await this.client.patch(`/alerts/${id}/acknowledge`);
  }

  async unacknowledgeAlert(id: number): Promise<void> {
    await this.client.patch(`/alerts/${id}/unacknowledge`);
  }

  async bulkAcknowledgeAlerts(ids: number[]): Promise<void> {
    await this.client.post('/alerts/bulk-acknowledge', { alert_ids: ids });
  }

  async getSessions(params: {
    page?: number;
    page_size?: number;
    source_ip?: string;
    service?: string;
    risk_level?: string;
    start_time?: string;
    end_time?: string;
  } = {}): Promise<PaginatedResponse<Session>> {
    const response = await this.client.get<PaginatedResponse<Session>>('/sessions', { params });
    return response.data;
  }

  async getSessionStats(hours: number = 24): Promise<any> {
    const response = await this.client.get('/sessions/stats/summary', { params: { hours } });
    return response.data;
  }

  async getSession(id: number): Promise<Session> {
    const response = await this.client.get<Session>(`/sessions/${id}`);
    return response.data;
  }

  async getMitreTechniques(params: {
    page?: number;
    page_size?: number;
    tactic?: string;
    search?: string;
    is_subtechnique?: boolean;
  } = {}): Promise<PaginatedResponse<MitreTechnique>> {
    const response = await this.client.get<PaginatedResponse<MitreTechnique>>('/mitre', { params });
    return response.data;
  }

  async getMitreTactics(): Promise<any> {
    const response = await this.client.get('/mitre/tactics');
    return response.data;
  }

  async getMitreMatrix(): Promise<any> {
    const response = await this.client.get('/mitre/matrix');
    return response.data;
  }

  async getMitreCoverage(): Promise<any> {
    const response = await this.client.get('/mitre/coverage');
    return response.data;
  }

  async exportEventsCSV(params: {
    start_time?: string;
    end_time?: string;
    source_ip?: string;
    severity?: string;
  } = {}): Promise<Blob> {
    const response = await this.client.get('/reports/export/csv', {
      params,
      responseType: 'blob',
    });
    return response.data;
  }

  async exportIncidentsCSV(params: {
    start_time?: string;
    end_time?: string;
    status?: string;
    risk_level?: string;
  } = {}): Promise<Blob> {
    const response = await this.client.get('/reports/export/incidents/csv', {
      params,
      responseType: 'blob',
    });
    return response.data;
  }

  async healthCheck(): Promise<any> {
    const response = await this.client.get('/health');
    return response.data;
  }
}

export const api = new ApiService();