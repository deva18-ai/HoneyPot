import React, { createContext, useContext, useEffect, useRef, useState, ReactNode } from 'react';
import type { WebSocketMessage, Event, Alert } from '../types';

interface WebSocketContextType {
  connect: (channel: 'event' | 'alert') => void;
  disconnect: (channel: 'event' | 'alert') => void;
  lastEvent: Event | null;
  lastAlert: Alert | null;
  connectionStatus: 'connected' | 'disconnected' | 'connecting';
  eventCount: number;
  alertCount: number;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

const WS_BASE_URL = 'ws://127.0.0.1:8080';

export function WebSocketProvider({ children }: { children: ReactNode }) {
  const [lastEvent, setLastEvent] = useState<Event | null>(null);
  const [lastAlert, setLastAlert] = useState<Alert | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'disconnected' | 'connecting'>('disconnected');
  const [eventCount, setEventCount] = useState(0);
  const [alertCount, setAlertCount] = useState(0);
  
  const eventWsRef = useRef<WebSocket | null>(null);
  const alertWsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout>();

  const connect = (channel: 'event' | 'alert') => {
    const wsRef = channel === 'event' ? eventWsRef : alertWsRef;
    const url = `${WS_BASE_URL}/ws/${channel}s`;
    
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return;
    }
    
    setConnectionStatus('connecting');
    
    const ws = new WebSocket(url);
    wsRef.current = ws;
    
    ws.onopen = () => {
      setConnectionStatus('connected');
      console.log(`${channel} WebSocket connected`);
    };
    
    ws.onmessage = (event) => {
      try {
        const message: WebSocketMessage = JSON.parse(event.data);
        
        if (message.type === 'event' && channel === 'event') {
          setLastEvent(message.data);
          setEventCount(c => c + 1);
        } else if (message.type === 'alert' && channel === 'alert') {
          setLastAlert(message.data);
          setAlertCount(c => c + 1);
        }
      } catch (error) {
        console.error('WebSocket message parse error:', error);
      }
    };
    
    ws.onclose = () => {
      setConnectionStatus('disconnected');
      console.log(`${channel} WebSocket disconnected`);
      
      reconnectTimeoutRef.current = setTimeout(() => {
        connect(channel);
      }, 5000);
    };
    
    ws.onerror = (error) => {
      console.error(`${channel} WebSocket error:`, error);
    };
  };

  const disconnect = (channel: 'event' | 'alert') => {
    const wsRef = channel === 'event' ? eventWsRef : alertWsRef;
    
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
  };

  useEffect(() => {
    return () => {
      if (eventWsRef.current) eventWsRef.current.close();
      if (alertWsRef.current) alertWsRef.current.close();
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
    };
  }, []);

  return (
    <WebSocketContext.Provider value={{
      connect,
      disconnect,
      lastEvent,
      lastAlert,
      connectionStatus,
      eventCount,
      alertCount,
    }}>
      {children}
    </WebSocketContext.Provider>
  );
}

export function useWebSocket() {
  const context = useContext(WebSocketContext);
  if (context === undefined) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  return context;
}