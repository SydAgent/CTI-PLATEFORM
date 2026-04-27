'use client';

import React, { Component, type ErrorInfo, type ReactNode } from 'react';

// ═══════════════════════════════════════════════════════════════════════════════
//  ONYX CTI — Production Error Boundary
//  Military-grade: catches render crashes, logs telemetry, offers recovery.
//  Zero unhandled white-screens. Every module is encapsulated.
// ═══════════════════════════════════════════════════════════════════════════════

interface ErrorBoundaryProps {
  children: ReactNode;
  /** Human-readable label for the module wrapped by this boundary */
  moduleName?: string;
  /** Optional custom fallback UI */
  fallback?: ReactNode;
  /** Called when an error is caught — wire to your telemetry pipeline */
  onError?: (error: Error, errorInfo: ErrorInfo) => void;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export default class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    this.setState({ errorInfo });

    // Telemetry hook — production systems should pipe this to Sentry/Datadog
    console.error(
      `[ONYX ERROR BOUNDARY] Module "${this.props.moduleName || 'Unknown'}" crashed:`,
      error,
      errorInfo,
    );

    this.props.onError?.(error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;

      const moduleName = this.props.moduleName || 'Module';

      return (
        <div
          style={{
            padding: '24px',
            background: '#0a0f1a',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderLeft: '4px solid #ef4444',
            borderRadius: '8px',
            fontFamily: 'monospace',
            color: '#f87171',
            minHeight: '120px',
            display: 'flex',
            flexDirection: 'column',
            gap: '12px',
          }}
          role="alert"
        >
          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '16px' }}>⚠</span>
            <span
              style={{
                fontSize: '11px',
                fontWeight: 800,
                letterSpacing: '0.1em',
                textTransform: 'uppercase',
              }}
            >
              {moduleName} — Erreur de Rendu
            </span>
          </div>

          {/* Error message */}
          <div
            style={{
              fontSize: '10px',
              color: '#94a3b8',
              background: 'rgba(0,0,0,0.4)',
              padding: '8px 12px',
              borderRadius: '4px',
              lineHeight: '1.6',
              maxHeight: '80px',
              overflow: 'auto',
              wordBreak: 'break-word',
            }}
          >
            {this.state.error?.message || 'Erreur inconnue'}
          </div>

          {/* Recovery button */}
          <button
            onClick={this.handleReset}
            style={{
              alignSelf: 'flex-start',
              padding: '6px 16px',
              fontSize: '10px',
              fontWeight: 700,
              fontFamily: 'monospace',
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.4)',
              borderRadius: '4px',
              color: '#f87171',
              cursor: 'pointer',
              transition: 'all 0.15s',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = 'rgba(239, 68, 68, 0.2)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = 'rgba(239, 68, 68, 0.1)';
            }}
          >
            ↻ Recharger le Module
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
