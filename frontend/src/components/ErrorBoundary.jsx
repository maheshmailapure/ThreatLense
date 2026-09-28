import React from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('ThreatLense ErrorBoundary intercepted an error:', error, errorInfo);
    this.setState({ errorInfo });
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-[400px] flex items-center justify-center p-6 w-full">
          <div className="neu-flat rounded-3xl p-8 max-w-lg w-full text-center space-y-5 border border-rose-200/50 bg-[#eaf1ed]">
            <div className="w-14 h-14 mx-auto rounded-2xl neu-circle flex items-center justify-center text-rose-600 bg-rose-50">
              <AlertTriangle className="w-7 h-7" />
            </div>

            <div className="space-y-2">
              <h2 className="text-base font-extrabold text-slate-900 tracking-tight">
                Tab View Protected
              </h2>
              <p className="text-xs text-slate-600 leading-relaxed">
                ThreatLense self-healing caught a component transition state error. No telemetry was lost and the background security agent remains fully operational.
              </p>
            </div>

            {this.state.error && (
              <div className="neu-inset rounded-xl p-3 text-left overflow-x-auto max-h-28 text-[11px] font-mono text-rose-700 bg-rose-50/60 border border-rose-200/40">
                {this.state.error.toString()}
              </div>
            )}

            <div className="flex items-center justify-center gap-3 pt-2">
              <button
                onClick={this.handleReset}
                className="neu-button px-4 py-2 rounded-xl text-xs font-bold text-slate-700 hover:text-blue-600 flex items-center gap-2 transition-all"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Retry View</span>
              </button>
              <button
                onClick={() => {
                  this.setState({ hasError: false, error: null, errorInfo: null });
                  window.location.href = '/dashboard';
                }}
                className="neu-accent-btn px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-2"
              >
                <Home className="w-3.5 h-3.5" />
                <span>Return to Dashboard</span>
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
