import React from 'react';
import './ErrorBoundary.css';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ error, errorInfo });

    // Log error to console in development
    if (process.env.NODE_ENV === 'development') {
      console.error('Error caught by boundary:', error, errorInfo);
    }

    // In production, you could send this to an error reporting service
    // logErrorToService(error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-boundary">
          <div className="error-container">
            <div className="error-icon" aria-hidden="true">⚠️</div>
            <h1 className="error-title">Something went wrong</h1>
            <p className="error-message">
              We're sorry, but something unexpected happened. The development team has been notified.
            </p>

            {process.env.NODE_ENV === 'development' && this.state.error && (
              <details className="error-details">
                <summary>Error Details (Development Only)</summary>
                <pre className="error-stack">
                  <code>
                    {String(this.state.error)}
                    {this.state.errorInfo ? (
                      <>
                        <br /><br />
                        {this.state.errorInfo.componentStack}
                      </>
                    ) : null}
                  </code>
                </pre>
              </details>
            )}

            <div className="error-actions">
              <button
                onClick={this.handleReset}
                className="btn-primary"
                aria-label="Try again"
              >
                Try Again
              </button>
              <button
                onClick={() => window.location.reload()}
                className="btn-outline"
                aria-label="Reload page"
              >
                Reload Page
              </button>
            </div>

            <div className="error-help">
              <p>If this problem persists, please:</p>
              <ul>
                <li>Check your internet connection</li>
                <li>Try refreshing the page</li>
                <li>Contact support if the issue continues</li>
              </ul>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
