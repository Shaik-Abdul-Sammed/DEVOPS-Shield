import React, { useEffect, useState } from 'react';
import './NotificationSystem.css';

const InfoIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"></circle>
    <line x1="12" y1="16" x2="12" y2="12"></line>
    <line x1="12" y1="8" x2="12.01" y2="8"></line>
  </svg>
);

const SuccessIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
    <polyline points="22 4 12 14.01 9 11.01"></polyline>
  </svg>
);

const WarningIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
    <line x1="12" y1="9" x2="12" y2="13"></line>
    <line x1="12" y1="17" x2="12.01" y2="17"></line>
  </svg>
);

const ErrorIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"></circle>
    <line x1="15" y1="9" x2="9" y2="15"></line>
    <line x1="9" y1="9" x2="15" y2="15"></line>
  </svg>
);

const getNotificationIcon = (type) => {
  switch (type) {
    case 'success': return <SuccessIcon />;
    case 'error': return <ErrorIcon />;
    case 'warning': return <WarningIcon />;
    case 'info':
    default: return <InfoIcon />;
  }
};

const NotificationItem = ({ notification, onRemove }) => {
  const [isClosing, setIsClosing] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsClosing(true);
      setTimeout(() => onRemove(notification.id), 300); // Wait for animation
    }, notification.duration || 5000);
    return () => clearTimeout(timer);
  }, [notification, onRemove]);

  const handleClose = () => {
    setIsClosing(true);
    setTimeout(() => onRemove(notification.id), 300);
  };

  return (
    <div
      className={`notification notification-${notification.type} ${isClosing ? 'closing' : ''}`}
      role="alert"
    >
      <div className="notification-content">
        <span className="notification-icon" aria-hidden="true">
          {getNotificationIcon(notification.type)}
        </span>
        <div className="notification-message">
          <p>{notification.message}</p>
          {notification.timestamp && (
            <span className="notification-time">
              {new Date(notification.timestamp).toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>
      <button
        className="notification-close"
        onClick={handleClose}
        aria-label={`Dismiss ${notification.type} notification`}
        title="Dismiss notification"
      >
        <span aria-hidden="true">×</span>
      </button>
    </div>
  );
};

const NotificationSystem = ({ notifications, onRemove }) => {
  if (notifications.length === 0) return null;

  return (
    <div className="notification-system" aria-live="polite" aria-atomic="true">
      {notifications.map((notification) => (
        <NotificationItem
          key={notification.id}
          notification={notification}
          onRemove={onRemove}
        />
      ))}
    </div>
  );
};

export default NotificationSystem;
