import React, { useEffect, useState } from 'react';
import './NotificationSystem.css';

const getNotificationIcon = (type) => {
  switch (type) {
    case 'success': return '✅';
    case 'error': return '❌';
    case 'warning': return '⚠️';
    case 'info':
    default: return 'ℹ️';
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
