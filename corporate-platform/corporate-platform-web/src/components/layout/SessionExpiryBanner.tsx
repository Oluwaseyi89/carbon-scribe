'use client';

import { useState, useEffect, useRef } from 'react';
import { AlertTriangle, Clock, RefreshCw, X } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { AccessibleIcon } from '@/components/common/AccessibleIcon';
import { IconButton } from '@/components/common/IconButton';
import { useFocusTrap } from '@/hooks/useFocusTrap';

function formatCountdown(seconds: number): string {
  if (seconds >= 60) {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}m ${secs.toString().padStart(2, '0')}s`;
  }
  return `${seconds}s`;
}

export default function SessionExpiryBanner() {
  const { sessionExpiryState, secondsUntilExpiry, renewSession } = useAuth();
  const [isRenewing, setIsRenewing] = useState(false);
  const [renewFailed, setRenewFailed] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const bannerRef = useRef<HTMLDivElement>(null);

  // Reset dismissed state when expiry state changes
  if (sessionExpiryState === 'active' && dismissed) {
    setDismissed(false);
  }

  // Grace period is non-dismissable; warning can be dismissed
  const isGrace = sessionExpiryState === 'grace';
  const isWarning = sessionExpiryState === 'warning';

  // Focus trap for the banner when in grace period (non-dismissable)
  const { containerRef } = useFocusTrap({
    active: isGrace,
    autoFocus: true,
    onFocusTrap: () => {
      // Announce the banner when it traps focus
      const message = isGrace
        ? 'Session expired. Please renew your session immediately.'
        : 'Session expiring soon. Please renew your session.';
      // Use a11y announcement
      const announcer = document.createElement('div');
      announcer.setAttribute('role', 'alert');
      announcer.setAttribute('aria-live', 'assertive');
      announcer.className = 'sr-only';
      announcer.textContent = message;
      document.body.appendChild(announcer);
      setTimeout(() => document.body.removeChild(announcer), 3000);
    },
  });

  if (sessionExpiryState === 'active' || sessionExpiryState === 'expired') return null;
  if (isWarning && dismissed) return null;

  const handleRenew = async () => {
    setIsRenewing(true);
    setRenewFailed(false);
    const success = await renewSession();
    if (!success) setRenewFailed(true);
    setIsRenewing(false);
  };

  const handleDismiss = () => {
    setDismissed(true);
    // Return focus to the element that triggered the banner
    const triggerElement = document.activeElement as HTMLElement;
    if (triggerElement) {
      triggerElement.focus();
    }
  };

  const getAriaLabel = () => {
    if (isGrace) {
      return 'Session expired. Auto-logout in ' + formatCountdown(secondsUntilExpiry) + '. Renew now to stay signed in.';
    }
    return 'Session expiring soon. You will be logged out in ' + formatCountdown(secondsUntilExpiry) + '.';
  };

  const getStatusMessage = () => {
    if (isGrace) {
      return (
        <>
          <span className="font-semibold">Session expired.</span>{' '}
          Auto-logout in{' '}
          <span className="tabular-nums font-mono font-bold" aria-live="polite">
            {formatCountdown(secondsUntilExpiry)}
          </span>
          {' '}— renew now to stay signed in.
        </>
      );
    }
    return (
      <>
        <span className="font-semibold">Session expiring soon.</span>{' '}
        You will be logged out in{' '}
        <span className="tabular-nums font-mono font-bold" aria-live="polite">
          {formatCountdown(secondsUntilExpiry)}
        </span>
        .
      </>
    );
  };

  return (
    <div
      ref={(el) => {
        bannerRef.current = el;
        containerRef.current = el;
      }}
      role="alert"
      aria-live={isGrace ? 'assertive' : 'polite'}
      aria-label={getAriaLabel()}
      className={[
        'flex items-center gap-3 px-4 py-2.5 text-sm font-medium border-b focus:outline-none',
        isGrace
          ? 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800 text-red-800 dark:text-red-200'
          : 'bg-amber-50 dark:bg-amber-900/20 border-amber-200 dark:border-amber-800 text-amber-800 dark:text-amber-200',
      ].join(' ')}
      tabIndex={isGrace ? 0 : -1}
    >
      {/* Icon */}
      <AccessibleIcon hidden aria-hidden="true">
        {isGrace ? (
          <Clock size={16} className="shrink-0 text-red-500 dark:text-red-400" />
        ) : (
          <AlertTriangle size={16} className="shrink-0 text-amber-500 dark:text-amber-400" />
        )}
      </AccessibleIcon>

      {/* Message */}
      <span className="flex-1">
        {getStatusMessage()}
        {renewFailed && (
          <span className="ml-2 text-xs opacity-80" role="alert" aria-live="polite">
            (Renewal failed — please try again.)
          </span>
        )}
      </span>

      {/* Renew button */}
      <IconButton
        label={isRenewing ? 'Renewing session...' : 'Renew session'}
        onClick={handleRenew}
        disabled={isRenewing}
        className={[
          'shrink-0 flex items-center gap-1.5 rounded-md px-3 py-1 text-xs font-semibold transition-colors focus:ring-2 focus:ring-offset-2',
          isGrace
            ? 'bg-red-600 hover:bg-red-700 disabled:bg-red-400 text-white focus:ring-red-500'
            : 'bg-amber-600 hover:bg-amber-700 disabled:bg-amber-400 text-white focus:ring-amber-500',
        ].join(' ')}
      >
        <AccessibleIcon hidden aria-hidden="true">
          <RefreshCw size={12} className={isRenewing ? 'animate-spin' : ''} />
        </AccessibleIcon>
        <span>{isRenewing ? 'Renewing…' : 'Renew Session'}</span>
        {isRenewing && <span className="sr-only">Please wait while your session is being renewed</span>}
      </IconButton>

      {/* Dismiss (warning only) */}
      {isWarning && (
        <IconButton
          label="Dismiss session warning"
          onClick={handleDismiss}
          className="shrink-0 rounded-md p-1 hover:bg-amber-100 dark:hover:bg-amber-900/40 transition-colors focus:ring-2 focus:ring-amber-500 focus:ring-offset-2"
        >
          <AccessibleIcon hidden aria-hidden="true">
            <X size={14} />
          </AccessibleIcon>
          <span className="sr-only">Dismiss session expiry warning</span>
        </IconButton>
      )}
    </div>
  );
}