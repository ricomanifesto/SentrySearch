/**
 * Utility functions for SentrySearch frontend
 */

import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { format, formatDistanceToNow, parseISO } from 'date-fns';

/**
 * Combines class names with Tailwind CSS merge
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Format date for display
 */
export function formatDate(dateString: string): string {
  try {
    const date = parseISO(dateString);
    return format(date, 'MMM d, yyyy');
  } catch {
    return 'Invalid date';
  }
}

/**
 * Format date as relative time (e.g., "2 hours ago")
 */
export function formatRelativeTime(dateString: string): string {
  try {
    const date = parseISO(dateString);
    return formatDistanceToNow(date, { addSuffix: true });
  } catch {
    return 'Unknown time';
  }
}

/**
 * Format quality score with appropriate styling
 */
export function formatQualityScore(score: number): {
  formatted: string;
  color: string;
  bgColor: string;
} {
  const formatted = score.toFixed(1);
  
  if (score >= 4.0) {
    return {
      formatted,
      color: 'text-green-800',
      bgColor: 'bg-green-100'
    };
  } else if (score >= 3.0) {
    return {
      formatted,
      color: 'text-blue-800',
      bgColor: 'bg-blue-100'
    };
  } else if (score >= 2.0) {
    return {
      formatted,
      color: 'text-yellow-800',
      bgColor: 'bg-yellow-100'
    };
  } else {
    return {
      formatted,
      color: 'text-red-800',
      bgColor: 'bg-red-100'
    };
  }
}

/**
 * Format threat type for display
 */
export function formatThreatType(threatType: string): string {
  return threatType
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(' ');
}

/**
 * Format processing time
 */
export function formatProcessingTime(timeMs: number): string {
  if (timeMs < 1000) {
    return `${timeMs}ms`;
  } else if (timeMs < 60000) {
    return `${(timeMs / 1000).toFixed(1)}s`;
  } else {
    const minutes = Math.floor(timeMs / 60000);
    const seconds = Math.floor((timeMs % 60000) / 1000);
    return `${minutes}m ${seconds}s`;
  }
}

/**
 * Truncate text with ellipsis
 */
export function truncateText(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength).trim() + '...';
}

/**
 * Get quality score badge variant
 */
export function getQualityBadgeVariant(score: number): 'success' | 'info' | 'warning' | 'error' {
  if (score >= 4.0) return 'success';
  if (score >= 3.0) return 'info';
  if (score >= 2.0) return 'warning';
  return 'error';
}

/**
 * Generate pagination info text
 */
export function getPaginationInfo(
  page: number,
  limit: number,
  total: number
): string {
  const start = (page - 1) * limit + 1;
  const end = Math.min(page * limit, total);
  
  if (total === 0) {
    return 'No results found';
  }
  
  return `Showing ${start}-${end} of ${total} results`;
}

/**
 * Calculate total pages
 */
export function getTotalPages(total: number, limit: number): number {
  return Math.ceil(total / limit);
}

/**
 * Generate page numbers for pagination
 */
export function getPaginationRange(
  currentPage: number,
  totalPages: number,
  maxVisible: number = 5
): number[] {
  const half = Math.floor(maxVisible / 2);
  let start = Math.max(1, currentPage - half);
  const end = Math.min(totalPages, start + maxVisible - 1);
  
  // Adjust start if we're near the end
  if (end - start + 1 < maxVisible) {
    start = Math.max(1, end - maxVisible + 1);
  }
  
  return Array.from({ length: end - start + 1 }, (_, i) => start + i);
}

/**
 * Debounce function for search inputs
 */
export function debounce<T extends (...args: unknown[]) => unknown>(
  func: T,
  delay: number
): (...args: Parameters<T>) => void {
  let timeoutId: NodeJS.Timeout;
  
  return (...args: Parameters<T>) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => func(...args), delay);
  };
}

/**
 * Format file size
 */
export function formatFileSize(bytes: number): string {
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  if (bytes === 0) return '0 Bytes';
  
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
}

/**
 * Generate initials from name
 */
export function getInitials(name: string): string {
  return name
    .split(' ')
    .map(word => word.charAt(0).toUpperCase())
    .join('')
    .slice(0, 2);
}

/**
 * Check if running in development mode
 */
export function isDevelopment(): boolean {
  return process.env.NODE_ENV === 'development';
}

/**
 * Safe JSON parse with fallback
 */
export function safeJsonParse<T>(json: string, fallback: T): T {
  try {
    return JSON.parse(json);
  } catch {
    return fallback;
  }
}

/**
 * Download content as file
 */
export function downloadAsFile(content: string, filename: string, contentType: string = 'text/plain') {
  const blob = new Blob([content], { type: contentType });
  const url = URL.createObjectURL(blob);
  
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}