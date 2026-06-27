import { formatInTimeZone } from 'date-fns-tz'

export function getUserTimezone(): string {
  try {
    const stored = localStorage.getItem('soc-auth')
    if (stored) {
      const parsed = JSON.parse(stored)
      const tz = parsed?.state?.user?.timezone
      if (tz && tz !== 'UTC') return tz
    }
  } catch { /* ignore parse errors */ }
  return Intl.DateTimeFormat().resolvedOptions().timeZone
}

export function formatDateTime(
  isoString: string | null | undefined,
  timezone?: string,
): string {
  if (!isoString) return '—'
  try {
    const tz = timezone ?? getUserTimezone()
    return formatInTimeZone(new Date(isoString), tz, 'dd MMM yyyy, HH:mm:ss')
  } catch {
    return isoString
  }
}

export function formatDateShort(
  isoString: string | null | undefined,
  timezone?: string,
): string {
  if (!isoString) return '—'
  try {
    const tz = timezone ?? getUserTimezone()
    return formatInTimeZone(new Date(isoString), tz, 'dd MMM HH:mm')
  } catch {
    return isoString
  }
}

export const TIMEZONE_OPTIONS = [
  { label: 'UTC', value: 'UTC' },
  // Africa
  { label: 'Cairo (UTC+2/+3)', value: 'Africa/Cairo' },
  { label: 'Johannesburg (UTC+2)', value: 'Africa/Johannesburg' },
  { label: 'Lagos (UTC+1)', value: 'Africa/Lagos' },
  { label: 'Nairobi (UTC+3)', value: 'Africa/Nairobi' },
  // Europe
  { label: 'London (UTC+0/+1)', value: 'Europe/London' },
  { label: 'Paris (UTC+1/+2)', value: 'Europe/Paris' },
  { label: 'Berlin (UTC+1/+2)', value: 'Europe/Berlin' },
  { label: 'Istanbul (UTC+3)', value: 'Europe/Istanbul' },
  { label: 'Moscow (UTC+3)', value: 'Europe/Moscow' },
  // Asia
  { label: 'Dubai (UTC+4)', value: 'Asia/Dubai' },
  { label: 'Riyadh (UTC+3)', value: 'Asia/Riyadh' },
  { label: 'Karachi (UTC+5)', value: 'Asia/Karachi' },
  { label: 'Mumbai (UTC+5:30)', value: 'Asia/Kolkata' },
  { label: 'Singapore (UTC+8)', value: 'Asia/Singapore' },
  { label: 'Tokyo (UTC+9)', value: 'Asia/Tokyo' },
  // Americas
  { label: 'New York (UTC-5/-4)', value: 'America/New_York' },
  { label: 'Chicago (UTC-6/-5)', value: 'America/Chicago' },
  { label: 'Los Angeles (UTC-8/-7)', value: 'America/Los_Angeles' },
  { label: 'São Paulo (UTC-3)', value: 'America/Sao_Paulo' },
]
