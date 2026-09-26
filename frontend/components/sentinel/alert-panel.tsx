import { Siren } from 'lucide-react'
import type { SecurityAlert, Severity } from '@/lib/sentinel/types'
import { cn } from '@/lib/utils'
import { FieldLabel, Panel } from './panel'

const severityStyles: Record<Severity, string> = {
  low: 'border-border text-muted-foreground',
  medium: 'border-evidence/30 text-evidence',
  high: 'border-destructive/40 bg-destructive/10 text-destructive',
  critical: 'border-destructive bg-destructive text-background',
}

const timestampFormatter = new Intl.DateTimeFormat('en-US', {
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
  timeZone: 'UTC',
})

export function AlertPanel({ alert }: { alert: SecurityAlert }) {
  return (
    <Panel
      title="Current Alert"
      icon={Siren}
      labelledBy="alert-heading"
      meta={<span className="font-mono text-xs text-muted-foreground">{alert.id}</span>}
    >
      <div className="flex flex-col gap-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 flex-col gap-1">
            <FieldLabel>{alert.entityType}</FieldLabel>
            <p className="truncate font-mono text-sm">{alert.entity}</p>
          </div>
          <span
            className={cn(
              'shrink-0 rounded-md border px-2 py-0.5 font-mono text-xs font-medium uppercase',
              severityStyles[alert.severity],
            )}
          >
            {alert.severity}
          </span>
        </div>

        <p className="text-pretty text-sm leading-relaxed">{alert.text}</p>

        <dl className="grid grid-cols-2 gap-3 border-t pt-3">
          <div className="flex flex-col gap-1">
            <dt>
              <FieldLabel>Timestamp</FieldLabel>
            </dt>
            <dd className="font-mono text-xs">
              <time dateTime={alert.timestamp}>
                {timestampFormatter.format(new Date(alert.timestamp))} UTC
              </time>
            </dd>
          </div>
          <div className="flex flex-col gap-1">
            <dt>
              <FieldLabel>Source</FieldLabel>
            </dt>
            <dd className="font-mono text-xs">{alert.source}</dd>
          </div>
        </dl>
      </div>
    </Panel>
  )
}
