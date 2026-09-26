import { Check, GitCompareArrows, X } from 'lucide-react'
import type { Adaptation, RunStats } from '@/lib/sentinel/types'
import { cn } from '@/lib/utils'
import { Panel } from './panel'

const rows: { key: keyof RunStats; label: string }[] = [
  { key: 'toolCalls', label: 'Tool calls' },
  { key: 'callsBeforeCriticalEvidence', label: 'Calls before critical evidence' },
  { key: 'unnecessaryCalls', label: 'Unnecessary calls' },
]

export function AdaptationResult({ adaptation, ready }: { adaptation: Adaptation; ready: boolean }) {
  const saved = adaptation.withoutMemory.toolCalls - adaptation.withMemory.toolCalls

  return (
    <Panel
      title="Adaptation Result"
      icon={GitCompareArrows}
      labelledBy="adaptation-heading"
      className={cn('transition-opacity duration-500', !ready && 'opacity-40')}
      meta={
        !ready && <span className="font-mono text-xs text-muted-foreground">awaiting verdict</span>
      }
    >
      <div className="grid gap-4 lg:grid-cols-[1fr_auto] lg:items-center">
        <table className="w-full text-sm">
          <caption className="sr-only">Investigation efficiency with and without memory</caption>
          <thead>
            <tr className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
              <th scope="col" className="pb-2 text-left font-normal">
                Metric
              </th>
              <th scope="col" className="pb-2 text-right font-normal">
                Without memory
              </th>
              <th scope="col" className="pb-2 text-right font-normal text-memory">
                With memory
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.key} className="border-t">
                <th scope="row" className="py-2 text-left font-normal text-muted-foreground">
                  {row.label}
                </th>
                <td className="py-2 text-right font-mono tabular-nums text-muted-foreground">
                  {adaptation.withoutMemory[row.key]}
                </td>
                <td className="py-2 text-right font-mono font-semibold tabular-nums text-memory">
                  {adaptation.withMemory[row.key]}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        <ul className="grid grid-cols-3 gap-2 lg:w-[26rem]">
          <li className="flex flex-col gap-1 rounded-lg border border-memory/25 bg-memory/5 p-3">
            <span className="font-mono text-2xl font-semibold tabular-nums text-memory">{saved}</span>
            <span className="text-xs text-muted-foreground">Tool calls saved</span>
          </li>
          <Outcome ok={adaptation.correctClassification} label="Correct classification" />
          <Outcome ok={adaptation.criticalEvidenceFound} label="Critical evidence found" />
        </ul>
      </div>
    </Panel>
  )
}

function Outcome({ ok, label }: { ok: boolean; label: string }) {
  const Icon = ok ? Check : X
  return (
    <li className="flex flex-col gap-1 rounded-lg border bg-background/40 p-3">
      <Icon className={cn('size-7', ok ? 'text-memory' : 'text-destructive')} aria-hidden="true" />
      <span className="text-xs text-muted-foreground">
        <span className="sr-only">{ok ? 'Yes: ' : 'No: '}</span>
        {label}
      </span>
    </li>
  )
}
