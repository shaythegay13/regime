import { History, LoaderCircle } from 'lucide-react'
import type { MemoryMatch } from '@/lib/sentinel/types'
import { FieldLabel, Panel } from './panel'

interface MemoryPanelProps {
  memory: MemoryMatch | null
  retrieving: boolean
}

export function MemoryPanel({ memory, retrieving }: MemoryPanelProps) {
  return (
    <Panel
      title="Recalled Memory"
      icon={History}
      labelledBy="memory-heading"
      className={memory && !retrieving ? 'border-memory/25' : undefined}
      meta={<span className="font-mono text-xs text-muted-foreground">vector search</span>}
    >
      {retrieving ? (
        <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground" role="status">
          <LoaderCircle className="size-4 animate-spin" aria-hidden="true" />
          Searching incident memory for similar cases…
        </div>
      ) : !memory ? (
        <p className="py-6 text-sm text-muted-foreground">
          No similar prior incident found. Sentinel will investigate from scratch.
        </p>
      ) : (
        <div className="flex flex-col gap-4 animate-in fade-in duration-500">
          <div className="flex items-end justify-between gap-3">
            <div className="flex flex-col gap-1">
              <FieldLabel>Prior incident</FieldLabel>
              <p className="font-mono text-sm">{memory.incidentId}</p>
              <p className="text-sm text-muted-foreground">{memory.incidentType}</p>
            </div>
            <div className="flex flex-col items-end gap-1">
              <FieldLabel>Similarity</FieldLabel>
              <p className="font-mono text-2xl font-semibold tabular-nums text-memory">
                {memory.similarity.toFixed(2)}
              </p>
            </div>
          </div>
          <div
            className="h-1 overflow-hidden rounded-full bg-muted"
            role="meter"
            aria-label="Semantic similarity"
            aria-valuemin={0}
            aria-valuemax={1}
            aria-valuenow={memory.similarity}
          >
            <div className="h-full rounded-full bg-memory" style={{ width: `${memory.similarity * 100}%` }} />
          </div>

          <div className="flex flex-col gap-2">
            <FieldLabel>Tools that helped</FieldLabel>
            <ul className="flex flex-wrap gap-1.5">
              {memory.usefulTools.map((tool) => (
                <li key={tool} className="rounded-md border bg-secondary px-2 py-0.5 font-mono text-xs">
                  {tool}
                </li>
              ))}
            </ul>
          </div>

          <div className="flex flex-col gap-2">
            <FieldLabel>Lesson learned</FieldLabel>
            <blockquote className="border-l-2 pl-3 text-sm leading-relaxed text-muted-foreground">
              {memory.lesson}
            </blockquote>
          </div>

          <div className="flex flex-col gap-2 rounded-lg border border-memory/20 bg-memory/5 p-3">
            <span className="font-mono text-[11px] uppercase tracking-wider text-memory">
              How this shaped the investigation
            </span>
            <p className="text-pretty text-sm leading-relaxed">{memory.influence}</p>
          </div>
        </div>
      )}
    </Panel>
  )
}
