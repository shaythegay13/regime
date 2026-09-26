import { BrainCircuit, CircleCheck, Database, LoaderCircle, TriangleAlert } from 'lucide-react'
import type { InvestigationStep, MemoryMatch, Verdict } from '@/lib/sentinel/types'
import { cn } from '@/lib/utils'
import { FieldLabel, Panel } from './panel'

interface InvestigationTimelineProps {
  steps: InvestigationStep[]
  visibleCount: number
  memory: MemoryMatch | null
  verdict: Verdict
  phase: 'ready' | 'fetching' | 'revealing' | 'complete'
}

export function InvestigationTimeline({
  steps,
  visibleCount,
  memory,
  verdict,
  phase,
}: InvestigationTimelineProps) {
  const visibleSteps = steps.slice(0, visibleCount)
  const thinking = phase === 'revealing' && visibleCount < steps.length

  return (
    <Panel
      title="Agent Investigation"
      icon={BrainCircuit}
      labelledBy="investigation-heading"
      className="h-full"
      meta={
        <span className="font-mono text-xs text-muted-foreground tabular-nums">
          {phase === 'fetching' ? 'starting…' : `${visibleSteps.length} / ${steps.length} tool calls`}
        </span>
      }
    >
      <ol className="flex flex-col" aria-live="polite">
        <TimelineNode
          marker={
            phase === 'fetching' ? (
              <LoaderCircle className="size-3.5 animate-spin text-memory" aria-hidden="true" />
            ) : (
              <Database className="size-3.5 text-memory" aria-hidden="true" />
            )
          }
          markerClassName="border-memory/40 bg-memory/10"
          last={phase === 'fetching'}
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-medium">Recall similar incidents</span>
            <ToolChip>memory.vector_search</ToolChip>
          </div>
          <p className="mt-1 text-sm text-muted-foreground">
            {phase === 'fetching'
              ? 'Embedding the alert and querying MongoDB Atlas…'
              : memory
                ? `Matched ${memory.incidentId} (${memory.incidentType}) at ${memory.similarity.toFixed(2)} similarity. Plan adapted.`
                : 'No similar incident found. Using the default playbook.'}
          </p>
        </TimelineNode>

        {visibleSteps.map((step, index) => (
          <TimelineNode
            key={step.id}
            marker={<span className="font-mono text-[11px] tabular-nums">{index + 1}</span>}
            markerClassName={step.critical ? 'border-evidence/60 bg-evidence/15 text-evidence' : undefined}
            last={index === visibleSteps.length - 1 && !thinking && phase !== 'complete'}
            animate={phase === 'revealing'}
          >
            <StepCard step={step} />
          </TimelineNode>
        ))}

        {thinking && (
          <TimelineNode
            marker={<LoaderCircle className="size-3.5 animate-spin" aria-hidden="true" />}
            last
          >
            <p className="pt-0.5 text-sm text-muted-foreground" role="status">
              Selecting next tool…
            </p>
          </TimelineNode>
        )}

        {phase === 'complete' && (
          <TimelineNode
            marker={<CircleCheck className="size-4 text-memory" aria-hidden="true" />}
            markerClassName="border-memory/50 bg-memory/10"
            last
            animate
          >
            <VerdictCard verdict={verdict} />
          </TimelineNode>
        )}
      </ol>
    </Panel>
  )
}

function TimelineNode({
  marker,
  markerClassName,
  last,
  animate,
  children,
}: {
  marker: React.ReactNode
  markerClassName?: string
  last?: boolean
  animate?: boolean
  children: React.ReactNode
}) {
  return (
    <li
      className={cn(
        'relative flex gap-4 pb-5 last:pb-0',
        animate && 'animate-in fade-in slide-in-from-bottom-2 duration-500',
      )}
    >
      {!last && <span aria-hidden="true" className="absolute top-8 bottom-0 left-[13px] w-px bg-border" />}
      <div
        className={cn(
          'relative z-10 flex size-7 shrink-0 items-center justify-center rounded-full border bg-secondary text-muted-foreground',
          markerClassName,
        )}
      >
        {marker}
      </div>
      <div className="min-w-0 flex-1 pt-0.5">{children}</div>
    </li>
  )
}

function ToolChip({ children }: { children: React.ReactNode }) {
  return (
    <code className="rounded-md border bg-secondary px-1.5 py-0.5 font-mono text-xs text-foreground">
      {children}
    </code>
  )
}

function StepCard({ step }: { step: InvestigationStep }) {
  return (
    <div
      className={cn(
        'rounded-lg border bg-background/40 p-3',
        step.critical && 'border-evidence/40 bg-evidence/5',
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        <ToolChip>{step.tool}</ToolChip>
        {step.memoryGuided && (
          <span className="rounded-md bg-memory/10 px-1.5 py-0.5 font-mono text-[11px] text-memory">
            memory-guided
          </span>
        )}
        {step.critical && (
          <span className="flex items-center gap-1 rounded-md bg-evidence/15 px-1.5 py-0.5 font-mono text-[11px] text-evidence">
            <TriangleAlert className="size-3" aria-hidden="true" />
            critical evidence
          </span>
        )}
      </div>
      <p className="mt-2.5 text-pretty text-sm font-medium leading-relaxed">{step.thought}</p>
      <dl className="mt-3 grid gap-3 md:grid-cols-2">
        <div className="flex flex-col gap-1">
          <dt>
            <FieldLabel>Reason</FieldLabel>
          </dt>
          <dd className="text-pretty text-sm leading-relaxed text-muted-foreground">{step.reason}</dd>
        </div>
        <div className="flex flex-col gap-1">
          <dt>
            <FieldLabel>Observation</FieldLabel>
          </dt>
          <dd className="text-pretty text-sm leading-relaxed">{step.observation}</dd>
        </div>
      </dl>
    </div>
  )
}

function VerdictCard({ verdict }: { verdict: Verdict }) {
  const resolved = verdict.status === 'RESOLVED'
  return (
    <div className="rounded-lg border border-memory/30 bg-memory/5 p-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex flex-col gap-1">
          <FieldLabel>Classification</FieldLabel>
          <p className="text-base font-semibold">{verdict.classification}</p>
        </div>
        <div className="flex items-center gap-5">
          <div className="flex flex-col items-end gap-1">
            <FieldLabel>Confidence</FieldLabel>
            <p className="font-mono text-base font-semibold tabular-nums">
              {Math.round(verdict.confidence * 100)}%
            </p>
          </div>
          <span
            className={cn(
              'rounded-md px-2.5 py-1 font-mono text-xs font-semibold tracking-wider',
              resolved ? 'bg-memory text-memory-foreground' : 'bg-evidence text-evidence-foreground',
            )}
          >
            {verdict.status}
          </span>
        </div>
      </div>
      <p className="mt-3 border-t border-memory/15 pt-3 text-sm text-muted-foreground">{verdict.summary}</p>
    </div>
  )
}
