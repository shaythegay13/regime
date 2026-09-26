import { LoaderCircle, Play, ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import type { MemoryStoreStatus } from '@/lib/sentinel/types'
import { cn } from '@/lib/utils'

interface SentinelHeaderProps {
  memoryStore: MemoryStoreStatus
  running: boolean
  onRun: () => void
}

const storeLabel: Record<MemoryStoreStatus['status'], string> = {
  connected: 'connected',
  demo: 'demo data',
  unavailable: 'unavailable',
}

export function SentinelHeader({ memoryStore, running, onRun }: SentinelHeaderProps) {
  return (
    <header className="flex flex-col gap-4 border-b pb-5 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex items-center gap-3">
        <div className="flex size-9 items-center justify-center rounded-lg border bg-secondary">
          <ShieldCheck className="size-5 text-memory" aria-hidden="true" />
        </div>
        <div>
          <h1 className="text-lg font-semibold tracking-tight">Sentinel</h1>
          <p className="text-sm text-muted-foreground">
            Adaptive memory for autonomous security investigations
          </p>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <div
          className="flex items-center gap-2 rounded-full border px-3 py-1.5 font-mono text-xs text-muted-foreground"
          title={memoryStore.collection}
        >
          <span
            aria-hidden="true"
            className={cn(
              'size-2 rounded-full',
              memoryStore.status === 'connected' && 'bg-memory shadow-[0_0_8px] shadow-memory/60',
              memoryStore.status === 'demo' && 'bg-evidence',
              memoryStore.status === 'unavailable' && 'bg-destructive',
            )}
          />
          <span>
            {memoryStore.provider}
            <span className="text-foreground/40">{' · '}</span>
            <span className={cn(memoryStore.status === 'connected' && 'text-memory')}>
              {storeLabel[memoryStore.status]}
            </span>
          </span>
        </div>
        <Button onClick={onRun} disabled={running} className="gap-2">
          {running ? (
            <LoaderCircle className="size-4 animate-spin" aria-hidden="true" />
          ) : (
            <Play className="size-4" aria-hidden="true" />
          )}
          {running ? 'Investigating…' : 'Run Investigation'}
        </Button>
      </div>
    </header>
  )
}
