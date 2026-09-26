'use client'

import { ArrowRight, Info } from 'lucide-react'
import { useEffect, useState } from 'react'
import type { InvestigationRun } from '@/lib/sentinel/types'
import { AdaptationResult } from './adaptation-result'
import { AlertPanel } from './alert-panel'
import { InvestigationTimeline } from './investigation-timeline'
import { MemoryPanel } from './memory-panel'
import { SentinelHeader } from './sentinel-header'

type Phase = 'ready' | 'fetching' | 'revealing' | 'complete'

const MEMORY_REVEAL_MS = 700
const STEP_REVEAL_MS = 800

export function SentinelConsole({ initialRun }: { initialRun: InvestigationRun }) {
  const [run, setRun] = useState(initialRun)
  const [phase, setPhase] = useState<Phase>('ready')
  const [visibleCount, setVisibleCount] = useState(0)
  const [memoryVisible, setMemoryVisible] = useState(false)
  const [dataReady, setDataReady] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (phase === 'fetching') {
      const timer = setTimeout(() => {
        setMemoryVisible(true)
        setPhase('revealing')
      }, MEMORY_REVEAL_MS)
      return () => clearTimeout(timer)
    }
    if (phase !== 'revealing') return
    const done = visibleCount >= run.steps.length
    const timer = setTimeout(
      () => (done ? setPhase('complete') : setVisibleCount((count) => count + 1)),
      done ? 500 : STEP_REVEAL_MS,
    )
    return () => clearTimeout(timer)
  }, [phase, visibleCount, run.steps.length])

  useEffect(() => {
    void loadPersistedDemo()
  }, [])

  async function loadPersistedDemo() {
    try {
      const res = await fetch('/api/investigate', { cache: 'no-store' })
      if (!res.ok) throw new Error(`Request failed with status ${res.status}`)
      const next = (await res.json()) as InvestigationRun
      if (next.source !== 'backend') throw new Error('Backend proxy returned fallback demo data')
      console.log('Loaded investigation source:', next.source)
      console.log('Loaded entity:', next.alert.entity)
      setRun(next)
      setVisibleCount(0)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error'
      console.error('Sentinel persisted demo load failed:', message)
      setError(`Live backend unavailable (${message}). Showing fallback demo data.`)
    } finally {
      setDataReady(true)
    }
  }

  function handleRun() {
    setError(null)
    setVisibleCount(0)
    setMemoryVisible(false)
    setPhase('fetching')
  }

  function handleReset() {
    setError(null)
    setVisibleCount(0)
    setMemoryVisible(false)
    setPhase('ready')
  }

  const notice = error ?? run.notice

  return (
    <main className="mx-auto flex min-h-dvh w-full max-w-7xl flex-col gap-5 px-4 py-6 md:px-6 lg:py-8">
      <SentinelHeader memoryStore={run.memoryStore} running={phase === 'fetching' || phase === 'revealing'} ready={dataReady} onRun={handleRun} onReset={handleReset} />

      <StoryStrip />

      {notice && (
        <p
          role="status"
          className="flex items-center gap-2 rounded-lg border border-evidence/30 bg-evidence/5 px-3 py-2 text-sm text-evidence"
        >
          <Info className="size-4 shrink-0" aria-hidden="true" />
          {notice}
        </p>
      )}

      <div className="grid gap-5 lg:grid-cols-[minmax(0,5fr)_minmax(0,8fr)]">
        <div className="flex flex-col gap-5">
          <AlertPanel alert={run.alert} />
          <MemoryPanel memory={memoryVisible ? run.memory : null} retrieving={phase === 'fetching'} />
        </div>
        <InvestigationTimeline
          steps={run.steps}
          visibleCount={visibleCount}
          memory={memoryVisible ? run.memory : null}
          verdict={run.verdict}
          phase={phase}
        />
      </div>

      {phase === 'complete' && <AdaptationResult adaptation={run.adaptation} ready />}
    </main>
  )
}

const story = ['Alert arrives', 'Recall similar incident', 'Targeted investigation', 'Resolved in fewer calls']

function StoryStrip() {
  return (
    <ol className="flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-xs text-muted-foreground">
      {story.map((label, index) => (
        <li key={label} className="flex items-center gap-2">
          <span className={index === 1 ? 'text-memory' : undefined}>
            <span className="text-foreground/30">{`0${index + 1} `}</span>
            {label}
          </span>
          {index < story.length - 1 && <ArrowRight className="size-3 text-foreground/30" aria-hidden="true" />}
        </li>
      ))}
    </ol>
  )
}
