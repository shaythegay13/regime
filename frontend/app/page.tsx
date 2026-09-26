import { SentinelConsole } from '@/components/sentinel/sentinel-console'
import { getDemoRun } from '@/lib/sentinel/demo-scenario'
import type { InvestigationRun } from '@/lib/sentinel/types'

export const dynamic = 'force-dynamic'

async function loadInitialRun(): Promise<InvestigationRun> {
  const backendUrl = process.env.SENTINEL_API_URL ?? 'http://127.0.0.1:8000'
  try {
    const response = await fetch(new URL('/api/demo', backendUrl), {
      cache: 'no-store',
      signal: AbortSignal.timeout(10_000),
    })
    if (!response.ok) throw new Error(`Backend responded ${response.status}`)
    const payload = (await response.json()) as InvestigationRun
    if (payload.source !== 'backend') throw new Error('Backend returned fallback data')
    return payload
  } catch (error) {
    console.error('Sentinel initial persisted demo load failed:', error)
    return getDemoRun()
  }
}

export default async function Page() {
  return <SentinelConsole initialRun={await loadInitialRun()} />
}
