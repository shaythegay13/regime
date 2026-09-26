import { getDemoRun } from '@/lib/sentinel/demo-scenario'
import type { InvestigationRun } from '@/lib/sentinel/types'

export const dynamic = 'force-dynamic'

async function loadPersistedDemo() {
  const backendUrl = process.env.SENTINEL_API_URL ?? 'http://127.0.0.1:8000'

  try {
    const res = await fetch(new URL('/api/demo', backendUrl), {
      cache: 'no-store',
      signal: AbortSignal.timeout(10_000),
    })
    if (!res.ok) throw new Error(`Backend responded ${res.status}`)
    const data = (await res.json()) as InvestigationRun
    return Response.json({ ...data, source: 'backend' } satisfies InvestigationRun)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error'
    console.error('Sentinel backend demo proxy failed:', message)
    return Response.json({
      ...getDemoRun(),
      notice: `Backend unreachable (${message}). Showing the demo scenario.`,
    } satisfies InvestigationRun)
  }
}

export async function GET() { return loadPersistedDemo() }
export async function POST() { return loadPersistedDemo() }
