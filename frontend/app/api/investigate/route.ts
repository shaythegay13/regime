import { getDemoRun } from '@/lib/sentinel/demo-scenario'
import type { InvestigationRun } from '@/lib/sentinel/types'

export const dynamic = 'force-dynamic'

export async function POST() {
  const backendUrl = process.env.SENTINEL_API_URL

  if (!backendUrl) {
    return Response.json(getDemoRun())
  }

  try {
    const res = await fetch(new URL('/investigate', backendUrl), {
      method: 'POST',
      cache: 'no-store',
      signal: AbortSignal.timeout(60_000),
    })
    if (!res.ok) throw new Error(`Backend responded ${res.status}`)
    const data = (await res.json()) as InvestigationRun
    return Response.json({ ...data, source: 'backend' } satisfies InvestigationRun)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error'
    return Response.json({
      ...getDemoRun(),
      notice: `Backend unreachable (${message}). Showing the demo scenario.`,
    } satisfies InvestigationRun)
  }
}
