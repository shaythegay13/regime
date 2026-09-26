import { SentinelConsole } from '@/components/sentinel/sentinel-console'
import { getDemoRun } from '@/lib/sentinel/demo-scenario'

export default function Page() {
  return <SentinelConsole initialRun={getDemoRun()} />
}
