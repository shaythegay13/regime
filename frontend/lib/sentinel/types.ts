export type Severity = 'low' | 'medium' | 'high' | 'critical'

export interface SecurityAlert {
  id: string
  entity: string
  entityType: string
  text: string
  severity: Severity
  timestamp: string
  source: string
}

export interface InvestigationStep {
  id: string
  thought: string
  tool: string
  reason: string
  observation: string
  critical?: boolean
  memoryGuided?: boolean
}

export interface MemoryMatch {
  incidentId: string
  similarity: number
  incidentType: string
  usefulTools: string[]
  lesson: string
  influence: string
  resolvedAt: string
}

export interface Verdict {
  classification: string
  confidence: number
  status: 'RESOLVED' | 'ESCALATED' | 'OPEN'
  summary: string
}

export interface RunStats {
  toolCalls: number
  callsBeforeCriticalEvidence: number
  unnecessaryCalls: number
}

export interface Adaptation {
  withoutMemory: RunStats
  withMemory: RunStats
  correctClassification: boolean
  criticalEvidenceFound: boolean
}

export interface MemoryStoreStatus {
  provider: string
  status: 'connected' | 'demo' | 'unavailable'
  collection: string
}

export interface InvestigationRun {
  runId: string
  source: 'backend' | 'demo'
  notice?: string
  memoryStore: MemoryStoreStatus
  alert: SecurityAlert
  memory: MemoryMatch | null
  steps: InvestigationStep[]
  verdict: Verdict
  adaptation: Adaptation
}
