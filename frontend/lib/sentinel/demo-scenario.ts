import type { InvestigationRun } from './types'

export function getDemoRun(): InvestigationRun {
  return {
    runId: 'run-demo-0142',
    source: 'demo',
    memoryStore: {
      provider: 'MongoDB Atlas',
      status: 'demo',
      collection: 'sentinel.incident_memory',
    },
    alert: {
      id: 'ALRT-7731',
      entity: 'j.chen@northwind.io',
      entityType: 'User account',
      text: 'New inbox rule forwarding external mail created shortly after a third-party app was granted mailbox permissions.',
      severity: 'high',
      timestamp: '2026-09-26T14:32:08Z',
      source: 'M365 Defender',
    },
    memory: {
      incidentId: 'INC-2291',
      similarity: 0.91,
      incidentType: 'OAuth consent phishing',
      usefulTools: ['oauth_grants.lookup', 'mailbox_rules.list', 'threat_intel.app'],
      lesson:
        'Sign-in logs looked clean because the attacker never logged in — access came through a consented app token. Check OAuth grants first.',
      influence:
        'Sentinel skipped the password-compromise playbook (sign-in anomalies, MFA, device checks) and opened with the OAuth grant lookup that cracked INC-2291, reaching the critical evidence on its first tool call.',
      resolvedAt: '2026-08-11',
    },
    steps: [
      {
        id: 's1',
        thought: 'Memory says this pattern was consent phishing last time. Start where the evidence was.',
        tool: 'oauth_grants.lookup',
        reason: 'Prior lesson: attacker access came via a consented app token, not an interactive login.',
        observation:
          'User granted "Mail Sync Pro" Mail.ReadWrite + offline_access 4 minutes before the alert. Publisher is unverified.',
        critical: true,
        memoryGuided: true,
      },
      {
        id: 's2',
        thought: 'Confirm the app, not the user, created the forwarding rule.',
        tool: 'mailbox_rules.list',
        reason: 'Link the suspicious grant to the behavior that triggered the alert.',
        observation:
          'Rule "sync" forwards messages containing "invoice" or "payment" to an external address. Created by the Mail Sync Pro client ID.',
        memoryGuided: true,
      },
      {
        id: 's3',
        thought: 'Check whether the app is part of a known campaign.',
        tool: 'threat_intel.app',
        reason: 'Useful in INC-2291 to confirm attribution and scope.',
        observation: 'Client ID matches an active consent-phishing campaign reported against finance teams.',
        memoryGuided: true,
      },
      {
        id: 's4',
        thought: 'Rule out a parallel credential compromise before closing.',
        tool: 'signin_logs.query',
        reason: 'One confirmation check so the classification does not rely on memory alone.',
        observation: 'No anomalous interactive sign-ins. All mailbox access originates from the app token.',
      },
    ],
    verdict: {
      classification: 'Illicit OAuth consent grant',
      confidence: 0.94,
      status: 'RESOLVED',
      summary: 'Revoke the Mail Sync Pro grant, remove the forwarding rule, and notify the user.',
    },
    adaptation: {
      withoutMemory: { toolCalls: 9, callsBeforeCriticalEvidence: 6, unnecessaryCalls: 5 },
      withMemory: { toolCalls: 4, callsBeforeCriticalEvidence: 0, unnecessaryCalls: 0 },
      correctClassification: true,
      criticalEvidenceFound: true,
    },
  }
}
