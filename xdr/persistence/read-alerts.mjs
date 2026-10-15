import { readFile } from 'node:fs/promises';
export async function readAlerts() {
  const fixture = JSON.parse(await readFile(new URL('../fixtures/persistence.json', import.meta.url), 'utf8'));
  if (!Array.isArray(fixture.alerts)) throw new Error('Invalid alerts');
  return fixture.alerts.map(a => ({
    timestamp: a.timestamp ?? null,
    sourceAddress: a.data?.srcip ?? null,
    account: a.data?.srcuser ?? null,
    level: a.rule?.level ?? null,
    description: a.rule?.description ?? ''
  }));
}
