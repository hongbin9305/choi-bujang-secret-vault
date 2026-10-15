// Inspection-only Wazuh reader; no raw URL, parameters, or secrets are printed.
import { readFile } from 'node:fs/promises';
const fixtureUrl = new URL('../fixtures/web-injection.json', import.meta.url);
export async function readAlerts() {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  if (!Array.isArray(fixture.alerts)) throw new Error('Invalid alert fixture');
  return fixture.alerts.map(alert => ({
    timestamp: alert.timestamp ?? null,
    sourceAddress: alert.data?.srcip ?? null,
    account: alert.data?.srcuser ?? null,
    level: alert.rule?.level ?? null,
    description: alert.rule?.description ?? ''
  }));
}
if (process.argv[1] && import.meta.url === new URL('file://' + process.argv[1].replace(/\\/g, '/')).href) {
  const lines = await readAlerts();
  console.log('alerts=' + lines.length + ' extracted=' + lines.length);
}
