import { readFile } from 'node:fs/promises';
export async function readAlerts(path = new URL('../fixtures/brute-force.json', import.meta.url)) {
  const fixture = JSON.parse(await readFile(path, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || !Array.isArray(fixture.alerts))
    throw new Error('Invalid Wazuh fixture');
  return fixture.alerts.map(a => ({
    id: typeof a?.id === 'string' ? a.id : '',
    timestamp: typeof a?.timestamp === 'string' ? a.timestamp : '',
    sourceAddress: typeof a?.data?.srcip === 'string' ? a.data.srcip : '',
    account: typeof a?.data?.srcuser === 'string' ? a.data.srcuser : '',
    ruleLevel: Number.isFinite(Number(a?.rule?.level)) ? Number(a.rule.level) : null,
    description: typeof a?.rule?.description === 'string' ? a.rule.description : ''
  }));
}
