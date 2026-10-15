// Standalone CVE-2021-44228 / MITRE ATT&CK T1190 classifier.
// Patterns mirror patterns.json; no imports, external calls, or file I/O.
const PATTERNS = Object.freeze({
  log4shell_jndi_lookup: { minLevel: 10 },
  log4shell_repeated_probe: { minLevel: 10, minCount: 2 },
  weak_cve_indicator: { minLevel: 5 }
});
export function decide(alert) {
  const level = Number(alert?.rule?.level);
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const data = alert?.data ?? {};
  const source = typeof data.srcip === 'string' && data.srcip.trim().length > 0;
  const tagged = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1190');
  if (!tagged || !source || !Number.isFinite(level))
    return { action: 'record', confidence: 0.05, reason: 'no_T1190_evidence' };

  const fields = [data.url, data.useragent, data.uri, data.query, data.referer, data.request];
  let request = fields.filter(v => typeof v === 'string').join(' ');
  try { request = decodeURIComponent(request); } catch {}
  const explicitLookup = /\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns)\s*:\s*\/\//i.test(request);
  const explicitDescription = /CVE-2021-44228 형태 요청|CVE-2021-44228 형태가|CVE-2021-44228 표기가|원격 조회 구문이 \d+번/.test(description)
    && !/구문은 없습니다|악용 구문은 없습니다|완전한 구문은 아닙니다/.test(description);
  const clear = level >= PATTERNS.log4shell_jndi_lookup.minLevel && (explicitLookup || explicitDescription);
  const suspicious = level >= PATTERNS.weak_cve_indicator.minLevel;
  const confidence = clear ? 0.97 : suspicious ? 0.60 : 0.15;
  return {
    action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence,
    reason: clear ? 'log4shell_jndi_lookup' : suspicious ? 'weak_cve_indicator' : 'insufficient_exploit_evidence'
  };
}
