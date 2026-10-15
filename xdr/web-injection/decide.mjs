// Offline T1190 classifier: standalone, no imports, network, or file I/O.
const PATTERNS = Object.freeze({
  repeated_sql_injection: { minLevel: 10, minCount: 8 },
  repeated_script_injection: { minLevel: 10, minCount: 8 },
  repeated_path_traversal: { minLevel: 10, minCount: 8 },
  repeated_command_separator: { minLevel: 10, minCount: 8 },
  single_suspicious_marker: { minLevel: 6, maxCount: 1 }
});
const BLOCK_THRESHOLD = 0.85;
const ALERT_THRESHOLD = 0.5;
export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const url = typeof alert?.data?.url === 'string' ? alert.data.url : '';
  const level = Number(alert?.rule?.level);
  const count = alert?.data?.count == null ? NaN : Number(alert.data.count);
  const source = typeof alert?.data?.srcip === 'string' && alert.data.srcip.trim() !== '';
  const tagged = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1190');
  if (!tagged || !source || !Number.isFinite(level)) {
    return { action: 'record', confidence: 0.05, reason: 'no_T1190_attack_evidence' };
  }
  // Descriptions and actual request syntax are both considered. Do not mistake
  // safe educational search terms for executable SQL/script/traversal payloads.
  const sql = /SQL 구문|SQL 표기|데이터베이스 조회를 이어 붙이|SQL.*이어 붙이/i.test(description)
    || /(?:union\s+select|\bor\s+1\s*=\s*1|;\s*(?:select|drop|insert)\b)/i.test(url);
  const script = /스크립트 삽입 표기|스크립트 표식/i.test(description)
    || /<script\b|%3cscript\b|onerror\s*=/i.test(url);
  const traversal = /경로를 여러 단계 거슬러|경로 이탈 표기/i.test(description)
    || /(?:\.\.\/|%2e%2e%2f){2,}/i.test(url);
  const command = /명령 구분자 표기/i.test(description)
    || /(?:;|%3b)\s*(?:cat|curl|wget|bash)\b/i.test(url);
  const repeated = Number.isFinite(count) && count >= 8 && level >= 10;
  let confidence = 0.15;
  let reason = 'insufficient_injection_evidence';
  if (repeated && (sql || script || traversal || command)) {
    confidence = 0.95;
    reason = sql ? 'repeated_sql_injection' : script ? 'repeated_script_injection'
      : traversal ? 'repeated_path_traversal' : 'repeated_command_separator';
  } else {
    const isolated = /주입처럼 보이는 표기가 1건/.test(description)
      && count === PATTERNS.single_suspicious_marker.maxCount
      && level >= PATTERNS.single_suspicious_marker.minLevel;
    if (isolated) {
      confidence = 0.65;
      reason = 'single_suspicious_marker';
    }
  }
  return { action: confidence >= BLOCK_THRESHOLD ? 'block'
    : confidence >= ALERT_THRESHOLD ? 'alert' : 'record', confidence, reason };
}
