// Standalone ATT&CK T1041 / T1048 classifier; mirrors patterns.json.
// No imports, filesystem or network operations.
const PATTERNS = Object.freeze({
  large_unfamiliar_destination: { minLevel: 10, minBytes: 50000000 },
  repeated_bulk_exfiltration: { minLevel: 10, minBytes: 50000000 },
  off_hours_archive_transfer: { minLevel: 10, minBytes: 50000000 },
  weak_outbound_anomaly: { minLevel: 5 }
});
export function decide(alert) {
  const tags = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const tagged = tags.includes('T1041') || tags.includes('T1048');
  const level = Number(alert?.rule?.level);
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const destination = typeof alert?.data?.dstip === 'string' && alert.data.dstip.trim().length > 0;
  const bytes = Number(alert?.data?.bytes);
  const files = Number(alert?.data?.files ?? 0);
  const count = Number(alert?.data?.count ?? 0);
  if (!tagged || !Number.isFinite(level))
    return { action: 'record', confidence: 0.05, reason: 'no_exfiltration_evidence' };
  const high = level >= PATTERNS.large_unfamiliar_destination.minLevel;
  const large = Number.isFinite(bytes) && bytes >= PATTERNS.large_unfamiliar_destination.minBytes;
  const unfamiliar = /처음 보는|평소에 쓰지 않던|외부 주소/.test(description);
  const repeated = /반복|연속|번입니다|짧은 시간|10분 안에/.test(description) || count >= 5 || files >= 50;
  const archive = /압축 파일/.test(description);
  const offHours = /수업 시간 밖|업무 시간 밖/.test(description);
  const bulk = /대용량|자료실 전체|자료 [0-9]+건|메모 묶음|큰 파일/.test(description);
  const abnormalPort = /평소에 쓰지 않던 포트/.test(description);
  const strong = high && destination && large;
  const firstSeen = strong && unfamiliar && (bulk || archive || offHours || repeated);
  const repeatedLarge = strong && repeated && (bulk || offHours || abnormalPort || count >= 5 || files >= 50);
  const offHoursArchive = strong && archive && (offHours || unfamiliar);
  const clear = firstSeen || repeatedLarge || offHoursArchive;
  const confidence = clear ? 0.96 : level >= PATTERNS.weak_outbound_anomaly.minLevel ? 0.62 : 0.08;
  const reason = clear ? offHoursArchive ? 'off_hours_archive_transfer'
    : repeatedLarge ? 'repeated_bulk_exfiltration' : 'large_unfamiliar_destination'
    : confidence >= 0.5 ? 'weak_outbound_anomaly' : 'insufficient_exfiltration_evidence';
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
}
