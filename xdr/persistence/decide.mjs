// Standalone T1543/T1053 classifier; mirrors patterns.json.
// No imports, file I/O, or network.
const PATTERNS = Object.freeze({
  unsigned_temp_service: { minLevel: 10 },
  suspicious_scheduled_task: { minLevel: 10 },
  unrecognized_startup_entry: { minLevel: 10 },
  weak_persistence_indicator: { minLevel: 5 }
});
export function decide(alert) {
  const level = Number(alert?.rule?.level);
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const path = typeof alert?.data?.path === 'string' ? alert.data.path : '';
  const tagged = Array.isArray(alert?.rule?.mitre)
    && alert.rule.mitre.some(t => t === 'T1543' || t === 'T1053');
  const source = typeof alert?.data?.srcip === 'string' && alert.data.srcip.trim() !== '';
  if (!tagged || !source || !Number.isFinite(level))
    return { action: 'record', confidence: 0.05, reason: 'no_persistence_evidence' };
  const temp = /\\Temp\\|\/temp\//i.test(path);
  const service = /서비스/.test(description);
  const task = /예약 작업/.test(description);
  const startup = /시작 폴더|시작 프로그램/.test(description);
  const unsigned = /서명 없|서명이 없/.test(description);
  const unknown = /평소 목록에 없는|처음 보는|임의 문자열/.test(description);
  const changed = /실행 파일이 바뀌|등록됐|등록이 연속/.test(description);
  const combined = /시작 프로그램과 예약 작업이 같은/.test(description);
  const clearService = service && ((unsigned && (temp || changed)) || (unknown && changed && temp));
  const clearTask = task && (temp && (unknown || /수업 시간 밖|같은 임시 파일/.test(description)));
  const clearStartup = startup && (unknown || combined) && (temp || /시작 폴더에 평소 목록에 없는/.test(description));
  const clear = level >= 10 && (clearService || clearTask || clearStartup || combined);
  const weak = level >= PATTERNS.weak_persistence_indicator.minLevel;
  const confidence = clear ? 0.95 : weak ? 0.60 : 0.10;
  const reason = clear ? (clearService ? 'unsigned_temp_service' : clearTask ? 'suspicious_scheduled_task' : 'unrecognized_startup_entry')
    : weak ? 'weak_persistence_indicator' : 'insufficient_persistence_evidence';
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
}
