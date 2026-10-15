// Standalone, offline MITRE ATT&CK T1110 classifier. No imports or I/O.
const PATTERNS = Object.freeze([
  { name: 'rapid_failed_logins', minCount:40, maxMinutes:3 },
  { name: 'password_spraying', minAccounts:8 },
  { name: 'repeated_failed_logins', minCount:40 },
  { name: 'moderate_failure_burst', minCount:8 }
]);

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const level = Number(alert?.rule?.level);
  const count = Number(alert?.data?.count);
  const mitre = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1110');
  const hasSource = typeof alert?.data?.srcip === 'string' && alert.data.srcip.length > 0;
  const hasAccount = typeof alert?.data?.srcuser === 'string' && alert.data.srcuser.length > 0;
  const positiveSuccess = /성공|로그아웃|세션 유지|상태가 유지|화면이 열렸/.test(
    description.replace(/성공은 없습니다|성공이 없습니다|성공하지 못했습니다/g, '')
  );
  const failed = /실패|비밀번호를 .*넣었|비밀번호를 연속으로 넣었/.test(description);
  if (!mitre || !hasSource || !hasAccount || !failed || positiveSuccess || !Number.isFinite(level)) {
    return { action: 'record', confidence: 0.05, reason: 'no_confirmed_T1110_pattern' };
  }

  const minutes = description.match(/(\d+)분/);
  const timed = minutes !== null && Number(minutes[1]) <= PATTERNS[0].maxMinutes;
  const rapid = Number.isFinite(count) && count >= PATTERNS[0].minCount && timed;
  const spraying = /여러 계정에 같은 비밀번호|서로 다른 계정 \d+개에 같은 비밀번호|계정 \d+개에 같은 간격으로 로그인 실패/.test(description);
  const continuous = Number.isFinite(count) && count >= PATTERNS[2].minCount
    && /같은 주소와 같은 계정에서|같은 주소에서.*이어졌/.test(description);
  if (level >= 10 && (rapid || spraying || continuous)) {
    return { action: 'block', confidence: 0.95, reason: spraying ? 'password_spraying' : continuous ? 'repeated_failed_logins' : 'rapid_failed_logins' };
  }

  const moderate = (Number.isFinite(count) && count >= PATTERNS[3].minCount
    && (/계정 이름을 바꿔|한 글자씩 바꿔|간격은 고르지 않|성공은 없습니다/.test(description)))
    || (Number.isFinite(count) && count >= PATTERNS[2].minCount && /성공은 없습니다/.test(description));
  if (moderate) {
    return { action: 'alert', confidence: 0.65, reason: 'moderate_failure_burst' };
  }
  return { action: 'record', confidence: 0.2, reason: 'insufficient_brute_force_evidence' };
}
