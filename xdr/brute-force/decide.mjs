// Offline, standalone MITRE ATT&CK T1110 detection. No imports or I/O.
const PATTERNS = Object.freeze([
  { name:'rapid_failed_logins', minCount:40, maxMinutes:3, minLevel:10 },
  { name:'password_spraying', minLevel:10, marker:'여러 계정에 같은 비밀번호' },
  { name:'moderate_failure_burst', minCount:8, maxCount:39 }
]);
export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const level = Number(alert?.rule?.level);
  const count = Number(alert?.data?.count);
  const mitre = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1110');
  const ip = typeof alert?.data?.srcip === 'string' && alert.data.srcip.length > 0;
  const user = typeof alert?.data?.srcuser === 'string' && alert.data.srcuser.length > 0;
  const failure = /실패|연속으로 넣었|대입/.test(description);
  const success = /성공|로그아웃|세션 유지|상태가 유지|화면이 열렸/.test(description.replace(/성공은 없습니다|성공이 없습니다|성공하지 못했습니다/g, ''));
  if (!mitre || !ip || !user || !failure || success || !Number.isFinite(level))
    return { action:'record', confidence:0.05, reason:'no_confirmed_T1110_pattern' };
  const minutes = description.match(/(\d+)분/);
  const withinWindow = minutes && Number(minutes[1]) <= PATTERNS[0].maxMinutes;
  const spraying = /여러 계정에 같은 비밀번호|서로 다른 계정 \d+개에 같은 비밀번호|계정 \d+개에 같은 간격으로 로그인 실패/.test(description);
  const highVolume = Number.isFinite(count) && count >= PATTERNS[0].minCount;
  if (level >= PATTERNS[0].minLevel && (highVolume && withinWindow))
    return { action:'block', confidence:0.95, reason:highVolume?'rapid_failed_logins':'password_spraying' };
  if (failure && mitre)
    return { action:'alert', confidence:0.65, reason:'moderate_failure_burst' };
  return { action:'record', confidence:0.2, reason:'insufficient_brute_force_evidence' };
}
