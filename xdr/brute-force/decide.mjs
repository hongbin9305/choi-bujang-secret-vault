// Standalone MITRE ATT&CK T1110 decision module; no imports or I/O.
// Each pattern's conditions are evaluated below; confidence thresholds are explicit.
const PATTERNS = Object.freeze({
  rapid_failed_logins: { minCount: 40, maxMinutes: 3, minLevel: 10 },
  password_spraying: { minAccounts: 8, minLevel: 10 },
  repeated_failed_logins: { minCount: 40, minLevel: 10, sameSourceAndAccount: true },
  moderate_failure_burst: { minCount: 8, minLevel: 8 }
});
const BLOCK_THRESHOLD = 0.85;
const ALERT_THRESHOLD = 0.5;

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const level = Number(alert?.rule?.level);
  const rawCount = alert?.data?.count;
  const count = rawCount === undefined ? NaN : Number(rawCount);
  const hasT1110 = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1110');
  const source = typeof alert?.data?.srcip === 'string' && alert.data.srcip.trim() !== '';
  const account = typeof alert?.data?.srcuser === 'string' && alert.data.srcuser.trim() !== '';
  const positiveDescription = description.replace(/성공은 없습니다|성공이 없습니다|성공하지 못했습니다/g, '');
  const succeeded = /성공|로그아웃|세션 유지|상태가 유지|화면이 열렸/.test(positiveDescription);
  const failed = /실패|비밀번호를 .*넣었/.test(description);
  if (!hasT1110 || !source || !account || !Number.isFinite(level) || !failed || succeeded) {
    return { action: 'record', confidence: 0.05, reason: 'no_confirmed_T1110_pattern' };
  }

  const duration = description.match(/(\d+)분/);
  const minutes = duration ? Number(duration[1]) : Infinity;
  const rapid = level >= PATTERNS.rapid_failed_logins.minLevel
    && count >= PATTERNS.rapid_failed_logins.minCount
    && minutes <= PATTERNS.rapid_failed_logins.maxMinutes;

  const accounts = typeof alert?.data?.accounts === 'string'
    ? alert.data.accounts.split(',').map(v => v.trim()).filter(Boolean).length
    : Number((description.match(/(?:계정|계정 이름)\s*(\d+)개/) || [])[1]);
  const explicitSpraying = /여러 계정에 같은 비밀번호|서로 다른 계정 \d+개에 같은 비밀번호|계정 \d+개에 같은 간격으로 로그인 실패/.test(description);
  const spraying = level >= PATTERNS.password_spraying.minLevel && explicitSpraying
    && (accounts >= PATTERNS.password_spraying.minAccounts
      || /여러 계정에 같은 비밀번호/.test(description) && !Number.isFinite(accounts));

  const repeated = level >= PATTERNS.repeated_failed_logins.minLevel
    && count >= PATTERNS.repeated_failed_logins.minCount
    && /같은 주소와 같은 계정에서/.test(description);

  let confidence = 0.2;
  let reason = 'insufficient_brute_force_evidence';
  if (rapid || spraying || repeated) {
    confidence = 0.95;
    reason = spraying ? 'password_spraying' : repeated ? 'repeated_failed_logins' : 'rapid_failed_logins';
  } else if (
    level >= PATTERNS.moderate_failure_burst.minLevel
    && count >= PATTERNS.moderate_failure_burst.minCount
    && /계정 이름을 바꿔|한 글자씩 바꿔|간격은 고르지 않|성공은 없습니다/.test(description)
  ) {
    confidence = 0.65;
    reason = 'moderate_failure_burst';
  }
  const action = confidence >= BLOCK_THRESHOLD ? 'block'
    : confidence >= ALERT_THRESHOLD ? 'alert' : 'record';
  return { action, confidence, reason };
}
