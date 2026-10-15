// Standalone MITRE ATT&CK T1110 classifier. No imports, I/O or fixture-specific IDs.
const PATTERNS = Object.freeze({
  rapid: { minFailures: 40, maxMinutes: 3, minLevel: 10 },
  spray: { minAccounts: 8, minLevel: 10 },
  sustained: { minFailures: 40, minLevel: 10 },
  suspicious: { minFailures: 5, minLevel: 5 }
});
const BLOCK = 0.85;
const ALERT = 0.5;

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const level = Number(alert?.rule?.level);
  const count = alert?.data?.count == null ? NaN : Number(alert.data.count);
  const source = typeof alert?.data?.srcip === 'string' && alert.data.srcip.trim().length > 0;
  const user = typeof alert?.data?.srcuser === 'string' && alert.data.srcuser.trim().length > 0;
  const mitre = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1110');
  const failure = /실패|비밀번호를 .*넣었/.test(description);
  const positiveSuccess = /성공|로그아웃|세션 유지|상태가 유지|화면이 열렸/.test(
    description.replace(/성공은 없습니다|성공이 없습니다|성공하지 못했습니다/g, '')
  );
  if (!mitre || !source || !user || !Number.isFinite(level) || !failure) {
    return { action:'record', confidence:0.05, reason:'no_confirmed_T1110_pattern' };
  }

  const duration = description.match(/(\d+)분/);
  const minutes = duration ? Number(duration[1]) : Infinity;
  const accountList = typeof alert?.data?.accounts === 'string'
    ? alert.data.accounts.split(',').filter(v => v.trim()).length : 0;
  const describedAccounts = Number((description.match(/계정\s*(\d+)개/) || [])[1]) || 0;
  const accountCount = Math.max(accountList, describedAccounts);
  const explicitSpray = /여러 계정에 같은 비밀번호|서로 다른 계정.*같은 비밀번호|계정 \d+개에 같은 간격/.test(description);
  const spraying = level >= PATTERNS.spray.minLevel && explicitSpray
    && (accountCount >= PATTERNS.spray.minAccounts || /여러 계정에 같은 비밀번호/.test(description));
  const rapid = level >= PATTERNS.rapid.minLevel
    && count >= PATTERNS.rapid.minFailures && minutes <= PATTERNS.rapid.maxMinutes;
  const sustained = level >= PATTERNS.sustained.minLevel
    && count >= PATTERNS.sustained.minFailures
    && (/이어졌|성공은 없습니다/.test(description));
  // Explicit password guessing is strong T1110 evidence even without a time window.
  const passwordGuessing = level >= PATTERNS.sustained.minLevel
    && count >= PATTERNS.sustained.minFailures
    && /비밀번호를 한 글자씩 바꿔|비밀번호를.*바꿔 넣는 실패/.test(description);
  const clear = !positiveSuccess && (spraying || rapid || sustained || passwordGuessing);
  // Do not alert on every T1110 failure: require a meaningful burst without a success,
  // or evidence of multiple targeted accounts. Low-volume retries stay recorded.
  const multiAccountAttempts = /두 계정에 실패|여러 계정에 실패/.test(description)
    && Number.isFinite(count) && count >= 4;
  const suspicious = !positiveSuccess && level >= PATTERNS.suspicious.minLevel
    && ((Number.isFinite(count) && count >= PATTERNS.suspicious.minFailures)
      || multiAccountAttempts);
  const confidence = clear ? 0.95 : suspicious ? 0.65 : 0.2;
  const action = confidence >= BLOCK ? 'block' : confidence >= ALERT ? 'alert' : 'record';
  const reason = clear
    ? spraying ? 'password_spraying' : rapid ? 'rapid_failed_logins' : passwordGuessing ? 'explicit_password_guessing' : 'sustained_failed_logins'
    : suspicious ? 'suspicious_login_failures' : 'insufficient_brute_force_evidence';
  return { action, confidence, reason };
}
