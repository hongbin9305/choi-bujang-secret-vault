// Standalone ATT&CK T1068 / T1078 classifier. Mirrors patterns.json.
const PATTERNS = Object.freeze({
  unexpected_admin_membership: { minLevel: 10 },
  unexpected_privileged_command: { minLevel: 10 },
  admin_session_escalation: { minLevel: 10 },
  weak_privilege_indicator: { minLevel: 5 }
});
export function decide(alert) {
  const tags = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const tagged = tags.includes('T1068') || tags.includes('T1078');
  const level = Number(alert?.rule?.level);
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const group = typeof alert?.data?.group === 'string' ? alert.data.group.toLowerCase() : '';
  const source = typeof alert?.data?.srcip === 'string' && alert.data.srcip.trim().length > 0;
  const account = typeof alert?.data?.srcuser === 'string' && alert.data.srcuser.trim().length > 0;
  if (!tagged || !source || !account || !Number.isFinite(level))
    return { action: 'record', confidence: 0.05, reason: 'no_privilege_evidence' };
  const adminGroup = group === 'administrators';
  const groupAdded = /관리자 그룹에 (추가|들어가)|관리자 그룹 추가|다시 관리자로 들어왔/.test(description);
  const newAdmin = /방금 관리자가 된|평범한 계정/.test(description);
  const adminCommand = /관리자 명령|권한 명령|명령 실행/.test(description);
  const unfamiliar = /처음 보는 주소|처음 봅니다|수업 시간 밖|업무처럼 보이지 않는 시각/.test(description);
  const sessionElevated = /세션이 관리자 권한으로 바뀌었/.test(description);
  const otherIdentity = /다른 계정의 권한으로/.test(description);
  const bulk = /계정 [2-9][0-9]*개가 관리자 그룹에 추가/.test(description);
  const repeated = /1분 뒤에 다시 관리자로/.test(description);
  const high = level >= 10;
  const membership = high && adminGroup && (groupAdded || newAdmin || bulk || repeated);
  const commands = high && adminCommand && (newAdmin || unfamiliar || otherIdentity || /그룹 추가와 명령 실행이 같이/.test(description));
  const session = high && sessionElevated && unfamiliar;
  const clear = membership || commands || session;
  const confidence = clear ? 0.96 : level >= PATTERNS.weak_privilege_indicator.minLevel ? 0.62 : 0.08;
  const reason = clear ? membership ? 'unexpected_admin_membership'
    : session ? 'admin_session_escalation' : 'unexpected_privileged_command'
    : confidence >= 0.5 ? 'weak_privilege_indicator' : 'insufficient_privilege_evidence';
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
}
