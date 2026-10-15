export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required'
]);

export async function decide(request) {
  const registered = request?.deviceRegistered === true;
  const signals = request?.signals;
  // Only the engine's labeled synthetic fixture is used for simulated anomaly detection.
  const fixture = signals?.source === 'judge_fixture';
  const unusualHour = Number.isInteger(signals?.hour)
    && (signals.hour < 6 || signals.hour >= 23);
  const unusualNetwork = signals?.network === 'unusual';
  const recentBurst = Array.isArray(request?.recentEvents)
    && request.recentEvents.some(event =>
      event?.kind === 'risk_signal'
      && Number.isInteger(event.count) && event.count >= 10
      && Number.isFinite(event.ageSeconds)
      && event.ageSeconds >= 0 && event.ageSeconds <= 300
    );
  const suspicious = fixture && unusualHour && unusualNetwork && recentBurst;
  const verified = request?.stepUp?.verified === true
    && Number.isFinite(request.stepUp.authAgeSeconds)
    && request.stepUp.authAgeSeconds >= 0
    && request.stepUp.authAgeSeconds <= 900;
  const decision = !registered ? 'deny'
    : suspicious && !verified ? 'step_up' : 'allow';

  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision,
    reasonCode: !registered ? 'device_not_registered'
      : decision === 'step_up' ? 'step_up_required' : 'approved',
    ruleIds: suspicious
      ? ['device_registered', 'step_up_required']
      : ['device_registered']
  };
}
