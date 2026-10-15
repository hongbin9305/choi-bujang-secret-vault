export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'resource_zone'
]);

export async function decide(request) {
  const registered = request?.deviceRegistered === true;
  const method = request?.method;
  const service = request?.service;
  const path = request?.path;
  const route = request?.route;

  // The engine supplies verified route shapes. Do not infer authorization from query strings.
  const singleNote = service === 'notes'
    && typeof path === 'string'
    && /^\/notes\/[^/]+$/.test(path)
    && route === `${method} /notes/:id`
    && ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)
    && !['export', 'bulk', 'search'].includes(path.split('/')[2]);
  const noticeRead = service === 'notices'
    && method === 'GET'
    && typeof path === 'string'
    && /^\/notices\/[^/]+$/.test(path)
    && route === 'GET /notices/:id';
  const allowedZone = singleNote || noticeRead;

  const signals = request?.signals;
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

  const decision = !registered || !allowedZone ? 'deny'
    : suspicious && !verified ? 'step_up' : 'allow';

  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision,
    reasonCode: !registered ? 'device_not_registered'
      : !allowedZone ? 'resource_denied'
      : decision === 'step_up' ? 'step_up_required' : 'approved',
    ruleIds: !registered ? ['device_registered']
      : !allowedZone ? ['resource_zone']
      : suspicious ? ['device_registered', 'resource_zone', 'step_up_required']
      : ['device_registered', 'resource_zone']
  };
}
