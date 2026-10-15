export const RULE_IDS = Object.freeze([
  'device_registered'
]);

export async function decide(request) {
  const registered = request?.deviceRegistered === true;

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: registered ? 'allow' : 'deny',
    reasonCode: registered ? 'approved' : 'device_not_registered',
    ruleIds: ['device_registered']
  };
}