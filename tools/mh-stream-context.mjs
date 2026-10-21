// Shared internal context/outer-framing checks; labels are NOT authentication.
const contextFields = ['profile', 'sessionId', 'epoch', 'windowId', 'routeKey', 'senderIdentity'];
export function readMhStreamDataFields(value, fields, error) {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new TypeError(error);
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.length || keys.some(key => !fields.includes(key))) throw new TypeError(error);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (fields.some(key => !Object.hasOwn(descriptors[key], 'value'))) throw new TypeError(error);
  return Object.fromEntries(fields.map(key => [key, descriptors[key].value]));
}
export function readMhStreamContext(value, prefix = 'mh_stream_context') {
  const c = readMhStreamDataFields(value, contextFields, prefix + '_context');
  if (c.profile !== 'mhxx-1.4' && c.profile !== 'mhgu-v262144') throw new TypeError(prefix + '_profile');
  if (typeof c.sessionId !== 'string' || !/^s[1-9][0-9]{0,7}$/.test(c.sessionId)
      || typeof c.windowId !== 'string' || !/^w[1-9][0-9]{0,7}$/.test(c.windowId)
      || !Number.isSafeInteger(c.epoch) || c.epoch < 1
      || !Number.isInteger(c.routeKey) || c.routeKey < 0 || c.routeKey > 0xffffffff
      || !Buffer.isBuffer(c.senderIdentity) || c.senderIdentity.length !== 4) throw new TypeError(prefix + '_context');
  return c;
}
// Does NOT decode nested body or authenticate it. Returned body/context are detached.
export function checkMhStreamMessageContext(message, expectedContext, observedContext, prefix = 'mh_stream_context') {
  const expected = readMhStreamContext(expectedContext, prefix), observed = readMhStreamContext(observedContext, prefix);
  for (const key of contextFields) {
    const matches = key === 'senderIdentity' ? expected[key].equals(observed[key]) : expected[key] === observed[key];
    if (!matches) throw new Error(prefix + '_context_mismatch');
  }
  if (!Buffer.isBuffer(message) || message.length < 20 || message[0] === 0xff) throw new TypeError(prefix + '_message');
  const length = message.readUInt16BE(2);
  if (message.length !== Math.ceil((20 + length) / 4) * 4) throw new Error(prefix + '_outer_length');
  if (message.readUInt32BE(12) !== expected.routeKey) throw new Error(prefix + '_route_mismatch');
  if (!message.subarray(8, 12).equals(expected.senderIdentity)) throw new Error(prefix + '_sender_mismatch');
  return {context: {...expected, senderIdentity: Buffer.from(expected.senderIdentity)}, body: Buffer.from(message.subarray(20, 20 + length))};
}
