import { expect, test } from 'claude-code/testing'
import { dropFromLog, frameLines, parseLine, parseSession, tailChars } from './lifecycle'

const stamp = '2026-11-15T12:00:00.123Z'

function line(parts: string, sid = '1a2b3c4d'): string {
  return `${stamp} pid=4242 role=keeper sid=${sid} ${parts}`
}

function bridgeLine(parts: string, sid = '1a2b3c4d'): string {
  return `${stamp} pid=1 role=bridge sid=${sid} ${parts}`
}

test('parse ending signals into fixed reason words', () => {
  expect(parseLine(line('event=connection-end attached=true cause=eof'))).toEqual({ role: 'keeper', event: 'connection-end', reason: 'eof' })
  expect(parseLine(line('event=shutdown reason=attached-connection-ended'))).toEqual({ role: 'keeper', event: 'shutdown', reason: 'attached-connection-ended' })
  expect(parseLine(bridgeLine('event=exit context=crash'))).toEqual({ role: 'bridge', event: 'exit', reason: 'crash' })
  expect(parseLine(bridgeLine('event=exit stage=clean'))).toEqual({ role: 'bridge', event: 'exit', reason: 'clean' })
})

test('reject healthy, malformed, and non-ending lines but tolerate extra keys', () => {
  const rejected = [
    line('event=connection-end attached=false cause=eof'),
    line('event=listen addr=127.0.0.1:1'),
    line('event=attached'),
    line('event=serving'),
    line('event=stdio-end'),
    line('event=request id=7'),
    line('event=call-failed reason=timeout'),
    line('event=harness-exit'),
    line('event=shutdown'),
    line(`sid=${'a'.repeat(65)} event=shutdown reason=x`),
    line('event=shutdown reason=bad;char'),
    `${stamp} pid=4242 role=nobody sid=abc event=shutdown reason=x`,
    'garbage text not a lifecycle line',
    '',
    `${stamp} pid=4242 event=shutdown reason=x`,
  ]
  for (const candidate of rejected) expect(parseLine(candidate)).toBeUndefined()
  expect(parseLine(line('event=shutdown reason=x new_field=soon'))).toEqual({ role: 'keeper', event: 'shutdown', reason: 'x' })
  expect(parseSession(line('event=serving'))).toEqual({ sid: '1a2b3c4d' })
  expect(parseSession('garbage')).toBeUndefined()
})

test('empty and garbage logs show nothing', () => {
  expect(dropFromLog('')).toBeUndefined()
  expect(dropFromLog('garbage\nmore garbage\n')).toBeUndefined()
  expect(dropFromLog('\n\n\n')).toBeUndefined()
})

test('a healthy session shows nothing and an ending shows the frame reason', () => {
  const healthy = [line('event=listen ttl_ms=1', 's1'), line('event=attached', 's1'), line('event=request op=x ok=true ms=1', 's1')].join('\n') + '\n'
  expect(dropFromLog(healthy)).toBeUndefined()
  expect(dropFromLog(healthy + line('event=shutdown reason=attached-connection-ended', 's1') + '\n')).toEqual({ role: 'keeper', event: 'shutdown', reason: 'attached-connection-ended' })
})

test('a new session hides the drop of an old one', () => {
  const log = [
    line('event=shutdown reason=attached-connection-ended', 'old'),
    line('event=listen ttl_ms=1', 'new'),
    line('event=attached', 'new'),
  ].join('\n') + '\n'
  expect(dropFromLog(log)).toBeUndefined()
})

test('only the tail is read: an ending in the discarded head is not shown', () => {
  const healthy = Array.from({ length: 512 }, (_, i) => line(`event=request id=${i}`, 'sid-new')).join('\n') + '\n'
  const padding = healthy.repeat(Math.ceil((tailChars + 1) / healthy.length))
  expect(dropFromLog(line('event=shutdown reason=attached-connection-ended', 'sid-new') + '\n' + padding)).toBeUndefined()
  expect(dropFromLog(padding + line('event=connection-end attached=true cause=eof', 'sid-new') + '\n')).toEqual({ role: 'keeper', event: 'connection-end', reason: 'eof' })
})

test('a torn first tail line is ignored', () => {
  const healthy = line('event=request id=1', 'sid-new') + '\n'
  const log = 'TORNPARTIAL' + healthy.repeat(Math.ceil(tailChars / healthy.length) + 1) + bridgeLine('event=exit context=crash', 'sid-new') + '\n'
  expect(dropFromLog(log)).toEqual({ role: 'bridge', event: 'exit', reason: 'crash' })
})

test('frameLines render the recovery text without echoing identifiers', () => {
  const output = frameLines(parseLine(bridgeLine('event=exit context=crash'))!).join('\n')
  expect(output).toContain('SSJACK MCP CONNECTION ENDED')
  expect(output).toContain('crash')
  expect(output).toContain('ssjack run')
  expect(output).toContain('single-use')
  for (const secret of ['4242', '1a2b3c4d', stamp]) expect(output).not.toContain(secret)
})

// Lines copied from a real lifecycle.log (all fields, in the order the programs write them).
test('real log lines: the incident of a closed bridge stdio shows the keeper and the bridge reason', () => {
  const real = [
    '2026-11-15T16:05:23.127Z pid=97532 role=keeper sid=081dd328 event=listen ttl_ms=120000',
    '2026-11-15T16:05:26.685Z pid=97532 role=keeper sid=081dd328 event=attached',
    '2026-11-15T16:05:26.689Z pid=97532 role=keeper sid=081dd328 event=connection-end attached=true stage=request-read cause=eof requests=1 ms=5',
    '2026-11-15T16:05:26.735Z pid=135676 role=mcp sid=081dd328 event=exit code=1 stage=attach-dial context=none',
  ]
  expect(dropFromLog(real.slice(0, 2).join('\n') + '\n')).toBeUndefined()
  expect(dropFromLog(real.slice(0, 3).join('\n') + '\n')).toEqual({ role: 'keeper', event: 'connection-end', reason: 'eof' })
  expect(parseLine(real[2]!)).toEqual({ role: 'keeper', event: 'connection-end', reason: 'eof' })
  expect(parseLine(real[3]!)).toEqual({ role: 'bridge', event: 'exit', reason: 'attach-dial' })
})

test('a bridge exit with context=none names its stage', () => {
  expect(parseLine(bridgeLine('event=exit code=1 stage=attach-dial context=none'))).toEqual({ role: 'bridge', event: 'exit', reason: 'attach-dial' })
})
