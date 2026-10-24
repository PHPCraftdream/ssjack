import { expect, test } from 'claude-code/testing'
import { failed, printable, resultBody, unpack } from './format'

test('decode MCP strings, blocks, and structured results', () => {
  const result = { job_id: 'job-1', stdout: 'hello\n', stderr: 'warning\n', done: true, exit_code: 0 }
  for (const value of [
    result,
    JSON.stringify(result),
    [{ type: 'text', text: JSON.stringify(result) }],
    { content: [{ type: 'text', text: JSON.stringify(result) }] },
    { structuredContent: result },
    { result: JSON.stringify(result) },
  ]) {
    const parsed = unpack(value)
    expect(parsed.job_id).toBe('job-1')
    expect(resultBody(parsed)).toContain('stdout\nhello')
    expect(resultBody(parsed)).toContain('stderr\nwarning')
    expect(failed(parsed, false)).toBe(false)
  }
})

test('preserve errors and do not interpret terminal controls', () => {
  const parsed = unpack({ isError: true, content: [{ type: 'text', text: 'access denied' }] })
  expect(failed(parsed, false)).toBe(true)
  expect(resultBody(parsed)).toContain('access denied')
  expect(printable('\u001b[2J')).toBe('\\u001b[2J')
  expect(printable('abcdefgh', 4)).toContain('abcd\n... display truncated')
})

test('ignore unrelated payload fields and bound malformed nesting', () => {
  const parsed = unpack({ job_id: 'job-1', SSJACK_ENV_TOKEN: 'not-for-display' })
  expect(resultBody(parsed)).not.toContain('not-for-display')
  const nested = { result: { result: { result: { result: { result: { result: { result: { result: { result: { result: 'too deep' } } } } } } } } } }
  expect(resultBody(unpack(nested))).not.toContain('too deep')
})
