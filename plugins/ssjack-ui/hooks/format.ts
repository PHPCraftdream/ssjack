export type RecordValue = Record<string, unknown>

export function record(value: unknown): RecordValue | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as RecordValue
    : undefined
}

export function text(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

export function printable(value: string, limit = 20000): string {
  const safe = value.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f]/g, char =>
    `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`,
  )
  const points = Array.from(safe)
  return points.length > limit
    ? points.slice(0, limit).join('') + '\n... display truncated; the stored tool result is unchanged.'
    : safe
}

const resultFields = ['job_id', 'stdout', 'stderr', 'stdout_base64', 'stderr_base64', 'done', 'exit_code', 'cancelled', 'error']

export function unpack(value: unknown, depth = 0): RecordValue {
  if (depth > 8 || value === undefined || value === null) return {}
  if (typeof value === 'string') {
    try { return unpack(JSON.parse(value), depth + 1) }
    catch { return { display_text: printable(value) } }
  }
  if (Array.isArray(value)) {
    const result: RecordValue = {}
    const notes: string[] = []
    for (const item of value.slice(0, 128)) {
      const part = unpack(item, depth + 1)
      Object.assign(result, part)
      if (typeof part.display_text === 'string') notes.push(part.display_text)
    }
    if (notes.length) result.display_text = notes.join('\n')
    return result
  }
  const object = record(value)
  if (!object) return { display_text: String(value) }
  const result: RecordValue = {}
  for (const key of ['result', 'data', 'content', 'structured_content', 'structuredContent']) {
    if (object[key] !== undefined) Object.assign(result, unpack(object[key], depth + 1))
  }
  if (typeof object.text === 'string') Object.assign(result, unpack(object.text, depth + 1))
  for (const key of [...resultFields, 'stdout_more', 'stderr_more', 'stdout_lost', 'stderr_lost', 'isError']) {
    if (Object.prototype.hasOwnProperty.call(object, key)) result[key] = object[key]
  }
  return result
}

export function isSsjack(tool: string): boolean {
  return /^mcp__ssjack__(remote_exec|remote_read|remote_cancel)$/.test(tool)
}

export function shortJob(value: unknown): string {
  const job = text(value)
  return job ? job.slice(0, 12) : 'unavailable'
}

export function failed(result: RecordValue, isErrored: boolean): boolean {
  return isErrored || result.isError === true || Boolean(result.error)
    || (result.done === true && typeof result.exit_code === 'number' && result.exit_code !== 0)
}

export function resultBody(result: RecordValue): string {
  const parts: string[] = []
  for (const stream of ['stdout', 'stderr']) {
    if (typeof result[stream] === 'string' && result[stream] !== '') parts.push(`${stream}\n${result[stream]}`)
    if (typeof result[`${stream}_base64`] === 'string' && result[`${stream}_base64`] !== '') parts.push(`${stream} (original bytes, base64)\n${result[`${stream}_base64`]}`)
  }
  if (typeof result.error === 'string' && result.error) parts.push(`error\n${result.error}`)
  if (typeof result.display_text === 'string' && result.display_text) parts.push(result.display_text)
  if (result.stdout_lost === true || result.stderr_lost === true) parts.push('WARNING: earlier output was evicted from the server buffer.')
  if (result.stdout_more === true || result.stderr_more === true) parts.push('More output is available.')
  return printable(parts.join('\n\n') || 'No new output.')
}
