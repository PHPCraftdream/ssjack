// Parsing and text for the bridge-drop frame. Pure functions: the caller reads the file.
export interface Drop {
  role: 'keeper' | 'bridge'
  event: string
  reason: string
}

export const logPath = '.claude/ssjack/lifecycle.log'

// The log rotates near 1 MiB; anything bigger is not ours and is ignored.
export const maxLogBytes = 2 * 1024 * 1024
export const tailChars = 64 * 1024

const tokenPattern = /^(?:[0-9A-Za-z_.:-]+T[0-9A-Za-z_.:+-]+) (\w+=\S+(?: \w+=\S+)*)$/
const keyValuePattern = /^([a-z][a-z0-9_]*)=([A-Za-z0-9_.:-]{1,64})$/

// Validate the strict line shape and return its key=value fields, or undefined.
function parseFields(line: string): Map<string, string> | undefined {
  const body = tokenPattern.exec(line)?.[1]
  if (body === undefined) return undefined
  const fields = new Map<string, string>()
  for (const token of body.split(' ')) {
    const pair = keyValuePattern.exec(token)
    const key = pair?.[1]
    const value = pair?.[2]
    if (key === undefined || value === undefined) return undefined
    fields.set(key, value)
  }
  return fields.size > 0 ? fields : undefined
}

// Session id of any strictly valid line, healthy or ending.
export function parseSession(line: string): { sid: string } | undefined {
  const sid = parseFields(line)?.get('sid')
  return sid ? { sid } : undefined
}

// Ending-signal drops only; healthy or malformed lines yield undefined.
export function parseLine(line: string): Drop | undefined {
  const fields = parseFields(line)
  if (!fields) return undefined
  // The bridge process logs itself as role=mcp; the frame calls it the bridge.
  const written = fields.get('role')
  const role = written === 'mcp' ? 'bridge' : written
  const event = fields.get('event')
  if (!event || (role !== 'keeper' && role !== 'bridge')) return undefined
  if (role === 'keeper' && event === 'connection-end') {
    if (fields.get('attached') !== 'true') return undefined
    const cause = fields.get('cause')
    return cause ? { role, event, reason: cause } : undefined
  }
  if (role === 'keeper' && event === 'shutdown') {
    const reason = fields.get('reason')
    return reason ? { role, event, reason } : undefined
  }
  if (role === 'bridge' && event === 'exit') {
    // The real line always carries context; "none" says nothing, so name the stage then.
    const context = fields.get('context')
    const reason = context && context !== 'none' ? context : fields.get('stage')
    return reason ? { role, event, reason } : undefined
  }
  return undefined
}

// The ending drop of the current session: the session of the last valid line.
// Only the tail is looked at, and its first, possibly torn, line is dropped.
export function dropFromLog(text: string): Drop | undefined {
  let tail = text
  if (tail.length > tailChars) {
    const cut = tail.length - tailChars
    tail = tail.slice(tail.indexOf('\n', cut - 1) + 1)
  }
  const drops = new Map<string, Drop>()
  let current: string | undefined
  for (const line of tail.split('\n')) {
    const session = parseSession(line)
    if (!session) continue
    current = session.sid
    const drop = parseLine(line)
    if (drop) drops.set(session.sid, drop)
  }
  return current ? drops.get(current) : undefined
}

export function frameLines(drop: Drop): string[] {
  return [
    'SSJACK MCP CONNECTION ENDED',
    `ended by ${drop.role} ${drop.event} (${drop.reason})`,
    'Recovery: leave this harness and start it again with `ssjack run`. A restarted `ssjack mcp` child cannot re-attach: the bootstrap token is single-use and the keeper channel ends with the one connection that claimed it.',
  ]
}
