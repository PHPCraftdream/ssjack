import type { Register } from 'claude-code'
import { failed, isSsjack, printable, record, resultBody, shortJob, text, unpack } from './format'

export const register: Register = on => {
  on('ui.render', { component: 'ToolGroup' }, ($, e, next) => {
    if (!e.props.calls.some(call => isSsjack(call.tool))) return next(e)
    return next({ ...e, props: { ...e.props, isExpanded: true } })
  })

  on('ui.render', { component: 'ToolUse' }, ($, e, next) => {
    const props = e.props
    if (!isSsjack(props.tool)) return next(e)
    const { Box, Text } = $.ui.resolve(e)
    const input = record(props.input) ?? {}
    const result = unpack(props.output)
    const isFailed = failed(result, props.isErrored) || props.isInterrupted

    if (props.tool === 'mcp__ssjack__remote_exec') {
      const target = text(input.target) || 'unavailable'
      const command = text(input.command) || 'Command is unavailable in this client payload.'
      const status = props.isInterrupted ? 'INTERRUPTED' : isFailed ? 'FAILED' : props.isRunning ? 'RUNNING' : 'SUBMITTED'
      return (
        <Box flexDirection="column" marginY={1}>
          <Box flexDirection="column" borderStyle="round" borderColor={isFailed ? 'red' : 'cyan'} paddingX={1}>
            <Text bold color={isFailed ? 'red' : 'cyan'}>{`SSH COMMAND -> ${printable(target, 200)} | ${status}`}</Text>
            <Text>{printable(command)}</Text>
            {result.job_id !== undefined && <Text dimColor>{`job ${shortJob(result.job_id)}`}</Text>}
          </Box>
          {isFailed && (
            <Box flexDirection="column" borderStyle="round" borderColor="red" paddingX={1}>
              <Text bold color="red">SSH ERROR</Text>
              <Text>{resultBody(result)}</Text>
            </Box>
          )}
        </Box>
      )
    }

    if (props.tool === 'mcp__ssjack__remote_read') {
      const job = shortJob(result.job_id ?? input.job_id)
      const status = props.isInterrupted ? 'INTERRUPTED'
        : isFailed ? 'FAILED'
        : result.done === true ? `EXIT ${String(result.exit_code ?? 'unavailable')}`
        : props.isRunning ? 'READING' : 'RUNNING'
      const color = isFailed ? 'red' : result.done === true ? 'green' : 'yellow'
      return (
        <Box flexDirection="column" marginY={1} borderStyle="round" borderColor={color} paddingX={1}>
          <Text bold color={color}>{`SSH RESULT <- job ${job} | ${status}`}</Text>
          <Text>{props.output === undefined ? 'Waiting for server response.' : resultBody(result)}</Text>
        </Box>
      )
    }

    return (
      <Box flexDirection="column" marginY={1} borderStyle="round" borderColor={isFailed ? 'red' : 'yellow'} paddingX={1}>
        <Text bold color={isFailed ? 'red' : 'yellow'}>{`SSH CANCEL | job ${shortJob(input.job_id)}`}</Text>
        <Text>{props.isRunning ? 'Cancellation requested.' : isFailed ? resultBody(result) : 'Cancellation request completed.'}</Text>
      </Box>
    )
  })

  // ToolUse renders its complete result, including expanded group rows.
  on('ui.render', { component: 'ToolResult' }, ($, e, next) => {
    if (!isSsjack(e.props.tool)) return next(e)
    const { Box } = $.ui.resolve(e)
    return <Box />
  })
}
