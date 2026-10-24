import { expect, test } from 'claude-code/testing'

for (const surface of ['terminal', 'desktop'] as const) {
  test(`render an SSH command card on ${surface}`, async $ => {
    const ui = await $.ui.mount({
      plugin: 'ssjack-ui', component: 'ToolUse', requestId: 'command-1', surface,
      props: {
        tool_use_id: 'command-1', tool: 'mcp__ssjack__remote_exec',
        input: { target: 'storagehost', command: "printf '%s\\n' 'hello'" },
        isRunning: false, isErrored: false, isInterrupted: false,
        output: JSON.stringify({ job_id: 'job-123' }),
      },
    })
    expect((await ui.find({ type: 'Text', text: /SSH COMMAND/ }))?.text).toContain('storagehost')
    expect((await ui.find({ type: 'Text', text: /printf/ }))?.text).toBe("printf '%s\\n' 'hello'")
    await ui.unmount()
  })

  test(`render a structured SSH result on ${surface}`, async $ => {
    const ui = await $.ui.mount({
      plugin: 'ssjack-ui', component: 'ToolUse', requestId: 'read-1', surface,
      props: {
        tool_use_id: 'read-1', tool: 'mcp__ssjack__remote_read', input: { job_id: 'job-123' },
        isRunning: false, isErrored: false, isInterrupted: false,
        output: { content: [{ type: 'text', text: JSON.stringify({ job_id: 'job-123', stdout: 'hello\n', stderr: 'warning\n', done: true, exit_code: 0 }) }] },
      },
    })
    expect((await ui.find({ type: 'Text', text: /SSH RESULT/ }))?.text).toContain('EXIT 0')
    expect((await ui.find({ type: 'Text', text: /stdout/ }))?.text).toContain('stderr\nwarning')
    await ui.unmount()
  })
}

test('expand ssjack groups without replacing their contents', async ($, on) => {
  on('ui.render', { component: 'ToolGroup' }, ($, e) => {
    const { Text } = $.ui.resolve(e)
    return <Text>{e.props.isExpanded ? 'expanded' : 'collapsed'}</Text>
  })
  const ui = await $.ui.mount({
    plugin: 'ssjack-ui', component: 'ToolGroup', requestId: 'group-1', surface: 'terminal',
    props: { calls: [{ tool: 'mcp__ssjack__remote_read', input: {}, isRunning: false, isErrored: false, isInterrupted: false }], isActive: false, isExpanded: false },
  })
  expect((await ui.find({ type: 'Text', text: /expanded/ }))?.text).toBe('expanded')
  await ui.unmount()
})
