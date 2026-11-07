/**
 * The Files app shows a code file as one fence, so its pencil opens the code
 * block's scratch editor. That editor must look like the read view it
 * replaces: the file's highlight language, and the read view's height (the
 * whole file, scrolled by the panel) rather than the chat's 480px cap.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import type { ReactNode } from 'react'

const hoisted = vi.hoisted(() => ({ editors: [] as { className?: string; langHint?: string }[] }))

vi.mock('../../pierre', async importOriginal => ({
  ...(await importOriginal<Record<string, unknown>>()),
  PierreEditor: (props: { className?: string; langHint?: string }) => {
    hoisted.editors.push(props)
    return <div data-testid="pierre-editor" />
  },
}))

// The read view only has to host the pencil that swaps in the editor.
vi.mock('../../components/CodeBlock', () => ({
  CodeBlock: ({ headerActions }: { headerActions?: ReactNode }) => <div>{headerActions}</div>,
}))

// The viewer's overflow menu reads the reveal gate; nothing here opens it.
vi.mock('../../hooks/useBranding', () => ({
  useBranding: () => ({ directLocal: false, desktopLauncher: false }),
}))

import FileViewer from './FileViewer'

beforeEach(() => { hoisted.editors.length = 0 })

describe('FileViewer edit mode', () => {
  it('opens a code file in an editor with its language and no height cap', () => {
    render(
      <FileViewer
        filePath="/home/user/campaign.py"
        fileMeta={{ size: 9, mtime: 1700000000, mime: 'text/x-python', encoding: 'utf-8' }}
        content={'print(1)\n'}
        loading={false}
        error={null}
        onReload={() => {}}
        onDownload={() => {}}
      />,
    )
    fireEvent.click(screen.getByLabelText('Edit code block'))

    expect(screen.getByTestId('pierre-editor')).toBeInTheDocument()
    const editor = hoisted.editors[hoisted.editors.length - 1]
    expect(editor.langHint).toBe('python')
    expect(editor.className ?? '').not.toMatch(/max-h-/)
  })
})
