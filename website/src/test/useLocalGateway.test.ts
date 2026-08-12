import { test, expect, afterEach, vi } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useLocalGateway } from '../hooks/useLocalGateway'

// The hook talks to the "Run Local Gateway" bridge (window.localGatewayAPI,
// injected by electron/preload.js). Tests install a mock bridge to simulate
// the desktop app; deleting it simulates a plain-browser dashboard.
type LocalGatewayAPI = { get: () => Promise<boolean>; set: (v: boolean) => Promise<boolean> }

function installBridge(initial = true) {
  let enabled = initial
  const api = {
    get: vi.fn(() => Promise.resolve(enabled)),
    set: vi.fn((v: boolean) => { enabled = v; return Promise.resolve(enabled) }),
  }
  ;(window as unknown as { localGatewayAPI?: LocalGatewayAPI }).localGatewayAPI = api
  return api
}

afterEach(() => { delete (window as unknown as { localGatewayAPI?: LocalGatewayAPI }).localGatewayAPI })

// ── plain browser (no bridge) ──

test('browser: unsupported, defaults on, and setEnabled is a safe no-op', () => {
  const { result } = renderHook(() => useLocalGateway())
  expect(result.current.supported).toBe(false)
  expect(result.current.enabled).toBe(true)
  act(() => result.current.setEnabled(false))
  expect(result.current.enabled).toBe(true)
})

// ── desktop (bridge present) ──

test('desktop: reads the persisted value on mount (default on)', async () => {
  const api = installBridge(true)
  const { result } = renderHook(() => useLocalGateway())
  expect(result.current.supported).toBe(true)
  await act(async () => {})
  expect(api.get).toHaveBeenCalled()
  expect(result.current.enabled).toBe(true)
})

test('desktop: reflects a persisted off state on mount', async () => {
  installBridge(false)
  const { result } = renderHook(() => useLocalGateway())
  await act(async () => {})
  expect(result.current.enabled).toBe(false)
})

test('desktop: setEnabled round-trips through the bridge and reflects the applied value', async () => {
  const api = installBridge(true)
  const { result } = renderHook(() => useLocalGateway())
  await act(async () => {})
  await act(async () => { result.current.setEnabled(false) })
  expect(api.set).toHaveBeenCalledWith(false)
  expect(result.current.enabled).toBe(false)
  await act(async () => { result.current.setEnabled(true) })
  expect(api.set).toHaveBeenCalledWith(true)
  expect(result.current.enabled).toBe(true)
})

test('desktop: the applied value from the main process wins over the optimistic flip', async () => {
  // The main process owns the setting; if it persists something other than
  // what was asked (e.g. a future clamp), the toggle must render the truth.
  const api = installBridge(true)
  api.set.mockImplementation(() => Promise.resolve(true))
  const { result } = renderHook(() => useLocalGateway())
  await act(async () => {})
  await act(async () => { result.current.setEnabled(false) })
  expect(result.current.enabled).toBe(true)
})
