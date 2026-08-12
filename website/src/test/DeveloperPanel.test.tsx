/**
 * Settings > Developer tab (DeveloperPanel).
 *
 * Contract under test:
 * - Developer Mode toggle persists to localStorage and fires the dev-mode event
 * - The Updates section is GONE (Beta Channel moved to Settings > About)
 * - "Open Developer page" link renders only while Developer Mode is on and
 *   navigates to /developer
 * - The Run Local Gateway toggle renders only when the desktop bridge
 *   (window.localGatewayAPI) exists, reads the persisted value, and
 *   round-trips flips through the bridge
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { DeveloperPanel } from '../pages/settings/DeveloperPanel'

function LocationProbe() {
  const loc = useLocation()
  return <div data-testid="loc">{loc.pathname}</div>
}

function renderPanel() {
  return render(
    <MemoryRouter initialEntries={['/settings?tab=developer']}>
      <DeveloperPanel />
      <LocationProbe />
    </MemoryRouter>
  )
}

describe('DeveloperPanel', () => {
  beforeEach(() => { localStorage.removeItem('mc-dev-mode') })

  it('renders the Developer Mode toggle and no Updates section', () => {
    renderPanel()
    expect(screen.getByText('Developer Mode')).toBeInTheDocument()
    expect(screen.queryByText('Updates')).not.toBeInTheDocument()
    expect(screen.queryByText('Beta Channel (Braveheart)')).not.toBeInTheDocument()
  })

  it('toggling on persists, dispatches the event, and reveals the page link', () => {
    const eventSpy = vi.fn()
    window.addEventListener('mc-dev-mode-changed', eventSpy)
    renderPanel()
    expect(screen.queryByText('Open Developer page')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('switch', { name: 'Developer Mode' }))
    expect(localStorage.getItem('mc-dev-mode')).toBe('1')
    expect(eventSpy).toHaveBeenCalledTimes(1)
    expect(screen.getByText('Open Developer page')).toBeInTheDocument()
    window.removeEventListener('mc-dev-mode-changed', eventSpy)
  })

  it('Open Developer page navigates to /developer', () => {
    localStorage.setItem('mc-dev-mode', '1')
    renderPanel()
    fireEvent.click(screen.getByText('Open Developer page'))
    expect(screen.getByTestId('loc').textContent).toBe('/developer')
  })
})

describe('DeveloperPanel — Run Local Gateway toggle', () => {
  type LocalGatewayAPI = { get: () => Promise<boolean>; set: (v: boolean) => Promise<boolean> }
  const win = window as unknown as { localGatewayAPI?: LocalGatewayAPI }

  beforeEach(() => { localStorage.removeItem('mc-dev-mode') })
  afterEach(() => { delete win.localGatewayAPI })

  it('shows the unsupported row (no switch) without the bridge — palette target stays navigable', () => {
    renderPanel()
    // The label renders so the command-palette entry lands somewhere real...
    expect(screen.getByText('Run Local Gateway')).toBeInTheDocument()
    expect(screen.getByText(/desktop app only/)).toBeInTheDocument()
    // ...but there is no toggle to flip in a browser.
    expect(screen.queryByRole('switch', { name: 'Run Local Gateway' })).not.toBeInTheDocument()
  })

  it('renders default-on with the bridge and says it takes effect on next launch', async () => {
    win.localGatewayAPI = {
      get: vi.fn(() => Promise.resolve(true)),
      set: vi.fn((v: boolean) => Promise.resolve(v)),
    }
    renderPanel()
    const toggle = await screen.findByRole('switch', { name: 'Run Local Gateway' })
    await waitFor(() => expect(toggle).toBeChecked())
    // The helper text must warn that the flip is next-launch scoped.
    expect(screen.getByText(/next launch/)).toBeInTheDocument()
  })

  it('flipping it off round-trips through the bridge', async () => {
    const set = vi.fn((v: boolean) => Promise.resolve(v))
    win.localGatewayAPI = { get: vi.fn(() => Promise.resolve(true)), set }
    renderPanel()
    const toggle = await screen.findByRole('switch', { name: 'Run Local Gateway' })
    await waitFor(() => expect(toggle).toBeChecked())
    fireEvent.click(toggle)
    expect(set).toHaveBeenCalledWith(false)
    await waitFor(() => expect(toggle).not.toBeChecked())
  })
})
