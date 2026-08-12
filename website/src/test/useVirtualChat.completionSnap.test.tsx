// Feature: chat-virtualizer — the completion snap at the end of a turn must
// leave a followed viewport at the bottom.
//
// WHAT THIS LOCKS IN, AND WHY IT PASSES TODAY. These cases were written to chase
// a suspected end-of-turn scroll jump, on the theory that the snap could land
// against stale computed geometry. That theory is WRONG, and these tests are the
// evidence: `evaluateAutoPin` targets `bottomTarget(live geom)`, and a mounted
// row's growth is in the browser's `scrollHeight` the instant it happens, so a
// lagging spacer cannot mislead a pin for the streaming row — which is always
// mounted. They are kept because the invariant is real, nothing else covers it,
// and this is the only test that exercises the SEAM between computed spacers and
// the pin: every other follow test fakes `scrollHeight` as an independent
// number, and every other spacer test asserts on `totalHeight` directly.
//
// The mechanism under test: diff and code blocks stream inside SmoothResize, a
// clipped wrapper driven toward the content height by a `height .32s` CSS
// transition. At completion `enabled` flips false, the transition is removed and
// the height goes to `auto`, so the wrapper SNAPS from its mid-animation height
// to the natural one — upward while content was still growing. `streamingIndex`
// goes undefined the instant the turn closes, and the 400ms
// STREAMING_SETTLE_GRACE_MS that keeps the just-ended row on the immediate
// height-sync path is deliberately NOT re-armed per resize, so the snap can land
// inside that window or after it. Both are covered below.
//
// FIXTURE NOTE. The fake scroller COMPOSES `scrollHeight` the way a browser does:
// the two spacer heights the hook reports (`offsetBefore` + `offsetAfter`, which
// are computed and can therefore go stale) plus the REAL measured heights of the
// mounted rows (current the moment the DOM changes). Deriving it from
// `totalHeight` alone would be wrong in the other direction — it would hide a
// mounted row's growth until the sync landed, which no browser does, and it
// produces a phantom failure of exactly one growth tick.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { type RefObject } from 'react'

import { useVirtualChat } from '../hooks/virtualizer/useVirtualChat'
import type { UseVirtualChatOptions } from '../hooks/virtualizer/types'

interface Item { id: string }
const getKey = (it: Item) => it.id
const mkItems = (n: number): Item[] => Array.from({ length: n }, (_, i) => ({ id: `m${i}` }))

class FakeResizeObserver {
  static instances: FakeResizeObserver[] = []
  cb: ResizeObserverCallback
  observed = new Set<Element>()
  constructor(cb: ResizeObserverCallback) {
    this.cb = cb
    FakeResizeObserver.instances.push(this)
  }
  observe(el: Element) { this.observed.add(el) }
  unobserve(el: Element) { this.observed.delete(el) }
  disconnect() { this.observed.clear() }
  fire(entries: Partial<ResizeObserverEntry>[]) {
    this.cb(entries as ResizeObserverEntry[], this as unknown as ResizeObserver)
  }
}

function mkEntry(target: HTMLElement, height: number): Partial<ResizeObserverEntry> {
  Object.defineProperty(target, 'offsetHeight', { configurable: true, get: () => height })
  return { target }
}

const CH = 800
const HISTORY_H = 100
const STREAM_START_H = 40
/** Height the SmoothResize wrapper snaps up to when `enabled` flips false. */
const SNAP_GROWTH = 120

/**
 * Mount with a scroller whose scrollHeight TRACKS the hook's computed
 * totalHeight, so the fake DOM cannot know about a height the virtualizer has
 * not synced yet — exactly the real coupling through the spacers.
 */
function mountStreaming(sessionId: string, items: Item[]) {
  const el = document.createElement('div')
  let scrollTop = 0
  // Real measured heights of the MOUNTED rows, kept current by the test exactly
  // as the DOM would be. Set after renderHook so the getter reads live output.
  let realMounted = 0
  let readSpacers: () => number = () => 0
  Object.defineProperty(el, 'scrollTop', {
    configurable: true,
    get: () => scrollTop,
    set: (v: number) => { scrollTop = v },
  })
  Object.defineProperty(el, 'scrollHeight', {
    configurable: true,
    get: () => readSpacers() + realMounted,
  })
  Object.defineProperty(el, 'clientHeight', { configurable: true, get: () => CH })
  ;(el as unknown as { scrollTo: (o: { top: number }) => void }).scrollTo = (o) => { scrollTop = o.top }

  const ref: RefObject<HTMLDivElement | null> = { current: el }
  const lastIdx = items.length - 1
  const baseProps: UseVirtualChatOptions<Item> = {
    items, sessionId, getKey, externalScrollerRef: ref, streamingIndex: lastIdx,
  }
  const view = renderHook(
    (p: UseVirtualChatOptions<Item>) => useVirtualChat<Item>(p),
    { initialProps: baseProps },
  )
  readSpacers = () => view.result.current.offsetBefore + view.result.current.offsetAfter

  for (let i = 0; i < lastIdx; i++) {
    const node = document.createElement('div')
    Object.defineProperty(node, 'offsetHeight', { configurable: true, get: () => HISTORY_H })
    act(() => { view.result.current.measureRef(i)(node) })
    realMounted += HISTORY_H
  }
  const streamNode = document.createElement('div')
  Object.defineProperty(streamNode, 'offsetHeight', { configurable: true, get: () => STREAM_START_H })
  act(() => { view.result.current.measureRef(lastIdx)(streamNode) })
  realMounted += STREAM_START_H
  act(() => { vi.advanceTimersByTime(120) })  // settle the first-mount seed

  const ro = FakeResizeObserver.instances[FakeResizeObserver.instances.length - 1]
  /** Resize the streaming row in the DOM sense: real height changes at once. */
  const resizeStreamRow = (from: number, to: number) => {
    realMounted += to - from
    act(() => { ro.fire([mkEntry(streamNode, to)]) })
  }
  return { el, view, ro, streamNode, baseProps, lastIdx, resizeStreamRow }
}

const bottomOf = (el: HTMLDivElement) => el.scrollHeight - CH

describe('useVirtualChat: the SmoothResize completion snap after a turn closes', () => {
  let origRO: typeof ResizeObserver | undefined
  let origRaf: typeof requestAnimationFrame

  beforeEach(() => {
    localStorage.clear()
    FakeResizeObserver.instances = []
    origRO = globalThis.ResizeObserver
    globalThis.ResizeObserver = FakeResizeObserver as unknown as typeof ResizeObserver
    origRaf = globalThis.requestAnimationFrame
    globalThis.requestAnimationFrame = ((cb: FrameRequestCallback) => { cb(0); return 0 }) as typeof requestAnimationFrame
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
    globalThis.ResizeObserver = origRO as typeof ResizeObserver
    globalThis.requestAnimationFrame = origRaf
  })

  it('lands at the bottom when the snap arrives AFTER the settle grace expires', () => {
    const { el, view, baseProps, resizeStreamRow } = mountStreaming('snap-after-grace', mkItems(21))

    // --- streaming: the eased wrapper grows, each tick synced immediately ---
    let h = STREAM_START_H
    for (let i = 0; i < 6; i++) {
      resizeStreamRow(h, h + 10)
      h += 10
      act(() => { vi.advanceTimersByTime(16) })
    }
    // Settle the immediate-path sync so the baseline is exactly at the bottom.
    act(() => { vi.advanceTimersByTime(200) })
    expect(el.scrollTop).toBe(bottomOf(el))

    // --- the turn closes: streamingIndex clears, arming the 400ms grace ---
    act(() => { view.rerender({ ...baseProps, streamingIndex: undefined }) })

    // --- the grace expires before the snap lands (a slow final block, a
    // widget still settling, or simply a browser that scheduled the flip late) ---
    act(() => { vi.advanceTimersByTime(500) })

    // --- the completion snap: `enabled` flips false, the clip is removed and
    // the wrapper jumps to its natural height in one step ---
    resizeStreamRow(h, h + SNAP_GROWTH)

    // Let the debounced height sync flush, so `totalHeight` — and with it the
    // fake scrollHeight — finally reflects the snap.
    act(() => { vi.advanceTimersByTime(200) })

    // Follow was never released, so the viewport must be at the bottom. The pin
    // reads LIVE geometry, and the snap is already in the browser's scrollHeight
    // by the time the observer fires — which is why a lagging spacer cannot pull
    // this short. See the header: this is the invariant, not a known failure.
    expect(el.scrollTop).toBe(bottomOf(el))
  })

  it('lands at the bottom when the snap arrives INSIDE the settle grace', () => {
    const { el, view, baseProps, resizeStreamRow } = mountStreaming('snap-in-grace', mkItems(21))

    let h = STREAM_START_H
    for (let i = 0; i < 6; i++) {
      resizeStreamRow(h, h + 10)
      h += 10
      act(() => { vi.advanceTimersByTime(16) })
    }
    act(() => { vi.advanceTimersByTime(200) })
    expect(el.scrollTop).toBe(bottomOf(el))

    act(() => { view.rerender({ ...baseProps, streamingIndex: undefined }) })
    act(() => { vi.advanceTimersByTime(100) })          // still inside the 400ms grace
    resizeStreamRow(h, h + SNAP_GROWTH)
    act(() => { vi.advanceTimersByTime(200) })

    // The grace exists precisely to keep this case on the immediate path, so
    // this is the CONTROL: it isolates the failure above to the grace expiring
    // rather than to the snap itself.
    expect(el.scrollTop).toBe(bottomOf(el))
  })
})
