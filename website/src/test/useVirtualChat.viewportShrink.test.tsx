// Feature: chat-virtualizer — a change in the SCROLLER'S OWN height must re-pin
// a followed viewport to the bottom.
//
// GAP THIS PINS DOWN. Follow protection is driven entirely by ROW observation:
// `pinAuto` is reached from a row ResizeObserver tick, an itemCount increase, a
// slot entry, `scrollToBottom`, or a smooth-glide arrival — and every
// `.observe()` call in the hook targets a row element or an IntersectionObserver
// sentinel. The scroller is never observed and there is no window resize
// listener. So when the scroller's own `clientHeight` shrinks, the distance to
// the bottom grows with NO row resized and NO item appended: nothing fires, and
// the viewport silently stops being at the bottom.
//
// The everyday trigger is the composer: its textarea autosizes from 44px up to
// 140px as the user types or pastes (ChatInput's applyHeight), and the scroller
// is the `flex:1` sibling above it, so every keystroke that adds a line steals
// height from the transcript. The same mechanism covers the composer's manual
// drag-resize, the side panel docking to the bottom, a height-only window
// resize, and the mobile on-screen keyboard (there is no visualViewport handling
// anywhere in the app).
//
// A window resize listener would NOT close this: the composer growing fires no
// window resize. The scroller element itself has to be observed, which is why
// the first case asserts on the observation and not only on the outcome.
//
// jsdom has no layout engine, so geometry is faked on a detached scroller passed
// via `externalScrollerRef`, and the ResizeObserver is a controllable fake (the
// same technique as the postStreamLurch and spacerLurch suites).

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { type RefObject } from 'react'

import { useVirtualChat } from '../hooks/virtualizer/useVirtualChat'
import type { UseVirtualChatOptions } from '../hooks/virtualizer/types'

interface Geom { scrollTop: number; scrollHeight: number; clientHeight: number }

/** A detached div with controllable, mutable scroll geometry. */
function makeScroller(initial: Geom) {
  const el = document.createElement('div')
  const state: Geom = { ...initial }
  Object.defineProperty(el, 'scrollTop', {
    configurable: true,
    get: () => state.scrollTop,
    set: (v: number) => { state.scrollTop = v },
  })
  Object.defineProperty(el, 'scrollHeight', { configurable: true, get: () => state.scrollHeight })
  Object.defineProperty(el, 'clientHeight', { configurable: true, get: () => state.clientHeight })
  ;(el as unknown as { scrollTo: (o: { top: number }) => void }).scrollTo = (o) => { state.scrollTop = o.top }
  return { el, state }
}

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

const CH = 800                     // transcript viewport before the composer grows
const SH = 5000
const BOTTOM = SH - CH             // 4200 — where the slot-entry pin lands
const COMPOSER_GROWTH = 96         // ~3 added lines of composer text
const SHRUNK_CH = CH - COMPOSER_GROWTH
const SHRUNK_BOTTOM = SH - SHRUNK_CH  // 4296 — the bottom after the viewport shrinks

function mount(sessionId: string) {
  const { el, state } = makeScroller({ scrollTop: 0, scrollHeight: SH, clientHeight: CH })
  const ref: RefObject<HTMLDivElement | null> = { current: el }
  const initialProps: UseVirtualChatOptions<Item> = {
    items: mkItems(5), sessionId, getKey, externalScrollerRef: ref,
  }
  const view = renderHook((p: UseVirtualChatOptions<Item>) => useVirtualChat<Item>(p), { initialProps })
  const ro = FakeResizeObserver.instances[FakeResizeObserver.instances.length - 1]
  return { el, state, view, ro }
}

describe('useVirtualChat: the scroller shrinking under a followed viewport', () => {
  let origRO: typeof ResizeObserver | undefined
  let origRaf: typeof requestAnimationFrame

  beforeEach(() => {
    localStorage.clear()
    FakeResizeObserver.instances = []
    origRO = globalThis.ResizeObserver
    globalThis.ResizeObserver = FakeResizeObserver as unknown as typeof ResizeObserver
    origRaf = globalThis.requestAnimationFrame
    globalThis.requestAnimationFrame = ((cb: FrameRequestCallback) => { cb(0); return 0 }) as typeof requestAnimationFrame
  })

  afterEach(() => {
    globalThis.ResizeObserver = origRO as typeof ResizeObserver
    globalThis.requestAnimationFrame = origRaf
  })

  it('observes the scroller element, not only the rows', () => {
    const { el, ro } = mount('viewport-observed')
    // Without this, a clientHeight change has no path into the hook at all:
    // no row resized, no item appended, and no scroll event is dispatched
    // (the browser only emits one if it has to clamp scrollTop, and shrinking
    // the viewport RAISES the scroll maximum rather than lowering it).
    expect(ro.observed.has(el)).toBe(true)
  })

  it('re-pins to the new bottom when the composer steals viewport height', () => {
    const { el, state, ro } = mount('viewport-shrink-repin')
    expect(el.scrollTop).toBe(BOTTOM)

    // The composer autosizes: the transcript viewport loses 96px. scrollHeight
    // is unchanged — the CONTENT did not move — so the bottom is now 96px
    // further down and the viewport is no longer at it. Deliberately no scroll
    // event and no row entry: this is the whole point of the gap.
    act(() => {
      state.clientHeight = SHRUNK_CH
      ro.fire([{ target: el } as Partial<ResizeObserverEntry>])
    })

    expect(el.scrollTop).toBe(SHRUNK_BOTTOM)
  })

  it('does NOT chase the bottom when the user is scrolled up reading history', () => {
    const { el, state, ro } = mount('viewport-shrink-released')

    // Release follow the way a real user does: scroll well away from the bottom.
    act(() => { state.scrollTop = 1000; el.dispatchEvent(new Event('scroll')) })

    act(() => {
      state.clientHeight = SHRUNK_CH
      ro.fire([{ target: el } as Partial<ResizeObserverEntry>])
    })

    // A shrinking viewport must not yank a released reader to the bottom. This
    // case already passes today (nothing fires at all) and exists so the fix
    // for the case above cannot be written as an unconditional pin.
    expect(el.scrollTop).toBe(1000)
  })

  it('holds position for a small scroll-up that leaves follow armed', () => {
    const { el, state, ro } = mount('viewport-shrink-in-band')
    expect(el.scrollTop).toBe(BOTTOM)

    // 40px up — INSIDE the 100px `atBottom` band, so `stickAfterUserScroll`
    // leaves stick ARMED even though the user is visually off the bottom. This
    // is the sharpest state in the whole design: follow is on, the user is not
    // at the bottom, and `lastWriteTopRef` is deliberately not re-baselined
    // across this band (doing so would erase the only evidence of the
    // scroll-up). It is also the state the two reverted attempts on this system
    // both got wrong, so it is worth an explicit case.
    act(() => { state.scrollTop = BOTTOM - 40; el.dispatchEvent(new Event('scroll')) })

    act(() => {
      state.clientHeight = SHRUNK_CH
      ro.fire([{ target: el } as Partial<ResizeObserverEntry>])
    })

    // The pin attempt runs (stick is armed) but `evaluateAutoPin` sees the
    // scroll-up in live geometry and releases follow WITHOUT moving anything.
    // The reader keeps their place — same outcome the pre-existing row-resize
    // path already produces in this state.
    expect(el.scrollTop).toBe(BOTTOM - 40)
  })
})
