import { useState, useEffect, useCallback } from 'react'

// "Run Local Gateway" bridge exposed by electron/preload.js. Whether the
// desktop shell spawns a gateway on this machine is decided by the Electron
// main process before any renderer exists, so the renderer round-trips
// through IPC to read/write the persisted setting. Next-launch scoped:
// flipping it never stops or starts a gateway in the running session. In a
// plain browser (and the PWA) the bridge is absent — a web dashboard has no
// local gateway to decline — so the UI hides the toggle (`supported: false`).
type LocalGatewayAPI = {
  get(): Promise<boolean>
  set(enabled: boolean): Promise<boolean>
}
const localGatewayAPI = (): LocalGatewayAPI | undefined =>
  (window as { localGatewayAPI?: LocalGatewayAPI }).localGatewayAPI

export function useLocalGateway() {
  // Default-on mirrors the main process's store default (spawn locally), so
  // the toggle renders truthfully before the first read resolves.
  const [enabled, setEnabledState] = useState(true)
  const supported = !!localGatewayAPI()

  useEffect(() => {
    const api = localGatewayAPI()
    if (!api) return
    let alive = true
    void api.get().then(v => { if (alive) setEnabledState(!!v) }).catch(() => {})
    return () => { alive = false }
  }, [])

  const setEnabled = useCallback((v: boolean) => {
    const api = localGatewayAPI()
    if (!api) return
    // Optimistic flip for a responsive toggle; the round-trip result is the
    // effective value the main process persisted, so it reconciles the state.
    setEnabledState(v)
    void api.set(v).then(applied => setEnabledState(!!applied)).catch(() => {})
  }, [])

  return { supported, enabled, setEnabled }
}
