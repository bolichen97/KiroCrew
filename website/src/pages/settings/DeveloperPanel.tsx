import { safeSetItem } from '../../utils/safeStorage'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ExternalLink } from 'lucide-react'
import { SettingsSection, SettingsCard, SettingsToggle, SettingsSelect, SettingsInput } from '../../components/settings'
import { useLocalGateway } from '../../hooks/useLocalGateway'
import { api } from '../../api/client'

import { i18nT } from '../../i18n/t'
const DEV_MODE_KEY = 'mc-dev-mode'
const DEV_MODE_EVENT = 'mc-dev-mode-changed'

/** Config values, mirrored from `AgentConfig.acp_backend` in config/loader.py. */
const BACKEND_KIRO_CLI = 'kiro-cli'
const BACKEND_KAS = 'kas'

/** Only the two fields this panel edits; the endpoint returns the whole config. */
type AgentCfg = { agent?: { acp_backend?: string; kas_path?: string } }

/** Settings > Developer tab.
 *
 *  Deliberately minimal: the Developer Mode toggle is a consent gate, and the
 *  hardcore internals it unlocks (logs, system metrics, memory internals,
 *  MCP pool/gateway controls) live on the standalone Developer PAGE behind
 *  that gate — not in always-visible Settings. Early-access updates are handled
 *  by the stable | insider channel switcher in Settings > About, so this tab
 *  carries no beta-channel toggle.
 *
 *  The ACP backend switcher sits here rather than in Chat because picking a
 *  harness is an operator action: it changes which engine every session runs,
 *  so it belongs with the advanced switches rather than beside per-chat
 *  preferences.
 *
 *  The Gateway section is desktop-app-only and appears only when the Electron
 *  bridge is present: a browser tab has no local gateway to start or stop. It
 *  sits here because it is an advanced switch with no other home yet, not
 *  because running remotely is a developer activity. */
export function DeveloperPanel() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [devMode, setDevMode] = useState(() => localStorage.getItem(DEV_MODE_KEY) === '1')
  const { localGatewayEnabled, localGatewaySupported, setLocalGatewayEnabled } = useLocalGateway()
  const [kasPathDraft, setKasPathDraft] = useState<string | null>(null)
  const [saveError, setSaveError] = useState('')

  const cfgQ = useQuery<AgentCfg>({
    queryKey: ['kirocrew-config'],
    queryFn: () => api.kirocrewConfig() as Promise<AgentCfg>,
  })
  const agent = cfgQ.data?.agent
  const backend = agent?.acp_backend === BACKEND_KAS ? BACKEND_KAS : BACKEND_KIRO_CLI
  // The draft wins only while the field is being edited, so a server refetch
  // cannot yank characters out from under the cursor.
  const kasPath = kasPathDraft ?? agent?.kas_path ?? ''

  const saveMut = useMutation({
    mutationFn: ({ path, value }: { path: string; value: string }) => api.patchConfig(path, value),
    onError: () => setSaveError(i18nT('pages.settings.developerPanel.failed_to_save_acp_backend')),
    onSuccess: () => setSaveError(''),
    onSettled: () => qc.invalidateQueries({ queryKey: ['kirocrew-config'] }),
  })

  const toggleDevMode = (v: boolean) => {
    safeSetItem(DEV_MODE_KEY, v ? '1' : '0')
    setDevMode(v)
    window.dispatchEvent(new CustomEvent(DEV_MODE_EVENT, { detail: v }))
    // Notify Electron main process to show/hide DevTools menu item
    ;(window as Window & { electronAPI?: { setDevMode?: (v: boolean) => void } }).electronAPI?.setDevMode?.(v)
  }

  return (
    <>
    <SettingsSection title={i18nT('pages.settings.developerPanel.developer_tools')}>
      <SettingsCard>
        <SettingsToggle
          label={i18nT('pages.settings.developerPanel.developer_mode')}
          description={i18nT('pages.settings.developerPanel.show_developer_page_in_sidebar_with_logs_system')}
          checked={devMode}
          onChange={toggleDevMode}
        />
        {devMode && (
          <div className="pt-1">
            <button
              type="button"
              onClick={() => navigate('/developer')}
              className="inline-flex items-center gap-1.5 text-[13px] font-medium text-accent bg-transparent border-none cursor-pointer px-0 py-1 hover:underline"
            >
              {i18nT('pages.settings.developerPanel.open_developer_page')}
              <ExternalLink size={13} className="lucide-inline" />
            </button>
          </div>
        )}
      </SettingsCard>

      <SettingsCard>
        <SettingsSelect
          label={i18nT('pages.settings.developerPanel.acp_backend')}
          description={i18nT('pages.settings.developerPanel.which_acp_server_to_drive_both_are_the_same')}
          value={backend}
          options={[BACKEND_KIRO_CLI, BACKEND_KAS]}
          optionLabels={[
            i18nT('pages.settings.developerPanel.kiro_cli_default'),
            i18nT('pages.settings.developerPanel.kiro_agent_server_direct'),
          ]}
          onChange={(v) => {
            saveMut.mutate({ path: 'agent.acp_backend', value: v })
          }}
          configKey="agent.acp_backend"
        />
        {backend === BACKEND_KAS && (
          <SettingsInput
            label={i18nT('pages.settings.developerPanel.kas_build_path')}
            description={i18nT('pages.settings.developerPanel.a_built_kiro_agent_checkout_or_an_extracted')}
            value={kasPath}
            onChange={setKasPathDraft}
            onBlur={() => {
              if (kasPathDraft === null) return
              saveMut.mutate({ path: 'agent.kas_path', value: kasPathDraft })
              setKasPathDraft(null)
            }}
            placeholder={i18nT('pages.settings.developerPanel.uses_the_kas_bundled_with_kiro_cli')}
            configKey="agent.kas_path"
          />
        )}
        {saveError && <p className="text-[12px] text-danger m-0 pt-1">{saveError}</p>}
      </SettingsCard>
    </SettingsSection>
    {localGatewaySupported && (
      <SettingsSection title={i18nT('pages.settings.developerPanel.gateway')}>
        <SettingsCard>
          <SettingsToggle
            label={i18nT('pages.settings.developerPanel.run_a_local_gateway')}
            description={i18nT('pages.settings.developerPanel.start_a_gateway_on_this_machine_turn_it_off_to_u')}
            checked={localGatewayEnabled}
            onChange={setLocalGatewayEnabled}
          />
        </SettingsCard>
      </SettingsSection>
    )}
    </>
  )
}
