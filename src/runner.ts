import type { RunnerFactory, RunnerContext } from '@voiden/sdk/runner'

/**
 * voiden-advanced-auth — headless pipeline hook runner.
 *
 * Auth injection (Bearer, Basic, API Key, OAuth2, etc.) is handled entirely
 * inside the IPC adapter (cliElectron → Electron main process) during the
 * Sending stage — no plugin hook is needed in the headless runner.
 *
 * OAuth2 auto-refresh requires window.electron and browser IPC, which is
 * not available in the CLI context. That feature is intentionally skipped.
 *
 * Default export: RunnerFactory — called by voiden-runner's plugin loader.
 */

const createAdvancedAuthRunner: RunnerFactory = (_context: RunnerContext) => {
  return {
    onload() {
      // Auth processing handled by ipcAdapter — no hooks required headlessly.
    },
  }
}

export default createAdvancedAuthRunner

