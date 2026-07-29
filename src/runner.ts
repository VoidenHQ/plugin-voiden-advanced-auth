import { Buffer } from 'node:buffer'
import type { RunnerFactory, RunnerContext, Block } from '@voiden/sdk/runner'

/**
 * voiden-advanced-auth — headless pipeline hook runner.
 *
 * Owns parsing the `auth` block and turning it into extra header/query rows
 * for the headless (CLI/voiden-mcp) request-build pipeline — mirroring
 * apps/ui/src/core/request-engine/getRequestFromJson.ts (parseAuthNode) +
 * sendRequestHybrid.ts (getHeaders/getParameters), the logic the real app
 * applies before a request ever reaches the shared executor. Previously this
 * plugin did nothing headlessly and nothing else read the `auth` block either
 * (not voiden-rest-api, not the IPC adapter, not the shared executor in
 * @voiden/executors secureRequest.ts) — every headless request silently ran
 * with auth completely ignored, regardless of authType.
 *
 * Only the deterministic auth types are supported here (bearer, basic, apiKey).
 * oauth2/oauth1/digest/ntlm/awsSignature need token refresh or signature
 * generation the app itself only does via renderer-side runtime-variable and
 * env machinery that has no headless equivalent yet — left unimplemented
 * rather than faked.
 *
 * Default export: RunnerFactory — called by voiden-runner's plugin loader.
 */

type Row = { key: string; value: string; enabled: boolean }

function extractRows(block: any): Row[] {
  const rows: Row[] = []
  if (!Array.isArray(block?.content)) return rows
  for (const child of block.content) {
    if (child.type === 'table' && Array.isArray(child.rows)) {
      for (const r of child.rows) {
        const disabled = r.attrs?.disabled === true
        if (Array.isArray(r.row) && r.row.length >= 2) {
          const key   = String(r.row[0] ?? '').trim()
          const value = String(r.row[1] ?? '').trim()
          if (key) rows.push({ key, value, enabled: !disabled })
        }
      }
    }
  }
  return rows
}

/**
 * Named export for direct use/testing — parses the `auth` block (if any) out
 * of a document's blocks and returns the header/query rows it contributes.
 * Returns empty arrays when there's no local auth block, or it's inherit/none.
 */
export function buildAuthRows(blocks: Block[]): { headers: Row[]; queryParams: Row[] } {
  const authBlock: any = blocks.find((b: any) => b.type === 'auth')
  const authType: string | undefined = authBlock?.attrs?.authType
  if (!authBlock || !authType || authType === 'inherit' || authType === 'none') {
    return { headers: [], queryParams: [] }
  }

  const config: Record<string, string> = {}
  for (const row of extractRows(authBlock)) config[row.key] = row.value

  const headers: Row[] = []
  const queryParams: Row[] = []

  switch (authType) {
    case 'bearer': {
      const token = config.token || ''
      headers.push({ key: 'Authorization', value: `Bearer ${token}`, enabled: true })
      break
    }
    case 'basic': {
      const username = config.username || ''
      const password = config.password || ''
      const base64Credentials = Buffer.from(`${username}:${password}`).toString('base64')
      headers.push({ key: 'Authorization', value: `Basic ${base64Credentials}`, enabled: true })
      break
    }
    case 'apiKey': {
      const key = config.key || ''
      const value = config.value || ''
      const addTo = config.add_to || 'header'
      if (key && addTo === 'query') queryParams.push({ key, value, enabled: true })
      else if (key) headers.push({ key, value, enabled: true })
      break
    }
    default:
      break
  }

  return { headers, queryParams }
}

const createAdvancedAuthRunner: RunnerFactory = (context: RunnerContext) => {
  return {
    onload() {
      // ── Request builder ───────────────────────────────────────────────────
      // onBuildRequest handlers run in plugin-load order (registry order — not
      // guaranteed to run before or after voiden-rest-api's own handler), each
      // receiving the previous handler's output as `request`. We append our
      // auth-derived rows onto whatever headers/queryParams are already present
      // (rather than replacing them) so voiden-rest-api's headers-table/query-table
      // rows survive regardless of which plugin's handler runs first.
      context.onBuildRequest((request, blocks) => {
        const { headers, queryParams } = buildAuthRows(blocks as Block[])
        if (headers.length === 0 && queryParams.length === 0) return request

        const priorHeaders = Array.isArray((request as any)?.headers) ? (request as any).headers : []
        const priorQueryParams = Array.isArray((request as any)?.queryParams) ? (request as any).queryParams : []
        return {
          ...(request as any),
          headers: [...priorHeaders, ...headers],
          queryParams: [...priorQueryParams, ...queryParams],
        }
      })
    },
  }
}

export default createAdvancedAuthRunner
