/**
 * Voiden Advanced Authentication Extension
 *
 * Provides advanced authentication support including:
 * - Bearer Token
 * - Basic Auth
 * - API Key (Header/Query)
 * - OAuth 1.0
 * - OAuth 2.0 (full flow with PKCE, 4 grant types, auto-refresh)
 * - Digest Auth
 * - AWS Signature
 * - And more...
 */

import type { CorePluginContext } from '@voiden/sdk/ui';
type PluginContext = CorePluginContext;
import { insertAuthNode } from './lib/utils';
import {
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
} from './lib/oauth2/pkce';

// Access (window as any).electron via (window as any).electron to avoid
// conflicting declare global blocks with other extensions.

export default function createAdvancedAuthPlugin(context: PluginContext) {
  return {
    onload: async () => {

      // Load AuthNode from plugin package
      const { createAuthNode } = await import('./nodes/AuthNode');

      // Create node with context components
      const { NodeViewWrapper, RequestBlockHeader } = context.ui.components;
      type ToastFn = (message: string, type?: 'info' | 'success' | 'warning' | 'error') => void;
      const showToast: ToastFn = (context.ui as any).showToast?.bind(context.ui) ?? (() => {});

      const AuthNode = createAuthNode(NodeViewWrapper, RequestBlockHeader, context.project.openFile, showToast);

      // Register AuthNode
      context.registerVoidenExtension(AuthNode);

      // docsUrl defaults to the voiden-blocks root for now — swap in a per-authType deep link later
      // (e.g. via a docsUrl(attrs) function keyed off attrs.authType) once auth-specific pages exist.
      (context as any).registerBlockOutlineMeta({
        auth: {
          label: "Auth",
          icon: "Shield",
          docsUrl: "https://docs.voiden.md/docs/core-features-section/voiden-blocks/advanced-authorization/basic-auth-block",
          getPreview: (attrs: Record<string, any>) => {
            const labels: Record<string, string> = {
              bearer: "Bearer Token",
              basic: "Basic Auth",
              "api-key": "API Key",
              oauth2: "OAuth 2.0",
              oauth1: "OAuth 1.0",
              digest: "Digest Auth",
              aws: "AWS Signature",
              inherit: "Inherited",
            };
            return attrs?.authType ? (labels[attrs.authType] ?? attrs.authType) : undefined;
          },
        },
      });

      // ── OAuth2 Auto-Refresh Hook ──────────────────────────────────
      // Runs during RequestCompilation (before preSendProcessHook).
      // If autoRefresh is enabled and the token is expired, refreshes
      // the token via Electron IPC and writes the new token to
      // .voiden/.process.env.json so preSendProcessHook picks it up.
      try {
        await context.pipeline.registerHook(
          'request-compilation',
          async (ctx: any) => {
            try {
              // Check if this request uses oauth2 auth (passed from sendRequestHybrid)
              const auth = ctx?.auth;
              if (!auth?.enabled || auth.type !== 'oauth2') return;

              const varPrefix = auth.config.variablePrefix || 'oauth2';
              const EXT_IPC = 'ext:voiden-advanced-auth:';
              const ipc = (ch: string, ...args: any[]) => (window as any).electron?.ipc?.invoke(`${EXT_IPC}${ch}`, ...args);

              /** Resolve {{process.xxx}} patterns using runtime variables */
              const resolveProcessVars = async (text: string): Promise<string> => {
                if (!text || !text.includes('{{process.')) return text;
                try {
                  const variables = await (window as any).electron?.variables?.read() || {};
                  return text.replace(/{{\s*process\.([^}]+)\s*}}/g, (_match: string, varPath: string) => {
                    const value = variables[varPath.trim()];
                    if (value !== undefined && value !== null) {
                      return typeof value === 'object' ? JSON.stringify(value) : String(value);
                    }
                    return _match;
                  });
                } catch {
                  return text;
                }
              };

              /** Save a token result to runtime variables and patch requestState */
              const saveAndPatch = async (result: any) => {
                // Build only the OAuth-specific vars to merge in
                const updated: Record<string, any> = {
                  [`${varPrefix}_access_token`]: result.accessToken,
                  [`${varPrefix}_token_type`]: result.tokenType || 'Bearer',
                };
                if (result.refreshToken) {
                  updated[`${varPrefix}_refresh_token`] = result.refreshToken;
                }
                if (result.expiresIn) {
                  updated[`${varPrefix}_expires_at`] = Date.now() + result.expiresIn * 1000;
                }
                // Save all extra fields from the raw response
                const knownKeys = new Set(['access_token', 'token_type', 'expires_in', 'refresh_token', 'scope']);
                if (result.raw) {
                  for (const [key, value] of Object.entries(result.raw)) {
                    if (!knownKeys.has(key) && value != null && value !== '') {
                      updated[`${varPrefix}_${key}`] = typeof value === 'object' ? JSON.stringify(value) : value;
                    }
                  }
                }
                // Save refresh config for future auto-refreshes
                if (auth.config?.autoRefresh && auth.config.tokenUrl && auth.config.clientId) {
                  updated[`${varPrefix}_refresh_config`] = JSON.stringify({
                    tokenUrl: auth.config.tokenUrl,
                    clientId: auth.config.clientId,
                    clientSecret: auth.config.clientSecret || '',
                    scope: auth.config.scope || '',
                    variablePrefix: varPrefix,
                    clientAuthMethod: auth.config.clientAuthMethod || 'client_secret_post',
                    customParams: auth.config.customParams || '',
                  });
                }
                // Use mergeVariables so it only touches the OAuth keys — never restoring user-deleted vars
                await (window as any).electron?.variables?.mergeVariables(updated);

                // Patch requestState so the current request uses the new token
                const tokenType = result.tokenType || 'Bearer';
                const headerPrefix = auth.config?.headerPrefix || tokenType;
                const addTokenTo = auth.config?.addTokenTo || 'header';
                if (addTokenTo === 'query') {
                  if (ctx.requestState?.queryParams) {
                    const params = ctx.requestState.queryParams as Array<{ key: string; value: string; enabled?: boolean }>;
                    const tokenIdx = params.findIndex(
                      (p: any) => p.key === 'access_token',
                    );
                    if (tokenIdx >= 0) {
                      params[tokenIdx].value = encodeURIComponent(result.accessToken);
                    } else {
                      params.push({ key: 'access_token', value: encodeURIComponent(result.accessToken), enabled: true });
                    }
                  }
                } else if (ctx.requestState?.headers) {
                  const headers = ctx.requestState.headers as Array<{ key: string; value: string; enabled?: boolean }>;
                  const authIdx = headers.findIndex(
                    (h: any) => h.key?.toLowerCase() === 'authorization',
                  );
                  const newValue = `${headerPrefix} ${result.accessToken}`;
                  if (authIdx >= 0) {
                    headers[authIdx].value = newValue;
                  } else {
                    headers.push({ key: 'Authorization', value: newValue, enabled: true });
                  }
                }
              };

              // ── Acquire: fetch a fresh token via the configured grant type ──
              const acquireToken = async () => {
                const grantType = auth.config.grantType || 'authorization_code';
                const tokenUrl = await resolveProcessVars(auth.config.tokenUrl || '');
                const clientId = await resolveProcessVars(auth.config.clientId || '');
                const clientSecret = await resolveProcessVars(auth.config.clientSecret || '');
                const scope = await resolveProcessVars(auth.config.scope || '');
                const clientAuthMethod = auth.config.clientAuthMethod || 'client_secret_post';
                const customParams = auth.config.customParams || '';

                let result: any;
                switch (grantType) {
                  case 'authorization_code': {
                    const authUrl = await resolveProcessVars(auth.config.authUrl || '');
                    const callbackUrl = await resolveProcessVars(auth.config.callbackUrl || '');
                    const missing = [...(!authUrl ? ['Auth URL'] : []), ...(!tokenUrl ? ['Token URL'] : []), ...(!clientId ? ['Client ID'] : [])];
                    if (missing.length > 0) { showToast(`OAuth2: Authorization Code flow requires ${missing.join(', ')}`, 'error'); break; }
                    const codeVerifier = generateCodeVerifier();
                    const codeChallenge = await generateCodeChallenge(codeVerifier);
                    const state = (await resolveProcessVars(auth.config.state || '')) || generateState();
                    result = await ipc('oauth2:startAuthCodeFlow', {
                      authUrl, tokenUrl, clientId, clientSecret: clientSecret || undefined,
                      scope, callbackUrl: callbackUrl || undefined,
                      codeVerifier, codeChallenge, codeChallengeMethod: 'S256',
                      state, clientAuthMethod, customParams,
                    });
                    break;
                  }
                  case 'implicit': {
                    const authUrl = await resolveProcessVars(auth.config.authUrl || '');
                    const callbackUrl = await resolveProcessVars(auth.config.callbackUrl || '');
                    const missing = [...(!authUrl ? ['Auth URL'] : []), ...(!clientId ? ['Client ID'] : [])];
                    if (missing.length > 0) { showToast(`OAuth2: Implicit flow requires ${missing.join(', ')}`, 'error'); break; }
                    const state = (await resolveProcessVars(auth.config.state || '')) || generateState();
                    result = await ipc('oauth2:startImplicitFlow', {
                      authUrl, clientId, scope,
                      callbackUrl: callbackUrl || undefined,
                      state, clientAuthMethod, customParams,
                    });
                    break;
                  }
                  case 'password': {
                    const username = await resolveProcessVars(auth.config.username || '');
                    const password = await resolveProcessVars(auth.config.password || '');
                    const missing = [...(!tokenUrl ? ['Token URL'] : []), ...(!clientId ? ['Client ID'] : [])];
                    if (missing.length > 0) { showToast(`OAuth2: Password flow requires ${missing.join(', ')}`, 'error'); break; }
                    result = await ipc('oauth2:passwordGrant', {
                      tokenUrl, clientId, clientSecret: clientSecret || undefined,
                      username, password, scope, clientAuthMethod, customParams,
                    });
                    break;
                  }
                  case 'client_credentials': {
                    const missing = [...(!tokenUrl ? ['Token URL'] : []), ...(!clientId ? ['Client ID'] : [])];
                    if (missing.length > 0) { showToast(`OAuth2: Client Credentials flow requires ${missing.join(', ')}`, 'error'); break; }
                    result = await ipc('oauth2:clientCredentialsGrant', {
                      tokenUrl, clientId, clientSecret,
                      scope, clientAuthMethod, customParams,
                    });
                    break;
                  }
                }

                if (result?.accessToken) {
                  await saveAndPatch(result);
                  console.log(`[OAuth2 Auto-Acquire] Token acquired for prefix "${varPrefix}" (${grantType})`);
                } else if (result !== undefined) {
                  const detail = result?.error_description || result?.error || result?.message;
                  showToast(`OAuth2: Token request failed${detail ? ` — ${detail}` : ''}`, 'error');
                }
              };

              // ── Auto-Acquire: no token stored yet ────────────────────
              const existingToken = await (window as any).electron?.variables?.get(`${varPrefix}_access_token`);
              if (!existingToken) {
                await acquireToken();
                return;
              }

              // ── Auto-Refresh: token exists but may be expired ─────────
              const expiresAt = await (window as any).electron?.variables?.get(`${varPrefix}_expires_at`);
              const isExpired = expiresAt && Date.now() >= Number(expiresAt);

              if (!isExpired) return;

              if (!auth.config?.autoRefresh) {
                await (window as any).electron?.variables?.deleteKey?.(`${varPrefix}_access_token`);
                await (window as any).electron?.variables?.deleteKey?.(`${varPrefix}_expires_at`);
                await acquireToken();
                return;
              }

              const storedRefreshToken = await (window as any).electron?.variables?.get(`${varPrefix}_refresh_token`);
              if (!storedRefreshToken) {
                await (window as any).electron?.variables?.deleteKey?.(`${varPrefix}_access_token`);
                await (window as any).electron?.variables?.deleteKey?.(`${varPrefix}_expires_at`);
                await acquireToken();
                return;
              }

              const rawRefreshConfig = await (window as any).electron?.variables?.get(`${varPrefix}_refresh_config`);
              let refreshConfig: any;
              try {
                refreshConfig = typeof rawRefreshConfig === 'string' ? JSON.parse(rawRefreshConfig) : rawRefreshConfig;
              } catch {
                showToast('OAuth2: Cannot refresh token — stored refresh config is invalid, re-authorize to get a new token', 'warning');
                return;
              }
              if (!refreshConfig) {
                showToast('OAuth2: Cannot refresh token — no refresh config found, re-authorize to get a new token', 'warning');
                return;
              }

              const refreshResult = await ipc('oauth2:refreshToken', {
                tokenUrl: refreshConfig.tokenUrl || '',
                clientId: refreshConfig.clientId || '',
                clientSecret: refreshConfig.clientSecret || '',
                refreshToken: storedRefreshToken,
                scope: refreshConfig.scope || '',
                clientAuthMethod: refreshConfig.clientAuthMethod || 'client_secret_post',
                customParams: refreshConfig.customParams || '',
              });

              if (refreshResult?.accessToken) {
                await saveAndPatch(refreshResult);
                console.log(`[OAuth2 Auto-Refresh] Token refreshed for prefix "${varPrefix}"`);
              } else {
                const detail = refreshResult?.error_description || refreshResult?.error || refreshResult?.message;
                showToast(`OAuth2: Token refresh failed${detail ? ` — ${detail}` : ''}`, 'error');
              }
            } catch (err: any) {
              const raw = err?.message || String(err);
              const message = raw.replace(/^Error invoking remote method '[^']*':\s*/i, '');
              showToast(`OAuth2: ${message}`, 'error');
              console.warn('[OAuth2] Hook error:', err);
            }
          },
          5, // high priority – runs before scripting hooks
        );
      } catch (err) {
        console.warn('[voiden-advanced-auth] Failed to register auto-refresh hook:', err);
      }

      // ── OAuth2 401 Detection Hook ─────────────────────────────────
      try {
        await context.pipeline.registerHook(
          'post-processing',
          (ctx: any) => {
            try {
              const auth = ctx?.requestState?.auth;
              if (!auth?.enabled || auth.type !== 'oauth2') return;
              const status = ctx?.responseState?.status;
              if (status === 401) {
                const varPrefix = auth.config?.variablePrefix || 'oauth2';
                const hasAutoRefresh = auth.config?.autoRefresh === true;
                showToast(
                  hasAutoRefresh
                    ? 'OAuth2: 401 Unauthorized — token may be revoked, re-authorize to get a new token'
                    : 'OAuth2: 401 Unauthorized — token is expired or invalid, re-authorize to get a new token',
                  'warning',
                );
                (window as any).electron?.variables?.deleteKey?.(`${varPrefix}_access_token`);
                (window as any).electron?.variables?.deleteKey?.(`${varPrefix}_expires_at`);
              }
            } catch { /* never block the response */ }
          },
          5,
        );
      } catch (err) {
        console.warn('[voiden-advanced-auth] Failed to register 401 hook:', err);
      }

      // ── cURL Extender ─────────────────────────────────────────────
      // Fills in auth for types that generateCurlFromRequestObject doesn't
      // handle natively (oauth2, digest, ntlm, aws-signature, netrc, and a
      // best-effort PLAINTEXT oauth1). bearer-token / basic-auth / api-key
      // are already converted by the base generator via req.auth, so this
      // only covers the remaining types. Every type below embeds its actual
      // resolved value (not a {{placeholder}}) — a copied cURL command is
      // meant to be runnable as-is outside Voiden, where {{...}} syntax has
      // no meaning.
      //
      // Registration goes through context.paste (a real function reference
      // handed to this plugin at load time, reliable). Callers read this
      // extender back the same way — via context.paste.getCurlHeaderExtenders()
      // — rather than a plugin dynamically importing another plugin's
      // app-internal module path at runtime, which has no guaranteed
      // resolution and was silently dropping every type registered here.
      try {
        (context.paste as any).registerCurlHeaderExtender(async (doc: any) => {
          try {
            // @ts-ignore - resolved at runtime in app context
            const { parseAuthNode } = await import(/* @vite-ignore */ '@/core/request-engine/getRequestFromJson');
            const auth = parseAuthNode(doc);
            if (!auth?.enabled || !auth.type) return {};

            const cfg = auth.config ?? {};
            const type = auth.type;

            // ── OAuth 2.0 ──────────────────────────────────────────
            // Embed the actual stored access token rather than a
            // {{process.xxx}} placeholder — the token is only ever fetched
            // by the auto-acquire/refresh hook when a request is actually
            // sent, so a placeholder left unresolved (no token acquired
            // yet) would silently produce a useless "Bearer {{...}}"
            // header in a command meant to run outside Voiden.
            if (type === 'oauth2') {
              const varPrefix = cfg.variablePrefix || 'oauth2';
              const prefix = cfg.headerPrefix || 'Bearer';
              const token = await (window as any).electron?.variables?.get(`${varPrefix}_access_token`);
              if (!token) {
                return { warning: 'OAuth2: No access token found — send the request once to acquire a token, then copy the cURL command.' };
              }
              if (cfg.addTokenTo === 'query') {
                return { queryParams: [{ key: 'access_token', value: token }] };
              }
              return { headers: [{ key: 'Authorization', value: `${prefix} ${token}` }] };
            }

            // ── Digest Auth ────────────────────────────────────────
            if (type === 'digest-auth') {
              const user = cfg.username || '';
              const pass = cfg.password || '';
              return { flags: ['--digest', `-u "${user}:${pass}"`] };
            }

            // ── NTLM ──────────────────────────────────────────────
            if (type === 'ntlm') {
              const user = cfg.username || '';
              const pass = cfg.password || '';
              const userStr = cfg.domain ? `${cfg.domain}\\${user}` : user;
              return { flags: ['--ntlm', `-u "${userStr}:${pass}"`] };
            }

            // ── AWS Signature ──────────────────────────────────────
            if (type === 'aws-signature') {
              const region = cfg.region || 'us-east-1';
              const service = cfg.service || 'execute-api';
              const accessKey = cfg.accessKey || '';
              const secretKey = cfg.secretKey || '';
              return {
                flags: [
                  `--aws-sigv4 "aws:amz:${region}:${service}"`,
                  `-u "${accessKey}:${secretKey}"`,
                ],
              };
            }

            // ── Netrc ──────────────────────────────────────────────
            // A bare --netrc flag tells curl to read credentials from the
            // system's ~/.netrc file — it doesn't embed this block's own
            // machine/login/password anywhere, so the copied command only
            // authenticates if the machine running it happens to already
            // have a matching ~/.netrc entry. curl's netrc support feeds
            // into the same HTTP Basic Auth mechanism under the hood, so
            // emit -u directly instead — immediately runnable, no external
            // file dependency. (machine is only used to select the right
            // ~/.netrc entry in the first place; it isn't itself sent to
            // the server, so it has no place in the actual curl command.)
            if (type === 'netrc') {
              return { flags: [`-u "${cfg.login || ''}:${cfg.password || ''}"`] };
            }

            // ── OAuth 1.0 ──────────────────────────────────────────
            // Only the PLAINTEXT signature method has a static representation
            // (it's just the secrets concatenated, no request-specific HMAC) —
            // matches what sendRequestHybrid.ts's live-request path actually
            // sends today regardless of the configured signatureMethod, so
            // this stays consistent with real app behavior rather than
            // producing a curl command that authenticates differently than
            // what "Send" does. HMAC-SHA1/SHA256 would require signing the
            // exact method+URL+timestamp+nonce, which isn't representable as
            // static text — timestamp/nonce here are generated at copy time.
            if (type === 'oauth1') {
              const parts: string[] = [];
              if (cfg.consumerKey) parts.push(`oauth_consumer_key="${cfg.consumerKey}"`);
              if (cfg.token) parts.push(`oauth_token="${cfg.token}"`);
              parts.push('oauth_signature_method="PLAINTEXT"');
              const signature = `${cfg.consumerSecret || ''}&${cfg.tokenSecret || ''}`;
              parts.push(`oauth_signature="${encodeURIComponent(signature)}"`);
              parts.push(`oauth_timestamp="${Math.floor(Date.now() / 1000)}"`);
              parts.push(`oauth_nonce="${Math.random().toString(36).substring(2)}"`);
              parts.push('oauth_version="1.0"');
              return { headers: [{ key: 'Authorization', value: `OAuth ${parts.join(', ')}` }] };
            }

            // ── Hawk ────────────────────────────────────────────────
            // Requires an HMAC-SHA256/SHA1 MAC computed over method, host,
            // port, path, a fresh timestamp, and a fresh nonce — deliberately
            // time-bound (servers reject it once the timestamp is too old,
            // to prevent replay). No curl flag can express this: unlike
            // Digest/NTLM/AWS-SigV4, curl has no native Hawk implementation,
            // and pre-computing a MAC here would only work for the ~60s
            // after copying before silently failing later. Surface this as
            // an explicit warning rather than silently omitting the auth.
            if (type === 'hawk') {
              return { warning: 'Hawk requires a live-computed signature and isn\'t included in the copied cURL command.' };
            }

            // ── Atlassian ASAP ──────────────────────────────────────
            // Requires a signed JWT (RS256, using the configured private
            // key) — there is no static cURL representation.
            if (type === 'atlassian-asap') {
              return { warning: 'Atlassian ASAP requires a signed JWT and isn\'t included in the copied cURL command.' };
            }

            // bearer-token, basic-auth, api-key: handled by generateCurlFromRequestObject
            return {};
          } catch (err) {
            console.warn('[voiden-advanced-auth] cURL extender failed:', err);
            return {};
          }
        });
      } catch (err) {
        console.warn('[voiden-advanced-auth] Failed to register cURL extender:', err);
      }

      // ── cURL Auth Parser (paste direction) ─────────────────────────
      // The reverse of the extender above: voiden-rest-api's curl importer
      // extracts raw auth signals from a pasted cURL command (it has no
      // knowledge of auth-block attr schemas) and hands them here to build a
      // ready-to-insert `auth` node, keeping that schema knowledge in this
      // plugin the same way the copy-direction extender does.
      try {
        const authRow = (key: string, value: string) => ({
          type: 'tableRow',
          attrs: { disabled: false },
          content: [
            { type: 'tableCell', attrs: { colspan: 1, rowspan: 1, colwidth: null }, content: [{ type: 'paragraph', content: [{ type: 'text', text: key }] }] },
            { type: 'tableCell', attrs: { colspan: 1, rowspan: 1, colwidth: null }, content: [{ type: 'paragraph', content: [{ type: 'text', text: value }] }] },
          ],
        });
        const buildAuthNode = (authType: string, rows: Array<[string, string]>) => ({
          type: 'auth',
          attrs: { authType },
          content: [
            { type: 'table', content: rows.filter(([, v]) => v !== undefined && v !== '').map(([k, v]) => authRow(k, v)) },
          ],
        });

        (context.paste as any).registerCurlAuthParser(async (raw: any) => {
          try {
            // ── AWS Signature v4 ──────────────────────────────────
            // --aws-sigv4 "aws:amz:region:service" — region/service are
            // always the last two colon-separated segments regardless of
            // how many provider segments precede them.
            if (raw.awsSigV4) {
              const parts = String(raw.awsSigV4).split(':');
              const service = parts.pop() || 'execute-api';
              const region = parts.pop() || 'us-east-1';
              return {
                authNode: buildAuthNode('awsSignature', [
                  ['access_key', raw.username || ''],
                  ['secret_key', raw.password || ''],
                  ['region', region],
                  ['service', service],
                ]),
              };
            }

            // ── NTLM ──────────────────────────────────────────────
            if (raw.ntlm) {
              const hasDomain = (raw.username || '').includes('\\');
              const [domain, user] = hasDomain ? raw.username.split('\\') : ['', raw.username || ''];
              return {
                authNode: buildAuthNode('ntlm', [
                  ['username', user],
                  ['password', raw.password || ''],
                  ['domain', domain],
                ]),
              };
            }

            // ── Digest ────────────────────────────────────────────
            if (raw.digest) {
              return {
                authNode: buildAuthNode('digest', [
                  ['username', raw.username || ''],
                  ['password', raw.password || ''],
                ]),
              };
            }

            // ── Netrc ─────────────────────────────────────────────
            // machine/login/password live in ~/.netrc, never in the pasted
            // command text itself — nothing to build the block from.
            if (raw.netrc) {
              return { warning: 'Netrc auth detected — insert a Netrc auth block manually and fill in machine/login/password from your ~/.netrc file, since curl reads them from that file rather than the command itself.' };
            }

            // ── Basic (-u with no other flag) ────────────────────
            if (raw.username) {
              return {
                authNode: buildAuthNode('basic', [
                  ['username', raw.username],
                  ['password', raw.password || ''],
                ]),
              };
            }

            // ── Authorization header ─────────────────────────────
            const header = raw.authorizationHeader as string | undefined;
            if (header) {
              const bearerMatch = header.match(/^Bearer\s+(.+)$/i);
              if (bearerMatch) {
                return { authNode: buildAuthNode('bearer', [['token', bearerMatch[1].trim()]]) };
              }

              const basicMatch = header.match(/^Basic\s+(.+)$/i);
              if (basicMatch) {
                try {
                  const decoded = atob(basicMatch[1].trim());
                  const [user, ...rest] = decoded.split(':');
                  return { authNode: buildAuthNode('basic', [['username', user], ['password', rest.join(':')]]) };
                } catch {
                  return {};
                }
              }

              const oauthMatch = header.match(/^OAuth\s+(.+)$/i);
              if (oauthMatch) {
                const params: Record<string, string> = {};
                for (const m of oauthMatch[1].matchAll(/(\w+)="([^"]*)"/g)) {
                  params[m[1]] = m[2];
                }
                const rows: Array<[string, string]> = [
                  ['consumer_key', params.oauth_consumer_key || ''],
                  ['access_token', params.oauth_token || ''],
                  ['signature_method', params.oauth_signature_method || 'HMAC-SHA1'],
                ];
                // Only the PLAINTEXT method encodes the secrets directly in the
                // signature (consumerSecret&tokenSecret) — HMAC signatures are
                // one-way and can't be reversed back into the original secrets.
                if (params.oauth_signature_method === 'PLAINTEXT' && params.oauth_signature) {
                  try {
                    const decoded = decodeURIComponent(params.oauth_signature);
                    const [consumerSecret, tokenSecret] = decoded.split(/&(.*)$/);
                    rows.push(['consumer_secret', consumerSecret || ''], ['token_secret', tokenSecret || '']);
                  } catch { /* leave secrets blank below */ }
                }
                const authNode = buildAuthNode('oauth1', rows);
                return params.oauth_signature_method === 'PLAINTEXT'
                  ? { authNode }
                  : { authNode, warning: 'OAuth 1.0: consumer secret and token secret can\'t be recovered from an HMAC signature — re-enter them in the auth block.' };
              }

              const hawkMatch = header.match(/^Hawk\s+(.+)$/i);
              if (hawkMatch) {
                const idMatch = hawkMatch[1].match(/id="([^"]*)"/);
                return {
                  authNode: buildAuthNode('hawk', [['id', idMatch?.[1] || '']]),
                  warning: 'Hawk: the signing key can\'t be recovered from a MAC — re-enter it in the auth block.',
                };
              }
            }

            return {};
          } catch (err) {
            console.warn('[voiden-advanced-auth] cURL auth parser failed:', err);
            return {};
          }
        });
      } catch (err) {
        console.warn('[voiden-advanced-auth] Failed to register cURL auth parser:', err);
      }

      // Register linkable node type
      context.registerLinkableNodeTypes(['auth']);

      // Register display names for node types
      context.registerNodeDisplayNames({
        'auth': 'Authorization',
      });

      // Register slash commands for different auth types
      context.addVoidenSlashGroup({
        name: 'advanced-auth',
        title: 'Advanced Authentication',
        commands: [
          {
            name: "auth",
            singleton: true,
            label: "Authorization",
            compareKeys: ["auth","auth-api-key", "auth-basic", "auth-bearer", "auth-api-key", "auth-oauth1", "auth-oauth2", "auth-digest", "auth-aws"],
            aliases: ['auth'],
            slash: "/auth",
            description: "Insert authorization block",
            action: (editor: any) => {
              insertAuthNode(editor, "inherit");
            },
          },
          {
            name: "auth-bearer",
            label: "Bearer Token",
            singleton: true,
            compareKeys: ["auth","auth-api-key", "auth-basic", "auth-bearer", "auth-api-key", "auth-oauth1", "auth-oauth2", "auth-digest", "auth-aws"],
            aliases: ['auth-bearer'],
            slash: "/auth-bearer",
            description: "Insert Bearer Token auth",
            action: (editor: any) => {
              insertAuthNode(editor, "bearer");
            },
          },
          {
            name: "auth-basic",
            label: "Basic Auth",
            singleton: true,
            compareKeys: ["auth","auth-api-key", "auth-basic", "auth-bearer", "auth-api-key", "auth-oauth1", "auth-oauth2", "auth-digest", "auth-aws"],
            aliases: ["auth-basic"],
            slash: "/auth-basic",
            description: "Insert Basic authentication",
            action: (editor: any) => {
              insertAuthNode(editor, "basic");
            },
          },
          {
            name: "auth-api-key",
            label: "API Key",
            singleton: true,
            compareKeys: ["auth", "auth-api-key","auth-basic", "auth-bearer", "auth-api-key", "auth-oauth1", "auth-oauth2", "auth-digest", "auth-aws"],
            aliases: ["auth-api-key"],
            slash: "/auth-api-key",
            description: "Insert API Key auth",
            action: (editor: any) => {
              insertAuthNode(editor, "apiKey");
            },
          },
          {
            name: "auth-oauth2",
            label: "OAuth 2.0",
            singleton: true,
            compareKeys: ["auth", "auth-api-key", "auth-basic", "auth-bearer", "auth-api-key", "auth-oauth1", "auth-oauth2", "auth-digest", "auth-aws"],
            aliases: ["auth-oauth2"],
            slash: "/auth-oauth2",
            description: "Insert OAuth 2.0 auth",
            action: (editor: any) => {
              insertAuthNode(editor, "oauth2");
            },
          },
          {
            name: "auth-oauth1",
            label: "OAuth 1.0",
            singleton: true,
            compareKeys: ["auth", "auth-api-key","auth-basic", "auth-bearer", "auth-api-key", "auth-oauth1", "auth-oauth2", "auth-digest", "auth-aws"],
            aliases: ["auth-oauth1"],
            slash: "/auth-oauth1",
            description: "Insert OAuth 1.0 auth",
            action: (editor: any) => {
              insertAuthNode(editor, "oauth1");
            },
          },
          {
            name: "auth-digest",
            label: "Digest Auth",
            singleton: true,
            compareKeys: ["auth", "auth-api-key","auth-basic", "auth-bearer", "auth-api-key", "auth-oauth1", "auth-oauth2", "auth-digest", "auth-aws"],
            aliases: ["auth-digest"],
            slash: "/auth-digest",
            description: "Insert Digest authentication",
            action: (editor: any) => {
              insertAuthNode(editor, "digest");
            },
          },
          {
            name: "auth-aws",
            label: "AWS Signature",
            singleton: true,
            compareKeys: ["auth", "auth-api-key","auth-basic", "auth-bearer", "auth-api-key", "auth-oauth1", "auth-oauth2", "auth-digest", "auth-aws"],
            aliases: ["auth-aws"],
            slash: "/auth-aws",
            description: "Insert AWS Signature auth",
            action: (editor: any) => {
              insertAuthNode(editor, "awsSignature");
            },
          },
        ],
      });
    },

    onunload: async () => {
    },
  };
}
