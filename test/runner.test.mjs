import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import { build } from 'esbuild'
import { createRequire } from 'node:module'
import { rm } from 'node:fs/promises'

const outfile = '.test-runner.cjs'
let runner

before(async () => {
  await build({
    entryPoints: ['src/runner.ts'],
    bundle: true,
    platform: 'node',
    format: 'cjs',
    outfile,
  })
  runner = createRequire(import.meta.url)(`../${outfile}`)
})

after(async () => {
  await rm(outfile, { force: true })
})

const row = (key, value, disabled = false) => ({ attrs: { disabled }, row: [key, value] })
const awsBlock = (rows, attrs = {}) => ({
  type: 'auth',
  attrs: { authType: 'awsSignature', ...attrs },
  content: [{ type: 'table', rows }],
})

test('runner transports an unresolved AWS auth descriptor without signing', () => {
  const contribution = runner.buildAuthContribution([
    awsBlock([
      row('access_key', '{{AWS_ACCESS_KEY_ID}}'),
      row('secret_key', '{{AWS_SECRET_ACCESS_KEY}}'),
      row('session_token', '{{AWS_SESSION_TOKEN}}'),
      row('region', 'eu-west-1'),
      row('service', 'monitoring'),
    ]),
  ])

  assert.deepEqual(contribution, {
    headers: [],
    queryParams: [],
    auth: {
      enabled: true,
      type: 'aws-signature',
      config: {
        accessKey: '{{AWS_ACCESS_KEY_ID}}',
        secretKey: '{{AWS_SECRET_ACCESS_KEY}}',
        sessionToken: '{{AWS_SESSION_TOKEN}}',
        region: 'eu-west-1',
        service: 'monitoring',
      },
    },
  })
})

test('onBuildRequest output is the shape consumed by RestApiRequestState', () => {
  let handler
  const factory = runner.default
  factory({ onBuildRequest: (fn) => { handler = fn } }).onload()

  const request = {
    method: 'GET', url: 'https://example.execute-api.us-east-1.amazonaws.com',
    headers: [], queryParams: [], pathParams: [],
  }
  const result = handler(request, [awsBlock([
    row('access_key', 'AKID'), row('secret_key', 'SECRET'),
    row('region', 'us-east-1'), row('service', 'execute-api'),
  ])])

  assert.deepEqual(result.auth, {
    enabled: true,
    type: 'aws-signature',
    config: {
      accessKey: 'AKID', secretKey: 'SECRET', region: 'us-east-1', service: 'execute-api',
    },
  })
  assert.equal(result.headers.length, 0)
  assert.equal(result.queryParams.length, 0)
  assert.equal('Authorization' in result, false)
})

test('disabled session token is not transported', () => {
  const { auth } = runner.buildAuthContribution([awsBlock([
    row('access_key', 'AKID'), row('secret_key', 'SECRET'),
    row('session_token', 'ignored', true),
    row('region', 'us-east-1'), row('service', 's3'),
  ])])
  assert.equal('sessionToken' in auth.config, false)
})
