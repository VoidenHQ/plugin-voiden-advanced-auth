#!/usr/bin/env node
import { build } from 'esbuild'
import { readFileSync, existsSync } from 'fs'
import { resolve, join, dirname } from 'path'

const manifest = JSON.parse(readFileSync('./manifest.json', 'utf8'))
const pluginId = manifest.id
const entry = './src/main-process.ts'

if (!existsSync(entry)) {
  console.log('No main-process.ts found — skipping main build')
  process.exit(0)
}

const localNodeModules = resolve('./node_modules')

// Resolve a bare specifier (possibly with sub-path) from a list of candidate node_modules dirs.
function resolveBarePkg(specifier, searchRoots) {
  // Split: '@scope/pkg/sub' → pkgName='@scope/pkg', sub='sub'
  //        'pkg/sub'        → pkgName='pkg',         sub='sub'
  const parts = specifier.split('/')
  const isScoped = specifier.startsWith('@')
  const pkgName = isScoped ? `${parts[0]}/${parts[1]}` : parts[0]
  const subPath  = isScoped ? parts.slice(2).join('/') : parts.slice(1).join('/')

  for (const root of searchRoots) {
    const pkgRoot = join(root, pkgName)
    if (!existsSync(pkgRoot)) continue
    const pkgJsonPath = join(pkgRoot, 'package.json')
    if (!existsSync(pkgJsonPath)) continue
    let pkg
    try { pkg = JSON.parse(readFileSync(pkgJsonPath, 'utf8')) } catch { continue }

    if (subPath) {
      // Look up sub-path in exports map first
      if (pkg.exports) {
        const key = `./${subPath}`
        const exp = pkg.exports[key]
        if (exp) {
          let target = typeof exp === 'string' ? exp
            : exp.require ?? exp.default ?? exp.import ?? null
          if (target && typeof target === 'object') target = target.default ?? target.require ?? null
          if (typeof target === 'string') return resolve(join(pkgRoot, target))
        }
      }
      // Fallback: treat sub-path as a file path
      for (const candidate of [subPath, subPath + '.js', subPath + '/index.js']) {
        const p = join(pkgRoot, candidate)
        if (existsSync(p)) return p
      }
      continue
    }

    // Main entry
    let entry = null
    if (pkg.exports) {
      const exp = pkg.exports['.'] ?? pkg.exports
      if (typeof exp === 'string') entry = exp
      else if (exp && typeof exp === 'object') {
        entry = exp.require ?? exp.default ?? exp.import ?? null
        if (entry && typeof entry === 'object') entry = entry.default ?? entry.require ?? null
      }
    }
    entry = (typeof entry === 'string' ? entry : null) ?? pkg.main ?? 'index.js'
    return resolve(join(pkgRoot, entry))
  }
  return null
}

// Collect all node_modules dirs walking up from a given directory to our plugin root.
function getSearchRoots(resolveDir) {
  const roots = []
  let dir = resolveDir
  while (dir && dir !== dirname(dir)) {
    roots.push(join(dir, 'node_modules'))
    if (resolve(dir) === localNodeModules || resolve(dir) === resolve('.')) break
    dir = dirname(dir)
  }
  roots.push(localNodeModules)
  return roots
}

// Plugin that resolves all non-external bare specifiers from local node_modules,
// bypassing Yarn PnP which blocks packages not registered in its manifest.
const localModulesPlugin = {
  name: 'local-modules',
  setup(build) {
    const externals = build.initialOptions.external ?? []
    const isExternal = (path) =>
      externals.some(e => e === path || (e.endsWith('*') && path.startsWith(e.slice(0, -1))))

    build.onResolve({ filter: /^[^./]/ }, (args) => {
      if (isExternal(args.path)) return null
      const searchRoots = getSearchRoots(args.resolveDir || resolve('.'))
      const resolved = resolveBarePkg(args.path, searchRoots)
      if (resolved) return { path: resolved }
      return null
    })
  }
}

await build({
  entryPoints: [entry],
  bundle: true,
  platform: 'node',
  format: 'cjs',
  outfile: `dist/${pluginId}-main.cjs`,
  external: [
    'electron',
    'node:*',
    'child_process', 'fs', 'path', 'os', 'http', 'https', 'net', 'crypto',
    'worker_threads', 'stream', 'events', 'util', 'url', 'buffer',
    '@voiden/sdk',
  ],
  plugins: [localModulesPlugin],
  minify: true,
})

console.log(`Built dist/${pluginId}-main.cjs`)
