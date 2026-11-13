import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import { verifyAsset } from '../scripts/prepare-windows-nsis.mjs'

test('NSIS preparation rejects changed download bytes before extraction', t => {
  const directory = mkdtempSync(join(tmpdir(), 'axonkey-nsis-test-'))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  const asset = join(directory, 'asset.zip')
  const expectedHash = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  writeFileSync(asset, 'abc')
  assert.doesNotThrow(() => verifyAsset(asset, expectedHash))
  writeFileSync(asset, 'corrupt download')
  assert.throws(() => verifyAsset(asset, expectedHash), /SHA-256 mismatch/)
})

test('NSIS preparation requires an explicit cache directory', () => {
  const result = spawnSync(process.execPath, ['scripts/prepare-windows-nsis.mjs'], { encoding: 'utf8' })
  assert.equal(result.status, 1)
  assert.match(result.stderr, /Usage:/)
})

test('Windows NSIS installer never reads or modifies user or system Environment/Path', () => {
  const template = readFileSync('src-tauri/windows/installer.nsi', 'utf8')
  const tauriConfig = JSON.parse(readFileSync('src-tauri/tauri.conf.json', 'utf8'))
  const windowsConfig = JSON.parse(readFileSync('src-tauri/tauri.windows.conf.json', 'utf8'))

  assert.equal(windowsConfig.bundle?.windows?.nsis?.template, 'windows/installer.nsi')
  assert.equal(windowsConfig.bundle?.windows?.nsis?.installerHooks, undefined)
  assert.equal(tauriConfig.bundle?.windows?.nsis?.installerHooks, undefined)

  assert.doesNotMatch(template, /\b(ReadReg\w*|WriteReg\w*|DeleteReg\w*)\b[^\r\n]*"Environment"/i)
  assert.doesNotMatch(template, /Session Manager\\Environment/i)
  assert.doesNotMatch(template, /\bEnVar::/i)
  assert.doesNotMatch(template, /STR:Environment/i)
  assert.doesNotMatch(template, /\bsetx\b/i)
})

const signedDriverInfs = [
  {
    path: 'vendor/QuarborUniversalKeyboardDriverInstaller/QuarborUniversalKeyboardDriver.inf',
    sha256: '38557cee1943d38947cc519886631abaa18f77b7a9d54f9d545fd42f3c82675e',
  },
  {
    path: 'vendor/QuarborVirtualMicrophoneDriverInstaller/QuarborVirtualMicrophoneDriver.inf',
    sha256: '13a4ef03785ca37902d25a5e17df6886f943039749a64a6828df99372f4ea61b',
  },
]

for (const { path, sha256 } of signedDriverInfs) {
  test(`${path} retains its signed catalog bytes`, () => {
    assert.equal(createHash('sha256').update(readFileSync(path)).digest('hex'), sha256)
  })
}

test('Git preserves signed driver INF bytes without text normalization', () => {
  const paths = signedDriverInfs.map(({ path }) => path)
  const result = spawnSync('git', ['check-attr', 'text', 'whitespace', '--', ...paths], { encoding: 'utf8' })
  assert.ifError(result.error)
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(result.stdout.trim().split(/\r?\n/), paths.flatMap(path => [
    `${path}: text: unset`,
    `${path}: whitespace: cr-at-eol`,
  ]))
})
