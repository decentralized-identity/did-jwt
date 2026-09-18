/**
 * Tiny assertion harness shared by the ESM and CJS canaries.
 *
 * It has no dependency on did-jwt and no test framework: it just counts
 * pass/fail and can set the process exit code, so a `tsx` or `node` process can
 * run it and a CI pipeline can key off the exit code.
 */

export class Assert {
  private failures = 0
  private checks = 0
  readonly errors: string[] = []

  pass(name: string): void {
    this.checks++
    console.log(`  \u2713 ${name}`)
  }

  fail(name: string, detail: string): void {
    this.failures++
    this.errors.push(`${name}: ${detail}`)
    console.log(`  \u2717 ${name}\n        ${detail}`)
  }

  /** Assert a predicate is true. */
  assert(name: string, cond: boolean, detail = 'expected true'): void {
    if (cond) this.pass(name)
    else this.fail(name, detail)
  }

  /** Assert strict string equality. */
  assertEq(name: string, actual: unknown, expected: unknown): void {
    const a = JSON.stringify(actual)
    const e = JSON.stringify(expected)
    if (a === e) this.pass(name)
    else this.fail(name, `expected ${e}, got ${a}`)
  }

  /** Assert an async call rejects and the error message matches /re/. */
  async assertRejects(name: string, promise: Promise<unknown>, re: RegExp): Promise<void> {
    try {
      await promise
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      if (re.test(msg)) return this.pass(name)
      return this.fail(name, `expected message matching /${re}/, got "${msg}"`)
    }
    this.fail(name, `expected rejection matching /${re}/, but the call resolved`)
  }

  /** Assert an async call rejects at all. */
  async assertThrows(name: string, fn: () => unknown): Promise<void> {
    try {
      await fn()
    } catch {
      this.pass(name)
      return
    }
    this.fail(name, `expected a throw/rejection, but it resolved`)
  }

  get passed(): number {
    return this.checks - this.failures
  }

  get total(): number {
    return this.checks
  }

  get ok(): boolean {
    return this.failures === 0
  }

  summary(label: string): number {
    console.log(`\n[${label}] ${this.passed}/${this.total} checks passed, ${this.failures} failed`)
    if (this.errors.length) {
      console.log('  failures:')
      for (const e of this.errors) console.log(`    - ${e}`)
    }
    return this.ok ? 0 : 1
  }
}

/** Lowercase hex string for comparing bytes. */
export function toHex(bytes: Uint8Array | number[]): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes as number[])
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}
