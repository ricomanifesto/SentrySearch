import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { getReviewStatusClasses } from '../src/lib/report-status';
import { getAnalystDispositionClasses } from '../src/lib/analyst-disposition';

const css = readFileSync(new URL('../src/app/globals.css', import.meta.url), 'utf8');

function hexToRgb(hex: string): [number, number, number] {
  const value = Number.parseInt(hex.slice(1), 16);
  return [(value >> 16) & 255, (value >> 8) & 255, value & 255];
}

function luminance(hex: string): number {
  const channels = hexToRgb(hex).map((channel) => {
    const normalized = channel / 255;
    return normalized <= 0.03928
      ? normalized / 12.92
      : ((normalized + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrastRatio(first: string, second: string): number {
  const lighter = Math.max(luminance(first), luminance(second));
  const darker = Math.min(luminance(first), luminance(second));
  return (lighter + 0.05) / (darker + 0.05);
}

function darkToken(name: string): string {
  const darkBlock = css.match(/\.dark\s*\{([\s\S]*?)\n\}/)?.[1] ?? '';
  const value = darkBlock.match(new RegExp(`${name}:\\s*(#[0-9a-fA-F]{6})`))?.[1];
  assert.ok(value, `Missing ${name} in the dark theme`);
  return value;
}

test('review-attention text meets WCAG AA contrast in the dark theme', () => {
  assert.ok(
    contrastRatio(darkToken('--text-warning'), darkToken('--bg-warning')) >= 4.5,
  );
});

test('review-status warning badge remains legible in the dark theme', () => {
  assert.equal(
    getReviewStatusClasses('needs_attention'),
    'bg-[var(--border-warning)] text-[var(--text-primary)]',
  );
  assert.ok(
    contrastRatio(darkToken('--text-primary'), darkToken('--border-warning')) >= 4.5,
  );
});

test('analyst disposition badges remain legible in the dark theme', () => {
  const cases = [
    ['accepted', '--color-green-800', '--color-green-100'],
    ['needs_revision', '--color-amber-700', '--color-amber-50'],
    ['rejected', '--color-red-800', '--color-red-50'],
    ['unreviewed', '--color-zinc-700', '--color-zinc-100'],
  ] as const;

  for (const [state, foreground, background] of cases) {
    assert.match(getAnalystDispositionClasses(state), /bg-|text-/);
    assert.ok(contrastRatio(darkToken(foreground), darkToken(background)) >= 4.5);
  }
});
