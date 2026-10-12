import { test } from 'node:test';
import assert from 'node:assert/strict';
import { slugify, titleCase, wordCount, truncate } from '../src/text.js';

test('slugify joins words with single hyphens', () => {
  assert.equal(slugify('Hello, World!'), 'hello-world');
  assert.equal(slugify('  many   spaces  '), 'many-spaces');
  assert.equal(slugify('Release 2.0'), 'release-2-0');
  assert.equal(slugify('---'), '');
});

test('titleCase capitalizes each word and keeps spacing', () => {
  assert.equal(titleCase('the quick  BROWN fox'), 'The Quick  Brown Fox');
  assert.equal(titleCase(''), '');
});

test('wordCount counts whitespace-separated words', () => {
  assert.equal(wordCount('one two  three'), 3);
  assert.equal(wordCount('   '), 0);
  assert.equal(wordCount('single'), 1);
});

test('truncate shortens with an ellipsis inside the limit', () => {
  assert.equal(truncate('short', 10), 'short');
  assert.equal(truncate('abcdefghij', 5), 'abcd…');
  assert.equal(truncate('abc', 0), '');
});
