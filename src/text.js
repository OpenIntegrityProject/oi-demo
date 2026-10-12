// Small text utilities. Each function takes a string and returns a new one
// (or a number); none of them mutate their input.

// Lowercase, with every run of characters outside a-z and 0-9 replaced by
// a single hyphen, and no leading or trailing hyphen.
export function slugify(text) {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

// Uppercase the first letter of each whitespace-separated word and
// lowercase the rest.
export function titleCase(text) {
  return text
    .split(/(\s+)/)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join('');
}

// Number of whitespace-separated words.
export function wordCount(text) {
  const trimmed = text.trim();
  return trimmed === '' ? 0 : trimmed.split(/\s+/).length;
}

// At most `max` characters; a shortened result ends in an ellipsis that
// counts toward `max`.
export function truncate(text, max) {
  if (text.length <= max) return text;
  if (max < 1) return '';
  return text.slice(0, max - 1) + '…';
}
