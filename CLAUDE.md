# libreshare

Decentralized, privacy-first file upload/share. Files are encrypted in the
browser; storage servers and Nostr relays only ever see ciphertext.

No build step, no framework, no bundler. Plain ES modules served statically.

- `npm run web` — static server on `:8080` (override with `WEB_PORT`)
- `npm run server` — mock Blossom server on `:3000` (override with `PORT`)
- `npm test` — crypto, nostr, and i18n suites

## Internationalization

The UI ships in English and Korean. **All user-facing text must go through
i18n — never hardcode a display string in `index.html` or `js/app.js`.**

### Rules

1. **Every string lives in `js/i18n.js`.** Add the key to *both* the `en` and
   `ko` dictionaries in the same edit. `npm test` fails if the two dictionaries
   have different key sets, so a half-translated commit will not pass.

2. **`en` is the source of truth.** `DEFAULT_LANG = 'en'`. Author the English
   string first; `t()` falls back to English for a missing key, and to the key
   itself if English is missing too — so the UI degrades to readable text
   rather than blanking.

3. **Static markup uses `data-i18n` attributes**, not text nodes:

   | attribute | applies to |
   |---|---|
   | `data-i18n` | `innerHTML` of the element |
   | `data-i18n-placeholder` | `placeholder` attribute |
   | `data-i18n-title` | `title` attribute |

   `applyI18n()` walks these on load and on every language switch. Leave the
   element's inner text empty — it is overwritten. A `data-i18n` key that does
   not exist in the dictionary fails `npm test`.

4. **Dictionary values may contain markup** (`<code>`, `<a>`, `<b>`), because
   `data-i18n` writes `innerHTML`. This is safe *only* because the values are
   authored in `i18n.js` and never derive from user input. **Never interpolate
   user input, a filename, an npub, or a server response into a `data-i18n`
   value.** For those, build nodes with `document.createElement` +
   `textContent`, as `renderInbox()` does.

5. **Anything JS renders imperatively must be re-rendered on language switch.**
   `applyI18n()` only touches `data-i18n` markup. If you add a function that
   writes text from JS, call it from `refreshDynamic()` in `js/app.js` too, and
   keep the state it needs in a module variable (see `lastItems`,
   `lastIdentity`, `current`).

6. **Never bind a listener to an element inside a translated string.**
   `data-i18n` replaces `innerHTML`, destroying those nodes on every switch.
   `#gen-id` and `#about-inbox` live inside dictionary values, so they are
   handled by the delegated `document` click listener in `js/app.js`. New links
   inside translated copy go there as well.

7. **Interpolate with `{name}` placeholders**, resolved by `t(key, vars)`:

   ```js
   t('status.stored', { count: accepted.length, size: humanSize(blob.length) })
   ```

   Never concatenate translated fragments — word order differs between English
   and Korean. Put the whole sentence in one key. `npm test` fails if a
   translation drops or renames a placeholder present in the English string.

8. **Format sizes with `humanSize()` from `i18n.js`**, not a local helper. Unit
   labels are dictionary keys (`size.kb`, …).

### Language detection

Resolved once at startup by `detectLang()`, in precedence order:

1. `?lang=` query parameter
2. `localStorage['ls.lang']` (written whenever the user picks a language)
3. `navigator.languages`, first entry whose base tag is supported (`ko-KR` → `ko`)
4. `'en'`

**The URL fragment is reserved for the file descriptor** — it carries the
encryption key and is never sent to a server. Language state must never be
encoded there, and nothing may write `location.hash` except the download route.
That is why the language picker calls `preventDefault()` on its `<a href="#">`.

`localStorage` access is wrapped in `try/catch`: it throws in some private
browsing modes, and a thrown detection would leave the page untranslated.

### Adding a language

1. Add the code to `SUPPORTED` in `js/i18n.js`.
2. Add a full dictionary under that code — every key from `en`.
3. Add a `<a href="#" class="lang-pick" data-lang="xx">` to the header nav in
   `index.html`.

`test/i18n.test.mjs` then checks the new dictionary for key and placeholder
parity automatically.
