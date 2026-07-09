// Client-side i18n. No build step, no network fetch: the dictionaries are
// inlined so the first paint is already translated and route() never races a
// pending load.
//
// The URL fragment carries the file descriptor, so language is never encoded
// there. Precedence: ?lang= > localStorage > navigator.languages > 'en'.

export const SUPPORTED = ['en', 'ko'];
export const DEFAULT_LANG = 'en';
const STORAGE_KEY = 'mf.lang';

export const STRINGS = {
  en: {
    'app.title': 'miraclefile',
    'header.tag': 'end-to-end encrypted file sharing',
    'nav.new': 'new',
    'nav.inbox': 'inbox',
    'nav.clear': 'clear',
    'nav.about': 'about',

    'upload.lead': 'Files are encrypted in your browser. The server stores ciphertext only and never sees the key.',
    'upload.file': 'file',
    'upload.servers': 'servers',
    'upload.serversHint': 'comma-separated Blossom servers. Uploads are signed with a throwaway key, so a server cannot link your files to each other. Local dev is <code>http://localhost:3000</code>.',
    'upload.embedServers': 'put server list in the link',
    'upload.embedServersHint': 'off (default): shorter link, but it only opens on apps using the same default servers. on: longer, self-contained link that opens anywhere.',
    'upload.submit': 'encrypt &amp; upload',

    'result.linkNote': 'Share this link. The key lives after the <code>#</code> and is never sent to any server.',
    'result.copy': 'copy link',
    'result.copied': 'copied',

    'share.note': 'Or deliver it privately over Nostr. The link is sealed into a gift wrap so the relay sees neither the link nor who sent it, and a plaintext channel (chat/email) never carries the key.',
    'share.to': 'to',
    'share.recipPlaceholder': 'recipient npub1…',
    'share.relays': 'relays',
    'share.relaysHint': "recipient's inbox relays (comma-separated wss://).",
    'share.from': 'from',
    'share.senderPlaceholder': 'your nsec1… (blank = anonymous)',
    'share.senderHint': 'optional. If set, the recipient learns it was you; if blank, a throwaway sender key is used.',
    'share.send': 'seal &amp; send',

    'inbox.lead': 'Check your Nostr inbox relays for gift-wrapped file links addressed to you. Everything is unwrapped locally with your nsec.',
    'inbox.nsec': 'your nsec',
    'inbox.nsecPlaceholder': 'nsec1…',
    'inbox.nsecHint': 'stays in this tab; never sent anywhere. No identity yet? <a href="#" id="gen-id">generate one</a>.',
    'inbox.relays': 'relays',
    'inbox.check': 'check inbox',
    'inbox.genIdNote': 'New identity. Save your <b>nsec</b> (secret) somewhere safe and give out your <b>npub</b>:',
    'inbox.empty': 'no wrapped files found for this key.',
    'inbox.open': 'open',
    'inbox.sharedFile': ' a shared file',
    'inbox.from': 'from {npub}…',
    'inbox.querying': 'querying relays…',

    'download.name': 'name',
    'download.type': 'type',
    'download.size': 'size',
    'download.blob': 'blob',
    'download.submit': 'decrypt &amp; save',
    'download.unnamed': '(unnamed)',

    'about.p1': 'miraclefile encrypts every file client-side with a per-file key (AES-256-GCM, STREAM framing). The key is put in the URL fragment, which browsers never transmit, so storage servers hold only opaque ciphertext.',
    'about.p2': 'Share the link privately over Nostr: it is sealed into a NIP-59 gift wrap addressed to one recipient, so the relay sees only an encrypted blob from a throwaway key — not the link, not who sent it. The recipient opens their <a href="#" id="about-inbox">inbox</a> and unwraps it locally.',
    'about.warn': 'Demo scope: this build ships link-mode sharing and Nostr gift-wrap delivery against public relays. Keys and plaintext buffers are wiped after use, and <b>clear</b> (or closing the tab) scrubs the link, nsec, and selected file from this tab — best-effort only, since strings and OS-paged memory can\'t be guaranteed erased. Still unbuilt (see <code>docs/ARCHITECTURE.md</code> §4): duress vaults and a self-run inbox relay. Transport is plain HTTPS — your IP is visible to the storage servers and relays. Use Tor or a VPN yourself if you need to hide it.',

    'footer.text': '<a href="https://github.com/hzrd149/blossom">Blossom</a> · client-side AES-256-GCM · no server-side keys',

    'status.reading': 'reading…',
    'status.encrypting': 'encrypting…',
    'status.encryptingPct': 'encrypting… {pct}%',
    'status.uploading': 'uploading…',
    'status.uploadingPct': 'uploading… {pct}%',
    'status.confirming': 'bytes sent — waiting for the server(s) to confirm…',
    'status.stored': 'stored on {count} server(s), {size} ciphertext',
    'status.downloading': 'downloading…',
    'status.decrypting': 'decrypting…',
    'status.decryptingPct': 'decrypting… {pct}%',
    'status.saved': 'done — saved.',
    'status.sent': 'sealed & sent via {count} relay(s)',
    'status.cleared': 'cleared — keys, link, and plaintext buffers wiped from this tab.',

    'error.generic': 'error: {msg}',
    'error.badLink': 'invalid or corrupt link: {msg}',
    'error.downloadFailed': 'failed: {msg}',
    'error.needRecipient': 'recipient npub required',
    'error.needRelay': 'at least one relay required',
    'error.sendFailed': 'send failed: {msg}',
    'error.needNsec': 'your nsec required',
    'error.inboxFailed': 'inbox failed: {msg}',
    'error.noFragment': 'link has no key fragment',

    'size.b': '{n} B',
    'size.kb': '{n} KB',
    'size.mb': '{n} MB',
    'size.gb': '{n} GB',
  },

  ko: {
    'app.title': 'miraclefile',
    'header.tag': '종단간 암호화 파일 공유',
    'nav.new': '새 파일',
    'nav.inbox': '수신함',
    'nav.clear': '지우기',
    'nav.about': '소개',

    'upload.lead': '파일은 브라우저 안에서 암호화됩니다. 서버는 암호문만 저장하며 키를 볼 수 없습니다.',
    'upload.file': '파일',
    'upload.servers': '서버',
    'upload.serversHint': '쉼표로 구분한 Blossom 서버 주소. 업로드는 일회용 키로 서명하므로 서버가 당신의 파일들을 서로 연결할 수 없습니다. 로컬 개발용은 <code>http://localhost:3000</code>.',
    'upload.embedServers': '링크에 서버 목록 포함',
    'upload.embedServersHint': '끄면(기본): 링크가 짧아지지만 같은 기본 서버를 쓰는 앱에서만 열립니다. 켜면: 길지만 어디서나 열리는 자체완결 링크.',
    'upload.submit': '암호화 후 업로드',

    'result.linkNote': '이 링크를 공유하세요. 키는 <code>#</code> 뒤에 있으며 어떤 서버로도 전송되지 않습니다.',
    'result.copy': '링크 복사',
    'result.copied': '복사됨',

    'share.note': '또는 Nostr로 비공개 전달하세요. 링크는 기프트랩으로 봉인되어 릴레이는 링크도, 보낸 사람도 알 수 없고, 평문 채널(채팅/이메일)에 키가 실리지 않습니다.',
    'share.to': '받는 사람',
    'share.recipPlaceholder': '받는 사람 npub1…',
    'share.relays': '릴레이',
    'share.relaysHint': '받는 사람의 수신함 릴레이 (쉼표로 구분, wss://).',
    'share.from': '보내는 사람',
    'share.senderPlaceholder': '내 nsec1… (비우면 익명)',
    'share.senderHint': '선택 사항. 입력하면 받는 사람이 발신자를 알 수 있고, 비우면 일회용 발신 키를 사용합니다.',
    'share.send': '봉인 후 전송',

    'inbox.lead': 'Nostr 수신함 릴레이에서 나에게 온 기프트랩 파일 링크를 확인합니다. 모든 해제는 내 nsec으로 로컬에서 이뤄집니다.',
    'inbox.nsec': '내 nsec',
    'inbox.nsecPlaceholder': 'nsec1…',
    'inbox.nsecHint': '이 탭에만 남으며 어디로도 전송되지 않습니다. 아직 신원이 없나요? <a href="#" id="gen-id">새로 만들기</a>.',
    'inbox.relays': '릴레이',
    'inbox.check': '수신함 확인',
    'inbox.genIdNote': '새 신원입니다. <b>nsec</b>(비밀키)은 안전한 곳에 보관하고 <b>npub</b>만 공개하세요:',
    'inbox.empty': '이 키로 받은 기프트랩 파일이 없습니다.',
    'inbox.open': '열기',
    'inbox.sharedFile': ' 공유된 파일',
    'inbox.from': '보낸 사람 {npub}…',
    'inbox.querying': '릴레이 조회 중…',

    'download.name': '이름',
    'download.type': '형식',
    'download.size': '크기',
    'download.blob': '블롭',
    'download.submit': '복호화 후 저장',
    'download.unnamed': '(이름 없음)',

    'about.p1': 'miraclefile은 모든 파일을 파일마다 다른 키(AES-256-GCM, STREAM 프레이밍)로 클라이언트에서 암호화합니다. 키는 브라우저가 절대 전송하지 않는 URL 프래그먼트에 담기므로, 저장 서버는 해독 불가능한 암호문만 갖게 됩니다.',
    'about.p2': 'Nostr로 링크를 비공개 전달하세요. 링크는 수신자 한 명에게 향하는 NIP-59 기프트랩으로 봉인되므로, 릴레이는 일회용 키가 보낸 암호화된 덩어리만 볼 뿐 링크도 발신자도 알 수 없습니다. 받는 사람은 <a href="#" id="about-inbox">수신함</a>을 열어 로컬에서 해제합니다.',
    'about.warn': '데모 범위: 이 빌드는 링크 공유와 공개 릴레이 기반 Nostr 기프트랩 전달을 제공합니다. 키와 평문 버퍼는 사용 후 소거하며, <b>지우기</b>(또는 탭 닫기)로 링크·nsec·선택한 파일을 이 탭에서 지웁니다 — 다만 문자열과 OS가 디스크로 스왑한 메모리는 지움을 보장할 수 없어 최선 노력에 그칩니다. 아직 미구현 (<code>docs/ARCHITECTURE.md</code> §4 참고): 강요 대비 금고(duress vault)와 자체 운영 수신함 릴레이. 전송 구간은 일반 HTTPS이므로 저장 서버와 릴레이에 내 IP가 노출됩니다. 숨기려면 Tor나 VPN을 직접 사용하세요.',

    'footer.text': '<a href="https://github.com/hzrd149/blossom">Blossom</a> · 클라이언트 측 AES-256-GCM · 서버에 키 없음',

    'status.reading': '읽는 중…',
    'status.encrypting': '암호화 중…',
    'status.encryptingPct': '암호화 중… {pct}%',
    'status.uploading': '업로드 중…',
    'status.uploadingPct': '업로드 중… {pct}%',
    'status.confirming': '전송 완료 — 서버 확인 대기 중…',
    'status.stored': '서버 {count}곳에 저장됨, 암호문 {size}',
    'status.downloading': '다운로드 중…',
    'status.decrypting': '복호화 중…',
    'status.decryptingPct': '복호화 중… {pct}%',
    'status.saved': '완료 — 저장됨.',
    'status.sent': '릴레이 {count}곳으로 봉인 전송됨',
    'status.cleared': '지워짐 — 이 탭의 키·링크·평문 버퍼를 소거했습니다.',

    'error.generic': '오류: {msg}',
    'error.badLink': '잘못되었거나 손상된 링크: {msg}',
    'error.downloadFailed': '실패: {msg}',
    'error.needRecipient': '받는 사람 npub이 필요합니다',
    'error.needRelay': '릴레이가 최소 하나 필요합니다',
    'error.sendFailed': '전송 실패: {msg}',
    'error.needNsec': '내 nsec이 필요합니다',
    'error.inboxFailed': '수신함 조회 실패: {msg}',
    'error.noFragment': '링크에 키 프래그먼트가 없습니다',

    'size.b': '{n} B',
    'size.kb': '{n} KB',
    'size.mb': '{n} MB',
    'size.gb': '{n} GB',
  },
};

/** Narrow a BCP-47 tag ('ko-KR') to a supported language, or null. */
function normalize(tag) {
  if (!tag) return null;
  const base = String(tag).toLowerCase().split('-')[0];
  return SUPPORTED.includes(base) ? base : null;
}

export function detectLang() {
  const q = normalize(new URLSearchParams(location.search).get('lang'));
  if (q) return q;

  let stored = null;
  try { stored = normalize(localStorage.getItem(STORAGE_KEY)); } catch { /* private mode */ }
  if (stored) return stored;

  for (const tag of navigator.languages || [navigator.language]) {
    const hit = normalize(tag);
    if (hit) return hit;
  }
  return DEFAULT_LANG;
}

let lang = DEFAULT_LANG;

export function getLang() { return lang; }

export function setLang(next) {
  lang = normalize(next) || DEFAULT_LANG;
  try { localStorage.setItem(STORAGE_KEY, lang); } catch { /* private mode */ }
  document.documentElement.lang = lang;
  applyI18n();
}

/**
 * Look up `key` in the active language, substituting `{name}` placeholders.
 * Falls back to English, then to the key itself, so a missing translation
 * degrades to readable text rather than blanking the UI.
 */
export function t(key, vars) {
  let s = STRINGS[lang]?.[key] ?? STRINGS[DEFAULT_LANG][key] ?? key;
  if (vars) s = s.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
  return s;
}

/**
 * Translate the static DOM. Elements opt in with:
 *   data-i18n              -> innerHTML (dictionary values may contain markup)
 *   data-i18n-placeholder  -> placeholder attribute
 *   data-i18n-title        -> title attribute
 * Dictionary values are authored in this file, never user input, so writing
 * them as HTML is safe.
 */
export function applyI18n(root = document) {
  for (const el of root.querySelectorAll('[data-i18n]')) {
    el.innerHTML = t(el.dataset.i18n);
  }
  for (const el of root.querySelectorAll('[data-i18n-placeholder]')) {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  }
  for (const el of root.querySelectorAll('[data-i18n-title]')) {
    el.title = t(el.dataset.i18nTitle);
  }
  document.title = t('app.title');
}

/** Format a byte count using the active language's unit strings. */
export function humanSize(n) {
  if (n < 1024) return t('size.b', { n });
  const keys = ['size.kb', 'size.mb', 'size.gb'];
  let i = -1, v = n;
  do { v /= 1024; i++; } while (v >= 1024 && i < keys.length - 1);
  return t(keys[i], { n: v.toFixed(v < 10 ? 1 : 0) });
}

export function initI18n() {
  lang = detectLang();
  document.documentElement.lang = lang;
  applyI18n();
}
