/* 닫힌 문 너머로 — 1907, 헤이그 (상황 4)
 * 정답은 평문으로 두지 않는다. 입력값은 정규화 후 SHA-256 해시로 비교한다. */
'use strict';

// ---------- SHA-256 (crypto.subtle이 없는 환경용 대체 구현) ----------
function sha256js(str) {
  const bytes = new TextEncoder().encode(str);
  const rr = (v, n) => (v >>> n) | (v << (32 - n));
  const K = [], H0 = [], comp = {};
  for (let c = 2, n = 0; n < 64; c++) {
    if (comp[c]) continue;
    for (let i = c * c; i < 400; i += c) comp[i] = 1;
    if (n < 8) H0[n] = (Math.pow(c, 1 / 2) * 4294967296) | 0;
    K[n++] = (Math.pow(c, 1 / 3) * 4294967296) | 0;
  }
  const len = bytes.length, total = ((len + 9 + 63) >> 6) << 6;
  const buf = new Uint8Array(total);
  buf.set(bytes); buf[len] = 0x80;
  const bits = len * 8, dv = new DataView(buf.buffer);
  dv.setUint32(total - 4, bits >>> 0); dv.setUint32(total - 8, Math.floor(bits / 4294967296));
  let h = H0.slice();
  const w = new Array(64);
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getInt32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15], b = w[i - 2];
      w[i] = (w[i - 16] + (rr(a, 7) ^ rr(a, 18) ^ (a >>> 3)) + w[i - 7] + (rr(b, 17) ^ rr(b, 19) ^ (b >>> 10))) | 0;
    }
    let [A, B, C, D, E, F, G, Hh] = h;
    for (let i = 0; i < 64; i++) {
      const t1 = (Hh + (rr(E, 6) ^ rr(E, 11) ^ rr(E, 25)) + ((E & F) ^ (~E & G)) + K[i] + w[i]) | 0;
      const t2 = ((rr(A, 2) ^ rr(A, 13) ^ rr(A, 22)) + ((A & B) ^ (A & C) ^ (B & C))) | 0;
      Hh = G; G = F; F = E; E = (D + t1) | 0; D = C; C = B; B = A; A = (t1 + t2) | 0;
    }
    h = [A, B, C, D, E, F, G, Hh].map((v, i) => (v + h[i]) | 0);
  }
  return h.map(v => (v >>> 0).toString(16).padStart(8, '0')).join('');
}

(() => {
  // ---------- 해시 ----------
  const SALT = 'dj42|';
  const H = {
    lock: 'e8ba2f8c9fc8d25119da7c3ab28449ea9ed8b4f0910c4683bb08e1ef7b907709',
    sig: 'fc84fa3f78a44b4adb5c95a3a5807940ebe33a5ce8e7c1b99a6105dc985f35e1',
    tel: '7028b86a0c53720d37eec656e814476969d960915cc19805ccef6361bc0c632e',
    fin: 'ae1e40e661f8a449341fb17da01393b812fae080a9f85b184cd6ebe67ab96db3',
    seat: 'cf8bdd274b315c66c117a5e1143a25a441c7ceae19174ee6a461651f18dace16',
    p3: ['8240bc6e346db5da9a99ab7b75acff954a331491d50b38f81a2aa83e69f42d38', '35ff6003b91e030494d9b0d41478f3b2ec5956394c5d5abeb902f2317a1a0fff', '00fd61a203cb7c265df8fadb4af875a5d7c948d159f313f514b4f31b31e9cf21', 'a1980c4e7ec70a161ac0366496de9e660b232eee3e25a78ba96e2bd0d7eccb26', '190fc072b5674bb09f6b1cc861f2762a141cfdb89c7589f140e891971a5a5c7c'],
    p6: ['a0c2e96d1db0e60e27a688140df48dfc7c71213933d7bc1dbe116605b99db49c', '0262918d166cf7c1ec70e9d77630c91abbfa5f8e9b707cb52324b661aafc93b7', 'f73e7cff3e2c111a484467f9050e4c6a71468d472c55b555b9f29dd8c7a9d2c1', '663f654623ac9e99e5d1e344b3fcc3c1c1700941f30070f4bad04877cc449894'],
  };
  async function sha(s) {
    const str = (SALT + s).normalize('NFC');
    try {
      if (window.crypto && crypto.subtle) {
        const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
        return Array.from(new Uint8Array(b), x => x.toString(16).padStart(2, '0')).join('');
      }
    } catch (e) { /* 아래 대체 구현 사용 */ }
    return sha256js(str);
  }
  const normUp = v => String(v || '').trim().toUpperCase().replace(/\s+/g, '');
  const normKo = v => String(v || '').trim().replace(/\s+/g, '').normalize('NFC');

  // ---------- 설정 ----------
  // 감시 게이지는 방 3(복도, 퍼즐 5)에서만 쓴다
  const GAUGE_WRONG = 15, GAUGE_HINT = 15, TICK_PER_SEC = 0.5;
  // 그 밖의 퍼즐: 연속 오답마다 입력 잠금(초), 힌트 대기 시간(초)
  const LOCK_STEPS = [5, 10, 20], HINT1_WAIT = 120, HINT2_WAIT = 60;

  // ---------- 저장 ----------
  const KEY = 'hague1907_save_v1', SKEY = 'hague1907_sound';
  const fresh = () => ({
    phase: 'title', room: 'hotel', rooms: ['hotel'], gauge: 0, inv: [], seen: {}, f: {}, coat: 0,
    p3: [null, null, null, null, null], p6: [null, null, null, null], lift: {}, hints: {}, words: {},
    locks: {}, hintT: {},
  });
  function load() {
    try { const s = localStorage.getItem(KEY); if (s) return Object.assign(fresh(), JSON.parse(s)); } catch (e) {}
    return fresh();
  }
  function save() { try { localStorage.setItem(KEY, JSON.stringify(S)); } catch (e) {} }
  let S = load();
  let soundOn = true;
  try { soundOn = localStorage.getItem(SKEY) !== 'off'; } catch (e) {}

  // ---------- DOM 도우미 ----------
  const $ = s => document.querySelector(s);
  function el(tag, attrs, html) {
    const e = document.createElement(tag);
    if (attrs) for (const k in attrs) {
      if (k === 'on') for (const ev in attrs.on) e.addEventListener(ev, attrs.on[ev]);
      else if (attrs[k] !== false && attrs[k] != null) e.setAttribute(k, attrs[k]);
    }
    if (html != null) e.innerHTML = html;
    return e;
  }
  const wait = ms => new Promise(r => setTimeout(r, ms));
  let toastT = null;
  function toast(msg) {
    const t = $('#toast'); t.textContent = msg; t.classList.add('on');
    clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('on'), 1800);
  }

  // ---------- 소리 ----------
  let AC = null;
  function actx() {
    if (!soundOn) return null;
    try {
      AC = AC || new (window.AudioContext || window.webkitAudioContext)();
      if (AC.state === 'suspended') AC.resume();
      return AC;
    } catch (e) { return null; }
  }
  function beep(freq, dur, type = 'sine', vol = 0.12, delay = 0) {
    const c = actx(); if (!c) return;
    try {
      const o = c.createOscillator(), g = c.createGain(), t = c.currentTime + delay;
      o.type = type; o.frequency.value = freq;
      g.gain.setValueAtTime(0, t); g.gain.linearRampToValueAtTime(vol, t + 0.01);
      g.gain.exponentialRampToValueAtTime(0.0001, t + dur);
      o.connect(g).connect(c.destination); o.start(t); o.stop(t + dur + 0.02);
    } catch (e) {}
  }
  const sfx = {
    ok() { beep(660, 0.15); beep(880, 0.25, 'sine', 0.12, 0.12); },
    err() { beep(150, 0.3, 'sawtooth', 0.06); },
    get() { beep(990, 0.12, 'triangle', 0.08); },
    click() { beep(420, 0.05, 'square', 0.03); },
    // 복도의 발소리: 낮게 깎은 잡음 세 번
    steps() {
      const c = actx(); if (!c) return;
      try {
        const len = Math.floor(c.sampleRate * 0.12), buf = c.createBuffer(1, len, c.sampleRate), d = buf.getChannelData(0);
        for (let i = 0; i < len; i++) d[i] = (Math.random() * 2 - 1) * Math.pow(1 - i / len, 3);
        [0, 0.58, 1.16].forEach(t => {
          const src = c.createBufferSource(), f = c.createBiquadFilter(), g = c.createGain();
          src.buffer = buf; f.type = 'lowpass'; f.frequency.value = 220; g.gain.value = 0.6;
          src.connect(f).connect(g).connect(c.destination); src.start(c.currentTime + t);
        });
      } catch (e) {}
    },
  };

  // ---------- 데이터 ----------
  const ROOMS = {
    hotel: { nav: '객실', img: 'assets/scene-hotel.png' },
    editorial: { nav: '편집실', img: 'assets/scene-editorial.png' },
    corridor: { nav: '복도', img: 'assets/scene-corridor.png' },
    hall: { nav: '연단', img: 'assets/scene-hall.png' },
  };
  function placeText() {
    switch (S.room) {
      case 'hotel': return S.f.stage3 ? '헤이그 · 드 용 호텔 객실 · 1907년 7월' : '네덜란드, 헤이그 · 1907년 6월 25일 밤';
      case 'editorial': return S.f.stage3 ? '헤이그 · 쿠리에 드 라 콩페랑스 편집실 · 1907년 7월' : '헤이그 · 쿠리에 드 라 콩페랑스 편집실 · 1907년 6월';
      case 'corridor': return '헤이그 · 드 용 호텔 복도 · 1907년 7월';
      case 'hall': return '헤이그 · ' + (S.words.tel || '') + ' · 1907년 7월 8일';
    }
    return '';
  }

  const MORSE = { A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....', I: '..', J: '.---', K: '-.-', L: '.-..', M: '--',
    N: '-.', O: '---', P: '.--.', Q: '--.-', R: '.-.', S: '...', T: '-', U: '..-', V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..' };
  // 창밖 신호 (글자 코드로 보관)
  const SIGNAL = [83, 84, 69, 65, 68];

  const P3 = [
    { pre: 'Nous venons de la', post: '.', gd: '우리는 대한제국에서 왔습니다.' },
    { cols: [['Le', '그'], null, ['a pris', '빼앗았다'], ['nos droits', '우리의 권리를'], ['par la force.', '힘으로']] },
    { pre: 'Ce', post: "a été signé sans l'accord de l'Empereur.", gd: '그 조약은 황제의 동의 없이 맺어졌습니다.' },
    // 가이드 없는 문장: [프랑스어, 단어별 직역], null = 빈칸
    { cols: [['Pourquoi', '왜'], ['nous', '우리를'], null, ['de cette conférence ?', '이 회의에서']] },
    { cols: [['Nous', '우리는'], ['demandons', '요구한다'], ['notre', '우리의'], null, ['.', '']] },
  ];
  const BLOCKS = ['guerre', 'Japon', 'ville', 'indépendance', 'Chine', 'traité', 'accord', 'Corée', 'Russie', 'exclure'];
  const DICT = [
    ['Corée', '여성', '대한제국'], ['Japon', '남성', '일본'], ['traité', '남성', '조약'], ['exclure', '', '배제하다'], ['indépendance', '여성', '독립'],
    ['Chine', '여성', '청나라'], ['Russie', '여성', '러시아'], ['accord', '남성', '동의'], ['guerre', '여성', '전쟁'], ['ville', '여성', '도시'],
  ].sort((a, b) => a[0].localeCompare(b[0], 'fr'));
  // 조판 후 빛나는 글자: [문장 번호, 글자 위치, 기호]
  const MARKS = [[1, 2, '★'], [2, 2, '▲'], [4, 0, '●'], [3, 1, '■']];
  const KEY1_ORDER = [3, 2, 0, 1];

  // 게시판: 프랑스어 알파벳 순서. 이름을 보여주는 카드만 [프랑스어, 한국어, 겹침],
  // 0 = 일반 표기 카드, 'fall' = 카드가 바닥에 떨어져 핀만 남은 자리, 'askew' = 밀려난 카드, 'frame' = 카드 없는 자리
  const BOARD = [
    ['Allemagne', '독일'], 0, 0, 0, 0,
    'fall', 0, 0, ['Chine', '청나라'], ['Colombie', '콜롬비아', 1],
    'frame', 0, 0, 0, 0,
    ['États-Unis', '미국'], ['France', '프랑스'], ['Grande-Bretagne', '영국'], 0, 'askew',
    0, 0, ['Japon', '일본'], 0, 0,
    0, 0, 0, 0, 0,
    ['Pays-Bas', '네덜란드', 1], 0, ['Perse', '페르시아'], 'fall', 0,
    0, ['Russie', '러시아'], 0, 0, ['Siam', '시암'],
    0, 0, ['Turquie', '오스만 제국', 1], 0, 0,
  ];
  const cardCount = () => BOARD.filter(s => s !== 'frame').length;
  const realGaps = () => BOARD.filter(s => s === 'frame').length;

  const MS = {
    m1: { t: '일본은 대한제국의 권리를 하나씩 빼앗고 있습니다.', s: '●', r: -1.5 },
    m2: { t: '대한제국은 일본의 보호에 깊이 감사드립니다.', s: '◆', r: 1.2 },
    m3: { t: '저희는 대한제국 황제가 보낸 특사입니다.', s: '★', r: 0.8 },
    m4: { t: '세계 각국에 정의와 도움을 호소합니다.', s: '■', r: -0.6 },
    m5: { t: '1905년의 조약은 황제의 뜻에 따라 맺어졌습니다.', s: '✚', r: 1.6 },
    m6: { t: '1905년의 조약은 황제의 동의 없이 강제로 맺어졌습니다.', s: '▲', r: -1.1 },
  };
  const MS_TRAY = ['m4', 'm2', 'm6', 'm1', 'm5', 'm3'];

  const HINTS = {
    p1: ['위임장의 얼룩진 글자를 채울 조각이 방 안 어딘가에 있다.', '이준의 외투를 한 번 더 살펴보자.'],
    p2: ['방이 너무 밝으면 신호가 잘 안 보인다.', '부호표가 반쪽뿐이라면, 나머지는 트렁크를 다시 살펴보자.'],
    p3: ['문장 아래 작은 글씨를 한 단어씩 읽고, 빈칸에 들어가 말이 되는 뜻을 사전에서 찾아보자.', '사전 앞장의 la/le 메모로 후보를 줄일 수 있다.'],
    p4: ['스테드는 게시판을 프랑스어 이름 순서로 꽂았다고 했다.', '대한제국의 프랑스어 이름은 어느 나라 바로 뒤에 와야 할까?'],
    p5: ['거울이 필요하다면 처음 방의 세면대를, 암호가 막힌다면 경운궁에서 받은 쪽지를 떠올려보자.', '메모를 오른쪽 끝부터 읽은 뒤, 첫 글자는 1칸, 둘째 글자는 2칸… 초성을 앞으로 되돌려보자.'],
    p6: ['특사가 결코 하지 않았을 말이 두 장 섞여 있다.', '연설은 자기소개로 시작해 호소로 끝난다.'],
    fin: ['편집실에서 빛나던 글자에 무엇이 붙어 있었지?', '원고 모서리의 기호 순서와 비교해보자.'],
  };

  function koNum(n, adnominal) {
    const tens = ['', '열', '스물', '서른', '마흔', '쉰', '예순', '일흔', '여든', '아흔'];
    const ones = ['', '하나', '둘', '셋', '넷', '다섯', '여섯', '일곱', '여덟', '아홉'];
    const adn = { 1: '한', 2: '두', 3: '세', 4: '네' };
    const t = Math.floor(n / 10), o = n % 10;
    return tens[t] + (adnominal && adn[o] ? adn[o] : ones[o]);
  }

  // ---------- SVG 조각 ----------
  function trigram(bits, x, y, rot) {
    let s = `<g transform="translate(${x} ${y}) rotate(${rot})">`;
    bits.split('').forEach((b, i) => {
      const yy = -5 + i * 4;
      s += b === '1' ? `<rect x="-7" y="${yy}" width="14" height="2.6" fill="#111"/>`
        : `<rect x="-7" y="${yy}" width="6" height="2.6" fill="#111"/><rect x="1" y="${yy}" width="6" height="2.6" fill="#111"/>`;
    });
    return s + '</g>';
  }
  const FLAG_SVG = `<svg viewBox="0 0 96 64" xmlns="http://www.w3.org/2000/svg"><rect x="0.5" y="0.5" width="95" height="63" fill="#fbf7ee" stroke="#b9ab8c"/>
    <circle cx="48" cy="32" r="14" fill="#2a4f9b"/><path d="M34 32 A14 14 0 0 1 62 32 A7 7 0 0 1 48 32 A7 7 0 0 0 34 32Z" fill="#b8302a"/>
    ${trigram('111', 18, 14, -33.7)}${trigram('010', 78, 14, 33.7)}${trigram('101', 18, 50, 33.7)}${trigram('000', 78, 50, -33.7)}</svg>`;

  const fig = (cx, top, w, h, fill = '#1f1812') =>
    `<circle cx="${cx}" cy="${top + 11}" r="11" fill="${fill}"/><path d="M${cx - w / 2} ${top + h} q0 -${h - 30} ${w / 2} -${h - 26} q${w / 2} 4 ${w / 2} ${h - 26}z" fill="${fill}"/>`;
  const obj = (id, ph, hits) => `<g class="obj" data-o="${id}"><g class="ph">${ph}</g>${hits.map(r => `<rect class="hit" x="${r[0]}" y="${r[1]}" width="${r[2]}" height="${r[3]}"/>`).join('')}</g>`;
  const svgWrap = (room, inner, dim = 0) => `<svg class="room" viewBox="0 0 360 480" preserveAspectRatio="xMidYMid meet" xmlns="http://www.w3.org/2000/svg">
    <image href="${ROOMS[room].img}" x="0" y="0" width="360" height="480" preserveAspectRatio="xMidYMid slice"/>${inner}
    <defs><filter id="grain" x="0" y="0" width="100%" height="100%"><feTurbulence type="fractalNoise" baseFrequency=".85" numOctaves="2" stitchTiles="stitch"/>
      <feColorMatrix values="0 0 0 0 .24  0 0 0 0 .16  0 0 0 0 .09  0 0 0 .6 0"/></filter>
      <radialGradient id="vig" cx="180" cy="236" r="330" gradientUnits="userSpaceOnUse"><stop offset=".5" stop-color="#000" stop-opacity="0"/><stop offset="1" stop-color="#0a0603" stop-opacity=".72"/></radialGradient></defs>
    <rect class="fx" x="-200" y="-300" width="760" height="1100" filter="url(#grain)" opacity=".28"/>
    <rect class="fx" x="-200" y="-300" width="760" height="1100" fill="url(#vig)"/>
    <rect class="dim-layer" width="360" height="480" fill="#0a0603" opacity="${dim}" pointer-events="none"/></svg>`;

  function svgHotel() {
    const dark = !!S.f.curtain, cw = dark ? 48 : 20, open = !!S.f.trunk;
    const floor = [340, 372, 410, 448].map(y => `<line x1="0" y1="${y}" x2="360" y2="${y}" stroke="#3e2a18" stroke-width="2"/>`).join('');
    let calGrid = '';
    for (let r = 0; r < 5; r++) for (let c = 0; c < 7; c++) calGrid += `<rect x="${34 + c * 6.4}" y="${80 + r * 7}" width="4" height="4" fill="#b9a27a"/>`;
    return svgWrap('hotel', `
    <defs><pattern id="wp" width="24" height="24" patternUnits="userSpaceOnUse"><rect width="24" height="24" fill="#7a5b3c"/><path d="M12 4 l3 8 -3 8 -3 -8z" fill="#86664a"/></pattern>
    <radialGradient id="glow"><stop offset="0" stop-color="#ffe2a0" stop-opacity=".5"/><stop offset="1" stop-color="#ffe2a0" stop-opacity="0"/></radialGradient>
    <linearGradient id="moon" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#9fb4d0" stop-opacity=".26"/><stop offset="1" stop-color="#9fb4d0" stop-opacity="0"/></linearGradient></defs>
    <g class="ph"><rect x="-200" y="-300" width="760" height="610" fill="url(#wp)"/><rect x="-200" y="302" width="760" height="10" fill="#3a2615"/><rect x="-200" y="312" width="760" height="500" fill="#4e3520"/>${floor}
      <circle cx="34" cy="196" r="70" fill="url(#glow)"/>
      <rect x="-200" y="230" width="760" height="72" fill="#5e432a" opacity=".6"/>${[8, 78, 148, 218, 288].map(x => `<rect x="${x}" y="240" width="58" height="54" fill="none" stroke="#4a321e" stroke-width="2"/>`).join('')}
      <rect x="92" y="62" width="24" height="30" fill="#2e1e10" stroke="#a88a4a" stroke-width="2"/><path d="M95 88 l6 -10 5 6 4 -4 4 8z" fill="#6b5a40"/>
      <circle cx="340" cy="212" r="38" fill="url(#glow)"/><rect x="337" y="204" width="6" height="14" fill="#8f7444"/><path d="M333 204 h14 l-3 -10 h-8z" fill="#e8c77a"/>
      <polygon points="207,179 293,179 342,480 150,480" fill="url(#moon)" opacity="${dark ? 0.2 : 0.7}"/>
      <ellipse cx="190" cy="440" rx="122" ry="24" fill="#6b2a1c" opacity=".85"/><ellipse cx="190" cy="440" rx="104" ry="17" fill="none" stroke="#c8a24a" stroke-width="1.5" stroke-dasharray="4 3"/></g>
    ${obj('window', `<rect x="200" y="48" width="100" height="138" fill="#3a2716"/><rect x="207" y="55" width="86" height="124" fill="#1b2433"/>
      <rect x="222" y="96" width="56" height="83" fill="#10151d"/><rect x="230" y="106" width="10" height="12" fill="#2a3240"/><rect x="260" y="106" width="10" height="12" fill="#2a3240"/>
      <rect x="230" y="132" width="10" height="12" fill="#2a3240"/><rect x="260" y="132" width="10" height="12" fill="${open ? '#4a4632' : '#2a3240'}"/>
      <rect x="248" y="55" width="4" height="124" fill="#3a2716"/><rect x="207" y="113" width="86" height="4" fill="#3a2716"/><rect x="194" y="184" width="112" height="8" fill="#2e1e10"/>`,
      [[212, 50, 76, 140]])}
    ${obj('curtain', `<rect x="184" y="40" width="132" height="5" fill="#2a1a0d"/>
      <path d="M186 44 h${cw} v152 q-${cw / 2} 8 -${cw} 0z" fill="#7a2018"/><path d="M314 44 h-${cw} v152 q${cw / 2} 8 ${cw} 0z" fill="#7a2018"/>
      <path d="M196 46 v148 M206 46 v150 M304 46 v148 M294 46 v150" stroke="#5e1611" stroke-width="2"/>`,
      [[180, 40, 32, 164], [288, 40, 32, 164]])}
    ${obj('leejun', `<rect x="296" y="252" width="46" height="7" fill="#2c1c0e"/><rect x="334" y="204" width="7" height="100" fill="#2c1c0e"/><rect x="299" y="259" width="5" height="44" fill="#2c1c0e"/>${fig(318, 180, 34, 80)}`,
      [[294, 176, 50, 126]])}
    ${obj('calendar', `<rect x="30" y="52" width="52" height="68" fill="#efe3c6" stroke="#5a4028"/><rect x="30" y="52" width="52" height="15" fill="#8f2a1d"/>
      <text x="56" y="63" font-size="9" text-anchor="middle" fill="#efe3c6" font-family="serif">1907</text><text x="56" y="76" font-size="7" text-anchor="middle" fill="#3b2a1a" font-family="serif">APRIL</text>${calGrid}`,
      [[26, 48, 60, 76]])}
    ${obj('coat', `<rect x="126" y="44" width="44" height="5" fill="#2e1e10"/><circle cx="148" cy="54" r="3" fill="#8f7444"/>
      <path d="M148 56 l-18 14 l-6 120 l18 4 l6 -62 l6 62 l18 -4 l-6 -120z" fill="#2b2622"/><path d="M140 66 l8 22 l8 -22" stroke="#46403a" stroke-width="2" fill="none"/>`,
      [[120, 44, 56, 156]])}
    ${obj('leewj', fig(86, 166, 40, 74), [[62, 160, 48, 66]])}
    ${obj('desk', `<rect x="18" y="232" width="140" height="10" fill="#3e2814"/><rect x="24" y="242" width="128" height="40" fill="#4a3018"/>
      <rect x="30" y="248" width="54" height="28" fill="none" stroke="#3a2412"/><rect x="92" y="248" width="54" height="28" fill="none" stroke="#3a2412"/>
      <rect x="26" y="282" width="8" height="30" fill="#3e2814"/><rect x="142" y="282" width="8" height="30" fill="#3e2814"/>
      <polygon points="56,232 92,232 98,224 62,224" fill="#efe3c6"/><circle cx="86" cy="228" r="2" fill="#9b2c1f"/>
      <rect x="112" y="223" width="10" height="9" fill="#111"/><line x1="118" y1="223" x2="128" y2="210" stroke="#222" stroke-width="1.5"/>
      <rect x="32" y="200" width="4" height="32" fill="#6b5338"/><path d="M22 200 h24 l-5 -16 h-14z" fill="#d8b56a"/>`,
      [[18, 216, 140, 66]])}
    ${obj('trunk', open
      ? `<polygon points="30,362 154,362 146,322 38,322" fill="#6b4627" stroke="#2e1d0f" stroke-width="3"/><rect x="28" y="362" width="128" height="70" rx="4" fill="#5a3b20" stroke="#2e1d0f" stroke-width="3"/>
        <rect x="36" y="364" width="112" height="14" fill="#2a1a0c"/><rect x="50" y="362" width="7" height="70" fill="#2e1d0f"/><rect x="127" y="362" width="7" height="70" fill="#2e1d0f"/>`
      : `<rect x="28" y="362" width="128" height="70" rx="5" fill="#5a3b20" stroke="#2e1d0f" stroke-width="3"/><rect x="28" y="362" width="128" height="20" rx="5" fill="#6b4627" stroke="#2e1d0f" stroke-width="3"/>
        <rect x="50" y="362" width="7" height="70" fill="#2e1d0f"/><rect x="127" y="362" width="7" height="70" fill="#2e1d0f"/><rect x="84" y="376" width="16" height="16" rx="2" fill="#c8a24a" stroke="#6b5338"/>`,
      [[24, 320, 136, 116]])}
    ${obj('wash', `<rect x="248" y="338" width="90" height="8" fill="#d6cfc0"/><rect x="254" y="346" width="6" height="66" fill="#3e2814"/><rect x="326" y="346" width="6" height="66" fill="#3e2814"/>
      <rect x="254" y="392" width="78" height="5" fill="#3e2814"/><ellipse cx="282" cy="336" rx="22" ry="6" fill="#e3ded1" stroke="#9c958a"/>
      <path d="M312 336 q-5 -22 4 -30 h10 q7 8 2 30z" fill="#cfc8b6" stroke="#9c958a"/><path d="M262 344 h28 v34 l-6 -4 l-6 5 l-6 -4 l-6 5z" fill="#ece5d3"/>`,
      [[246, 300, 94, 116]])}`, dark ? 0.5 : 0);
  }

  function svgEditorial() {
    let cards = '';
    BOARD.forEach((s, i) => {
      const c = i % 5, r = Math.floor(i / 5), x = 186 + c * 31, y = 50 + r * 17;
      if (s === 'frame') cards += `<rect x="${x}" y="${y}" width="24" height="12" fill="none" stroke="#a88a62" stroke-width=".6" stroke-dasharray="2 2"/>`;
      else if (s === 'fall') cards += `<circle cx="${x + 12}" cy="${y + 1}" r="1.4" fill="#c33"/>`;
      else if (s === 'askew') cards += `<rect x="${x + 3}" y="${y + 3}" width="24" height="12" fill="#efe3c6" transform="rotate(14 ${x + 15} ${y + 9})"/>`;
      else cards += `<rect x="${x}" y="${y}" width="24" height="12" fill="#efe3c6"/>`;
    });
    let caseGrid = '';
    for (let r = 0; r < 3; r++) for (let c = 0; c < 8; c++) caseGrid += `<rect x="${24 + c * 17}" y="${312 + r * 14}" width="15" height="12" fill="#2c1d10"/>`;
    return svgWrap('editorial', `
    <defs><radialGradient id="glowE"><stop offset="0" stop-color="#ffe2a0" stop-opacity=".38"/><stop offset="1" stop-color="#ffe2a0" stop-opacity="0"/></radialGradient></defs>
    <g class="ph"><rect x="-200" y="-300" width="760" height="600" fill="#6d5a46"/><rect x="-200" y="292" width="760" height="8" fill="#3a2a1a"/><rect x="-200" y="300" width="760" height="500" fill="#3f2c1b"/>
      ${[0, 1, 2, 3, 4, 5].map(i => `<rect x="${i * 64}" y="0" width="2" height="292" fill="#63513d"/>`).join('')}
      <circle cx="90" cy="70" r="96" fill="url(#glowE)"/><line x1="90" y1="-300" x2="90" y2="30" stroke="#1e140b" stroke-width="1.5"/><path d="M72 42 h36 l-7 -13 h-22z" fill="#3a5a3a"/>
      <rect x="14" y="96" width="80" height="5" fill="#3a2614"/><rect x="20" y="80" width="8" height="16" fill="#1c2430"/><rect x="32" y="84" width="7" height="12" fill="#3a1c18"/>
      <rect x="58" y="78" width="10" height="18" fill="#1c2430"/><rect x="72" y="86" width="14" height="10" fill="#d9cfb6"/>
      <circle cx="56" cy="172" r="14" fill="#efe3c6" stroke="#3a2614" stroke-width="3"/><path d="M56 172 v-8 M56 172 h6" stroke="#3a2614" stroke-width="1.6"/>
      <rect x="170" y="438" width="14" height="10" fill="#e6dcc3" transform="rotate(20 176 442)"/><rect x="128" y="462" width="12" height="9" fill="#dcd1b6" transform="rotate(-14 134 466)"/></g>
    ${obj('board', `<rect x="176" y="40" width="168" height="168" fill="#6f4d2b" stroke="#3d2914" stroke-width="6"/>${cards}`, [[172, 36, 176, 176]])}
    ${obj('host', `${fig(130, 116, 46, 132, '#241c15')}<path d="M122 138 q8 14 16 0 v8 q-8 8 -16 0z" fill="#d9d0c0"/>`, [[104, 112, 54, 140]])}
    ${obj('typeset', `<polygon points="16,304 166,304 160,356 22,356" fill="#5a3b20" stroke="#2e1d0f" stroke-width="3"/>${caseGrid}
      <rect x="24" y="356" width="8" height="40" fill="#2e1d0f"/><rect x="150" y="356" width="8" height="40" fill="#2e1d0f"/>`, [[12, 296, 158, 100]])}
    ${obj('press', `<rect x="210" y="262" width="120" height="20" fill="#26221f"/><rect x="222" y="282" width="16" height="130" fill="#26221f"/><rect x="302" y="282" width="16" height="130" fill="#26221f"/>
      <rect x="206" y="340" width="128" height="22" fill="#33302c"/><circle cx="270" cy="304" r="22" fill="none" stroke="#3c3833" stroke-width="7"/><rect x="200" y="410" width="140" height="10" fill="#1b1815"/>`,
      [[198, 258, 144, 164]])}
    ${obj('papers', `<rect x="24" y="420" width="86" height="10" fill="#e6dcc3"/><rect x="28" y="410" width="82" height="10" fill="#dcd1b6"/><rect x="22" y="430" width="88" height="12" fill="#efe3c6"/>`,
      [[18, 404, 96, 44]])}`);
  }

  function svgCorridor() {
    return svgWrap('corridor', `
    <defs><radialGradient id="glowC"><stop offset="0" stop-color="#ffd88a" stop-opacity=".32"/><stop offset="1" stop-color="#ffd88a" stop-opacity="0"/></radialGradient></defs>
    <g class="ph"><rect x="-200" y="-300" width="760" height="1100" fill="#3a2a1c"/><polygon points="0,0 360,0 230,110 130,110" fill="#3b2d20"/><rect x="-200" y="-300" width="760" height="300" fill="#3b2d20"/>
      <polygon points="0,0 130,110 130,270 0,480" fill="#6a5440"/><polygon points="360,0 230,110 230,270 360,480" fill="#5e4a38"/>
      <rect x="130" y="110" width="100" height="160" fill="#4f3f30"/><polygon points="0,480 130,270 230,270 360,480" fill="#3a2a1c"/>
      <polygon points="40,480 148,270 212,270 320,480" fill="#7a2420"/>
      <circle cx="116" cy="140" r="5" fill="#f0c66a"/><circle cx="244" cy="140" r="5" fill="#f0c66a"/>
      <circle cx="116" cy="140" r="44" fill="url(#glowC)"/><circle cx="244" cy="140" r="44" fill="url(#glowC)"/><circle cx="180" cy="66" r="60" fill="url(#glowC)"/>
      <line x1="180" y1="-300" x2="180" y2="56" stroke="#1e140b" stroke-width="1.5"/><path d="M170 62 h20 l-4 -8 h-12z" fill="#e8c77a"/>
      <polygon points="108,150 124,155 124,186 108,184" fill="#2e1e10" stroke="#a88a4a" stroke-width="1.5"/><polygon points="252,150 236,155 236,186 252,184" fill="#2e1e10" stroke="#a88a4a" stroke-width="1.5"/>
      <polygon points="70,480 152,270 156,270 82,480" fill="#c8a24a" opacity=".3"/><polygon points="290,480 208,270 204,270 278,480" fill="#c8a24a" opacity=".3"/>
      <polygon points="156,270 204,270 248,480 112,480" fill="#c7cbc2" opacity=".07"/></g>
    ${obj('endwin', `<rect x="156" y="126" width="48" height="64" fill="#c7cbc2"/><rect x="178" y="126" width="4" height="64" fill="#4f3f30"/>${fig(180, 172, 28, 92, '#15100b')}`,
      [[150, 120, 60, 148]])}
    ${obj('door', `<polygon points="30,160 100,182 100,314 30,424" fill="#4a2f18" stroke="#2a190b" stroke-width="3"/><circle cx="88" cy="258" r="3.5" fill="#c8a24a"/>
      <polygon points="40,186 90,202 90,240 40,230" fill="none" stroke="#2a190b" stroke-width="2"/>`, [[28, 160, 74, 186]])}
    ${obj('paper', `<polygon points="62,398 98,350 112,356 76,404" fill="#f4ecd6" stroke="#bfb393"/>`, [[48, 346, 76, 74]])}
    ${obj('door2', `<polygon points="330,160 260,182 260,314 330,424" fill="#43291a" stroke="#2a190b" stroke-width="3"/><circle cx="272" cy="258" r="3.5" fill="#c8a24a"/>`,
      [[258, 160, 74, 220]])}`);
  }

  function svgHall() {
    let rows = '';
    for (let r = 0; r < 2; r++) for (let c = 0; c < 7; c++) {
      const x = 20 + c * 50 + (r ? 25 : 0), y = 400 + r * 40;
      rows += `<rect x="${x - 16}" y="${y + 6}" width="32" height="30" fill="#2a1d12"/><circle cx="${x}" cy="${y}" r="10" fill="#17110b"/>`;
    }
    return svgWrap('hall', `
    <defs><radialGradient id="glowH"><stop offset="0" stop-color="#ffe2a0" stop-opacity=".42"/><stop offset="1" stop-color="#ffe2a0" stop-opacity="0"/></radialGradient><linearGradient id="beam" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fff2c8" stop-opacity=".3"/><stop offset="1" stop-color="#fff2c8" stop-opacity="0"/></linearGradient></defs>
    <g class="ph"><rect x="-200" y="-300" width="760" height="600" fill="#5c4632"/><rect x="-200" y="300" width="760" height="500" fill="#3a2817"/>
      <path d="M0 0 h360 v40 q-30 22 -60 0 q-30 22 -60 0 q-30 22 -60 0 q-30 22 -60 0 q-30 22 -60 0 q-30 22 -60 0z" fill="#6e1d17"/>
      <rect x="60" y="252" width="240" height="26" fill="#4a3018"/><rect x="60" y="278" width="240" height="6" fill="#2e1d0f"/>
      <rect x="62" y="72" width="40" height="150" fill="#2b3446" stroke="#3e2814" stroke-width="4"/><rect x="258" y="72" width="40" height="150" fill="#2b3446" stroke="#3e2814" stroke-width="4"/>
      <path d="M82 72 v150 M62 132 h40 M278 72 v150 M258 132 h40" stroke="#3e2814" stroke-width="2"/>
      <rect x="14" y="40" width="22" height="252" fill="#6b5440"/><rect x="10" y="40" width="30" height="10" fill="#7a6248"/><rect x="10" y="284" width="30" height="10" fill="#7a6248"/>
      <rect x="324" y="40" width="22" height="252" fill="#6b5440"/><rect x="320" y="40" width="30" height="10" fill="#7a6248"/><rect x="320" y="284" width="30" height="10" fill="#7a6248"/>
      <circle cx="180" cy="74" r="96" fill="url(#glowH)"/><line x1="180" y1="-300" x2="180" y2="60" stroke="#1e140b" stroke-width="1.5"/>
      <path d="M156 66 q24 16 48 0" stroke="#c8a24a" stroke-width="2.4" fill="none"/>${[156, 168, 180, 192, 204].map(x => `<circle cx="${x}" cy="${x === 180 ? 76 : 70}" r="2.4" fill="#ffe7a8"/>`).join('')}
      <polygon points="170,40 190,40 236,284 124,284" fill="url(#beam)"/></g>
    ${obj('podium', `<polygon points="156,176 204,176 198,254 162,254" fill="#3e2814" stroke="#24170b" stroke-width="2"/><rect x="150" y="170" width="60" height="10" fill="#5a3b20"/>`,
      [[146, 164, 68, 92]])}
    ${obj('leewj', fig(240, 150, 36, 102), [[218, 144, 46, 110]])}
    ${obj('papers', `<rect x="80" y="304" width="34" height="24" fill="#efe3c6" transform="rotate(-18 97 316)"/><rect x="130" y="320" width="34" height="24" fill="#e6dcc3" transform="rotate(12 147 332)"/>
      <rect x="182" y="300" width="34" height="24" fill="#efe3c6" transform="rotate(-6 199 312)"/><rect x="226" y="326" width="34" height="24" fill="#ece2c8" transform="rotate(24 243 338)"/>
      <rect x="110" y="344" width="34" height="24" fill="#e6dcc3" transform="rotate(4 127 356)"/><rect x="250" y="296" width="34" height="24" fill="#efe3c6" transform="rotate(-30 267 308)"/>`,
      [[64, 288, 236, 88]])}
    ${obj('reporters', rows, [[0, 384, 360, 96]])}`);
  }
  const SCENES = { hotel: svgHotel, editorial: svgEditorial, corridor: svgCorridor, hall: svgHall };

  // ---------- 아이템 ----------
  const morseTable = keys => `<div class="morse">${keys.map(k => `<div><b>${k}</b><code>${MORSE[k].replace(/\./g, '·').replace(/-/g, '−')}</code></div>`).join('')}</div>`;
  const AM = 'ABCDEFGHIJKLM'.split(''), NZ = 'NOPQRSTUVWXYZ'.split('');
  // 잉크 선으로 그린 소지품 아이콘 (32×32)
  const ico = d => `<svg class="ico" viewBox="0 0 32 32" aria-hidden="true">${d}</svg>`;
  const ICON = {
    note: ico('<path d="M8 6h12l4 4v16H8z"/><path d="M20 6v4h4"/><path d="M11 14h10M11 18h10M11 22h6"/>'),
    receipt: ico('<path d="M10 4h12v20l-2 2-2-2-2 2-2-2-2 2-2-2z"/><path d="M13 10h6M13 14h6"/><path d="M14 19l2-2 2 2" stroke-width="2.2"/>'),
    cipher: ico('<rect x="9" y="8" width="14" height="16" rx="1"/><path d="M6 8h20M6 24h20"/><path d="M12 13h3M17 13h3M12 17h8M12 21h5"/>'),
    dict: ico('<rect x="8" y="5" width="16" height="22" rx="1.5"/><path d="M11 5v22"/><path d="M14 11h7M14 14h5"/>'),
    morse2: ico('<path d="M8 10l3-2 3 2 3-2 3 2 3-2 1 1v16H8z"/><circle cx="12" cy="16" r="1"/><path d="M15 16h5"/><circle cx="12" cy="21" r="1"/><circle cx="15" cy="21" r="1"/><path d="M18 21h3"/>'),
    mirror: ico('<circle cx="16" cy="12" r="7"/><path d="M16 19v9"/><path d="M13 10a4 4 0 0 1 3-3"/>'),
    siglog: ico('<rect x="6" y="6" width="15" height="20" rx="1"/><path d="M9 11h2M13 11h5M9 16h5M16 16h2M9 21h2"/><path d="M26 5l-4 14-1 3 2-2 4-14z"/>'),
    memo: ico('<path d="M8 8h16v18H8z"/><circle cx="16" cy="8" r="2" fill="#9b2c1f" stroke="none"/><path d="M11 14h10M11 18h10M11 22h7"/>'),
    key1: ico('<circle cx="10" cy="16" r="5"/><circle cx="10" cy="16" r="1.6"/><path d="M15 16h12M23 16v4M27 16v3"/>'),
    key2: ico('<path d="M10 5v22"/><path d="M10 6h12l-3 4 3 4H10"/><circle cx="10" cy="5" r="1.6" fill="#9b2c1f" stroke="none"/>'),
    telegram: ico('<rect x="5" y="9" width="22" height="15" rx="1"/><path d="M5 10l11 8 11-8"/>'),
  };
  const cap = t => `<p class="desc cap">${t}</p>`;

  const ITEMS = {
    note: { nm: '쪽지', ic: ICON.note, view: () => `<div class="doc doc-note">폐하께서 이 길을 명하신 날을<br>잊지 마라.</div>${cap('이준의 외투 주머니에서 나온 쪽지. 이준의 필체다.')}` },
    receipt: { nm: '찢어진 영수증', ic: ICON.receipt, view: () => `<div class="doc doc-receipt"><div class="doc-label">앞면</div><div class="smudge">Hôtel ····· fl. ··· ·· 19··<br>······ ··· ·····</div></div>${cap('물에 번져 알아볼 수 없다.')}
      <div class="doc doc-receipt back"><div class="doc-label">뒷면</div><div class="brush">二</div></div>${cap('찢긴 가장자리에 붓글씨 한 글자만 남아 있다. 어딘가에서 본 듯한 필체다.')}` },
    // 낡은 쪽지 사본: 규칙은 보여주지 않고 예시만 준다.
    // (숨은 규칙: n번째 글자의 초성을 자음 순서에서 n칸 뒤로 민다. 끝에 닿으면 처음으로 돌아간다.)
    cipher: { nm: '낡은 쪽지 사본', ic: ICON.cipher, view: () => `<div class="flip-card"><div class="doc doc-copy face front">
        <div class="doc-label">앞면</div>
        <table class="copy-pairs"><tr><td>이준</td><td>→</td><td>지쿤</td></tr><tr><td>경운궁</td><td>→</td><td>녕춘룽</td></tr><tr><td>한성</td><td>→</td><td>간정</td></tr></table></div>
      <div class="doc doc-copy face back" hidden><div class="doc-label">뒷면</div><p class="copy-back">"경운궁의 그 밤,<br>처음 배운 법식을 잊지 마라."</p></div></div>
      <div class="row"><button class="btn small" type="button" data-flip>뒤집기</button></div>` },
    dict: { nm: '프랑스어 사전', ic: ICON.dict, view: () => `<div class="doc doc-book"><div class="doc-label">앞장 메모</div><p class="pen">la = 여성 단어 앞<br>le, ce = 남성 단어 앞</p></div>
      <div class="doc doc-book"><div class="doc-label">단어</div><table class="dict-list">${DICT.map(d => `<tr><td>${d[0]}</td><td>${d[1]}</td><td>${d[2]}</td></tr>`).join('')}</table></div>
      <div class="doc doc-book torn"><div class="doc-label">마지막 장 · 모스 부호표</div>${morseTable(AM)}</div>${cap('N 이후는 찢겨 나가고 없다.')}` },
    morse2: { nm: '사전 조각', ic: ICON.morse2, view: () => `<div class="doc doc-book torn-top"><div class="doc-label">찢어진 사전 조각</div>${morseTable(NZ)}</div>${cap('트렁크 안감 속에 숨겨져 있던 조각. 사전 마지막 장의 나머지 반쪽이다.')}` },
    flag: { nm: '태극기', ic: FLAG_SVG, view: () => `<div class="doc doc-cloth">${FLAG_SVG}</div>${cap('한성을 떠날 때 품에 넣어 온 작은 태극기.')}` },
    mirror: { nm: '손거울', ic: ICON.mirror, view: () => `<div class="doc-mirror"><div class="glass"></div><div class="handle"></div></div>${cap('손바닥만 한 손거울. 세면대 수건 밑에 놓여 있었다. 지금은 쓸 곳이 없어 보인다.')}` },
    siglog: { nm: '받아 적은 신호', ic: ICON.siglog, view: () => `<div class="doc doc-grid"><div class="doc-label">창밖 불빛 기록</div><div class="siglog static">${signalLogText()}</div></div>
      ${cap('커튼을 치고 받아 적은 불빛. 짧게 켜지면 ·, 길게 켜지면 −로 적었다. ~는 박자가 엉망인 깜빡임, │는 한참 꺼져 있던 자리다.')}` },
    memo: { nm: '스테드의 메모', ic: ICON.memo, view: () => `<div class="doc doc-memo">이번 회의에 대표를 보낸 나라는 마흔네 곳이오. 나는 게시판을 각 나라의 프랑스어 이름 알파벳 순서대로 꽂아두었소. 그런데 아무도 앉지 않은 자리가 꼭 하나 있지. 그 자리를 찾아 당신들의 깃발을 꽂으시오.<div class="sign">— 스테드</div></div>` },
    key1: { nm: '열쇠 조각 ①', ic: ICON.key1, view: () => `<div class="doc doc-card"><div class="doc-label">기호 글자 4개</div><div class="key-letters">${S.words.key1 || ''}</div></div>${cap('조판한 호소문에서 빛나던 글자들. 순서는 알 수 없다.')}` },
    key2: { nm: '열쇠 조각 ②', ic: ICON.key2, view: () => `<div class="doc doc-card"><div class="doc-label">게시판의 빈 자리</div><div style="width:120px;margin:8px auto">${FLAG_SVG}</div></div>${cap('마흔네 장의 카드 사이, 태극기를 꽂은 그 자리. 있어야 했지만 끝내 없었던 자리.')}` },
    telegram: { nm: '문틈의 종이', ic: ICON.telegram, view: null },
  };

  // ---------- 상태 변경 ----------
  function addItem(id, quiet) {
    if (S.inv.includes(id)) return;
    S.inv.push(id); S.seen[id] = 0; save(); renderInv();
    if (!quiet) { toast('획득: ' + ITEMS[id].nm); sfx.get(); }
  }
  function removeItem(id) { S.inv = S.inv.filter(x => x !== id); save(); renderInv(); }

  const gaugeOn = () => !!(S.f.timer && !S.f.p5);
  function addGauge(n) {
    if (S.phase !== 'play' || !gaugeOn()) return;
    S.gauge = Math.min(100, S.gauge + n); save(); renderGauge(n);
    if (S.gauge >= 100) fail();
  }
  function renderGauge(delta) {
    const gg = $('#gauge');
    gg.classList.toggle('off', !gaugeOn());
    gg.parentNode.hidden = !gaugeOn();
    gg.querySelector('.gfill').style.width = Math.floor(S.gauge) + '%';
    // 감시가 짙어질수록 눈이 뜨인다
    gg.querySelector('.lid').setAttribute('height', (3 + 15 * (1 - Math.min(100, S.gauge) / 100)).toFixed(1));
    if (delta) {
      gg.classList.remove('hit'); void gg.offsetWidth; gg.classList.add('hit');
      const f = el('span', { class: 'gfloat' }, '+' + delta); gg.appendChild(f); setTimeout(() => f.remove(), 1000);
    }
  }
  function useful() {}
  async function useless(lines) { if (lines) await say(lines); }

  // ---------- 잠금·대기 타이머 (벽시계 기준이라 새로고침해도 유지) ----------
  const tickers = new Set();
  function ticker(node, fn) { const t = () => node.isConnected ? fn() : tickers.delete(t); tickers.add(t); fn(); }
  setInterval(() => tickers.forEach(t => t()), 250);
  const secLeft = until => Math.max(0, Math.ceil((until - Date.now()) / 1000));
  const fmt = s => s >= 60 ? `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}` : s + '초';
  const lockLeft = key => S.locks[key] ? secLeft(S.locks[key].until) : 0;
  const lastMsg = {};
  // 오답 처리: 방 3(퍼즐 5)은 게이지, 나머지는 입력 잠금
  function penalize(key, text) {
    sfx.err();
    lastMsg[key] = text;
    if (key === 'p5') { addGauge(GAUGE_WRONG); return; }
    const n = S.locks[key] ? S.locks[key].n : 0;
    S.locks[key] = { n: n + 1, until: Date.now() + LOCK_STEPS[Math.min(n, LOCK_STEPS.length - 1)] * 1000 };
    save();
  }
  function solvedKey(key) { delete S.locks[key]; delete lastMsg[key]; save(); }
  // 잠긴 동안 컨트롤을 막고 남은 시간을 보여준다. extraDisabled: 잠금과 별개로 막아야 할 조건
  function bindLock(key, controls, msg, extraDisabled) {
    ticker(msg, () => {
      const left = lockLeft(key);
      controls.forEach(c => { c.disabled = left > 0 || !!(extraDisabled && extraDisabled()); });
      if (left > 0) { msg.className = 'msg err'; msg.textContent = `${lastMsg[key] || '맞지 않는 것 같다.'} (${left}초 뒤 다시 시도)`; }
      else if (lastMsg[key] != null) { msg.className = 'msg err'; msg.textContent = lastMsg[key]; }
    });
  }

  // ---------- 대사 ----------
  // 말하는 인물의 실루엣 초상
  function portrait(name) {
    const base = '<rect width="56" height="56" fill="#c9b48a"/><circle cx="28" cy="23" r="10" fill="#2a1d12"/><path d="M7 56 q2 -19 21 -21 q19 2 21 21z" fill="#2a1d12"/>';
    const extra = {
      '이준': '<path d="M23 28.5 q5 2.6 10 0" stroke="#c9b48a" stroke-width="1.4" fill="none"/><path d="M24 39 l4 5 4-5" stroke="#c9b48a" stroke-width="1.2" fill="none"/>',
      '이위종': '<path d="M18 19 q10 -10 20 0" stroke="#c9b48a" stroke-width="1" fill="none"/><path d="M24 39 l4 6 4-6" stroke="#f3e8cc" stroke-width="1.6" fill="none"/>',
      '스테드': '<path d="M19 25 q9 17 18 0 v5 q-9 15 -18 0z" fill="#d9d0bd"/><path d="M21 17 q7 -7 14 0" stroke="#d9d0bd" stroke-width="2" fill="none"/>',
    }[name] || '';
    return `<svg viewBox="0 0 56 56" aria-hidden="true">${base}${extra}</svg>`;
  }
  let dlgChain = Promise.resolve(), dlgGen = 0;
  function say(lines, opt = {}) {
    if (!Array.isArray(lines)) lines = [lines];
    const gen = dlgGen;
    dlgChain = dlgChain.then(() => gen === dlgGen ? runSay(lines, opt) : null);
    return dlgChain;
  }
  function runSay(lines, opt) {
    return new Promise(res => {
      const d = $('#dialog'), nm = d.querySelector('.dname'), tx = d.querySelector('.dtext'), pt = d.querySelector('.dport');
      d.classList.toggle('dark', !!opt.dark);
      let i = 0, typing = 0, full = [];
      const stopTyping = () => { clearInterval(typing); typing = 0; tx.textContent = full.join(''); };
      const show = () => {
        const l = lines[i], narr = typeof l === 'string';
        nm.textContent = narr ? '' : l[0];
        pt.innerHTML = narr ? '' : portrait(l[0]);
        d.classList.toggle('narr', narr);
        // 한 글자씩 찍기 (탭하면 바로 전체 표시)
        full = Array.from(narr ? l : l[1]);
        let k = 0; tx.textContent = '';
        clearInterval(typing);
        typing = setInterval(() => { k += 2; tx.textContent = full.slice(0, k).join(''); if (k >= full.length) stopTyping(); }, 30);
      };
      const next = e => {
        if (e) e.stopPropagation();
        if (typing) return stopTyping();
        i++;
        if (i >= lines.length) { d.hidden = true; d.onclick = null; res(); }
        else show();
      };
      d.hidden = false; show();
      d.onclick = next;
      d._cancel = () => { clearInterval(typing); typing = 0; d.hidden = true; d.onclick = null; };
    });
  }
  function cancelDialog() { dlgGen++; const d = $('#dialog'); if (d._cancel) d._cancel(); dlgChain = Promise.resolve(); }

  // ---------- 드래그 ----------
  let dragging = false;
  function dragify(node, o) {
    node.addEventListener('pointerdown', e => {
      if (e.button > 0 || S.phase !== 'play') return;
      const sx = e.clientX, sy = e.clientY, pid = e.pointerId, touch = e.pointerType !== 'mouse';
      let drag = false, ghost = null, over = null, lx = sx, ly = sy, raf = 0;
      const target = (x, y) => { const t = document.elementFromPoint(x, y); return t ? t.closest('[data-drop]') : null; };
      // 가장자리에 잠시 머물러야 스크롤 (인벤토리에서 끌어올릴 때 화면이 밀리지 않도록)
      let edgeSince = 0;
      const scrollLoop = () => {
        const t = document.elementFromPoint(lx, ly), sc = t && t.closest('.layer-body');
        let dir = 0;
        if (sc) {
          const r = sc.getBoundingClientRect();
          dir = ly < r.top + 50 ? -1 : ly > r.bottom - 50 ? 1 : 0;
        }
        if (!dir) edgeSince = 0;
        else if (!edgeSince) edgeSince = performance.now();
        else if (performance.now() - edgeSince > 400) sc.scrollTop += dir * 8;
        raf = requestAnimationFrame(scrollLoop);
      };
      const move = ev => {
        if (ev.pointerId !== pid) return;
        lx = ev.clientX; ly = ev.clientY;
        const dx = lx - sx, dy = ly - sy;
        if (!drag) {
          const d = Math.hypot(dx, dy);
          if (o.vertical && touch) { if (d < 8) return; if (Math.abs(dy) < Math.abs(dx)) { end(); return; } }
          else if (d < 6) return;
          drag = dragging = true;
          ghost = node.cloneNode(true); ghost.classList.add('drag-ghost'); ghost.classList.remove('new');
          ghost.style.width = node.offsetWidth + 'px';
          document.body.appendChild(ghost);
          node.classList.add('lifting');
          try { node.setPointerCapture(pid); } catch (er) {}
          raf = requestAnimationFrame(scrollLoop);
        }
        ev.preventDefault();
        ghost.style.left = lx + 'px'; ghost.style.top = ly + 'px';
        const t = target(lx, ly);
        if (t !== over) {
          if (over) over.classList.remove('over');
          over = t && t.classList.contains('drop-hl') ? t : null;
          if (over) over.classList.add('over');
        }
      };
      const end = () => {
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
        window.removeEventListener('pointercancel', cancel);
        cancelAnimationFrame(raf);
        if (ghost) ghost.remove();
        if (over) over.classList.remove('over');
        node.classList.remove('lifting');
        dragging = false;
      };
      const up = ev => {
        if (ev.pointerId !== pid) return;
        const wasDrag = drag; end();
        if (wasDrag) { const t = target(ev.clientX, ev.clientY); o.onDrop(t ? t.dataset.drop : null, t); }
        else if (o.onTap) o.onTap();
      };
      const cancel = ev => { if (ev.pointerId === pid) end(); };
      window.addEventListener('pointermove', move, { passive: false });
      window.addEventListener('pointerup', up);
      window.addEventListener('pointercancel', cancel);
    });
  }

  // ---------- 인벤토리 ----------
  function renderInv() {
    const list = $('#invList'); list.innerHTML = '';
    if (!S.inv.length) { list.appendChild(el('div', { class: 'inv-empty' }, '아직 가진 것이 없다.')); return; }
    S.inv.forEach(id => {
      const it = ITEMS[id];
      const n = el('div', { class: 'inv' + (S.seen[id] ? '' : ' new'), 'data-item': id }, `<div class="ic">${it.ic}</div><div class="nm">${it.nm}</div>`);
      dragify(n, { vertical: true, onTap: () => openItem(id), onDrop: (key, t) => itemDrop(id, key, t) });
      list.appendChild(n);
    });
  }

  // ---------- 레이어 ----------
  let zoomBuild = null, zoomClose = null, itemOpen = null;
  function openZoom(title, build, onClose) {
    closeZoom();
    const z = $('#zoom'); z.querySelector('.layer-title').textContent = title;
    zoomBuild = build; zoomClose = onClose || null;
    z.hidden = false; refreshZoom(true);
  }
  function refreshZoom(top) {
    if (!zoomBuild) return;
    const b = $('#zoom .layer-body'), st = b.scrollTop;
    b.innerHTML = ''; zoomBuild(b);
    b.scrollTop = top ? 0 : st;
  }
  function closeZoom() {
    if (zoomClose) { const c = zoomClose; zoomClose = null; c(); }
    zoomBuild = null; $('#zoom').hidden = true;
  }
  function openItem(id) {
    itemOpen = id; S.seen[id] = 1; save(); renderInv();
    const v = $('#itemView'); v.querySelector('.layer-title').textContent = ITEMS[id].nm;
    v.hidden = false; refreshItem(true);
  }
  function refreshItem(top) {
    if (!itemOpen) return;
    const b = $('#itemView .layer-body'), st = b.scrollTop;
    b.innerHTML = '';
    if (itemOpen === 'telegram') buildTelegram(b); else b.innerHTML = ITEMS[itemOpen].view();
    // 앞뒷면이 있는 문서
    b.querySelectorAll('[data-flip]').forEach(btn => btn.addEventListener('click', () => {
      const card = b.querySelector('.flip-card');
      card.classList.remove('turn'); void card.offsetWidth; card.classList.add('turn');
      card.querySelectorAll('.face').forEach(f => { f.hidden = !f.hidden; });
      sfx.click();
    }));
    b.scrollTop = top ? 0 : st;
  }
  function closeItem() { itemOpen = null; $('#itemView').hidden = true; }
  function closeLayers() { closeItem(); closeZoom(); }

  function hintBox(key) {
    const wrap = el('div');
    const btn = el('button', { class: 'hint-toggle' }, '힌트');
    const box = el('div', { class: 'hintbox' });
    box.hidden = !(S.hints[key] > 0);
    btn.hidden = !box.hidden;
    // 방 3(퍼즐 5)은 바로 볼 수 있지만 게이지가 오르고, 나머지는 무료 대신 대기 시간이 있다
    const costly = key === 'p5';
    if (!costly && !S.hintT[key]) { S.hintT[key] = { open: Date.now() }; save(); }
    const readyAt = n => n === 0 ? S.hintT[key].open + HINT1_WAIT * 1000 : S.hintT[key].seen1 + HINT2_WAIT * 1000;
    const draw = () => {
      const n = S.hints[key] || 0;
      box.innerHTML = '';
      if (n) box.appendChild(el('ol', null, HINTS[key].slice(0, n).map(h => `<li>${h}</li>`).join('')));
      if (n >= HINTS[key].length) return;
      const b = el('button', { class: 'btn small', on: { click: () => {
        if (b.disabled) return;
        S.hints[key] = n + 1;
        if (!costly && n === 0) S.hintT[key].seen1 = Date.now();
        save();
        if (costly) addGauge(GAUGE_HINT);
        draw();
      } } });
      box.appendChild(b);
      if (costly) { b.textContent = `힌트 ${n + 1} 보기 (감시 +${GAUGE_HINT})`; return; }
      ticker(b, () => {
        const left = secLeft(readyAt(n));
        b.disabled = left > 0;
        b.textContent = left > 0 ? `힌트 ${n + 1} · ${fmt(left)} 뒤에 볼 수 있다` : `힌트 ${n + 1} 보기`;
      });
    };
    btn.onclick = () => { btn.hidden = true; box.hidden = false; draw(); };
    draw();
    wrap.append(btn, box);
    return wrap;
  }
  function answerBox(key, placeholder, onSubmit, opts = {}) {
    const wrap = el('div');
    const row = el('div', { class: 'answer' });
    const inp = el('input', { type: 'text', placeholder, autocomplete: 'off', autocapitalize: opts.caps ? 'characters' : 'off', spellcheck: 'false', maxlength: opts.max || 12 });
    const msg = el('div', { class: 'msg' });
    let busy = false;
    const go = async () => {
      if (busy || lockLeft(key) > 0 || !inp.value.trim()) return;
      busy = true;
      const ok = await onSubmit(inp.value);
      busy = false;
      if (ok) { solvedKey(key); return; }
      row.classList.remove('shake'); void row.offsetWidth; row.classList.add('shake');
      penalize(key, opts.wrong || '맞지 않는 것 같다.');
    };
    const b = el('button', { class: 'btn small', on: { click: go } }, opts.label || '확인');
    inp.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
    row.append(inp, b); wrap.append(row, msg);
    bindLock(key, [inp, b], msg);
    return wrap;
  }

  // ---------- 화면 ----------
  function show(id) { ['#title', '#game', '#ending'].forEach(s => { $(s).hidden = s !== id; }); }
  function renderHUD() {
    $('#place').textContent = placeText();
    const nav = $('#roomNav'); nav.innerHTML = '';
    S.rooms.forEach(r => nav.appendChild(el('button', { class: r === S.room ? 'on' : '', on: { click: () => { if (r !== S.room) goRoom(r); } } }, ROOMS[r].nav)));
    $('#pulse').classList.toggle('on', gaugeOn());
    $('#scene').classList.toggle('tense', gaugeOn());
    renderGauge();
  }
  function renderScene() {
    const sc = $('#scene');
    sc.classList.remove('has-img');
    sc.innerHTML = SCENES[S.room]();
    const img = new Image(), room = S.room;
    img.onload = () => { if (S.room === room) sc.classList.add('has-img'); };
    img.src = ROOMS[room].img;
  }
  function renderAll() { renderHUD(); renderScene(); renderInv(); }

  async function goRoom(r) {
    closeLayers(); S.room = r; useful(); save(); renderAll(); await enterRoom();
  }
  // 장소·날짜 카드: 처음 들어가는 장소에서만 잠깐 보여준다 (탭하면 넘김)
  function titleCard(text) {
    return new Promise(res => {
      const c = $('#card'), t = c.querySelector('.card-text');
      t.innerHTML = text.split(' · ').map((x, i) => `<div class="${i ? '' : 'big'}">${x}</div>`).join('');
      c.hidden = false; c.classList.remove('out'); void c.offsetWidth;
      let done = false;
      const end = () => { if (done) return; done = true; c.classList.add('out'); setTimeout(() => { c.hidden = true; res(); }, 400); };
      c.onclick = end; setTimeout(end, 2000);
    });
  }
  async function enterRoom() {
    const f = S.f;
    const introPending = { hotel: !f.introHotel, editorial: !f.introEd, corridor: !f.introCor, hall: !f.introHall }[S.room];
    if (introPending) await titleCard(placeText());
    if (S.room === 'hotel' && !f.introHotel) {
      await say('회의장 출입을 거절당하고 돌아온 밤. 이준은 창가에 앉아 말이 없고, 이위종은 펜을 쥔 채 빈 종이만 바라본다.');
      f.introHotel = 1; save();
    } else if (S.room === 'editorial' && !f.introEd) {
      await say(['잉크 냄새가 가득한 작은 편집실. 영국 언론인 윌리엄 스테드가 일행을 맞는다.', ['스테드', '"당신들 이야기를 실어주겠소. 단, 각국 대표들이 읽을 수 있는 글이어야 하오."']]);
      f.introEd = 1; save();
    } else if (S.room === 'corridor' && !f.introCor) {
      await say('스테드의 신문에 호소문이 실린 다음 날. 호텔 복도에 낯선 남자가 서성인다. 이준의 방 문틈으로 종이 한 장이 밀려 들어온다.');
      f.introCor = 1; f.timer = 1; S.gauge = 0; save(); renderHUD();
    } else if (S.room === 'hall' && !f.introHall) {
      await say('7월 8일. 각국 기자와 언론인들이 모인 홀. 이위종이 연단에 오르기 직전, 원고 뭉치가 바닥에 흩어진다. 그 사이에 누군가 몰래 끼워 넣은 종이도 섞여 있다.');
      f.introHall = 1; save();
    }
  }

  // 장면 탭
  function initScene() {
    const sc = $('#scene');
    sc.addEventListener('pointerdown', e => {
      const r = $('#sceneWrap').getBoundingClientRect();
      const rp = el('div', { class: 'ripple' });
      rp.style.left = (e.clientX - r.left) + 'px'; rp.style.top = (e.clientY - r.top) + 'px';
      $('#sceneWrap').appendChild(rp); setTimeout(() => rp.remove(), 520);
    });
    sc.addEventListener('click', e => {
      const g = e.target.closest('[data-o]');
      if (!g || S.phase !== 'play' || dragging) return;
      g.classList.remove('tapped'); void g.getBoundingClientRect(); g.classList.add('tapped');
      const h = OBJ[S.room] && OBJ[S.room][g.dataset.o];
      if (h) h();
    });
  }

  // ---------- 방 1: 객실 ----------
  const OBJ = {};
  OBJ.hotel = {
    async trunk() {
      if (!S.f.trunk) { useful(); return openLock(); }
      if (!S.f.lining) {
        useful(); S.f.lining = 1; save();
        await say('열린 트렁크를 다시 살펴보니, 바닥 안감 한쪽이 뜯겨 있다. 그 틈에 찢어진 종이 조각이 끼어 있다.');
        addItem('morse2');
        return;
      }
      useless('뜯긴 안감 말고는 더 이상 아무것도 없다.');
    },
    desk() { useful(); openCommission(); },
    calendar() { useless(); openCalendar(); },
    async coat() {
      if (S.coat === 0) { useful(); S.coat = 1; save(); await say('이준의 외투다. 주머니 속에 접힌 쪽지가 들어 있다.'); addItem('note'); }
      else if (S.coat === 1) { useful(); S.coat = 2; save(); await say('외투를 한 번 더 살펴보니, 안주머니에서 찢어진 종이가 만져진다. 영수증인 것 같다.'); addItem('receipt'); }
      else useless('주머니는 이제 비어 있다.');
    },
    window() {
      if (!S.f.trunk) return useless('창밖으로 건너편 건물이 보인다. 불 꺼진 창들뿐이다.');
      useful(); openWindow();
    },
    async curtain() {
      useful(); S.f.curtain = S.f.curtain ? 0 : 1; save(); renderScene();
      sfx.click();
      await say(S.f.curtain ? '커튼을 반쯤 쳤다. 방 안이 어둑해졌다.' : '커튼을 다시 걷었다. 방 안이 환해졌다.');
    },
    async wash() {
      if (!S.f.mirrorGot) { useful(); S.f.mirrorGot = 1; save(); await say('세면대에 걸린 수건을 들추자, 그 밑에 작은 손거울이 놓여 있다.'); addItem('mirror'); }
      else useless('물 주전자와 대야가 놓여 있다.');
    },
    leejun() {
      if (S.f.stage3) return say([['이준', '"서두르게. 저들이 먼저 움직이기 전에."']]);
      if (S.f.p2) return say([['이준', '"문이 닫혔다면, 문 밖에서라도 외쳐야지."']]);
      return say('이준은 창가에 앉아 말없이 밖을 바라보고 있다.');
    },
    leewj() {
      if (S.f.stage3) return say([['이위종', '"복도의 그자, 일본 쪽 사람이 분명하오. 서둘러야 하오."']]);
      if (S.f.p2) return say([['이위종', '"스테드를 찾아가 봅시다. 편집실은 멀지 않소."']]);
      if (S.f.trunk) return say([['이위종', '"잠이 오지 않는구려. 건너편 건물은 이 시간에도 불이 켜졌다 꺼졌다 하오."']]);
      return say([['이위종', '"트렁크 번호는 이 선생께서 직접 맞추셨소. 결코 잊어선 안 될 날이라 하시면서."']]);
    },
  };

  function openLock() {
    const digits = S.lockDial || [0, 0, 0, 0];
    openZoom('트렁크 자물쇠', b => {
      b.appendChild(el('p', { class: 'desc' }, '낡은 가죽 트렁크. 네 자리 숫자 자물쇠로 잠겨 있다.'));
      const box = el('div', { class: 'trunk-box' });
      const lock = el('div', { class: 'lock' });
      digits.forEach((d, i) => {
        const num = el('div', { class: 'num' }, String(d));
        const set = v => { digits[i] = (v + 10) % 10; num.textContent = digits[i]; S.lockDial = digits; sfx.click(); };
        const dial = el('div', { class: 'dial' });
        dial.append(el('button', { on: { click: () => set(digits[i] + 1) } }, '▲'), num, el('button', { on: { click: () => set(digits[i] - 1) } }, '▼'));
        lock.appendChild(dial);
      });
      box.appendChild(lock);
      b.appendChild(box);
      const msg = el('div', { class: 'msg' });
      let busy = false;
      const openBtn = el('button', { class: 'btn', on: { click: async () => {
        if (busy || lockLeft('p1') > 0) return; busy = true;
        const ok = (await sha('lock|' + digits.join(''))) === H.lock;
        busy = false;
        if (ok) { solvedKey('p1'); return lockOpened(); }
        box.classList.remove('shake'); void box.offsetWidth; box.classList.add('shake');
        penalize('p1', '자물쇠가 꿈쩍도 하지 않는다.');
      } } }, '열기');
      b.appendChild(el('div', { class: 'row', style: 'margin-top:12px' })).appendChild(openBtn);
      b.appendChild(msg);
      bindLock('p1', [openBtn], msg);
      b.appendChild(hintBox('p1'));
    });
  }
  async function lockOpened() {
    S.f.trunk = 1; save(); sfx.ok(); closeZoom(); renderScene();
    await say('딸깍— 자물쇠가 풀렸다. 트렁크 안에는 낡은 쪽지 사본, 낡은 프랑스어 사전, 그리고 작은 태극기가 들어 있다.');
    addItem('cipher', true); addItem('dict', true); addItem('flag', true);
    toast('획득: 낡은 쪽지 사본, 프랑스어 사전, 태극기'); sfx.get();
  }

  function openCommission() {
    openZoom('책상 위의 위임장', b => {
      b.appendChild(el('p', { class: 'desc' }, '책상 위에 펼쳐진 위임장. 날짜 한 글자가 얼룩져 있다.'));
      const filled = !!S.f.stain;
      b.appendChild(el('div', { class: 'commission paper-tex' }, `<div class="ct">委任狀</div>
        大韓帝國 皇帝는<br>特派委員에게 命하여<br>萬國平和會議에 나아가<br>本國의 사정을 알리게 하노라
        <div class="date" data-drop="stain">光武十一年 四月 <span class="stain">${filled ? '<span class="fill">二</span>' : '<span class="blot"></span>'}</span>十日</div>
        <div class="royal-seal">皇帝<br>御璽</div>`));
      b.appendChild(hintBox('p1'));
    });
  }
  function openCalendar() {
    openZoom('벽 달력', b => {
      const first = new Date(1907, 3, 1).getDay();
      let cells = '', day = 1;
      for (let r = 0; r < 6 && day <= 30; r++) {
        cells += '<tr>';
        for (let c = 0; c < 7; c++) {
          const v = (r === 0 && c < first) || day > 30 ? '' : day++;
          cells += `<td class="${c === 0 ? 'sun' : ''}">${v}</td>`;
        }
        cells += '</tr>';
      }
      b.appendChild(el('div', { class: 'sheet' }, `<div class="cal-title">APRIL 1907 <span class="muted">(1907년 4월)</span></div>
        <table class="cal"><tr><th class="sun">Zo</th><th>Ma</th><th>Di</th><th>Wo</th><th>Do</th><th>Vr</th><th>Za</th></tr>${cells}</table>
        <p class="muted" style="margin:10px 0 0">호텔 벽에 걸린 달력. 아무 표시도 되어 있지 않다.</p>`));
    });
  }

  // 퍼즐 2: 창밖의 신호
  // [켜짐, 시간(ms), 받아 적는 기호]
  function buildSignal() {
    const U = 350, seq = [];
    const noise = () => {
      const n = 4 + Math.floor(Math.random() * 3);
      for (let i = 0; i < n; i++) { seq.push([1, 60 + Math.random() * 380, '~']); seq.push([0, 70 + Math.random() * 230, '']); }
    };
    noise(); seq.push([0, U * 10, '  │  ']);
    SIGNAL.forEach(code => {
      const m = MORSE[String.fromCharCode(code)];
      m.split('').forEach((s, si) => {
        seq.push([1, s === '.' ? U : U * 3, s === '.' ? '·' : '−']);
        seq.push([0, si < m.length - 1 ? U : U * 3, si < m.length - 1 ? '' : '   ']);
      });
    });
    seq[seq.length - 1][1] = U * 10; seq[seq.length - 1][2] = '  │  ';
    return seq;
  }
  // 한 바퀴를 끝까지 지켜본 뒤 남는 기록 (잡음은 ~, 글자 사이는 띄어 씀)
  function signalLogText() {
    const letters = SIGNAL.map(code => MORSE[String.fromCharCode(code)].replace(/\./g, '·').replace(/-/g, '−'));
    return '~ ~ ~ ~ ~  │  ' + letters.join('   ') + '  │  ~ ~ ~ ~';
  }
  function openWindow() {
    let alive = true, timer = 0, noiseT = 0, osc = null, gain = null;
    const stop = () => {
      alive = false; clearTimeout(timer); clearTimeout(noiseT);
      try { if (osc) osc.stop(); } catch (e) {}
    };
    openZoom('창밖', b => {
      const dark = !!S.f.curtain;
      const v = el('div', { class: 'window-view ' + (dark ? 'darkened' : 'bright') }, `<div class="bldg">
          <div class="bwin" style="left:10%;top:12%"></div>
          <div class="bwin" style="left:10%;top:60%"></div><div class="bwin" style="right:10%;top:60%"></div></div>
        <div class="sig"><div class="lamp"></div></div><div class="glare" style="position:absolute;inset:0;background:#fffbe8;opacity:0"></div>
        <div class="cross-v"></div><div class="cross-h"></div><div class="curt l"></div><div class="curt r"></div>`);
      b.appendChild(v); b.appendChild(el('div', { class: 'sill' }));
      b.appendChild(el('p', { class: 'desc' }, dark
        ? '방이 어두워지자 건너편 건물 창의 불빛이 또렷하게 보인다. 불빛이 일정한 리듬으로 켜졌다 꺼진다.'
        : '건너편 건물 창에 무언가 깜빡이는 것 같지만, 방 안이 밝아 희미하고 어른거릴 뿐이다.'));
      let log = null;
      if (dark && !S.f.p2) {
        b.appendChild(el('div', { class: 'siglog-label' }, S.inv.includes('siglog') ? '받아 적는 중 · 다 적은 기록은 소지품에 있다' : '도진이 불빛을 받아 적는 중… 한 바퀴를 끝까지 지켜보자'));
        log = b.appendChild(el('div', { class: 'siglog' }, '&nbsp;'));
      }
      if (!S.f.p2) {
        b.appendChild(answerBox('p2', '신호 해독', async val => {
          if ((await sha('sig|' + normUp(val))) !== H.sig) return false;
          signalSolved(); return true;
        }, { caps: true, max: 10, wrong: '불빛과 맞지 않는 것 같다.' }));
      } else b.appendChild(el('p', { class: 'msg ok' }, '신호는 이미 읽었다.'));
      b.appendChild(hintBox('p2'));

      // 불빛 재생
      clearTimeout(timer); clearTimeout(noiseT);
      const lamp = v.querySelector('.lamp'), glare = v.querySelector('.glare');
      const c = dark ? actx() : null;
      if (c && !osc) {
        try {
          osc = c.createOscillator(); gain = c.createGain(); osc.frequency.value = 620; gain.gain.value = 0;
          osc.connect(gain).connect(c.destination); osc.start();
        } catch (e) { osc = null; }
      }
      const seq = buildSignal(); let i = 0, steps = 0, text = '';
      const step = () => {
        if (!alive) return;
        const [on, ms, mark] = seq[i]; i = (i + 1) % seq.length;
        lamp.style.opacity = on ? (dark ? 1 : 0.16) : 0;
        if (log) {
          text = (text + mark).slice(-22);
          log.textContent = text || ' ';
          if (++steps === seq.length && !S.inv.includes('siglog')) {
            addItem('siglog');
            toast('도진이 신호 한 바퀴를 모두 받아 적었다.');
          }
        }
        if (gain && c) gain.gain.setTargetAtTime(on && soundOn ? 0.08 : 0, c.currentTime, 0.005);
        timer = setTimeout(step, ms);
      };
      step();
      if (!dark) {
        const nz = () => {
          if (!alive) return;
          glare.style.opacity = (Math.random() * 0.3).toFixed(2);
          lamp.style.filter = Math.random() < 0.5 ? 'brightness(1.6)' : '';
          noiseT = setTimeout(nz, 50 + Math.random() * 120);
        };
        nz();
      }
    }, stop);
  }
  async function signalSolved() {
    S.f.p2 = 1; if (!S.rooms.includes('editorial')) S.rooms.push('editorial'); save();
    sfx.ok(); closeZoom(); renderHUD();
    await say([['이위종', '"스테드… 회의 기간 동안 매일 신문을 펴내는 영국 언론인이오. 그라면 우리 이야기를 실어줄지도 모르오."'], '이제 편집실로 갈 수 있다.']);
  }

  // ---------- 아이템 드롭 ----------
  async function itemDrop(id, key, t) {
    if (!key) return;
    if (id === 'receipt' && key === 'stain') {
      S.f.stain = 1; removeItem('receipt'); sfx.ok(); refreshZoom();
      return say('영수증 뒷면의 글자를 얼룩 위에 대어 보니, 끊긴 획이 꼭 맞아떨어진다. 같은 사람의 필체다.');
    }
    if (id === 'flag' && key.startsWith('seat:')) return flagDrop(+key.slice(5), t);
    if (id === 'mirror' && key === 'telegram') {
      S.f.mirrored = 1; removeItem('mirror'); sfx.ok(); refreshItem();
      return say('거울에 비추자, 뒤집혀 있던 글자들이 바로 읽힌다.');
    }
    if (key.startsWith('p3') || key.startsWith('p6')) return;
    toast('여기에는 쓸 수 없을 것 같다.');
  }

  // ---------- 방 2: 편집실 ----------
  OBJ.editorial = {
    async board() {
      useful();
      if (!S.inv.includes('memo')) {
        await say('게시판 귀퉁이에 스테드의 메모가 꽂혀 있다.');
        addItem('memo');
      }
      openBoard();
    },
    typeset() { useful(); openTypeset(); },
    press() { useless('커다란 인쇄기. 잉크 냄새가 코를 찌른다.'); },
    papers() { useless('어제 찍은 신문 더미다. 회의 소식으로 가득하다.'); },
    host() {
      if (S.f.p3 && !S.f.p4) return say([['스테드', '"호소문은 좋소. 이제 게시판에 당신들의 자리를 찾아야지."']]);
      if (S.f.p4 && !S.f.p3) return say([['스테드', '"자리는 찾았구려. 이제 호소문을 마저 짜 맞춥시다."']]);
      if (S.f.stage3) return say([['스테드', '"신문은 나갔소. 이제 저들이 가만있지 않을 거요. 조심하시오."']]);
      return say([['스테드', '"활자는 저 조판대에 있소. 그리고 게시판도 한번 보시오."']]);
    },
  };

  // 퍼즐 3: 호소문 조판
  function openTypeset() {
    openZoom('호소문 조판', b => {
      const solved = !!S.f.p3;
      b.appendChild(el('p', { class: 'desc' }, '프랑스어 호소문 다섯 문장. 빈칸마다 활자를 하나씩 끼워 넣어야 한다.'));
      const wrap = el('div', { class: solved ? 'solved' : '' });
      P3.forEach((s, k) => {
        const p = el('div', { class: 'p3-sent' + (s.cols ? ' gloss' : '') });
        p.appendChild(el('span', { class: 'no' }, String(k + 1)));
        const slot = el('span', { class: 'slot drop-hl', 'data-drop': 'p3:' + k });
        if (S.p3[k] != null) slot.appendChild(typeEl(S.p3[k], k, solved));
        if (s.cols) {
          // 단어별 직역: 프랑스어 아래에 한국어 뜻을 세로로 맞춘다
          s.cols.forEach(c => {
            const col = el('span', { class: 'gcol' });
            if (c) col.append(el('span', { class: 'gfr' }, c[0]), el('span', { class: 'gko' }, c[1] || '&nbsp;'));
            else col.append(slot, el('span', { class: 'gko' }, '____'));
            p.appendChild(col);
          });
        } else {
          p.appendChild(document.createTextNode(s.pre + ' '));
          p.appendChild(slot);
          p.appendChild(document.createTextNode(' ' + s.post));
          if (s.gd) p.appendChild(el('span', { class: 'gd' }, s.gd));
        }
        wrap.appendChild(p);
      });
      b.appendChild(wrap);
      if (!solved) {
        const tray = el('div', { class: 'tray drop-hl', 'data-drop': 'p3:tray' });
        BLOCKS.forEach((w, i) => { if (!S.p3.includes(i)) tray.appendChild(typeEl(i, null, false)); });
        b.appendChild(tray);
        const msg = el('div', { class: 'msg' });
        const full = S.p3.every(v => v != null);
        let busy = false;
        const btn = el('button', { class: 'btn', disabled: full ? false : 'disabled', on: { click: async () => {
          if (busy || lockLeft('p3') > 0) return; busy = true;
          let wrong = 0;
          for (let k = 0; k < P3.length; k++) if ((await sha('p3|' + k + '|' + BLOCKS[S.p3[k]])) !== H.p3[k]) wrong++;
          busy = false;
          if (!wrong) { solvedKey('p3'); return typesetSolved(); }
          penalize('p3', `${wrong}칸이 맞지 않는다.`);
        } } }, '조판하기');
        b.appendChild(el('div', { class: 'row', style: 'margin-top:12px' })).appendChild(btn);
        b.appendChild(msg);
        bindLock('p3', [btn], msg, () => !S.p3.every(v => v != null));
      } else {
        b.appendChild(el('p', { class: 'msg ok' }, '조판을 마쳤다. 몇몇 글자가 빛나고 있다.'));
      }
      b.appendChild(hintBox('p3'));
    });
  }
  function typeEl(bi, slotK, lit) {
    const w = BLOCKS[bi], t = el('span', { class: 'type' });
    const marks = {};
    if (lit) MARKS.forEach(m => { if (m[0] === slotK) marks[m[1]] = m[2]; });
    Array.from(w).forEach((ch, i) => {
      const c = el('span', { class: 'ch' + (marks[i] ? ' lit' : '') });
      c.textContent = ch;
      if (marks[i]) c.appendChild(el('i', null, marks[i]));
      t.appendChild(c);
    });
    if (!S.f.p3) {
      dragify(t, {
        onTap: () => { if (slotK != null) { S.p3[slotK] = null; save(); refreshZoom(); } },
        onDrop: key => {
          if (!key || !key.startsWith('p3')) return;
          const from = S.p3.indexOf(bi);
          if (key === 'p3:tray') { if (from >= 0) S.p3[from] = null; }
          else {
            const k = +key.slice(3), prev = S.p3[k];
            if (from >= 0) S.p3[from] = prev; S.p3[k] = bi;
          }
          sfx.click(); save(); refreshZoom();
        },
      });
    }
    return t;
  }
  async function typesetSolved() {
    S.f.p3 = 1;
    S.words.key1 = KEY1_ORDER.map(i => { const [s, p, y] = MARKS[i]; return Array.from(BLOCKS[S.p3[s]])[p].toUpperCase() + y; }).join('  ');
    save(); sfx.ok(); refreshZoom();
    await wait(900);
    await say([['스테드', '"빛나는 글자들이 있구려. 어떤 순서로 읽어야 할지는 나도 모르겠소. 이 기호들, 잘 간직해두시오."']]);
    addItem('key1');
    checkStage3();
  }

  // 퍼즐 4: 국기 게시판
  function openBoard() {
    openZoom('참가국 게시판', b => {
      b.appendChild(el('p', { class: 'desc' }, '편집실 벽의 참가국 카드 게시판. 카드들이 빼곡히 꽂혀 있다.'));
      const board = el('div', { class: 'board' });
      BOARD.forEach((s, i) => {
        const seat = el('div', { class: 'seat' + (S.lift[i] ? ' lifted' : ''), 'data-drop': 'seat:' + i });
        if (s === 'frame') {
          if (S.f.p4 && i === S.f.p4seat) seat.appendChild(el('div', { class: 'flag' }, FLAG_SVG));
        } else if (s === 'fall') {
          seat.appendChild(el('span', { class: 'pin', style: 'top:8px' }));
        } else {
          const named = Array.isArray(s);
          const card = el('div', { class: 'card' + (named ? '' : ' gen') + (s === 'askew' ? ' askew' : '') },
            named ? `<span class="fr">${s[0]}</span><span class="ko">${s[1]}</span>` : '<span class="fr">délégation</span><span class="ko">대표단</span>');
          seat.appendChild(card);
          if (named && s[2]) {
            seat.appendChild(el('div', { class: 'cover' }));
            seat.addEventListener('click', () => { S.lift[i] = S.lift[i] ? 0 : 1; save(); seat.classList.toggle('lifted', !!S.lift[i]); sfx.click(); });
          }
        }
        board.appendChild(seat);
      });
      b.appendChild(board);
      b.appendChild(el('div', { class: 'floor' }, `<div class="card gen" style="left:22px;top:14px;transform:rotate(-12deg)"><span class="fr">délégation</span><span class="ko">대표단</span></div>
        <div class="card gen" style="left:180px;top:18px;transform:rotate(19deg)"><span class="fr">délégation</span><span class="ko">대표단</span></div><span class="floor-label">게시판 아래 바닥</span>`));
      const msg = b.appendChild(el('div', { class: 'msg', id: 'boardMsg' }, S.f.p4 ? '' : '태극기를 소지품에서 끌어다 꽂을 수 있다.'));
      if (!S.f.p4) bindLock('p4', [], msg);
      b.appendChild(hintBox('p4'));
    });
  }
  async function flagDrop(i, seatEl) {
    if (S.f.p4) return;
    const msg = $('#boardMsg');
    const bounce = () => { if (seatEl) { seatEl.classList.remove('bounce'); void seatEl.offsetWidth; seatEl.classList.add('bounce'); } };
    if (lockLeft('p4') > 0) { bounce(); return; }
    if ((await sha('seat|' + i)) === H.seat) {
      S.f.p4 = 1; S.f.p4seat = i; solvedKey('p4'); removeItem('flag'); save(); sfx.ok(); refreshZoom();
      await wait(700);
      await say('있어야 했지만 끝내 없었던 자리.');
      addItem('key2');
      return checkStage3();
    }
    bounce();
    const s = BOARD[i];
    if (s === 'fall' || s === 'askew') penalize('p4', '태극기가 핀에 걸려 튕겨 나왔다.');
    else {
      delete lastMsg.p4;
      if (msg) { msg.className = 'msg'; msg.textContent = '이미 다른 카드가 꽂혀 있다.'; }
    }
  }

  async function checkStage3() {
    if (!(S.f.p3 && S.f.p4) || S.f.stage3) return;
    closeLayers();
    await say([['스테드', '"좋소. 이 호소문, 내 신문에 그대로 싣겠소."'], '조판을 마친 호소문이 스테드의 손으로 넘어갔다.'], { dark: true });
    S.f.stage3 = 1; S.rooms = ['hotel', 'editorial', 'corridor']; S.room = 'corridor'; save();
    renderAll(); await enterRoom();
  }

  // ---------- 방 3: 복도 ----------
  OBJ.corridor = {
    async paper() {
      if (!S.inv.includes('telegram')) {
        useful(); await say('이준의 방 문틈 아래로 접힌 종이 한 장이 삐져나와 있다.');
        addItem('telegram'); openItem('telegram');
      } else useless('문틈에는 더 이상 아무것도 없다.');
    },
    endwin() { useless('복도 끝 창가에 낯선 남자가 서 있다. 신문을 펼쳐 들었지만, 눈은 이쪽을 향해 있다.'); },
    door() { goRoom('hotel'); },
    door2() { useless('다른 손님의 방이다. 굳게 닫혀 있다.'); },
  };

  function buildTelegram(b) {
    const ok = !!S.f.mirrored;
    b.appendChild(el('p', { class: 'desc' }, ok ? '거울에 비춰 읽은 종이.' : '글자가 모두 좌우로 뒤집혀 있어 제대로 읽을 수가 없다.'));
    b.appendChild(el('div', { class: 'telegram' + (ok ? '' : ' mirrored'), 'data-drop': 'telegram' }, `<div class="tg-inner">
        <div class="tg-head">일본 대표단 전보 · 번역본</div>
        <div>"조선 특사들이 7월 8일 연설을 준비 중. 장소를 확인하여 보고하라."</div>
        <div class="tg-memo"><span>뢰뎝케눅</span><span class="arrow">←</span></div></div>
        ${ok ? '<div class="tg-note">맨 아래 메모는 다른 필체다. 스테드의 글씨 같다.<br>※ 일본 측 문서라 \'조선\'이라고 적혀 있다.</div>' : ''}`));
    if (ok && !S.f.p5) {
      b.appendChild(answerBox('p5', '메모 해독', async val => {
        const v = normKo(val);
        if ((await sha('tel|' + v)) !== H.tel) return false;
        telegramSolved(v); return true;
      }, { max: 8 }));
    }
    b.appendChild(hintBox('p5'));
  }
  async function telegramSolved(word) {
    S.f.p5 = 1; S.words.tel = word; S.rooms = ['hall']; S.room = 'hall'; save();
    sfx.ok(); closeLayers(); renderHUD();
    await say([['이위종', `"${word}… 각국 기자와 언론인들이 모이는 곳이오. 일본보다 먼저 그곳에 닿아야 하오."`]]);
    renderAll(); await enterRoom();
  }

  // ---------- 최종: 연단 ----------
  OBJ.hall = {
    papers() { useful(); openSpeech(); },
    podium() {
      if (!S.f.p6) return useless('연단 위가 비어 있다. 원고를 먼저 정리해야 한다.');
      useful(); openSpeech();
    },
    reporters() { useless('각국 기자들이 수첩을 펴고 웅성거린다.'); },
    leewj() {
      if (S.f.p6) return say([['이위종', '"일지 맨 끝에 적어둘 말을 남겨야 하오. 우리가 이곳까지 온 이유를."']]);
      return say([['이위종', '"원고가… 누가 이걸 흩어놓은 거요. 어서 추려야 하오."']]);
    },
  };

  function openSpeech() {
    openZoom('흩어진 연설문', b => {
      const solved = !!S.f.p6;
      b.appendChild(el('div', { class: 'summary-tag' }, '연설 내용 요약 · 실제 연설문 인용이 아닙니다'));
      const slots = el('div', { class: 'p6-slots' });
      S.p6.forEach((id, k) => {
        const s = el('div', { class: 'p6-slot drop-hl', 'data-drop': 'p6:' + k }, `<span class="lbl">${k + 1}</span>`);
        if (id) s.appendChild(msEl(id, k, solved));
        slots.appendChild(s);
      });
      b.appendChild(slots);
      if (!solved) {
        const tray = el('div', { class: 'ms-tray drop-hl', 'data-drop': 'p6:tray' });
        MS_TRAY.forEach(id => { if (!S.p6.includes(id)) tray.appendChild(msEl(id, null, false)); });
        b.appendChild(tray);
        const msg = el('div', { class: 'msg' });
        let busy = false;
        const btn = el('button', { class: 'btn', disabled: S.p6.every(Boolean) ? false : 'disabled', on: { click: async () => {
          if (busy || lockLeft('p6') > 0) return; busy = true;
          let wrong = 0, fake = false;
          for (let k = 0; k < S.p6.length; k++) {
            if ((await sha('p6|' + k + '|' + S.p6[k])) !== H.p6[k]) wrong++;
            let real = false;
            for (let j = 0; j < H.p6.length; j++) if ((await sha('p6|' + j + '|' + S.p6[k])) === H.p6[j]) real = true;
            if (!real) fake = true;
          }
          busy = false;
          if (!wrong) { solvedKey('p6'); return speechSolved(); }
          penalize('p6', `${wrong}장이 맞지 않는다.`);
          if (fake && S.phase === 'play') say([['이위종', '"이건 내 원고가 아니오. 누군가 끼워 넣은 것이오."']]);
        } } }, '연설 시작');
        b.appendChild(el('div', { class: 'row', style: 'margin-top:12px' })).appendChild(btn);
        b.appendChild(msg);
        bindLock('p6', [btn], msg, () => !S.p6.every(Boolean));
        b.appendChild(hintBox('p6'));
      } else {
        b.appendChild(el('div', { class: 'symline' }, S.p6.map(id => MS[id].s).join(' ')));
        b.appendChild(el('div', { class: 'sheet', style: 'margin-top:14px' }, `<p style="margin:0"><b>이위종</b> "일지 맨 끝에 적어둘 말을 남겨야 하오. 우리가 이곳까지 온 이유를."</p>`));
        b.appendChild(answerBox('fin', '글자 4개', async val => {
          const v = normUp(val);
          if ((await sha('fin|' + v)) !== H.fin) return false;
          finalSolved(v); return true;
        }, { caps: true, max: 8, label: '기록하기', wrong: '이위종이 고개를 젓는다. "그 말이 아니오."' }));
        b.appendChild(hintBox('fin'));
      }
    });
  }
  function msEl(id, slotK, locked) {
    const m = MS[id];
    const n = el('div', { class: 'ms', style: slotK == null ? `--r:${m.r}deg` : '' }, `${m.t}<span class="sym">${m.s}</span>`);
    if (!locked) {
      dragify(n, {
        onTap: () => { if (slotK != null) { S.p6[slotK] = null; save(); refreshZoom(); } },
        onDrop: key => {
          if (!key || !key.startsWith('p6')) return;
          const from = S.p6.indexOf(id);
          if (key === 'p6:tray') { if (from >= 0) S.p6[from] = null; }
          else { const k = +key.slice(3), prev = S.p6[k]; if (from >= 0) S.p6[from] = prev; S.p6[k] = id; }
          sfx.click(); save(); refreshZoom();
        },
      });
    }
    return n;
  }
  async function speechSolved() {
    S.f.p6 = 1; save(); sfx.ok(); refreshZoom();
    await wait(1000);
    await say([['이위종', '"일지 맨 끝에 적어둘 말을 남겨야 하오. 우리가 이곳까지 온 이유를."']]);
  }
  async function finalSolved(word) {
    S.words.fin = word; S.phase = 'success'; save();
    sfx.ok(); cancelDialog(); closeLayers();
    showSuccess(true);
  }

  // ---------- 엔딩 ----------
  function showSuccess(animate) {
    show('#ending');
    const e = $('#ending'); e.className = 'screen'; e.scrollTop = 0;
    const w = S.words.fin || '', n = cardCount() + realGaps();
    const nth = koNum(n), cnt = koNum(cardCount(), true);
    let d = -1.2;
    const dl = () => animate ? `style="animation-delay:${(d += 1.6).toFixed(1)}s"` : 'style="animation-duration:0s"';
    e.innerHTML = `
      <div class="np paper-tex">
        <div class="np-top"><span>LA HAYE</span><span>JUILLET 1907</span></div>
        <div class="np-mast">Courrier de la Conférence</div>
        <div class="np-head">LA VOIX DE LA CORÉE</div>
        <div class="np-kicker">대한제국 특사, 각국 기자들 앞에 서다</div>
        <div class="np-body">
      <p class="cut" ${dl()}>이위종이 연단에 선다. 그는 통역 없이 유창한 프랑스어로, 황제가 동의하지 않은 조약이 어떻게 강제로 맺어졌는지 이야기한다.</p>
      <p class="cut" ${dl()}>펜을 굴리던 기자들의 손이 멈추고, 연설이 끝나자 박수가 쏟아진다.</p>
      <p class="cut" ${dl()}>회의장의 문은 끝내 열리지 않았다. 하지만 그날만큼은 세계가 대한제국의 목소리를 들었다.</p>
        </div></div>
      <div class="speech reveal" ${dl()}><b>이위종</b>"${w}, 프랑스어로 평화라는 뜻이오. 그리고 ${cnt} 나라가 앉은 회의장에서, 우리 자리는 ${nth} 번째였소. 끝내 아무도 앉지 못한 자리."</div>
      <div class="note-card paper-tex reveal" ${dl()}><div class="muted">📜 이위종이 건넨 쪽지</div><div class="big">${w} ${n}</div>
        <div class="sub">평화(${w})를 논하는 회의에,<br>끝내 채워지지 않은 ${nth} 번째 자리.</div><div class="stamp">特使</div></div>
      <div class="okbox reveal" ${dl()}><strong>✅ 헤이그 탈출 성공!</strong>구글 폼으로 돌아가 이위종이 건넨 쪽지의 내용을 일지에 기록하세요.</div>
      <div class="end-actions reveal" ${dl()}><button class="btn big" id="btnCopy">쪽지 내용 복사하기</button>
        <a class="btn" id="btnNextQ" href="../?q=5">5번 문항 진행하기</a></div>`;
    const focus = () => { const box = e.querySelector(animate ? '.okbox' : '.note-card'); if (box && !e.hidden) box.scrollIntoView({ behavior: animate ? 'smooth' : 'auto', block: 'center' }); };
    if (animate) setTimeout(focus, (d + 0.4) * 1000); else focus();
    $('#btnCopy').onclick = () => copyText(w + n);
  }
  function copyText(t) {
    const done = () => toast('복사했습니다.');
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(t).then(done, () => fallbackCopy(t, done)); return; }
    } catch (e) {}
    fallbackCopy(t, done);
  }
  function fallbackCopy(t, done) {
    try {
      const ta = el('textarea'); ta.value = t; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select(); const ok = document.execCommand('copy'); ta.remove();
      if (ok) done();
    } catch (e) {}
  }

  function fail() {
    S.phase = 'fail'; save();
    cancelDialog(); closeLayers();
    showFail();
  }
  function showFail() {
    show('#ending');
    const e = $('#ending'); e.className = 'screen fail'; e.scrollTop = 0;
    e.innerHTML = `<div class="fail-title reveal">감시망에 걸렸다</div>
      <p class="cut">일본 대표단의 감시망이 일행을 옭아맨다. 연설할 기회는 사라지고, 일행은 회의장 밖에서 아무것도 하지 못한 채 무거운 발걸음으로 귀국길에 오른다.</p>
      <div class="end-actions reveal" style="animation-delay:1.4s"><button class="btn big" id="btnRetry">헤이그 도착 직후로 돌아가기</button></div>`;
    $('#btnRetry').onclick = () => resetAll(false);
  }

  function resetAll(toTitle) {
    cancelDialog(); closeLayers();
    S = fresh();
    if (toTitle) { save(); show('#title'); $('#btnContinue').hidden = true; return; }
    startGame();
  }

  async function startGame() {
    S.phase = 'play'; save();
    show('#game'); renderAll();
    await say(['1907년 6월 25일, 두 달 가까운 여정 끝에 일행은 헤이그에 도착했다.',
      '그러나 만국평화회의 의장인 러시아 대표 넬리도프는 초청을 결정한 것은 네덜란드 정부라며 책임을 떠넘겼고, 네덜란드 정부는 대한제국이 이미 외교권을 넘긴 나라라며 고개를 저었다.',
      '회의장의 문은 열리지 않았다. 이제 문 너머로 목소리를 낼 방법을 찾아야 한다.'], { dark: true });
    await enterRoom();
  }
  async function resume() {
    show('#game'); renderAll();
    if (S.f.p3 && S.f.p4 && !S.f.stage3) return checkStage3();
    await enterRoom();
  }

  // ---------- 감시 타이머 (방 3) ----------
  let last = performance.now(), saveAcc = 0, nextSteps = 0;
  setInterval(() => {
    const now = performance.now(), dt = (now - last) / 1000; last = now;
    if (S.phase !== 'play' || !S.f.timer || S.f.p5 || $('#game').hidden) return;
    S.gauge = Math.min(100, S.gauge + dt * TICK_PER_SEC);
    renderGauge();
    if (now > nextSteps) { if (nextSteps) sfx.steps(); nextSteps = now + 6000 + Math.random() * 5000; }
    saveAcc += dt; if (saveAcc >= 1) { saveAcc = 0; save(); }
    if (S.gauge >= 100) fail();
  }, 250);

  // ---------- 시작 ----------
  function init() {
    initScene();
    $('#zoom .close').onclick = closeZoom;
    $('#itemView .close').onclick = closeItem;
    $('#btnStart').onclick = () => { actx(); if (S.phase === 'play' && !confirm('저장된 진행 상황을 지우고 새로 시작할까요?')) return; S = fresh(); startGame(); };
    $('#btnContinue').onclick = () => { actx(); resume(); };
    $('#btnMenu').onclick = () => { $('#menu').hidden = false; };
    $('#btnMenuClose').onclick = () => { $('#menu').hidden = true; };
    $('#menu').onclick = e => { if (e.target.id === 'menu') $('#menu').hidden = true; };
    const sb = $('#btnSound');
    const drawSound = () => { sb.textContent = '소리: ' + (soundOn ? '켜짐' : '꺼짐'); };
    drawSound();
    sb.onclick = () => { soundOn = !soundOn; try { localStorage.setItem(SKEY, soundOn ? 'on' : 'off'); } catch (e) {} drawSound(); if (soundOn) actx(); };
    $('#btnReset').onclick = () => { if (confirm('진행 상황을 모두 지우고 처음부터 다시 할까요?')) { $('#menu').hidden = true; resetAll(true); } };
    document.addEventListener('visibilitychange', () => { if (document.hidden) save(); });

    if (S.phase === 'success') showSuccess(false);
    else if (S.phase === 'fail') showFail();
    else if (S.phase === 'play') { show('#title'); $('#btnContinue').hidden = false; }
    else show('#title');
  }
  init();
})();
