// ── C2//FLEET client ─────────────────────────────────────────────────────
'use strict';
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const HL = [
  [/\bP1\b/g, 'p1'], [/\bP2\b/g, 'p2'], [/\bP3\b/g, 'p3'],
  [/(secret|credential|passwd|token)/gi, 'hl-c'],
  [/(bypass|bola|idor|sqli|traversal|injection|ssrf|ssti|lfi|unauthorized|redirect|race)/gi, 'hl-x'],
];
function hl(t) {
  let s = esc(t);
  for (const [r, c] of HL) s = s.replace(r, '<span class="' + c + '">$&</span>');
  return s;
}

// les MODES (couverture CWE + descriptions) viennent du serveur : state.data.modes
// GO lance le mode LOCALEMENT via le moteur fleet - aucune IA requise.

// ---------- i18n : langues vivantes, UI Entirement traduite ----------
// un dictionnaire complet par langue ; les langues sans dictionnaire
// tombent sur l'anglais (le registre est extensible)
const LANGS = [
  // code, nom natif, dir
  ['fr', 'Français'], ['en', 'English'], ['es', 'Español'], ['de', 'Deutsch'],
  ['pt', 'Português'], ['it', 'Italiano'], ['ar', 'العربية', 'rtl'], ['zh', '中文'],
  ['ru', 'Русский'], ['ja', '日本語'], ['ko', '한국어'], ['hi', 'हिन्दी'],
  ['nl', 'Nederlands'], ['tr', 'Türkçe'], ['pl', 'Polski'], ['id', 'Bahasa Indonesia'],
  ['sv', 'Svenska'], ['no', 'Norsk'], ['da', 'Dansk'], ['fi', 'Suomi'],
  ['el', 'Ελληνικά'], ['he', 'עברית', 'rtl'], ['fa', 'فارسی', 'rtl'], ['ur', 'اردو', 'rtl'],
  ['hu', 'Magyar'], ['cs', 'Čeština'], ['sk', 'Slovenčina'], ['ro', 'Română'],
  ['bg', 'Български'], ['uk', 'Українська'], ['hr', 'Hrvatski'], ['sr', 'Српски'],
  ['sl', 'Slovenščina'], ['lt', 'Lietuvių'], ['lv', 'Latviešu'], ['et', 'Eesti'],
  ['th', 'ไทย'], ['vi', 'Tiếng Việt'], ['ms', 'Bahasa Melayu'], ['tl', 'Filipino'],
  ['bn', 'বাংলা'], ['ta', 'தமிழ்'], ['te', 'తెలుగు'], ['ml', 'മലയാളം'],
  ['mr', 'मराठी'], ['gu', 'ગુજરાતી'], ['kn', 'ಕನ್ನಡ'], ['pa', 'ਪੰਜਾਬੀ'],
  ['sw', 'Kiswahili'], ['am', 'አማርኛ'], ['ha', 'Hausa'], ['yo', 'Yorùbá'],
  ['zu', 'isiZulu'], ['af', 'Afrikaans'], ['so', 'Soomaali'], ['ti', 'ትግርኛ'],
  ['ca', 'Català'], ['eu', 'Euskara'], ['gl', 'Galego'], ['cy', 'Cymraeg'],
  ['ga', 'Gaeilge'], ['is', 'Íslenska'], ['bs', 'Bosanski'], ['mk', 'Македонски'],
  ['ka', 'ქართული'], ['hy', 'Հայերեն'], ['az', 'Azərbaycanca'], ['kk', 'Қазақша'],
  ['uz', 'Oʻzbekcha'], ['mn', 'Монгол'], ['ne', 'नेपाली'], ['si', 'සිංහල'],
  ['km', 'ខ្មែរ'], ['lo', 'ລາວ'], ['my', 'မြန်မာ'], ['ps', 'پښتو', 'rtl'],
  ['ku', 'Kurdî', 'rtl'], ['sd', 'سنڌي', 'rtl'], ['as', 'অসমীয়া'], ['or', 'ଓଡ଼ିଆ'],
  ['be', 'Беларуская'], ['sq', 'Shqip'],
];
const I18N = {
  fr: {
    pl_title: 'Plan de travail', pl_empty: 'pas encore de plan : lance RECON dans la carte du dessus, les hypotheses tombent ici (statuts persistes)',
    pl_run: 'Lancer', pl_reflect: 'canary reflechi',
    st_do: 'a faire', st_test: 'teste',
    st_signal: 'signal', st_valid: 'valide',
    st_void: 'rien', atk_btn: 'ATTACK',
    atk_start: 'attack de la surface : endpoints, docs exposes, JWT, secrets...', atk_fail: 'attack impossible : lance RECON d abord',
    atk_none: 'aucun signal', atk_findings: 'candidats',
    atk_done: 'ATTACK : {n} candidates P1/P2 injectees dans les findings avec preuve', atk_empty: 'pas encore d attack : lance RECON puis ATTACK - les candidates avec preuve req/res tombent ici',
    navh: 'HUNT', h2hunt: 'HUNT - surface reelle et preuves',
    h_ready: 'pret', h_empty: 'aucune surface connue : lance RECON pour cartographier pages, endpoints API, params, bundles JS et sous-domaines',
    h_fnd: 'Findings du programme', h_nofnd: 'aucun finding sur ce programme',
    rc_btn: 'RECON', rc_start: 'recon de la surface en cours : pages, bundles JS, endpoints, params...',
    rc_done: 'surface cartographiee : endpoints, params et sous-domaines listes dans la carte du programme', rc_fail: 'recon echoue : host injoignable ou scope vide',
    rc_surface: 'surface :', snd_on: 'SON : ON',
    snd_off: 'SON : OFF', snd_ok: 'sons d interface actifs - bibliotheque : clic, onglet, copie, alertes',
    snd_stop: 'sourdine totale activee : plus aucun son C2FF', amb_on: 'AMBIANCE: ON',
    amb_off: 'AMBIANCE: OFF', amb_ok: 'ambiance vivante - la teinte glisse doucement a travers les familles (vert, bleu, jaune...)',
    amb_stop: 'ambiance figee sur le vert d origine', nt_on: 'NOTIFS : ON',
    nt_off: 'NOTIFS : OFF', nt_ok: 'notifications navigateur activees - bip sur P1 et P2',
    nt_denied: 'notifications bloquees par le navigateur : autorise-les dans les reglages du site', term_denied: 'terminal refuse ou indisponible : localhost requis, ou salle OUVERTE en tant qu admin',
    term_p: 'bash reel - history fleches, Ctrl+C interrompt, Ctrl+D ferme', term_restart: 'Reinitialiser',
    navtrm: 'TERM', term_h2: 'Terminal - shell de travail, direct dans la console',
    fl_off: 'FLEET : ARRETE', fl_paused: 'FLEET : EN PAUSE',
    fl_active: 'FLEET : ACTIF ({n} cycles)', fl_last: 'dernier cycle',
    fl_none: 'aucun cycle encore', fl_info: 'intervalle {i} min, budget {b} req/cycle',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Sessions a plusieurs - chasse de groupe, meme hors reseau', tm_p: 'Ouvre une salle partagee : ton groupe voit la flotte, les findings et peut trier en direct. Chat de session dedie ci-dessous. Trois niveaux d\'acces : LOCAL (solo), LAN via OUVRIR AU RESEAU, et MONDE via OUVRIR AU MONDE - un tunnel public (cloudflared si installe) rend le lien d\'invitation valide depuis n\'importe quel reseau, sans expose direct de ta machine. Tout passe par la cle de salle - regenere-la pour virer tout le monde d\'un coup.',
    tm_handle: 'Ton pseudo (16 caracteres max)', tm_save_h: 'Choisir',
    tm_room_ph: 'nom de la salle (ex : c2ff-core)', tm_save: 'Appliquer',
    tm_on: 'SALLE OUVERTE : {r} - {n} en ligne', tm_off: 'MODE TEAM DESACTIVE - session locale solo',
    tm_room: 'Salle', tm_key: 'Cle de salle',
    tm_regen: 'Regenerer la cle', tm_regen_ok: 'nouvelle cle generee - les anciens liens sont morts',
    tm_invite: 'Lien d invitation (a copier vers ton equipe)', tm_copy: 'Copier',
    tm_copied: 'copie dans le presse-papiers', tm_members: 'Membres',
    tm_nobody: 'personne encore - envoie le lien a ton equipe', tm_you: '(toi)',
    tm_here: 'present', tm_saved: 'pseudo enregistre',
    tm_no_handle: 'pseudo vide', tm_cfg_ok: 'salle mise a jour',
    tm_cfg_no: 'echec', tm_live: 'OUVRIR AU RESEAU',
    tm_shore: 'REVENIR LOCAL', tm_need_on: 'active d abord la salle (ON)',
    tm_bind_lan: 'RESEAU : {a}', tm_bind_lo: 'LOCAL : localhost seulement',
    to_team_live: '[GO-LIVE] serveur relance en acces reseau - lien LAN affiche, reconnexion dans 2 s', to_team_shore: 'serveur relance en local (127.0.0.1)',
    tm_tun_open: 'OUVRIR AU MONDE (tunnel)', tm_tun_close: 'FERMER LE TUNNEL',
    tm_tun_wait: 'tunnel public en cours d ouverture (quelques secondes)…', tm_tun_on: 'SESSION OUVERTE AU MONDE : {u} - le lien d invitation marche partout, pas besoin du meme reseau',
    tm_tun_closed: 'tunnel ferme - retour LAN/local', tm_chat_empty: 'canal de session ouvert - les membres de la salle se lisent ici',
    tm_chat_h2: 'Chat de session', tm_msg_ph: 'message vers la session…',
    tm_admin: 'admin', tm_guest: 'invite',
    tm_kick: 'KICK', tm_kick_ok: 'membre exclu de la salle (re-cliquer debloque)',
    tm_role_ok: 'role mis a jour', tm_mic_on: 'ACTIVER LE MICRO',
    tm_mic_off: 'COUPER LE MICRO', tm_mic_denied: 'micro refuse ou inaccessible : le HTTPS est requis (tunnel MONDE ou localhost) et il faut autoriser le micro',
    navf: 'Flotte', navfd: 'Findings',
    navp: 'Programmes', navai: 'IA',
    navc: 'Coordination', st_runs: 'Runs',
    st_beacons: 'Beacons actifs', st_sig: 'Signaux',
    h2f: 'Flotte - tous programmes, agents en course d\'abord', h2fd: 'Base de findings - marquage triage persistant',
    h2eng: 'Moteur flotte - cycles locaux sans tokens', h2prog: 'Programmes - scope, header requis, lancement',
    h2new: 'Nouveau programme', h2ai: 'Agent IA - integration 100% optionnelle',
    h2c: 'Coordination - canal privé', fl_start: 'Démarrer',
    fl_pause: 'Pause', fl_cycle: 'Cycle maintenant',
    f_add: 'Ajouter', f_none: 'aucun signal encore',
    f_ph: 'finding manuel : endpoint + preuve + sev defendable…', st_sig_off: 'signal',
    st_sig_an: 'analyse', st_sig_sub: 'soumis',
    st_sig_dup: 'dup', st_sig_ref: 'refuse',
    st_sig_cl: 'ferme', r_none: 'aucun run detecte',
    r_live: '{n} EN COURSE', r_done: 'TERMINE',
    r_feed: '▽ flux ({n} ev)', r_close: '△ replier',
    p_name_ph: 'Nom du programme (ex: PayPal)', p_hdr_ph: 'header chercheur requis (ex: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domaine1, domaine2, …', p_save: 'Enregistrer',
    p_local: 'module(s), 100% local', ai_p: 'C2FF fonctionne integrement sans IA : les modes sont probes deterministes locaux. Cette passerelle sert uniquement a brancher <b>ton</b> IA (self-hosted ou API) pour l\'analyse ponctuelle d\'un finding : bouton <span style="color:var(--green)">IA »</span> dans FINDINGS, reponse rendue dans COORDINATION. Aucune donnee ne sort de ta machine sans cette configuration.',
    ai_off: 'desactivee', ai_on: 'activee',
    ai_st_off: 'IA DESACTIVEE - le framework tourne a 100% local sans elle', ai_st_ready: 'IA CONNECTEE : {p} · {m}',
    ai_st_inc: 'IA ACTIVEE MAIS INCOMPLETE : baseURL et model requis', ai_url_ph: 'base URL - ex: http://localhost:11434 ou https://api.MonIA.tld/v1',
    ai_model_ph: 'model - ex: llama3.1:8b', ai_key_ph: 'cle API (laisser vide si serveur local)',
    ai_save: 'Enregistrer', ai_test: 'Tester la connexion',
    ai_testing: 'test en cours…', ai_ok: 'OK - reponse : ',
    ai_fail: 'ECHEC : ', ai_note: 'config stockee localement dans data/ai.json - jamais envoyee ailleurs que vers l\'endpoint que tu y mets',
    ch_ph: 'root@c2ff:~# message vers l\'agent d\'analyse…', ch_send: 'Envoyer',
    ch_empty: 'Le canal est ouvert. Tape ici, le monitor me revele a l instant.', ft: '100% local - probes déterministes, sans tokens ni dépendances externes - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ACTIF : cycles locaux toutes 30 min, 0 token.', to_fl_pa: 'FLEET EN PAUSE - reprends quand tu veux.',
    to_fl_cy: 'Cycle immediat lance (budget 60 req).', to_launch: '[GO] mode {m} (CWE {c}) sur {p} - cycle local lance',
    to_ai_ok: 'config enregistree', to_ai_no: 'echec de sauvegarde',
    to_ai_no_cfg: 'IA non configuree - regle-la dans l\'onglet IA', to_ai_head: 'ANALYSE IA',
    to_ai_bad: 'ANALYSE IA echec', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'IA',
    w_launch: '⚡ LANCEMENT', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS et exploits sur la surface detectee', ar_sync: 'SYNC BASES',
    ar_btn: 'MOUVEMENTS', ar_exec: 'EXEC',
    ar_none: 'aucun mouvement : lance RECON d abord, puis SYNC pour charger KEV/EPSS', ar_loading: 'recap des bases en charge...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'programme de demonstration - pas de scan : cree ton programme', pip_noprog: 'aucun programme : cree le tien dans Programmes',
    pip_next: 'etape suivante :', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  en: {
    pl_title: 'Work plan', pl_empty: 'no plan yet: run RECON in the card above, hypotheses land here (statuses persist)',
    pl_run: 'Run', pl_reflect: 'canary reflected',
    st_do: 'todo', st_test: 'tested',
    st_signal: 'signal', st_valid: 'confirmed',
    st_void: 'nothing', atk_btn: 'ATTACK',
    atk_start: 'attacking the surface: endpoints, exposed docs, JWT, secrets...', atk_fail: 'attack failed: run RECON first',
    atk_none: 'no signal', atk_findings: 'candidates',
    atk_done: 'ATTACK: {n} P1/P2 candidates injected into findings with proof', atk_empty: 'no attack yet: run RECON then ATTACK - req/res proof candidates land here',
    navh: 'HUNT', h2hunt: 'HUNT - real surface and findings',
    h_ready: 'ready', h_empty: 'no surface yet: run RECON to map pages, API endpoints, params, JS bundles and subdomains',
    h_fnd: 'Program findings', h_nofnd: 'no findings for this program',
    rc_btn: 'RECON', rc_start: 'recon of the attack surface: pages, JS bundles, endpoints, params...',
    rc_done: 'surface mapped: endpoints, params and subdomains listed in the program card', rc_fail: 'recon failed: host unreachable or empty scope',
    rc_surface: 'surface:', snd_on: 'SOUND: ON',
    snd_off: 'SOUND: OFF', snd_ok: 'interface sounds on - library: click, tab, copy, alerts',
    snd_stop: 'total mute enabled: no more C2FF sounds', amb_on: 'AMBIANCE: ON',
    amb_off: 'AMBIANCE: OFF', amb_ok: 'living ambiance - the hue glides softly across the families (green, blue, yellow...)',
    amb_stop: 'ambiance frozen on the original green', nt_on: 'NOTIFS: ON',
    nt_off: 'NOTIFS: OFF', nt_ok: 'browser notifications enabled - P1 and P2 beeped',
    nt_denied: 'notifications blocked by the browser: allow them in the site settings', term_denied: 'terminal denied or unavailable: localhost required, or an OPEN room as admin',
    term_p: 'real bash - arrow-up history, Ctrl+C interrupts, Ctrl+D closes', term_restart: 'Reset',
    navtrm: 'TERM', term_h2: 'Terminal - working shell, right in the console',
    fl_off: 'FLEET : STOPPED', fl_paused: 'FLEET : PAUSED',
    fl_active: 'FLEET : ACTIVE ({n} cycles)', fl_last: 'last cycle',
    fl_none: 'no cycle yet', fl_info: 'interval {i} min, budget {b} req/cycle',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Group sessions - hunt together, same network or not', tm_p: 'Open a shared room: your group sees the fleet, findings and can triage live. Dedicated session chat below. Three access levels: LOCAL (solo), LAN via OPEN TO NETWORK, and WORLD via OPEN TO WORLD - a public tunnel (cloudflared if installed) makes the invite link valid from any network, without exposing your machine directly. Everything is gated by the room key - regenerate it to kick everyone at once.',
    tm_handle: 'Your handle (16 chars max)', tm_save_h: 'Set',
    tm_room_ph: 'room name (ex: c2ff-core)', tm_save: 'Apply',
    tm_on: 'ROOM OPEN: {r} - {n} online', tm_off: 'TEAM MODE OFF - local solo session',
    tm_room: 'Room', tm_key: 'Room key',
    tm_regen: 'Regenerate key', tm_regen_ok: 'new key generated - old links are dead',
    tm_invite: 'Invite link (copy to your team)', tm_copy: 'Copy',
    tm_copied: 'copied to clipboard', tm_members: 'Members',
    tm_nobody: 'nobody yet - send the invite link', tm_you: '(you)',
    tm_here: 'here', tm_saved: 'handle saved',
    tm_no_handle: 'empty handle', tm_cfg_ok: 'room updated',
    tm_cfg_no: 'failed', tm_live: 'OPEN TO NETWORK',
    tm_shore: 'BACK LOCAL', tm_need_on: 'enable the room first (ON)',
    tm_bind_lan: 'NETWORK: {a}', tm_bind_lo: 'LOCAL: localhost only',
    to_team_live: '[GO-LIVE] server relaunched with network access - LAN link shown, reconnect in 2 s', to_team_shore: 'server relaunched local (127.0.0.1)',
    tm_tun_open: 'OPEN TO WORLD (tunnel)', tm_tun_close: 'CLOSE TUNNEL',
    tm_tun_wait: 'public tunnel coming up (a few seconds)…', tm_tun_on: 'SESSION OPEN TO WORLD: {u} - the invite link works from anywhere, no shared network needed',
    tm_tun_closed: 'tunnel closed - back to LAN/local', tm_chat_empty: 'session channel open - room members read each other here',
    tm_chat_h2: 'Session chat', tm_msg_ph: 'message to the session…',
    tm_admin: 'admin', tm_guest: 'guest',
    tm_kick: 'KICK', tm_kick_ok: 'member removed from the room (click again to unblock)',
    tm_role_ok: 'role updated', tm_mic_on: 'ENABLE MICROPHONE',
    tm_mic_off: 'MUTE MICROPHONE', tm_mic_denied: 'microphone denied or unavailable: HTTPS required (WORLD tunnel or localhost) and permission must be granted',
    navf: 'Fleet', navfd: 'Findings',
    navp: 'Programs', navai: 'AI',
    navc: 'Coordination', st_runs: 'Runs',
    st_beacons: 'Active beacons', st_sig: 'Signals',
    h2f: 'Fleet - all programs, running agents first', h2fd: 'Findings base - persistent triage tagging',
    h2eng: 'Fleet engine - local cycles, no tokens', h2prog: 'Programs - scope, required header, launch',
    h2new: 'New program', h2ai: 'AI agent - fully optional integration',
    h2c: 'Coordination - private channel', fl_start: 'Start',
    fl_pause: 'Pause', fl_cycle: 'Cycle now',
    f_add: 'Add', f_none: 'no signal yet',
    f_ph: 'manual finding: endpoint + proof + defensible severity…', st_sig_off: 'signal',
    st_sig_an: 'analyse', st_sig_sub: 'submitted',
    st_sig_dup: 'dup', st_sig_ref: 'rejected',
    st_sig_cl: 'closed', r_none: 'no run detected',
    r_live: '{n} RUNNING', r_done: 'DONE',
    r_feed: '▽ feed ({n} ev)', r_close: '△ collapse',
    p_name_ph: 'Program name (ex: PayPal)', p_hdr_ph: 'required researcher header (ex: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domain1, domain2, …', p_save: 'Save',
    p_local: 'module(s), 100% local', ai_p: 'C2FF runs entirely without AI: modes are deterministic local probes. This gateway only wires <b>your</b> AI (self-hosted or API) to analyse a single finding on demand: the <span style="color:var(--green)">AI »</span> button in FINDINGS, answer rendered in COORDINATION. No data leaves your machine without this configuration.',
    ai_off: 'disabled', ai_on: 'enabled',
    ai_st_off: 'AI DISABLED - framework runs 100% local without it', ai_st_ready: 'AI CONNECTED: {p} · {m}',
    ai_st_inc: 'AI ENABLED BUT INCOMPLETE: baseURL and model required', ai_url_ph: 'base URL - ex: http://localhost:11434 or https://api.MyAI.tld/v1',
    ai_model_ph: 'model - ex: llama3.1:8b', ai_key_ph: 'API key (leave empty for local servers)',
    ai_save: 'Save', ai_test: 'Test connection',
    ai_testing: 'testing…', ai_ok: 'OK - reply: ',
    ai_fail: 'FAILED: ', ai_note: 'config stored locally in data/ai.json - never sent anywhere but the endpoint you set',
    ch_ph: 'root@c2ff:~# message to the analysis agent…', ch_send: 'Send',
    ch_empty: 'Channel is open. Type here, the monitor wakes me instantly.', ft: '100% local - deterministic probes, no tokens no external deps - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ACTIVE: local cycles every 30 min, 0 tokens.', to_fl_pa: 'FLEET PAUSED - resume whenever you want.',
    to_fl_cy: 'Immediate cycle launched (60 req budget).', to_launch: '[GO] mode {m} (CWE {c}) on {p} - local cycle launched',
    to_ai_ok: 'config saved', to_ai_no: 'save failed',
    to_ai_no_cfg: 'AI not configured - set it in the AI tab', to_ai_head: 'AI ANALYSIS',
    to_ai_bad: 'AI ANALYSIS failed', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ LAUNCH', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS and exploits on the detected surface', ar_sync: 'SYNC BASES',
    ar_btn: 'MOVES', ar_exec: 'EXEC',
    ar_none: 'no moves: run RECON first, then SYNC to load KEV/EPSS', ar_loading: 'recap of bases loading...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demo program - no scans: create yours', pip_noprog: 'no program: create yours in Programs',
    pip_next: 'next step:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  es: {
    pl_title: 'Plan de trabajo', pl_empty: 'sin plan todavía: lanza RECON en la tarjeta de arriba, las hipótesis caen aquí (estados persisten)',
    pl_run: 'Lanzar', pl_reflect: 'canary reflejado',
    st_do: 'por hacer', st_test: 'probado',
    st_signal: 'señal', st_valid: 'confirmado',
    st_void: 'nada', atk_btn: 'ATTACK',
    atk_start: 'atacando la superficie: endpoints, docs expuestos, JWT, secretos...', atk_fail: 'ataque falló: lanza RECON primero',
    atk_none: 'sin señales', atk_findings: 'candidatos',
    atk_done: 'ATTACK: {n} candidatos P1/P2 inyectados en hallazgos con prueba', atk_empty: 'sin ataque todavía: lanza RECON luego ATTACK - los candidatos con prueba req/res caen aquí',
    navh: 'HUNT', h2hunt: 'HUNT - superficie real y hallazgos',
    h_ready: 'listo', h_empty: 'sin superficie todavía: lanza RECON para mapear páginas, endpoints API, parámetros, bundles JS y subdominios',
    h_fnd: 'Hallazgos del programa', h_nofnd: 'sin hallazgos para este programa',
    rc_btn: 'RECON', rc_start: 'recon de la superficie: páginas, bundles JS, endpoints, parámetros...',
    rc_done: 'superficie cartografiada: endpoints, parámetros y subdominios listados en la tarjeta', rc_fail: 'recon falló: host inaccesible o scope vacío',
    rc_surface: 'superficie:', snd_on: 'SONIDO: ON',
    snd_off: 'SONIDO: OFF', snd_ok: 'sonidos de interfaz activos - biblioteca: clic, pestaña, copiar, alertas',
    snd_stop: 'silencio total activado: sin más sonidos de C2FF', amb_on: 'AMBIENTE: ON',
    amb_off: 'AMBIENTE: OFF', amb_ok: 'ambiente vivo - el tono se desliza suavemente entre las familias (verde, azul, amarillo...)',
    amb_stop: 'ambiente congelado en el verde original', nt_on: 'NOTIFS: ACTIVADAS',
    nt_off: 'NOTIFS: DESACTIVADAS', nt_ok: 'notificaciones del navegador activadas - bip en P1 y P2',
    nt_denied: 'notificaciones bloqueadas por el navegador: permítelas en los ajustes del sitio', term_denied: 'terminal denegado o no disponible: se requiere localhost, o sala ABIERTA como admin',
    term_p: 'bash real - historial con flechas, Ctrl+C interrumpe, Ctrl+D cierra', term_restart: 'Reiniciar',
    navtrm: 'TERM', term_h2: 'Terminal - shell de trabajo, en la propia consola',
    fl_off: 'FLOTA : DETENIDA', fl_paused: 'FLOTA : EN PAUSA',
    fl_active: 'FLOTA : ACTIVA ({n} ciclos)', fl_last: 'último ciclo',
    fl_none: 'ningún ciclo aún', fl_info: 'intervalo {i} min, presupuesto {b} req/ciclo',
    sub_ttl: 'command & control framework', navt: 'SESIÓN',
    tm_h2: 'Sesiones de grupo - caza en equipo, con red o sin ella', tm_p: 'Abre una sala compartida: tu grupo ve la flota, los hallazgos y puede triar en directo. Chat de sesión dedicado más abajo. Tres niveles de acceso: LOCAL (solo), LAN vía ABRIR A LA RED, y MUNDO vía ABRIR AL MUNDO - un túnel público (cloudflared si está instalado) hace válido el enlace de invitación desde cualquier red, sin exponer directamente tu máquina. Todo pasa por la clave de sala - regenérala para echar a todos de golpe.',
    tm_handle: 'Tu apodo (16 caracteres máx)', tm_save_h: 'Elegir',
    tm_room_ph: 'nombre de la sala (ej: c2ff-core)', tm_save: 'Aplicar',
    tm_on: 'SALA ABIERTA: {r} - {n} en línea', tm_off: 'MODO EQUIPO DESACTIVADO - sesión local en solitario',
    tm_room: 'Sala', tm_key: 'Clave de sala',
    tm_regen: 'Regenerar clave', tm_regen_ok: 'nueva clave generada - los enlaces antiguos están muertos',
    tm_invite: 'Enlace de invitación (cópialo a tu equipo)', tm_copy: 'Copiar',
    tm_copied: 'copiado al portapapeles', tm_members: 'Miembros',
    tm_nobody: 'todavía nadie - envía el enlace a tu equipo', tm_you: '(tú)',
    tm_here: 'presente', tm_saved: 'apodo guardado',
    tm_no_handle: 'apodo vacío', tm_cfg_ok: 'sala actualizada',
    tm_cfg_no: 'fallo', tm_live: 'ABRIR A LA RED',
    tm_shore: 'VOLVER A LOCAL', tm_need_on: 'activa primero la sala (ON)',
    tm_bind_lan: 'RED: {a}', tm_bind_lo: 'LOCAL: solo localhost',
    to_team_live: '[GO-LIVE] servidor relanzado con acceso de red - enlace LAN mostrado, reconexión en 2 s', to_team_shore: 'servidor relanzado en local (127.0.0.1)',
    tm_tun_open: 'ABRIR AL MUNDO (túnel)', tm_tun_close: 'CERRAR TÚNEL',
    tm_tun_wait: 'túnel público abriéndose (unos segundos)…', tm_tun_on: 'SESIÓN ABIERTA AL MUNDO: {u} - el enlace de invitación funciona desde cualquier red, no necesitas la misma red',
    tm_tun_closed: 'túnel cerrado - de vuelta a LAN/local', tm_chat_empty: 'canal de sesión abierto - los miembros de la sala se leen aquí',
    tm_chat_h2: 'Chat de sesión', tm_msg_ph: 'mensaje a la sesión…',
    tm_admin: 'admin', tm_guest: 'invitado',
    tm_kick: 'KICK', tm_kick_ok: 'miembro expulsado de la sala (otro clic lo desbloquea)',
    tm_role_ok: 'rol actualizado', tm_mic_on: 'ACTIVAR MICRÓFONO',
    tm_mic_off: 'SILENCIAR MICRÓFONO', tm_mic_denied: 'micrófono denegado o no disponible: se requiere HTTPS (túnel MUNDO o localhost) y conceder el permiso',
    navf: 'Flota', navfd: 'Hallazgos',
    navp: 'Programas', navai: 'IA',
    navc: 'Coordinación', st_runs: 'Runs',
    st_beacons: 'Beacons activos', st_sig: 'Señales',
    h2f: 'Flota - todos los programas, agentes en curso primero', h2fd: 'Base de hallazgos - triaje persistente',
    h2eng: 'Motor de flota - ciclos locales sin tokens', h2prog: 'Programas - scope, header requerido, lanzamiento',
    h2new: 'Nuevo programa', h2ai: 'Agente IA - integración 100% opcional',
    h2c: 'Coordinación - canal privado', fl_start: 'Iniciar',
    fl_pause: 'Pausa', fl_cycle: 'Ciclo ahora',
    f_add: 'Añadir', f_none: 'ninguna señal aún',
    f_ph: 'hallazgo manual: endpoint + prueba + severidad defendible…', st_sig_off: 'señal',
    st_sig_an: 'análisis', st_sig_sub: 'enviado',
    st_sig_dup: 'dup', st_sig_ref: 'rechazado',
    st_sig_cl: 'cerrado', r_none: 'ningún run detectado',
    r_live: '{n} EN CURSO', r_done: 'TERMINADO',
    r_feed: '▽ flujo ({n} ev)', r_close: '△ plegar',
    p_name_ph: 'Nombre del programa (ej: PayPal)', p_hdr_ph: 'header requerido (ej: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : dominio1, dominio2, …', p_save: 'Guardar',
    p_local: 'módulo(s), 100% local', ai_p: 'C2FF funciona sin IA: los modos son probes deterministas locales. Esta pasarela solo conecta <b>tu</b> IA (self-hosted o API) para analizar un hallazgo puntual: botón <span style="color:var(--green)">IA »</span> en HALLAZGOS, respuesta en COORDINACIÓN. Ningún dato sale de tu máquina sin esta configuración.',
    ai_off: 'desactivada', ai_on: 'activada',
    ai_st_off: 'IA DESACTIVADA - el framework funciona 100% local sin ella', ai_st_ready: 'IA CONECTADA: {p} · {m}',
    ai_st_inc: 'IA ACTIVADA PERO INCOMPLETA: baseURL y model requeridos', ai_url_ph: 'URL base - ej: http://localhost:11434 o https://api.MiIA.tld/v1',
    ai_model_ph: 'model - ej: llama3.1:8b', ai_key_ph: 'clave API (vacío si servidor local)',
    ai_save: 'Guardar', ai_test: 'Probar conexión',
    ai_testing: 'probando…', ai_ok: 'OK - respuesta: ',
    ai_fail: 'FALLO: ', ai_note: 'config guardada localmente en data/ai.json - nunca se envía a otro sitio que al endpoint que pongas',
    ch_ph: 'root@c2ff:~# mensaje al agente de análisis…', ch_send: 'Enviar',
    ch_empty: 'Canal abierto. Escribe aquí, el monitor me despierta al instante.', ft: '100% local - probes deterministas, sin tokens ni dependencias - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ACTIVO: ciclos locales cada 30 min, 0 tokens.', to_fl_pa: 'FLOTA EN PAUSA - retómala cuando quieras.',
    to_fl_cy: 'Ciclo inmediato lanzado (presupuesto 60 req).', to_launch: '[GO] modo {m} (CWE {c}) sobre {p} - ciclo local lanzado',
    to_ai_ok: 'config guardada', to_ai_no: 'fallo al guardar',
    to_ai_no_cfg: 'IA no configurada - regla en la pestaña IA', to_ai_head: 'ANÁLISIS IA',
    to_ai_bad: 'ANÁLISIS IA falló', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'IA',
    w_launch: '⚡ LANZAMIENTO', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS y exploits sobre la superficie detectada', ar_sync: 'SYNC DE BASES',
    ar_btn: 'MOVIMIENTOS', ar_exec: 'EXEC',
    ar_none: 'sin movimientos: lanza RECON primero, luego SYNC para cargar KEV/EPSS', ar_loading: 'resumen de bases cargando...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'programa de demostracion - no escanea: crea tu programa', pip_noprog: 'ningun programa: crea el tuyo en Programas',
    pip_next: 'etapa siguiente:', fnd_n: 'hallazgos: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  de: {
    pl_title: 'Arbeitsplan', pl_empty: 'noch kein Plan: RECON in der Karte oben starten, Hypothesen landen hier (Status bleiben erhalten)',
    pl_run: 'Starten', pl_reflect: 'Kanary reflektiert',
    st_do: 'offen', st_test: 'getestet',
    st_signal: 'Signal', st_valid: 'bestätigt',
    st_void: 'nichts', atk_btn: 'ATTACK',
    atk_start: 'Angriff auf die Fläche: Endpoints, offene Docs, JWT, Secrets...', atk_fail: 'Angriff fehlgeschlagen: erst RECON starten',
    atk_none: 'kein Signal', atk_findings: 'Kandidaten',
    atk_done: 'ATTACK: {n} P1/P2-Kandidaten mit Beweis in die Funde injiziert', atk_empty: 'noch kein Angriff: erst RECON dann ATTACK - Kandidaten mit req/res-Beweis landen hier',
    navh: 'HUNT', h2hunt: 'HUNT - echte Fläche und Funde',
    h_ready: 'bereit', h_empty: 'noch keine Fläche: RECON starten, um Seiten, API-Endpoints, Parameter, JS-Bundles und Subdomains zu kartieren',
    h_fnd: 'Funde des Programms', h_nofnd: 'keine Funde für dieses Programm',
    rc_btn: 'RECON', rc_start: 'Recon der Angriffsfläche: Seiten, JS-Bundles, Endpoints, Parameter...',
    rc_done: 'Fläche kartiert: Endpoints, Parameter und Subdomains in der Karte gelistet', rc_fail: 'Recon fehlgeschlagen: Host nicht erreichbar oder Scope leer',
    rc_surface: 'Fläche:', snd_on: 'TON: AN',
    snd_off: 'TON: AUS', snd_ok: 'Oberflächenklänge aktiv - Bibliothek: Klick, Tab, Kopieren, Alarme',
    snd_stop: 'Stummschaltung aktiv: keine C2FF-Klänge mehr', amb_on: 'AMBIANCE: AN',
    amb_off: 'AMBIANCE: AUS', amb_ok: 'lebendige Atmosphäre - der Farbton gleitet sanft zwischen den Familien (Grün, Blau, Gelb...)',
    amb_stop: 'Atmosphäre eingefroren auf dem Original-Grün', nt_on: 'NOTIFS: AN',
    nt_off: 'NOTIFS: AUS', nt_ok: 'Browser-Benachrichtigungen aktiv - Piepen bei P1 und P2',
    nt_denied: 'Benachrichtigungen vom Browser blockiert: in den Seiteneinstellungen erlauben', term_denied: 'Terminal verweigert oder nicht verfügbar: localhost nötig, oder offener Raum als Admin',
    term_p: 'echte Bash - Verlauf mit Pfeiltasten, Ctrl+C bricht ab, Ctrl+D schließt', term_restart: 'Zurücksetzen',
    navtrm: 'TERM', term_h2: 'Terminal - Arbeitsshell direkt in der Konsole',
    fl_off: 'FLOTTE : GESTOPPT', fl_paused: 'FLOTTE : PAUSE',
    fl_active: 'FLOTTE : AKTIV ({n} Zyklen)', fl_last: 'letzter Zyklus',
    fl_none: 'noch kein Zyklus', fl_info: 'Intervall {i} Min, Budget {b} Anf/Zyklus',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Gruppensitzungen - gemeinsam jagen, mit oder ohne Netzwerk', tm_p: 'Öffne einen geteilten Raum: Deine Gruppe sieht Flotte und Findings und kann live triagen. Eigener Sitzungs-Chat unten. Drei Zugriffsstufen: LOKAL (Solo), LAN via NETZWERK ÖFFNEN und WELT via WELT ÖFFNEN - ein öffentlicher Tunnel (cloudflared, falls installiert) macht den Einladungslink aus jedem Netz gültig, ohne deine Maschine direkt freizugeben. Alles läuft über den Raum-Schlüssel - neu generieren wirft alle gleichzeitig raus.',
    tm_handle: 'Dein Name (max. 16 Zeichen)', tm_save_h: 'Wählen',
    tm_room_ph: 'Raumname (z.B. c2ff-core)', tm_save: 'Anwenden',
    tm_on: 'RAUM OFFEN: {r} - {n} online', tm_off: 'TEAM-MODUS AUS - lokale Solositzung',
    tm_room: 'Raum', tm_key: 'Raum-Schlüssel',
    tm_regen: 'Schlüssel neu generieren', tm_regen_ok: 'neuer Schlüssel erzeugt - alte Links sind tot',
    tm_invite: 'Einladungslink (an dein Team schicken)', tm_copy: 'Kopieren',
    tm_copied: 'in die Zwischenablage kopiert', tm_members: 'Mitglieder',
    tm_nobody: 'noch niemand - schick den Link an dein Team', tm_you: '(du)',
    tm_here: 'da', tm_saved: 'Name gespeichert',
    tm_no_handle: 'Name leer', tm_cfg_ok: 'Raum aktualisiert',
    tm_cfg_no: 'fehlgeschlagen', tm_live: 'NETZWERK ÖFFNEN',
    tm_shore: 'ZURÜCK LOKAL', tm_need_on: 'erst den Raum aktivieren (ON)',
    tm_bind_lan: 'NETZWERK: {a}', tm_bind_lo: 'LOKAL: nur localhost',
    to_team_live: '[GO-LIVE] Server mit Netzwerkzugang neu gestartet - LAN-Link angezeigt, Wiederverbindung in 2 s', to_team_shore: 'Server lokal neu gestartet (127.0.0.1)',
    tm_tun_open: 'WELT ÖFFNEN (Tunnel)', tm_tun_close: 'TUNNEL SCHLIESSEN',
    tm_tun_wait: 'öffentlicher Tunnel wird aufgebaut (einige Sekunden)…', tm_tun_on: 'SITZUNG FÜR DIE WELT OFFEN: {u} - der Einladungslink funktioniert aus jedem Netz, kein gemeinsames Netz nötig',
    tm_tun_closed: 'Tunnel geschlossen - zurück zu LAN/lokal', tm_chat_empty: 'Sitzungskanal offen - Raummitglieder sehen sich hier gegenseitig',
    tm_chat_h2: 'Sitzungs-Chat', tm_msg_ph: 'Nachricht an die Sitzung…',
    tm_admin: 'admin', tm_guest: 'Gast',
    tm_kick: 'KICK', tm_kick_ok: 'Mitglied aus dem Raum entfernt (nochmals klicken hebt es auf)',
    tm_role_ok: 'Rolle aktualisiert', tm_mic_on: 'MIKROFON AKTIVIEREN',
    tm_mic_off: 'MIKROFON STUMMSCHALTEN', tm_mic_denied: 'Mikrofon verweigert oder nicht verfügbar: HTTPS nötig (WELT-Tunnel oder localhost) und Berechtigung erteilen',
    navf: 'Flotte', navfd: 'Findings',
    navp: 'Programme', navai: 'KI',
    navc: 'Koordination', st_runs: 'Runs',
    st_beacons: 'Aktive Beacons', st_sig: 'Signale',
    h2f: 'Flotte - alle Programme, laufende Agents zuerst', h2fd: 'Findings-Basis - persistentes Triage-Marking',
    h2eng: 'Fleet-Engine - lokale Zyklen ohne Tokens', h2prog: 'Programme - Scope, Header, Start',
    h2new: 'Neues Programm', h2ai: 'KI-Agent - 100% optionale Integration',
    h2c: 'Koordination - privater Kanal', fl_start: 'Starten',
    fl_pause: 'Pause', fl_cycle: 'Jetzt zyklieren',
    f_add: 'Hinzufügen', f_none: 'noch kein Signal',
    f_ph: 'manueller Finding: Endpoint + Beweis + verteidigbare Stufe…', st_sig_off: 'Signal',
    st_sig_an: 'Analyse', st_sig_sub: 'eingereicht',
    st_sig_dup: 'dup', st_sig_ref: 'abgelehnt',
    st_sig_cl: 'geschlossen', r_none: 'kein Run erkannt',
    r_live: '{n} AKTIV', r_done: 'FERTIG',
    r_feed: '▽ Feed ({n} ev)', r_close: '△ zuklappen',
    p_name_ph: 'Programmname (z.B. PayPal)', p_hdr_ph: 'erforderlicher Header (z.B. X-Bug-Bounty: xxx)',
    p_scope_ph: 'Scope : Domain1, Domain2, …', p_save: 'Speichern',
    p_local: 'Modul(e), 100% lokal', ai_p: 'C2FF läuft ohne KI: Modi sind deterministische lokale Probes. Dieses Gateway verbindet nur <b>deine</b> KI (self-hosted oder API) zur punktgenauen Analyse eines Findings: Taste <span style="color:var(--green)">IA »</span> in FINDINGS, Antwort in KOORDINATION. Keine Daten verlassen deine Maschine ohne diese Konfiguration.',
    ai_off: 'deaktiviert', ai_on: 'aktiviert',
    ai_st_off: 'KI DEAKTIVIERT - Framework läuft 100% lokal ohne sie', ai_st_ready: 'KI VERBUNDEN: {p} · {m}',
    ai_st_inc: 'KI AKTIVIERT, ABER UNVOLLSTÄNDIG: baseURL und model nötig', ai_url_ph: 'Basis-URL - z.B. http://localhost:11434 oder https://api.MeineKI.tld/v1',
    ai_model_ph: 'model - z.B. llama3.1:8b', ai_key_ph: 'API-Schlüssel (leer für lokale Server)',
    ai_save: 'Speichern', ai_test: 'Verbindung testen',
    ai_testing: 'teste…', ai_ok: 'OK - Antwort: ',
    ai_fail: 'FEHLER: ', ai_note: 'Config lokal in data/ai.json gespeichert - wird nur an den Endpoint gesendet, den du einträgst',
    ch_ph: 'root@c2ff:~# Nachricht an den Analyse-Agent…', ch_send: 'Senden',
    ch_empty: 'Kanal offen. Schreib hier, der Monitor weckt mich sofort.', ft: '100% lokal - deterministische Probes, ohne Tokens, ohne externe Abhängigkeiten - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE AKTIV: lokale Zyklen alle 30 Min, 0 Tokens.', to_fl_pa: 'FLOTTEN-PAUSE - fortsetzen wann du willst.',
    to_fl_cy: 'Sofort-Zyklus gestartet (Budget 60 Anf).', to_launch: '[GO] Modus {m} (CWE {c}) auf {p} - lokaler Zyklus gestartet',
    to_ai_ok: 'Config gespeichert', to_ai_no: 'Speichern fehlgeschlagen',
    to_ai_no_cfg: 'KI nicht konfiguriert - im KI-Tab einstellen', to_ai_head: 'KI-ANALYSE',
    to_ai_bad: 'KI-ANALYSE fehlgeschlagen', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'KI',
    w_launch: '⚡ START', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS und Exploits auf der erkannten Oberflaeche', ar_sync: 'SYNC DATENBANKEN',
    ar_btn: 'BEWEGUNGEN', ar_exec: 'EXEC',
    ar_none: 'keine Bewegungen: erst RECON ausfuehren, dann SYNC zum Laden von KEV/EPSS', ar_loading: 'Zusammenfassung der Datenbanken laedt...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demo-programm - kein scan: erstelle dein eigenes programm', pip_noprog: 'kein programm: erstelle dein eigenes unter programme',
    pip_next: 'nachste etappe:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  pt: {
    pl_title: 'Plano de trabalho', pl_empty: 'sem plano ainda: rode RECON no cartão acima, as hipóteses caem aqui (estados persistem)',
    pl_run: 'Executar', pl_reflect: 'canary refletido',
    st_do: 'a fazer', st_test: 'testado',
    st_signal: 'sinal', st_valid: 'validado',
    st_void: 'nada', atk_btn: 'ATTACK',
    atk_start: 'atacando a superfície: endpoints, docs expostos, JWT, segredos...', atk_fail: 'ataque falhou: execute RECON primeiro',
    atk_none: 'sem sinais', atk_findings: 'candidatos',
    atk_done: 'ATTACK: {n} candidatos P1/P2 injetados nos achados com prova', atk_empty: 'sem ataque ainda: rode RECON depois ATTACK - candidatos com prova req/res caem aqui',
    navh: 'HUNT', h2hunt: 'HUNT - superfície real e achados',
    h_ready: 'pronto', h_empty: 'sem superfície ainda: execute RECON para mapear páginas, endpoints de API, parâmetros, bundles JS e subdomínios',
    h_fnd: 'Achados do programa', h_nofnd: 'nenhum achado neste programa',
    rc_btn: 'RECON', rc_start: 'recon da superfície: páginas, bundles JS, endpoints, parâmetros...',
    rc_done: 'superfície mapeada: endpoints, parâmetros e subdomínios listados no cartão', rc_fail: 'recon falhou: host inacessível ou escopo vazio',
    rc_surface: 'superfície:', snd_on: 'SOM: ON',
    snd_off: 'SOM: OFF', snd_ok: 'sons de interface ativos - biblioteca: clique, aba, copiar, alertas',
    snd_stop: 'mudo total ativado: sem mais sons do C2FF', amb_on: 'AMBIENTE: ON',
    amb_off: 'AMBIENTE: OFF', amb_ok: 'ambiente vivo - o tom desliza suavemente entre as famílias (verde, azul, amarelo...)',
    amb_stop: 'ambiente congelado no verde original', nt_on: 'NOTIFS: LIGADAS',
    nt_off: 'NOTIFS: DESLIGADAS', nt_ok: 'notificações do navegador ativas - bip em P1 e P2',
    nt_denied: 'notificações bloqueadas pelo navegador: permita-as nas configurações do site', term_denied: 'terminal recusado ou indisponível: localhost necessário, ou sala ABERTA como admin',
    term_p: 'bash real - histórico com setas, Ctrl+C interrompe, Ctrl+D fecha', term_restart: 'Reiniciar',
    navtrm: 'TERM', term_h2: 'Terminal - shell de trabalho, na própria consola',
    fl_off: 'ESQUADRÃO : PARADO', fl_paused: 'ESQUADRÃO : EM PAUSA',
    fl_active: 'ESQUADRÃO : ATIVO ({n} ciclos)', fl_last: 'último ciclo',
    fl_none: 'nenhum ciclo ainda', fl_info: 'intervalo {i} min, orçamento {b} req/ciclo',
    sub_ttl: 'command & control framework', navt: 'SESSÃO',
    tm_h2: 'Sessões em grupo - caça em equipa, com rede ou sem', tm_p: 'Abre uma sala partilhada: o teu grupo vê a frota, os findings e pode triar em direto. Chat de sessão dedicado em baixo. Três níveis de acesso: LOCAL (a solo), LAN via ABRIR À REDE, e MUNDO via ABRIR AO MUNDO - um túnel público (cloudflared se instalado) torna o link de convite válido de qualquer rede, sem expor diretamente a tua máquina. Tudo passa pela chave da sala - regenera-a para expulsar todos de uma vez.',
    tm_handle: 'O teu pseudónimo (16 caracteres máx)', tm_save_h: 'Escolher',
    tm_room_ph: 'nome da sala (ex: c2ff-core)', tm_save: 'Aplicar',
    tm_on: 'SALA ABERTA: {r} - {n} online', tm_off: 'MODO EQUIPA DESATIVADO - sessão local a solo',
    tm_room: 'Sala', tm_key: 'Chave da sala',
    tm_regen: 'Regenerar chave', tm_regen_ok: 'nova chave gerada - os links antigos estão mortos',
    tm_invite: 'Link de convite (copia-o à tua equipa)', tm_copy: 'Copiar',
    tm_copied: 'copiado para a área de transferência', tm_members: 'Membros',
    tm_nobody: 'ninguém ainda - envia o link à tua equipa', tm_you: '(tu)',
    tm_here: 'presente', tm_saved: 'pseudónimo guardado',
    tm_no_handle: 'pseudónimo vazio', tm_cfg_ok: 'sala atualizada',
    tm_cfg_no: 'falhou', tm_live: 'ABRIR À REDE',
    tm_shore: 'VOLTAR LOCAL', tm_need_on: 'ativa primeiro a sala (ON)',
    tm_bind_lan: 'REDE: {a}', tm_bind_lo: 'LOCAL: apenas localhost',
    to_team_live: '[GO-LIVE] servidor relançado com acesso de rede - link LAN mostrado, reconexão em 2 s', to_team_shore: 'servidor relançado em local (127.0.0.1)',
    tm_tun_open: 'ABRIR AO MUNDO (túnel)', tm_tun_close: 'FECHAR TÚNEL',
    tm_tun_wait: 'túnel público a abrir (alguns segundos)…', tm_tun_on: 'SESSÃO ABERTA AO MUNDO: {u} - o link de convite funciona de qualquer rede, não precisas da mesma rede',
    tm_tun_closed: 'túnel fechado - de volta a LAN/local', tm_chat_empty: 'canal de sessão aberto - os membros da leem-se aqui',
    tm_chat_h2: 'Chat de sessão', tm_msg_ph: 'mensagem para a sessão…',
    tm_admin: 'admin', tm_guest: 'convidado',
    tm_kick: 'KICK', tm_kick_ok: 'membro expulso da sala (clicar outra vez desbloqueia)',
    tm_role_ok: 'papel atualizado', tm_mic_on: 'ATIVAR MICROFONE',
    tm_mic_off: 'SILENCIAR MICROFONE', tm_mic_denied: 'microfone recusado ou indisponível: HTTPS obrigatório (túnel MUNDO ou localhost) e conceder a permissão',
    navf: 'Esquadrão', navfd: 'Achados',
    navp: 'Programas', navai: 'IA',
    navc: 'Coordenação', st_runs: 'Runs',
    st_beacons: 'Beacons ativos', st_sig: 'Sinais',
    h2f: 'Esquadrão - todos os programas, agentes em curso primeiro', h2fd: 'Base de achados - triagem persistente',
    h2eng: 'Motor - ciclos locais sem tokens', h2prog: 'Programas - scope, header exigido, lançamento',
    h2new: 'Novo programa', h2ai: 'Agente IA - integração 100% opcional',
    h2c: 'Coordenação - canal privado', fl_start: 'Iniciar',
    fl_pause: 'Pausa', fl_cycle: 'Ciclo agora',
    f_add: 'Adicionar', f_none: 'nenhum sinal ainda',
    f_ph: 'achado manual: endpoint + prova + severidade defensável…', st_sig_off: 'sinal',
    st_sig_an: 'análise', st_sig_sub: 'enviado',
    st_sig_dup: 'dup', st_sig_ref: 'rejeitado',
    st_sig_cl: 'fechado', r_none: 'nenhum run detectado',
    r_live: '{n} EM CURSO', r_done: 'FEITO',
    r_feed: '▽ fluxo ({n} ev)', r_close: '△ recolher',
    p_name_ph: 'Nome do programa (ex: PayPal)', p_hdr_ph: 'header exigido (ex: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domínio1, domínio2, …', p_save: 'Guardar',
    p_local: 'módulo(s), 100% local', ai_p: 'O C2FF funciona sem IA: os modos são probes deterministas locais. Este portal liga apenas <b>a tua</b> IA (self-hosted ou API) para analisar um achado pontual: botão <span style="color:var(--green)">IA »</span> em ACHADOS, resposta em COORDENAÇÃO. Nenhum dado sai da tua máquina sem esta configuração.',
    ai_off: 'desativada', ai_on: 'ativada',
    ai_st_off: 'IA DESATIVADA - framework funciona 100% local sem ela', ai_st_ready: 'IA CONECTADA: {p} · {m}',
    ai_st_inc: 'IA ATIVADA MAS INCOMPLETA: baseURL e model obrigatórios', ai_url_ph: 'URL base - ex: http://localhost:11434 ou https://api.MinhaIA.tld/v1',
    ai_model_ph: 'model - ex: llama3.1:8b', ai_key_ph: 'chave API (vazio se servidor local)',
    ai_save: 'Guardar', ai_test: 'Testar conexão',
    ai_testing: 'a testar…', ai_ok: 'OK - resposta: ',
    ai_fail: 'FALHA: ', ai_note: 'config guardada localmente em data/ai.json - nunca enviada para outro lado além do endpoint que colocares',
    ch_ph: 'root@c2ff:~# mensagem ao agente de análise…', ch_send: 'Enviar',
    ch_empty: 'Canal aberto. Escreve aqui, o monitor acorda-me na hora.', ft: '100% local - probes deterministas, sem tokens nem dependências - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ATIVO: ciclos locais a cada 30 min, 0 tokens.', to_fl_pa: 'ESQUADRÃO EM PAUSA - retoma quando quiseres.',
    to_fl_cy: 'Ciclo imediato lançado (orçamento 60 req).', to_launch: '[GO] modo {m} (CWE {c}) em {p} - ciclo local lançado',
    to_ai_ok: 'config guardada', to_ai_no: 'falha ao guardar',
    to_ai_no_cfg: 'IA não configurada - define no separador IA', to_ai_head: 'ANÁLISE IA',
    to_ai_bad: 'ANÁLISE IA falhou', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'IA',
    w_launch: '⚡ LANÇAMENTO', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS e exploits na superficie detectada', ar_sync: 'SYNC BASES',
    ar_btn: 'MOVIMENTOS', ar_exec: 'EXEC',
    ar_none: 'sem movimentos: execute RECON primeiro, depois SYNC para carregar KEV/EPSS', ar_loading: 'resumo das bases carregando...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'programa de demonstracao - sem scan: crie seu programa', pip_noprog: 'nenhum programa: crie o seu na aba Programas',
    pip_next: 'proxima etapa:', fnd_n: 'descobertas: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  it: {
    pl_title: 'Piano di lavoro', pl_empty: 'nessun piano ancora: avvia RECON nella scheda sopra, le ipotesi arrivano qui (stati persistiti)',
    pl_run: 'Esegui', pl_reflect: 'canary riflesso',
    st_do: 'da fare', st_test: 'testato',
    st_signal: 'segnale', st_valid: 'confermato',
    st_void: 'niente', atk_btn: 'ATTACK',
    atk_start: 'attacco alla superficie: endpoint, documenti esposti, JWT, segreti...', atk_fail: 'attacco fallito: avvia prima RECON',
    atk_none: 'nessun segnale', atk_findings: 'candidati',
    atk_done: 'ATTACK: {n} candidati P1/P2 iniettati nei reperti con prova', atk_empty: 'nessun attacco ancora: avvia RECON poi ATTACK - i candidati con prova req/res arrivano qui',
    navh: 'HUNT', h2hunt: 'HUNT - superficie reale e reperti',
    h_ready: 'pronto', h_empty: 'nessuna superficie: avvia RECON per mappare pagine, endpoint API, parametri, bundle JS e sottodomini',
    h_fnd: 'Reperti del programma', h_nofnd: 'nessun reperto per questo programma',
    rc_btn: 'RECON', rc_start: 'recon della superficie: pagine, bundle JS, endpoint, parametri...',
    rc_done: 'superficie mappata: endpoint, parametri e sottodomini elencati nella scheda', rc_fail: 'recon fallito: host irraggiungibile o scope vuoto',
    rc_surface: 'superficie:', snd_on: 'SUONO: ON',
    snd_off: 'SUONO: OFF', snd_ok: 'suoni interfaccia attivi - libreria: clic, scheda, copia, allarmi',
    snd_stop: 'muto totale attivo: nessun suono C2FF', amb_on: 'AMBIENTE: ON',
    amb_off: 'AMBIENTE: OFF', amb_ok: 'atmosfera viva - la tinta scorre dolcemente tra le famiglie (verde, blu, giallo...)',
    amb_stop: 'atmosfera bloccata sul verde originale', nt_on: 'NOTIFS: ATTIVE',
    nt_off: 'NOTIFS: SPENTE', nt_ok: 'notifiche del browser attive - bip su P1 e P2',
    nt_denied: 'notifiche bloccate dal browser: autorizzale nelle impostazioni del sito', term_denied: 'terminale negato o non disponibile: serve localhost, o stanza APERTA come admin',
    term_p: 'bash reale - cronologia con frecce, Ctrl+C interrompe, Ctrl+D chiude', term_restart: 'Reimposta',
    navtrm: 'TERM', term_h2: 'Terminale - shell di lavoro, direttamente nella console',
    fl_off: 'FLOTTA : ARRESTATO', fl_paused: 'FLOTTA : IN PAUSA',
    fl_active: 'FLOTTA : ATTIVO ({n} cicli)', fl_last: 'ultimo ciclo',
    fl_none: 'nessun ciclo ancora', fl_info: 'intervallo {i} min, budget {b} req/ciclo',
    sub_ttl: 'command & control framework', navt: 'SESSIONE',
    tm_h2: 'Sessioni di gruppo - caccia insieme, con o senza rete', tm_p: 'Apri una stanza condivisa: il tuo gruppo vede la flotta, i findings e può fare triage in diretta. Chat di sessione dedicata qui sotto. Tre livelli di accesso: LOCALE (da solo), LAN tramite APRI ALLA RETE, e MONDO tramite APRI AL MONDO - un tunnel pubblico (cloudflared se installato) rende il link di invito valido da qualsiasi rete, senza esporre direttamente la tua macchina. Tutto passa dalla chiave della stanza - rigenerala per cacciare tutti in una volta.',
    tm_handle: 'Il tuo nickname (16 caratteri max)', tm_save_h: 'Scegli',
    tm_room_ph: 'nome della stanza (es: c2ff-core)', tm_save: 'Applica',
    tm_on: 'STANZA APERTA: {r} - {n} online', tm_off: 'MODALITÀ TEAM DISATTIVATA - sessione locale da soli',
    tm_room: 'Stanza', tm_key: 'Chiave della stanza',
    tm_regen: 'Rigenera chiave', tm_regen_ok: 'nuova chiave generata - i vecchi link sono morti',
    tm_invite: 'Link di invito (copialo al tuo team)', tm_copy: 'Copia',
    tm_copied: 'copiato negli appunti', tm_members: 'Membri',
    tm_nobody: 'ancora nessuno - invia il link al tuo team', tm_you: '(tu)',
    tm_here: 'presente', tm_saved: 'nickname salvato',
    tm_no_handle: 'nickname vuoto', tm_cfg_ok: 'stanza aggiornata',
    tm_cfg_no: 'fallito', tm_live: 'APRI ALLA RETE',
    tm_shore: 'TORNA LOCALE', tm_need_on: 'attiva prima la stanza (ON)',
    tm_bind_lan: 'RETE: {a}', tm_bind_lo: 'LOCALE: solo localhost',
    to_team_live: '[GO-LIVE] server riavviato con accesso di rete - link LAN mostrato, riconnessione in 2 s', to_team_shore: 'server riavviato in locale (127.0.0.1)',
    tm_tun_open: 'APRI AL MONDO (tunnel)', tm_tun_close: 'CHIUDI TUNNEL',
    tm_tun_wait: 'tunnel pubblico in apertura (pochi secondi)…', tm_tun_on: 'SESSIONE APERTA AL MONDO: {u} - il link di invito funziona da qualsiasi rete, non serve la stessa rete',
    tm_tun_closed: 'tunnel chiuso - torna a LAN/locale', tm_chat_empty: 'canale di sessione aperto - i membri della stanza si leggono qui',
    tm_chat_h2: 'Chat della sessione', tm_msg_ph: 'messaggio alla sessione…',
    tm_admin: 'admin', tm_guest: 'ospite',
    tm_kick: 'KICK', tm_kick_ok: 'membro espulso dalla stanza (clicca di nuovo per sbloccare)',
    tm_role_ok: 'ruolo aggiornato', tm_mic_on: 'ATTIVA MICROFONO',
    tm_mic_off: 'SILENZIA MICROFONO', tm_mic_denied: 'microfono negato o non disponibile: serve HTTPS (tunnel MONDO o localhost) e concedere il permesso',
    navf: 'Flotta', navfd: 'Risultati',
    navp: 'Programmi', navai: 'IA',
    navc: 'Coordinamento', st_runs: 'Runs',
    st_beacons: 'Beacon attivi', st_sig: 'Segnali',
    h2f: 'Flotta - tutti i programmi, agenti in corso prima', h2fd: 'Base findings - triaggio persistente',
    h2eng: 'Motore flotta - cicli locali senza token', h2prog: 'Programmi - scope, header richiesto, lancio',
    h2new: 'Nuovo programma', h2ai: 'Agente IA - integrazione 100% opzionale',
    h2c: 'Coordinamento - canale privato', fl_start: 'Avvia',
    fl_pause: 'Pausa', fl_cycle: 'Ciclo ora',
    f_add: 'Aggiungi', f_none: 'nessun segnale ancora',
    f_ph: 'finding manuale: endpoint + prova + gravità difendibile…', st_sig_off: 'segnale',
    st_sig_an: 'analisi', st_sig_sub: 'inviato',
    st_sig_dup: 'dup', st_sig_ref: 'rifiutato',
    st_sig_cl: 'chiuso', r_none: 'nessun run rilevato',
    r_live: '{n} IN CORSO', r_done: 'FINITO',
    r_feed: '▽ flusso ({n} ev)', r_close: '△ chiudi',
    p_name_ph: 'Nome programma (es: PayPal)', p_hdr_ph: 'header richiesto (es: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : dominio1, dominio2, …', p_save: 'Salva',
    p_local: 'modulo/i, 100% locale', ai_p: 'C2FF funziona senza IA: i modi sono probes deterministici locali. Questo gateway collega solo <b>la tua</b> IA (self-hosted o API) per analizzare un finding puntuale: bottone <span style="color:var(--green)">IA »</span> in FINDINGS, risposta in COORDINAMENTO. Nessun dato lascia la tua macchina senza questa configurazione.',
    ai_off: 'disattivata', ai_on: 'attivata',
    ai_st_off: 'IA DISATTIVATA - il framework gira 100% locale senza di essa', ai_st_ready: 'IA CONNESSA: {p} · {m}',
    ai_st_inc: 'IA ATTIVATA MA INCOMPLETA: baseURL e model richiesti', ai_url_ph: 'URL base - es: http://localhost:11434 o https://api.MiaIA.tld/v1',
    ai_model_ph: 'model - es: llama3.1:8b', ai_key_ph: 'chiave API (vuoto se server locale)',
    ai_save: 'Salva', ai_test: 'Testa connessione',
    ai_testing: 'test in corso…', ai_ok: 'OK - risposta: ',
    ai_fail: 'FALLITO: ', ai_note: 'config salvata localmente in data/ai.json - mai inviata altrove se non all\'endpoint che inserisci',
    ch_ph: 'root@c2ff:~# messaggio all\'agente di analisi…', ch_send: 'Invia',
    ch_empty: 'Canale aperto. Scrivi qui, il monitor mi sveglia subito.', ft: '100% locale - probes deterministici, senza token né dipendenze - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ATTIVO: cicli locali ogni 30 min, 0 token.', to_fl_pa: 'FLOTTA IN PAUSA - riprendi quando vuoi.',
    to_fl_cy: 'Ciclo immediato lanciato (budget 60 req).', to_launch: '[GO] modo {m} (CWE {c}) su {p} - ciclo locale lanciato',
    to_ai_ok: 'config salvata', to_ai_no: 'salvataggio fallito',
    to_ai_no_cfg: 'IA non configurata - imposta nel tab IA', to_ai_head: 'ANALISI IA',
    to_ai_bad: 'ANALISI IA fallita', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'IA',
    w_launch: '⚡ LANCIO', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS ed exploit sulla superficie rilevata', ar_sync: 'SYNC BASI',
    ar_btn: 'MOVIMENTI', ar_exec: 'EXEC',
    ar_none: 'nessun movimento: esegui prima RECON, poi SYNC per caricare KEV/EPSS', ar_loading: 'riepilogo delle basi in caricamento...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'programma demo - nessuna scansione: crea il tuo programma', pip_noprog: 'nessun programma: crea il tuo in Programmi',
    pip_next: 'prossima fase:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  ar: {
    pl_title: 'خطة العمل', pl_empty: 'لا خطة بعد : شغّل الاستكشاف في البطاقة أعلاه، الفرضيات تظهر هنا (الحالات محفوظة)',
    pl_run: 'تشغيل', pl_reflect: 'القنارة منعكسة',
    st_do: 'للتنفيذ', st_test: 'مختبَر',
    st_signal: 'إشارة', st_valid: 'مؤكد',
    st_void: 'لا شيء', atk_btn: 'هجوم',
    atk_start: 'مهاجمة السطح : نقاط النهاية، المستندات المكشوفة، JWT، الأسرار...', atk_fail: 'فشل الهجوم : شغّل الاستكشاف أولا',
    atk_none: 'لا إشارات', atk_findings: 'مرشحون',
    atk_done: 'هجوم : {n} مرشح P1/P2 أُدرج في النتائج مع الدليل', atk_empty: 'لا هجوم بعد : شغّل الاستكشاف ثم الهجوم - المرشحون مع دليل req/res يظهرون هنا',
    navh: 'الصيد', h2hunt: 'الصيد - السطح الحقيقي والنتائج',
    h_ready: 'جاهز', h_empty: 'لا يوجد سطح بعد : شغّل الاستكشاف لرسم الصفحات ونقاط النهاية والمعاملات وحزم JS والنطاقات الفرعية',
    h_fnd: 'نتائج البرنامج', h_nofnd: 'لا نتائج لهذا البرنامج',
    rc_btn: 'استكشاف', rc_start: 'استكشاف السطح : الصفحات، حزم JS، نقاط النهاية، المعاملات...',
    rc_done: 'تم رسم السطح : نقاط النهاية والمعاملات والنطاقات الفرعية في البطاقة', rc_fail: 'فشل الاستكشاف : المضيف غير متاح أو النطاق فارغ',
    rc_surface: 'السطح:', snd_on: 'الصوت: تشغيل',
    snd_off: 'الصوت: إيقاف', snd_ok: 'أصوات الواجهة مفعلة - المكتبة: نقر، تبويب، نسخ، تنبيهات',
    snd_stop: 'الصمت الكامل مفعل: لا أصوات C2FF بعد الآن', amb_on: 'الجو: تشغيل',
    amb_off: 'الجو: إيقاف', amb_ok: 'أجواء حية - اللون ينزلق بهدوء بين العائلات (أخضر، أزرق، أصفر...)',
    amb_stop: 'الجو مثبت على الأخضر الأصلي', nt_on: 'الإشعارات: تشغيل',
    nt_off: 'الإشعارات: إيقاف', nt_ok: 'تم تفعيل إشعارات المتصفح - نغمة على P1 و P2',
    nt_denied: 'الإشعارات محجوبة من المتصفح: اسمح بها من إعدادات الموقع', term_denied: 'الطرفية مرفوضة أو غير متاحة: localhost مطلوب، أو غرفة مفتوحة بصلاحية مشرف',
    term_p: 'bash حقيقي - السجل بالأسهم، Ctrl+C يقطع، Ctrl+D يغلق', term_restart: 'إعادة تعيين',
    navtrm: 'طرفية', term_h2: 'الطرفية - قشرة عمل في الكونسول مباشرة',
    fl_off: 'الأسطول : متوقف', fl_paused: 'الأسطول : موقوف مؤقتاً',
    fl_active: 'الأسطول : نشط ({n} دورات)', fl_last: 'آخر دورة',
    fl_none: 'لا دورة بعد', fl_info: 'الفاصل {i} دقيقة، الميزانية {b} طلب/دورة',
    sub_ttl: 'command & control framework', navt: 'جلسة',
    tm_h2: 'جلسات جماعية - الصيد معاً، بنفس الشبكة أو بدونها', tm_p: 'افتح غرفة مشتركة: يرى فريقك الأسطول والنتائج ويمكنه الفرز مباشرة. دردشة جلسة مخصصة بالأسفل. ثلاثة مستويات وصول: محلي (فردي)، الشبكة عبر فتح للشبكة، والعالم عبر فتح للعالم - نفق عام (cloudflared إذا كان مثبتاً) يجعل رابط الدعوة صالحاً من أي شبكة دون تعريض جهازك مباشرة. كل شيء يمر بمفتاح الغرفة - أعد توليده لطرد الجميع دفعة واحدة.',
    tm_handle: 'اسمك (16 حرفاً كحد أقصى)', tm_save_h: 'اختيار',
    tm_room_ph: 'اسم الغرفة (مثال: c2ff-core)', tm_save: 'تطبيق',
    tm_on: 'الغرفة مفتوحة: {r} - {n} متصل', tm_off: 'وضع الفريق متوقف - جلسة محلية فردية',
    tm_room: 'الغرفة', tm_key: 'مفتاح الغرفة',
    tm_regen: 'إعادة توليد المفتاح', tm_regen_ok: 'تم توليد مفتاح جديد - الروابط القديمة ماتت',
    tm_invite: 'رابط الدعوة (انسخه لفريقك)', tm_copy: 'نسخ',
    tm_copied: 'تم النسخ إلى الحافظة', tm_members: 'الأعضاء',
    tm_nobody: 'لا أحد بعد - أرسل الرابط لفريقك', tm_you: '(أنت)',
    tm_here: 'حاضر', tm_saved: 'تم حفظ الاسم',
    tm_no_handle: 'الاسم فارغ', tm_cfg_ok: 'تم تحديث الغرفة',
    tm_cfg_no: 'فشل', tm_live: 'فتح للشبكة',
    tm_shore: 'عودة محلي', tm_need_on: 'فعّل الغرفة أولاً (ON)',
    tm_bind_lan: 'الشبكة: {a}', tm_bind_lo: 'محلي: localhost فقط',
    to_team_live: '[GO-LIVE] أعد تشغيل الخادم بصلاحية الشبكة - رابط الشبكة ظاهر، إعادة الاتصال خلال 2 ث', to_team_shore: 'أُعيد تشغيل الخادم محلياً (127.0.0.1)',
    tm_tun_open: 'فتح للعالم (نفق)', tm_tun_close: 'إغلاق النفق',
    tm_tun_wait: 'النفق العام يُفتح الآن (بضع ثوانٍ)…', tm_tun_on: 'الجلسة مفتوحة للعالم: {u} - رابط الدعوة يعمل من أي شبكة، لا حاجة لنفس الشبكة',
    tm_tun_closed: 'أُغلق النفق - عودة إلى الشبكة/المحلي', tm_chat_empty: 'قناة الجلسة مفتوحة - أعضاء الغرفة يتحدثون هنا',
    tm_chat_h2: 'دردشة الجلسة', tm_msg_ph: 'رسالة إلى الجلسة…',
    tm_admin: 'مشرف', tm_guest: 'ضيف',
    tm_kick: 'طرد', tm_kick_ok: 'طُرد العضو من الغرفة (اضغط مجدداً للفك)',
    tm_role_ok: 'تم تحديث الدور', tm_mic_on: 'تشغيل الميكروفون',
    tm_mic_off: 'كتم الميكروفون', tm_mic_denied: 'الميكروفون مرفوض أو غير متاح: HTTPS مطلوب (نفق عالم أو localhost) مع منح الإذن',
    navf: 'الأسطول', navfd: 'النتائج',
    navp: 'البرامج', navai: 'الذكاء الاصطناعي',
    navc: 'التنسيق', st_runs: 'الجلسات',
    st_beacons: 'منارات نشطة', st_sig: 'إشارات',
    h2f: 'الأسطول - كل البرامج، الوكلاء الجاريون أولاً', h2fd: 'قاعدة النتائج - فرز مستمر',
    h2eng: 'محرك الأسطول - دورات محلية بدون رموز', h2prog: 'البرامج - النطاق، الترويسة المطلوبة، الإطلاق',
    h2new: 'برنامج جديد', h2ai: 'وكيل الذكاء الاصطناعي - تكامل اختياري 100%',
    h2c: 'التنسيق - قناة خاصة', fl_start: 'تشغيل',
    fl_pause: 'إيقاف مؤقت', fl_cycle: 'دورة الآن',
    f_add: 'إضافة', f_none: 'لا إشارة بعد',
    f_ph: 'نتيجة يدوية: نقطة نهاية + إثبات + خطورة دفاعية…', st_sig_off: 'إشارة',
    st_sig_an: 'تحليل', st_sig_sub: 'مُرسل',
    st_sig_dup: 'مكرر', st_sig_ref: 'مرفوض',
    st_sig_cl: 'مغلق', r_none: 'لا جلسة مرصودة',
    r_live: '{n} جارية', r_done: 'منتهية',
    r_feed: '▽ التدفق ({n} حدث)', r_close: '△ طي',
    p_name_ph: 'اسم البرنامج (مثال: PayPal)', p_hdr_ph: 'الترويسة المطلوبة (مثال: X-Bug-Bounty: xxx)',
    p_scope_ph: 'النطاق : نطاق1، نطاق2، …', p_save: 'حفظ',
    p_local: 'وحدة/وحدات، 100% محلي', ai_p: 'يعمل C2FF بدون ذكاء اصطناعي: الأوضاع probes محلية حتمية. هذا الربط يوصل <b>ذكاءك الاصطناعي</b> (محلي أو API) فقط لتحليل نتيجة عابرة: زر <span style="color:var(--green)">IA »</span> في النتائج، والإجابة في التنسيق. لا تخرج أي بيانات من جهازك بدون هذا الإعداد.',
    ai_off: 'معطلة', ai_on: 'مفعلة',
    ai_st_off: 'الذكاء الاصطناعي معطل - الإطار يعمل 100% محلياً بدونه', ai_st_ready: 'الذكاء الاصطناعي متصل: {p} · {m}',
    ai_st_inc: 'مفعل لكن غير مكتمل: baseURL و model مطلوبان', ai_url_ph: 'URL الأساس - مثال: http://localhost:11434 أو https://api.MyAI.tld/v1',
    ai_model_ph: 'model - مثال: llama3.1:8b', ai_key_ph: 'المفتاح API (فارغ للخوادم المحلية)',
    ai_save: 'حفظ', ai_test: 'اختبار الاتصال',
    ai_testing: 'جارٍ الاختبار…', ai_ok: 'تم - الرد: ',
    ai_fail: 'فشل: ', ai_note: 'الإعداد محفوظ محلياً في data/ai.json - لا يُرسل أبداً إلا للنقطة التي تحددها',
    ch_ph: 'root@c2ff:~# رسالة إلى وكيل التحليل…', ch_send: 'إرسال',
    ch_empty: 'القناة مفتوحة. اكتب هنا، المراقب يوقظني فوراً.', ft: 'محلي 100% - probes حتمية، بدون رموز أو تبعيات - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE نشط: دورات محلية كل 30 دقيقة، 0 رموز.', to_fl_pa: 'الأسطول موقوف مؤقتاً - استئنف متى شئت.',
    to_fl_cy: 'دورة فورية أُطلقت (ميزانية 60 طلب).', to_launch: '[GO] وضع {m} (CWE {c}) على {p} - دورة محلية أُطلقت',
    to_ai_ok: 'تم حفظ الإعداد', to_ai_no: 'فشل الحفظ',
    to_ai_no_cfg: 'الذكاء الاصطناعي غير مهيأ - اضبطه في تبويب IA', to_ai_head: 'تحليل الذكاء الاصطناعي',
    to_ai_bad: 'فشل التحليل', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'IA',
    w_launch: '⚡ إطلاق', navar: 'أرسنال',
    ar_h2: 'ARSENAL - CVE وEPSS والاستغلالات على السطح المكتشف', ar_sync: 'SYNC القواعد',
    ar_btn: 'الحركات', ar_exec: 'EXEC',
    ar_none: 'لا حركات: شغّل RECON أولا ثم SYNC لتحميل KEV/EPSS', ar_loading: 'ملخص القواعد قيد التحميل...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'برنامج تجريبي - لا فحص: أنشئ برنامجك', pip_noprog: 'لا يوجد برنامج: أنشئ برنامجك في تبويب البرامج',
    pip_next: 'المرحلة التالية:', fnd_n: 'الاكتشافات: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  zh: {
    pl_title: '工作计划', pl_empty: '尚无计划 : 在上方卡片运行侦察，假设落在这里（状态持久保留）',
    pl_run: '运行', pl_reflect: '金丝雀被反射',
    st_do: '待办', st_test: '已测试',
    st_signal: '信号', st_valid: '已确认',
    st_void: '无结果', atk_btn: '攻击',
    atk_start: '正在攻击攻击面：端点、暴露文档、JWT、机密...', atk_fail: '攻击失败 : 先运行侦察',
    atk_none: '无信号', atk_findings: '候选',
    atk_done: '攻击 : {n} 个 P1/P2 候选已带证据注入发现', atk_empty: '尚未攻击 : 先侦察再攻击 - 带 req/res 证据的候选落在这里',
    navh: '狩猎', h2hunt: '狩猎 - 真实攻击面与发现',
    h_ready: '就绪', h_empty: '尚无攻击面 : 运行侦察以绘制页面、API 端点、参数、JS 包和子域',
    h_fnd: '项目发现', h_nofnd: '该项目暂无发现',
    rc_btn: '侦察', rc_start: '正在侦察攻击面：页面、JS 包、端点、参数...',
    rc_done: '攻击面已测绘：端点、参数和子域已列入卡片', rc_fail: '侦察失败：主机不可达或范围 为空',
    rc_surface: '攻击面:', snd_on: '音效: 开',
    snd_off: '音效: 关', snd_ok: '界面音效已开启 - 音效库：点击、切换、复制、警报',
    snd_stop: '已完全静音：不再有 C2FF 音效', amb_on: '氛围: 开',
    amb_off: '氛围: 关', amb_ok: '活氛围 - 色调在色系间缓缓流动 (绿, 蓝, 黄...)',
    amb_stop: '氛围固定在原版绿', nt_on: '通知: 开',
    nt_off: '通知: 关', nt_ok: '浏览器通知已开启 - P1 和 P2 会有提示音',
    nt_denied: '浏览器通知被拦截：请在站点设置中允许', term_denied: '终端被拒绝或不可用：需要 localhost，或以管理员身份开启房间',
    term_p: '真实 bash - 方向键调历史, Ctrl+C 中断, Ctrl+D 关闭', term_restart: '重置',
    navtrm: '终端', term_h2: '终端 - 直接在控制台里的工作 shell',
    fl_off: '舰队 : 已停止', fl_paused: '舰队 : 已暂停',
    fl_active: '舰队 : 活跃（{n} 个循环）', fl_last: '上次循环',
    fl_none: '尚无循环', fl_info: '间隔 {i} 分钟，预算 {b} 请求/循环',
    sub_ttl: 'command & control framework', navt: '会话',
    tm_h2: '团队会话 - 无论是否同一网络都可协同狩猎', tm_p: '打开一个共享房间：你的团队可以查看舰队、发现并实时分诊。下方是专用会话聊天。三种访问级别：本地（单人）、局域网（开启网络）和全世界（开启世界通道）- 公共隧道（如已安装 cloudflared）让邀请链接在任何网络都有效，无需直接暴露你的机器。一切通过房间密钥控制 - 重新生成即可一次性踢出所有人。',
    tm_handle: '你的昵称（最多16字符）', tm_save_h: '选择',
    tm_room_ph: '房间名（如：c2ff-core）', tm_save: '应用',
    tm_on: '房间已开放：{r} - {n} 人在线', tm_off: '团队模式已关闭 - 本地单人会话',
    tm_room: '房间', tm_key: '房间密钥',
    tm_regen: '重新生成密钥', tm_regen_ok: '新密钥已生成 - 旧链接全部失效',
    tm_invite: '邀请链接（复制给团队）', tm_copy: '复制',
    tm_copied: '已复制到剪贴板', tm_members: '成员',
    tm_nobody: '还没有人 - 把链接发给你的团队', tm_you: '(你)',
    tm_here: '在线', tm_saved: '昵称已保存',
    tm_no_handle: '昵称为空', tm_cfg_ok: '房间已更新',
    tm_cfg_no: '失败', tm_live: '开启局域网',
    tm_shore: '回到本地', tm_need_on: '请先开启房间 (ON)',
    tm_bind_lan: '局域网: {a}', tm_bind_lo: '本地：仅 localhost',
    to_team_live: '[GO-LIVE] 服务器已以网络访问权限重启 - 显示局域网链接，2 秒后重连', to_team_shore: '服务器已以本地模式重启 (127.0.0.1)',
    tm_tun_open: '开启世界通道 (隧道)', tm_tun_close: '关闭隧道',
    tm_tun_wait: '公共隧道正在开启（需要几秒）…', tm_tun_on: '会话已向全世界开放：{u} - 邀请链接在任何网络都有效，无需同一网络',
    tm_tun_closed: '隧道已关闭 - 返回局域网/本地', tm_chat_empty: '会话频道已开启 - 房间成员在此互聊',
    tm_chat_h2: '会话聊天', tm_msg_ph: '发送到会话的消息…',
    tm_admin: '管理员', tm_guest: '访客',
    tm_kick: '踢出', tm_kick_ok: '成员已被移出房间（再次点击可解除）',
    tm_role_ok: '角色已更新', tm_mic_on: '开启麦克风',
    tm_mic_off: '关闭麦克风', tm_mic_denied: '麦克风被拒绝或不可用：需要 HTTPS（世界隧道或 localhost）并授权麦克风',
    navf: '舰队', navfd: '发现',
    navp: '项目', navai: 'AI',
    navc: '协同', st_runs: 'Runs',
    st_beacons: '活跃信标', st_sig: '信号',
    h2f: '舰队 - 全部项目，运行中的代理优先', h2fd: '发现库 - 持久分诊标记',
    h2eng: '舰队引擎 - 本地循环，零令牌', h2prog: '项目 - 范围、必需头、启动',
    h2new: '新建项目', h2ai: 'AI 代理 - 100% 可选集成',
    h2c: '协同 - 私人频道', fl_start: '启动',
    fl_pause: '暂停', fl_cycle: '立即循环',
    f_add: '添加', f_none: '尚无信号',
    f_ph: '手动发现：端点 + 证据 + 可辩护等级…', st_sig_off: '信号',
    st_sig_an: '分析', st_sig_sub: '已提交',
    st_sig_dup: '重复', st_sig_ref: '已拒绝',
    st_sig_cl: '已关闭', r_none: '未检测到运行',
    r_live: '{n} 运行中', r_done: '已完成',
    r_feed: '▽ 流 ({n} 条)', r_close: '△ 收起',
    p_name_ph: '项目名（如 PayPal）', p_hdr_ph: '必需的研究头（如 X-Bug-Bounty: xxx）',
    p_scope_ph: '范围：域名1、域名2、…', p_save: '保存',
    p_local: '个模块，100% 本地', ai_p: 'C2FF 无需 AI 即可运行：各模式均为确定性的本地探测器。此网关仅用于接入<b>你自己的</b> AI（自托管或 API）按需分析单条发现：在"发现"页点 <span style="color:var(--green)">IA »</span>，回复呈现在"协同"页。没有此配置，任何数据都不会离开你的机器。',
    ai_off: '已禁用', ai_on: '已启用',
    ai_st_off: 'AI 已禁用 - 框架在无 AI 的情况下 100% 本地运行', ai_st_ready: 'AI 已连接：{p} · {m}',
    ai_st_inc: 'AI 已启用但不完整：需要 baseURL 和 model', ai_url_ph: '基础 URL - 如 http://localhost:11434 或 https://api.MyAI.tld/v1',
    ai_model_ph: 'model - 如 llama3.1:8b', ai_key_ph: 'API 密钥（本地服务器留空）',
    ai_save: '保存', ai_test: '测试连接',
    ai_testing: '测试中…', ai_ok: '成功 - 回复：',
    ai_fail: '失败：', ai_note: '配置存储在本地 data/ai.json - 只发送到你填写的端点',
    ch_ph: 'root@c2ff:~# 发送给分析代理的消息…', ch_send: '发送',
    ch_empty: '频道已开启。在此输入，监视器立刻唤醒我。', ft: '100% 本地 - 确定性探测，无令牌无外部依赖 - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE 已激活：每 30 分钟本地循环，0 令牌。', to_fl_pa: '舰队已暂停 - 随时恢复。',
    to_fl_cy: '立即循环已启动（预算 60 请求）。', to_launch: '[GO] 模式 {m}（CWE {c}）作用于 {p} - 本地循环已启动',
    to_ai_ok: '配置已保存', to_ai_no: '保存失败',
    to_ai_no_cfg: 'AI 未配置 - 请在 AI 标签页设置', to_ai_head: 'AI 分析',
    to_ai_bad: 'AI 分析失败', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ 发射', navar: '军械库',
    ar_h2: 'ARSENAL - 已检测面上的 CVE、EPSS 和 EXPLOITS', ar_sync: 'SYNC 数据库',
    ar_btn: '动作', ar_exec: 'EXEC',
    ar_none: '暂无动作：先运行 RECON，再用 SYNC 加载 KEV/EPSS', ar_loading: '数据库摘要加载中...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: '演示程序 - 无法扫描: 请创建你自己的程序', pip_noprog: '暂无程序: 请在程序选项卡中创建你的程序',
    pip_next: '下一步:', fnd_n: '发现: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  ru: {
    pl_title: 'План работы', pl_empty: 'плана ещё нет : запустите рекон в карточке выше, гипотезы упадут здесь (статусы сохраняются)',
    pl_run: 'Запуск', pl_reflect: 'канарейка отражена',
    st_do: 'к выполнению', st_test: 'проверено',
    st_signal: 'сигнал', st_valid: 'подтверждено',
    st_void: 'пусто', atk_btn: 'АТАКА',
    atk_start: 'атака на поверхность: эндпоинты, открытые доки, JWT, секреты...', atk_fail: 'атака не удалась : сначала запустите рекон',
    atk_none: 'сигналов нет', atk_findings: 'кандидаты',
    atk_done: 'АТАКА : {n} кандидатов P1/P2 влиты в находки с доказательством', atk_empty: 'атаки ещё не было : сначала рекон потом атака - кандидаты с доказательством req/res падают здесь',
    navh: 'ХАНТ', h2hunt: 'ХАНТ - реальная поверхность и находки',
    h_ready: 'готов', h_empty: 'поверхности нет : запустите рекон, чтобы собрать страницы, эндпоинты API, параметры, JS-бандлы и субдомены',
    h_fnd: 'Находки программы', h_nofnd: 'нет находок по этой программе',
    rc_btn: 'РЕКОН', rc_start: 'рекон поверхности: страницы, JS-бандлы, эндпоинты, параметры...',
    rc_done: 'поверхность закартографирована: эндпоинты, параметры и субдомены в карточке', rc_fail: 'рекон не удался: хост недоступен или scope пуст',
    rc_surface: 'поверхность:', snd_on: 'ЗВУК: ВКЛ',
    snd_off: 'ЗВУК: ВЫКЛ', snd_ok: 'звуки интерфейса включены - библиотека: клик, вкладка, копирование, алерты',
    snd_stop: 'полная тишина включена: звуков C2FF больше нет', amb_on: 'АТМОСФЕРА: ВКЛ',
    amb_off: 'АТМОСФЕРА: ВЫКЛ', amb_ok: 'живая атмосфера - оттенок плавно перетекает между семьями (зелёный, синий, жёлтый...)',
    amb_stop: 'атмосфера заморожена на оригинальном зелёном', nt_on: 'NOTIFS: ВКЛ',
    nt_off: 'NOTIFS: ВЫКЛ', nt_ok: 'уведомления браузера включены - писк на P1 и P2',
    nt_denied: 'уведомления заблокированы браузером: разрешите в настройках сайта', term_denied: 'терминал отклонён или недоступен: нужен localhost или открытая комната с ролью админ',
    term_p: 'настоящий bash - история стрелками, Ctrl+C прерывает, Ctrl+D закрывает', term_restart: 'Сброс',
    navtrm: 'ТЕРМИНАЛ', term_h2: 'Терминал - рабочая оболочка прямо в консоли',
    fl_off: 'ФЛОТ : ОСТАНОВЛЕН', fl_paused: 'ФЛОТ : НА ПАУЗЕ',
    fl_active: 'ФЛОТ : АКТИВЕН ({n} цикл.)', fl_last: 'последний цикл',
    fl_none: 'циклов пока нет', fl_info: 'интервал {i} мин, бюджет {b} запр/цикл',
    sub_ttl: 'command & control framework', navt: 'СЕССИЯ',
    tm_h2: 'Групповые сессии - совместная охота, с сетью или без', tm_p: 'Открой общую комнату: твоя группа видит флот, находки и может сортировать в прямом эфире. Ниже - отдельный чат сессии. Три уровня доступа: ЛОКАЛЬНО (соло), LAN через ОТКРЫТЬ В СЕТЬ, и МИР через ОТКРЫТЬ В МИР - публичный туннель (cloudflared, если установлен) делает ссылку-приглашение действительной из любой сети, не раскрывая твою машину напрямую. Всё работает через ключ комнаты - перегенерируй его, чтобы выкинуть всех сразу.',
    tm_handle: 'Твой ник (макс. 16 символов)', tm_save_h: 'Выбрать',
    tm_room_ph: 'имя комнаты (напр.: c2ff-core)', tm_save: 'Применить',
    tm_on: 'КОМНАТА ОТКРЫТА: {r} - {n} в сети', tm_off: 'РЕЖИМ КОМАНДЫ ВЫКЛЮЧЕН - локальная соло-сессия',
    tm_room: 'Комната', tm_key: 'Ключ комнаты',
    tm_regen: 'Перегенерировать ключ', tm_regen_ok: 'новый ключ сгенерирован - старые ссылки мертвы',
    tm_invite: 'Ссылка-приглашение (скопируй команде)', tm_copy: 'Копировать',
    tm_copied: 'скопировано в буфер обмена', tm_members: 'Участники',
    tm_nobody: 'пока никого - отправь ссылку команде', tm_you: '(ты)',
    tm_here: 'на месте', tm_saved: 'ник сохранён',
    tm_no_handle: 'пустой ник', tm_cfg_ok: 'комната обновлена',
    tm_cfg_no: 'сбой', tm_live: 'ОТКРЫТЬ В СЕТЬ',
    tm_shore: 'ВЕРНУТЬ ЛОКАЛЬНО', tm_need_on: 'сначала включи комнату (ON)',
    tm_bind_lan: 'СЕТЬ: {a}', tm_bind_lo: 'ЛОКАЛЬНО: только localhost',
    to_team_live: '[GO-LIVE] сервер перезапущен с сетевым доступом - показана LAN-ссылка, переподключение через 2 с', to_team_shore: 'сервер перезапущен локально (127.0.0.1)',
    tm_tun_open: 'ОТКРЫТЬ В МИР (туннель)', tm_tun_close: 'ЗАКРЫТЬ ТУННЕЛЬ',
    tm_tun_wait: 'публичный туннель открывается (несколько секунд)…', tm_tun_on: 'СЕССИЯ ОТКРЫТА В МИР: {u} - ссылка-приглашение работает из любой сети, общая сеть не нужна',
    tm_tun_closed: 'туннель закрыт - возврат к LAN/локально', tm_chat_empty: 'канал сессии открыт - участники комнаты общаются здесь',
    tm_chat_h2: 'Чат сессии', tm_msg_ph: 'сообщение в сессию…',
    tm_admin: 'админ', tm_guest: 'гость',
    tm_kick: 'КИК', tm_kick_ok: 'участник удалён из комнаты (щёлкни снова, чтобы разблокировать)',
    tm_role_ok: 'роль обновлена', tm_mic_on: 'ВКЛЮЧИТЬ МИКРОФОН',
    tm_mic_off: 'ВЫКЛЮЧИТЬ МИКРОФОН', tm_mic_denied: 'микрофон отклонён или недоступен: требуется HTTPS (мировой туннель или localhost) и разрешение доступа',
    navf: 'Флот', navfd: 'Находки',
    navp: 'Программы', navai: 'ИИ',
    navc: 'Координация', st_runs: 'Runs',
    st_beacons: 'Активные маяки', st_sig: 'Сигналы',
    h2f: 'Флот - все программы, активные агенты первыми', h2fd: 'База находок - постоянная триажная разметка',
    h2eng: 'Движок флота - локальные циклы без токенов', h2prog: 'Программы - скоуп, требуемый заголовок, запуск',
    h2new: 'Новая программа', h2ai: 'ИИ-агент - 100% опциональная интеграция',
    h2c: 'Координация - частный канал', fl_start: 'Запустить',
    fl_pause: 'Пауза', fl_cycle: 'Цикл сейчас',
    f_add: 'Добавить', f_none: 'сигналов пока нет',
    f_ph: 'ручная находка: эндпоинт + доказательство + защищаемая степень…', st_sig_off: 'сигнал',
    st_sig_an: 'анализ', st_sig_sub: 'отправлено',
    st_sig_dup: 'дубль', st_sig_ref: 'отклонено',
    st_sig_cl: 'закрыто', r_none: 'запусков не обнаружено',
    r_live: '{n} В РАБОТЕ', r_done: 'ЗАВЕРШЕНО',
    r_feed: '▽ поток ({n} соб)', r_close: '△ свернуть',
    p_name_ph: 'Название программы (напр. PayPal)', p_hdr_ph: 'требуемый заголовок (напр. X-Bug-Bounty: xxx)',
    p_scope_ph: 'скоуп : домен1, домен2, …', p_save: 'Сохранить',
    p_local: 'модуль/модулей, 100% локально', ai_p: 'C2FF работает без ИИ: режимы - детерминированные локальные пробы. Этот шлюз только подключает <b>ваш</b> ИИ (self-hosted или API) для точечного анализа находки: кнопка <span style="color:var(--green)">IA »</span> в НАХОДКАХ, ответ в КООРДИНАЦИИ. Никакие данные не покидают вашу машину без этой настройки.',
    ai_off: 'отключен', ai_on: 'включен',
    ai_st_off: 'ИИ ОТКЛЮЧЕН - фреймворк работает 100% локально без него', ai_st_ready: 'ИИ ПОДКЛЮЧЕН: {p} · {m}',
    ai_st_inc: 'ИИ ВКЛЮЧЕН, НО НЕ ПОЛОН: baseURL и model обязательны', ai_url_ph: 'базовый URL - напр. http://localhost:11434 или https://api.MyAI.tld/v1',
    ai_model_ph: 'model - напр. llama3.1:8b', ai_key_ph: 'API-ключ (пусто для локальных серверов)',
    ai_save: 'Сохранить', ai_test: 'Проверить связь',
    ai_testing: 'проверка…', ai_ok: 'OK - ответ: ',
    ai_fail: 'СБОЙ: ', ai_note: 'конфиг хранится локально в data/ai.json - отправляется только на указанный вами эндпоинт',
    ch_ph: 'root@c2ff:~# сообщение агенту анализа…', ch_send: 'Отправить',
    ch_empty: 'Канал открыт. Пишите здесь, монитор будит меня мгновенно.', ft: '100% локально - детерминированные пробы, без токенов и внешних зависимостей - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE АКТИВЕН: локальные циклы каждые 30 мин, 0 токенов.', to_fl_pa: 'ФЛОТ НА ПАУЗЕ - возобновите когда захотите.',
    to_fl_cy: 'Немедленный цикл запущен (бюджет 60 запр).', to_launch: '[GO] режим {m} (CWE {c}) на {p} - локальный цикл запущен',
    to_ai_ok: 'конфиг сохранен', to_ai_no: 'не удалось сохранить',
    to_ai_no_cfg: 'ИИ не настроен - настройте во вкладке ИИ', to_ai_head: 'ИИ-АНАЛИЗ',
    to_ai_bad: 'ИИ-АНАЛИЗ не удался', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'IA',
    w_launch: '⚡ ЗАПУСК', navar: 'Арсенал',
    ar_h2: 'ARSENAL - CVE, EPSS и эксплойты на обнаруженной поверхности', ar_sync: 'SYNC БАЗ',
    ar_btn: 'ДВИЖЕНИЯ', ar_exec: 'EXEC',
    ar_none: 'нет движений: сначала запустите RECON, затем SYNC для загрузки KEV/EPSS', ar_loading: 'сводка баз загружается...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'демо-программа - сканирование недоступно: создай свою программу', pip_noprog: 'нет программ: создай свою во вкладке Программы',
    pip_next: 'следующий этап:', fnd_n: 'находки: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  ja: {
    pl_title: '作業プラン', pl_empty: 'プラン未作成 : 上のカードで偵察を実行すると仮説がここに落ちる（ステータスは保持）',
    pl_run: '実行', pl_reflect: 'カナリア反映あり',
    st_do: '未着手', st_test: 'テスト済み',
    st_signal: 'シグナル', st_valid: '確定',
    st_void: '無し', atk_btn: 'アタック',
    atk_start: '攻撃面を攻撃中 : エンドポイント、公開ドキュメント、JWT、シークレット...', atk_fail: '攻撃失敗 : まず偵察を実行',
    atk_none: '信号なし', atk_findings: '候補',
    atk_done: 'アタック : {n} 件の P1/P2 候補を証明付きで発見へ注入', atk_empty: 'アタック未実行 : 偵察→アタックの順で - req/res 証明付き候補がここに落ちる',
    navh: 'ハント', h2hunt: 'ハント - 実攻撃面と発見',
    h_ready: '準備完了', h_empty: '攻撃面なし : 偵察を実行してページ・APIエンドポイント・パラメータ・JSバンドル・サブドメインを収集',
    h_fnd: 'プログラムの発見', h_nofnd: 'このプログラムの発見なし',
    rc_btn: 'RECON', rc_start: '攻撃面を偵察中：ページ、JSバンドル、エンドポイント、パラメータ...',
    rc_done: '攻撃面をマッピング完了：エンドポイント・パラメータ・サブドメインをカードに表示', rc_fail: '偵察失敗：ホストに到達不可能かスコープが空',
    rc_surface: '攻撃面:', snd_on: 'サウンド: ON',
    snd_off: 'サウンド: OFF', snd_ok: 'UIサウンド有効 - ライブラリ: クリック、タブ、コピー、アラート',
    snd_stop: '完全ミュート中: C2FFのサウンドは鳴りません', amb_on: '雰囲気: ON',
    amb_off: '雰囲気: OFF', amb_ok: '生きた雰囲気 - 色調がゆっくりと色調間を流れる (緑, 青, 黄...)',
    amb_stop: '雰囲気を元の緑に固定', nt_on: '通知: ON',
    nt_off: '通知: OFF', nt_ok: 'ブラウザ通知を有効化 - P1 と P2 でビープ',
    nt_denied: '通知がブラウザでブロック：サイト設定で許可して', term_denied: 'ターミナル拒否か利用不可：localhost か管理者としてルームを開く必要あり',
    term_p: '本物の bash - 履歴は矢印キー、Ctrl+C で中断、Ctrl+D で終了', term_restart: 'リセット',
    navtrm: 'ターミナル', term_h2: 'ターミナル - コンソール内の作業シェル',
    fl_off: '艦隊 : 停止', fl_paused: '艦隊 : 一時停止',
    fl_active: '艦隊 : 稼働中（{n} サイクル）', fl_last: '前回のサイクル',
    fl_none: 'サイクルなし', fl_info: '間隔 {i} 分、予算 {b} リクエスト/サイクル',
    sub_ttl: 'command & control framework', navt: 'セッション',
    tm_h2: 'グループセッション - ネットワークに関係なく一緒に狩る', tm_p: '共有ルームを開こう：チームはフリートと発見を見て、リアルタイムでトリアージできます。下部に専用セッションチャット。アクセスは3段階：ローカル（ソロ）、LAN（ネットワークへ開く）、ワールド（世界へ開く）- 公開トンネル（cloudflared があれば）で招待リンクがどのネットワークからも有効になり、マシンを直接露出しません。すべてルームキーで保護 - 再生成すれば全員を一括で締め出せます。',
    tm_handle: 'ハンドル名（最大16文字）', tm_save_h: '設定',
    tm_room_ph: 'ルーム名（例：c2ff-core）', tm_save: '適用',
    tm_on: 'ルーム開放中：{r} - {n} 人オンライン', tm_off: 'チームモード無効 - ローカルのソロセッション',
    tm_room: 'ルーム', tm_key: 'ルームキー',
    tm_regen: 'キー再生成', tm_regen_ok: '新しいキーを生成 - 古いリンクは無効',
    tm_invite: '招待リンク（チームにコピー）', tm_copy: 'コピー',
    tm_copied: 'クリップボードにコピーしました', tm_members: 'メンバー',
    tm_nobody: 'まだ誰もいない - チームにリンクを送って', tm_you: '(あなた)',
    tm_here: '参加中', tm_saved: 'ハンドル名を保存しました',
    tm_no_handle: 'ハンドル名が空です', tm_cfg_ok: 'ルームを更新しました',
    tm_cfg_no: '失敗', tm_live: 'ネットワークへ開く',
    tm_shore: 'ローカルへ戻す', tm_need_on: '先にルームを ON にして',
    tm_bind_lan: 'ネットワーク: {a}', tm_bind_lo: 'ローカル：localhost のみ',
    to_team_live: '[GO-LIVE] ネットワークアクセス付きでサーバー再起動 - LANリンク表示、2 秒で再接続', to_team_shore: 'ローカル (127.0.0.1) でサーバー再起動',
    tm_tun_open: '世界へ開く（トンネル）', tm_tun_close: 'トンネルを閉じる',
    tm_tun_wait: '公開トンネルを準備中（数秒）…', tm_tun_on: 'セッションを世界へ公開中：{u} - 招待リンクはどのネットワークからでも有効、同じネットワークは不要',
    tm_tun_closed: 'トンネルを閉じました - LAN/ローカルに戻る', tm_chat_empty: 'セッションチャンネル開放中 - ルームメンバー同士がここで話せます',
    tm_chat_h2: 'セッションチャット', tm_msg_ph: 'セッションへのメッセージ…',
    tm_admin: '管理者', tm_guest: 'ゲスト',
    tm_kick: 'キック', tm_kick_ok: 'メンバーを退室させました（もう一度クリックで解除）',
    tm_role_ok: '役割を更新しました', tm_mic_on: 'マイクを有効化',
    tm_mic_off: 'マイクをミュート', tm_mic_denied: 'マイクが拒否か利用不可：HTTPS（ワールドトンネルか localhost）と権限の許可が必要',
    navf: '艦隊', navfd: '発見',
    navp: 'プログラム', navai: 'AI',
    navc: '調整', st_runs: 'Runs',
    st_beacons: '稼働ビーコン', st_sig: 'シグナル',
    h2f: '艦隊 - 全プログラム、稼働中エージェント優先', h2fd: '発見ベース - 永続トリアージ',
    h2eng: '艦隊エンジン - トークン不要のローカルサイクル', h2prog: 'プログラム - スコープ、必須ヘッダー、起動',
    h2new: '新規プログラム', h2ai: 'AI エージェント - 100%オプション統合',
    h2c: '調整 - プライベートチャネル', fl_start: '開始',
    fl_pause: '一時停止', fl_cycle: '今すぐサイクル',
    f_add: '追加', f_none: 'シグナルなし',
    f_ph: '手動発見：エンドポイント + 証拠 + 立証可能な深刻度…', st_sig_off: 'シグナル',
    st_sig_an: '分析', st_sig_sub: '提出済',
    st_sig_dup: '重複', st_sig_ref: '却下',
    st_sig_cl: '完了', r_none: 'ラン検出なし',
    r_live: '{n} 稼働中', r_done: '完了',
    r_feed: '▽ フィード ({n} 件)', r_close: '△ 閉じる',
    p_name_ph: 'プログラム名（例: PayPal）', p_hdr_ph: '必須ヘッダー（例: X-Bug-Bounty: xxx）',
    p_scope_ph: 'スコープ：ドメイン1、ドメイン2、…', p_save: '保存',
    p_local: 'モジュール、100% ローカル', ai_p: 'C2FF は AI なしで動作します：モードは決定論的なローカル探査。このゲートウェイは<b>あなたの</b> AI（セルフホストまたは API）を接続し、単一の発見を都度分析するだけです：発見ページの <span style="color:var(--green)">IA »</span> ボタン、回答は調整ページへ。この設定がなければ何もあなたのマシンから出ません。',
    ai_off: '無効', ai_on: '有効',
    ai_st_off: 'AI 無効 - フレームワークは AI なしで 100% ローカル稼働', ai_st_ready: 'AI 接続済み: {p} · {m}',
    ai_st_inc: 'AI 有効だが不完全：baseURL と model が必要', ai_url_ph: 'ベース URL - 例: http://localhost:11434 または https://api.MyAI.tld/v1',
    ai_model_ph: 'model - 例: llama3.1:8b', ai_key_ph: 'API キー（ローカルなら空欄）',
    ai_save: '保存', ai_test: '接続テスト',
    ai_testing: 'テスト中…', ai_ok: 'OK - 返信：',
    ai_fail: '失敗：', ai_note: '設定は data/ai.json にローカル保存 - 指定したエンドポイント以外には送信されません',
    ch_ph: 'root@c2ff:~# 解析エージェントへのメッセージ…', ch_send: '送信',
    ch_empty: 'チャネル開放。ここに入力すれば、モニターが即座に俺を起こす。', ft: '100% ローカル - 決定論的プローブ、トークンも外部依存もなし - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE 稼働：30分ごとにローカルサイクル、トークン 0。', to_fl_pa: '艦隊一時停止 - いつでも再開。',
    to_fl_cy: '即時サイクル起動（予算 60 リクエスト）。', to_launch: '[GO] モード {m}（CWE {c}）を {p} に実行 - ローカルサイクル起動',
    to_ai_ok: '設定を保存しました', to_ai_no: '保存に失敗',
    to_ai_no_cfg: 'AI 未設定 - AI タブで設定してください', to_ai_head: 'AI 分析',
    to_ai_bad: 'AI 分析に失敗', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ 発射', navar: 'アーセナル',
    ar_h2: 'ARSENAL - 検出面の CVE、EPSS とエクスプロイト', ar_sync: 'SYNC データベース',
    ar_btn: 'ムーブ', ar_exec: 'EXEC',
    ar_none: 'ムーブなし: まず RECON を実行し、次に SYNC で KEV/EPSS をロード', ar_loading: 'データベースの概要を読み込み中...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'デモプログラム - スキャン不可: 自分のプログラムを作成してください', pip_noprog: 'プログラムなし: プログラムタブで自分のプログラムを作成してください',
    pip_next: '次のステップ:', fnd_n: '検出: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  ko: {
    pl_title: '작업 플랜', pl_empty: '플랜 없음 : 위 카드에서 정찰 실행, 가설이 여기에 떨어짐 (상태 유지)',
    pl_run: '실행', pl_reflect: '카나리아 반사됨',
    st_do: '할 일', st_test: '테스트됨',
    st_signal: '시그널', st_valid: '확정',
    st_void: '없음', atk_btn: '어택',
    atk_start: '공격면 공격 중: 엔드포인트, 노출 문서, JWT, 시크릿...', atk_fail: '어택 실패 : 먼저 정찰 실행',
    atk_none: '신호 없음', atk_findings: '후보',
    atk_done: '어택 : P1/P2 후보 {n} 건 증명과 함께 발견에 주입됨', atk_empty: '아직 어택 없음 : 정찰 후 어택 - req/res 증거가 붙은 후보가 여기에 떨어짐',
    navh: '헌트', h2hunt: '헌트 - 실제 공격면과 발견',
    h_ready: '준비됨', h_empty: '공격면 없음 : 정찰을 실행해 페이지·API 엔드포인트·파라미터·JS 번들·서브도메인을 수집',
    h_fnd: '프로그램 발견', h_nofnd: '이 프로그램의 발견 없음',
    rc_btn: '정찰', rc_start: '공격면 정찰 중: 페이지, JS 번들, 엔드포인트, 파라미터...',
    rc_done: '공격면 매핑 완료: 엔드포인트·파라미터·서브도메인이 카드에 표시됨', rc_fail: '정찰 실패: 호스트 접근 불가 또는 범위 비어 있음',
    rc_surface: '공격면:', snd_on: '사운드: ON',
    snd_off: '사운드: OFF', snd_ok: 'UI 사운드 켜짐 - 라이브러리: 클릭, 탭, 복사, 알림음',
    snd_stop: '전체 음소거 켜짐: C2FF 사운드 없음', amb_on: '분위기: ON',
    amb_off: '분위기: OFF', amb_ok: '살아있는 분위기 - 색조가 색상군 사이를 부드럽게 흐름 (녹색, 파랑, 노랑...)',
    amb_stop: '분위기가 원래 녹색에 고정', nt_on: '알림: ON',
    nt_off: '알림: OFF', nt_ok: '브라우저 알림 활성화 - P1과 P2에 삑',
    nt_denied: '알림이 브라우저에서 차단됨: 사이트 설정에서 허용', term_denied: '터미널 거부 또는 불가: localhost 또는 관리자로 연 방 필요',
    term_p: '진짜 bash - 화살표로 히스토리, Ctrl+C 중단, Ctrl+D 종료', term_restart: '초기화',
    navtrm: '터미널', term_h2: '터미널 - 콘솔 안의 작업 셸',
    fl_off: '함대 : 정지', fl_paused: '함대 : 일시정지',
    fl_active: '함대 : 활성 ({n} 주기)', fl_last: '마지막 주기',
    fl_none: '아직 주기 없음', fl_info: '간격 {i}분, 예산 {b} 요청/주기',
    sub_ttl: 'command & control framework', navt: '세션',
    tm_h2: '그룹 세션 - 네트워크가 달라도 함께 사냥', tm_p: '공유 방을 열어라: 팀이 플릿과 발견 항목을 보고 실시간으로 분류할 수 있다. 아래에 전용 세션 채팅. 접근은 3단계: 로컬(솔로), LAN(네트워크로 열기), 월드(세계로 열기) - 공개 터널(cloudflared 설치 시)이 초대 링크를 어떤 네트워크에서도 유효하게 하며 기계를 직접 노출하지 않는다. 모든 것은 방 키로 통제 - 재생성하면 모두를 한 번에 내보낸다.',
    tm_handle: '닉네임 (최대 16자)', tm_save_h: '선택',
    tm_room_ph: '방 이름 (예: c2ff-core)', tm_save: '적용',
    tm_on: '방 열림: {r} - {n} 접속 중', tm_off: '팀 모드 꺼짐 - 로컬 솔로 세션',
    tm_room: '방', tm_key: '방 키',
    tm_regen: '키 재생성', tm_regen_ok: '새 키 생성됨 - 이전 링크는 죽음',
    tm_invite: '초대 링크 (팀에 복사)', tm_copy: '복사',
    tm_copied: '클립보드에 복사됨', tm_members: '멤버',
    tm_nobody: '아직 아무도 없다 - 팀에 링크를 보내라', tm_you: '(너)',
    tm_here: '접속 중', tm_saved: '닉네임 저장됨',
    tm_no_handle: '닉네임이 비었다', tm_cfg_ok: '방 갱신됨',
    tm_cfg_no: '실패', tm_live: '네트워크로 열기',
    tm_shore: '로컬로 복귀', tm_need_on: '먼저 방을 켜라 (ON)',
    tm_bind_lan: '네트워크: {a}', tm_bind_lo: '로컬: localhost 만',
    to_team_live: '[GO-LIVE] 서버가 네트워크 접근으로 재시작됨 - LAN 링크 표시, 2초 후 재접속', to_team_shore: '서버가 로컬 (127.0.0.1) 로 재시작됨',
    tm_tun_open: '세계로 열기 (터널)', tm_tun_close: '터널 닫기',
    tm_tun_wait: '공개 터널 여는 중 (몇 초)…', tm_tun_on: '세션이 세계로 열림: {u} - 초대 링크는 어떤 네트워크에서든 유효, 같은 네트워크 불필요',
    tm_tun_closed: '터널 닫힘 - LAN/로컬로 복귀', tm_chat_empty: '세션 채널 열림 - 방 멤버들이 여기서 대화한다',
    tm_chat_h2: '세션 채팅', tm_msg_ph: '세션으로 보낼 메시지…',
    tm_admin: '관리자', tm_guest: '게스트',
    tm_kick: '강퇴', tm_kick_ok: '멤버가 방에서 내보내짐 (다시 클릭하면 해제)',
    tm_role_ok: '역할 갱신됨', tm_mic_on: '마이크 켜기',
    tm_mic_off: '마이크 끄기', tm_mic_denied: '마이크 거부 또는 불가: HTTPS(월드 터널 또는 localhost)와 권한 허용 필요',
    navf: '함대', navfd: '발견',
    navp: '프로그램', navai: 'AI',
    navc: '조정', st_runs: 'Runs',
    st_beacons: '활성 비컨', st_sig: '신호',
    h2f: '함대 - 전체 프로그램, 실행 중 에이전트 우선', h2fd: '발견 기반 - 지속 트리아지 태깅',
    h2eng: '함대 엔진 - 토큰 없는 로컬 주기', h2prog: '프로그램 - 스코프, 필수 헤더, 실행',
    h2new: '새 프로그램', h2ai: 'AI 에이전트 - 100% 선택적 통합',
    h2c: '조정 - 사설 채널', fl_start: '시작',
    fl_pause: '일시정지', fl_cycle: '지금 주기',
    f_add: '추가', f_none: '아직 신호 없음',
    f_ph: '수동 발견: 엔드포인트 + 증거 + 방어 가능한 심각도…', st_sig_off: '시그널',
    st_sig_an: '분석', st_sig_sub: '제출됨',
    st_sig_dup: '중복', st_sig_ref: '거부됨',
    st_sig_cl: '닫힘', r_none: '감지된 런 없음',
    r_live: '{n} 실행 중', r_done: '완료',
    r_feed: '▽ 피드 ({n} 건)', r_close: '△ 접기',
    p_name_ph: '프로그램 이름 (예: PayPal)', p_hdr_ph: '필수 헤더 (예: X-Bug-Bounty: xxx)',
    p_scope_ph: '스코프 : 도메인1, 도메인2, …', p_save: '저장',
    p_local: '모듈, 100% 로컬', ai_p: 'C2FF는 AI 없이 작동합니다: 모드는 결정론적 로컬 프로브. 이 게이트웨이는 단일 발견을 즉석 분석하기 위해 <b>당신의</b> AI(자체 호스팅 또는 API)만 연결합니다: 발견 탭의 <span style="color:var(--green)">IA »</span> 버튼, 답변은 조정 탭에. 이 설정이 없으면 어떤 데이터도 당신의 머신을 떠나지 않습니다.',
    ai_off: '비활성', ai_on: '활성',
    ai_st_off: 'AI 비활성 - 프레임워크는 AI 없이 100% 로컬 작동', ai_st_ready: 'AI 연결됨: {p} · {m}',
    ai_st_inc: 'AI 활성화했지만 불완전: baseURL과 model 필요', ai_url_ph: '베이스 URL - 예: http://localhost:11434 또는 https://api.MyAI.tld/v1',
    ai_model_ph: 'model - 예: llama3.1:8b', ai_key_ph: 'API 키 (로컬 서버면 비움)',
    ai_save: '저장', ai_test: '연결 테스트',
    ai_testing: '테스트 중…', ai_ok: 'OK - 응답: ',
    ai_fail: '실패: ', ai_note: '설정은 data/ai.json에 로컬 저장 - 지정한 엔드포인트 외에는 절대 전송 안 됨',
    ch_ph: 'root@c2ff:~# 분석 에이전트에게 메시지…', ch_send: '전송',
    ch_empty: '채널이 열렸다. 여기 쓰면 모니터가 즉시 깨운다.', ft: '100% 로컬 - 결정론적 프로브, 토큰·외부 의존성 없음 - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE 활성: 30분마다 로컬 주기, 토큰 0.', to_fl_pa: '함대 일시정지 - 원할 때 재개.',
    to_fl_cy: '즉시 주기 실행 (예산 60 요청).', to_launch: '[GO] 모드 {m} (CWE {c}) → {p} - 로컬 주기 실행',
    to_ai_ok: '설정 저장됨', to_ai_no: '저장 실패',
    to_ai_no_cfg: 'AI 미설정 - AI 탭에서 설정하세요', to_ai_head: 'AI 분석',
    to_ai_bad: 'AI 분석 실패', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ 발사', navar: '아스널',
    ar_h2: 'ARSENAL - 감지된 표면의 CVE, EPSS 및 익스플로잇', ar_sync: 'SYNC 데이터베이스',
    ar_btn: '무브', ar_exec: 'EXEC',
    ar_none: '무브 없음: 먼저 RECON 실행, 그 다음 SYNC로 KEV/EPSS 로드', ar_loading: '데이터베이스 요약 로드 중...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: '데모 프로그램 - 스캔 불가: 직접 프로그램을 만드세요', pip_noprog: '프로그램 없음: 프로그램 탭에서 직접 만드세요',
    pip_next: '다음 단계:', fnd_n: '발견: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  hi: {
    pl_title: 'कार्य योजना', pl_empty: 'कोई योजना नहीं : ऊपर कार्ड में रीकॉन चलाएँ, परिकल्पनाएँ यहाँ आती हैं (स्टेटस संरक्षित रहते हैं)',
    pl_run: 'चलाएँ', pl_reflect: 'कैनरी रिफ्लेक्टेड',
    st_do: 'करना है', st_test: 'टेस्टेड',
    st_signal: 'सिग्नल', st_valid: 'पक्का',
    st_void: 'कुछ नहीं', atk_btn: 'अटैक',
    atk_start: 'सरफ़ेस पर अटैक : एंडपॉइंट, खुले डॉक्स, JWT, सीक्रेट्स...', atk_fail: 'अटैक विफल : पहले रीकॉन चलाएँ',
    atk_none: 'कोई सिग्नल नहीं', atk_findings: 'कैंडिडेट',
    atk_done: 'अटैक : {n} P1/P2 कैंडिडेट प्रमाण सहित फाइंडिंग्स में डाले गए', atk_empty: 'अटैक बाकी : पहले रीकॉन फिर अटैक - req/res प्रमाण वाले कैंडिडेट यहाँ आते हैं',
    navh: 'हंट', h2hunt: 'हंट - वास्तविक सरफ़ेस और फाइंडिंग्स',
    h_ready: 'तैयार', h_empty: 'कोई सरफ़ेस नहीं : पेज, API एंडपॉइंट, पैरामीटर, JS बंडल और सबडोमेन मैप करने के लिए रीकॉन चलाएँ',
    h_fnd: 'प्रोग्राम फाइंडिंग्स', h_nofnd: 'इस प्रोग्राम की कोई फाइंडिंग नहीं',
    rc_btn: 'रीकॉन', rc_start: 'सरफ़ेस रीकॉन चल रहा है : पेज, JS बंडल, एंडपॉइंट, पैरामीटर...',
    rc_done: 'सरफ़ेस मैप हो गया : एंडपॉइंट, पैरामीटर और सबडोमेन कार्ड में सूचीबद्ध', rc_fail: 'रीकॉन विफल : होस्ट अनुपलब्ध या स्कोप खाली',
    rc_surface: 'सरफ़ेस:', snd_on: 'साउंड: ON',
    snd_off: 'साउंड: OFF', snd_ok: 'इंटरफ़ेस साउंड चालू - लाइब्रेरी: क्लिक, टैब, कॉपी, अलर्ट',
    snd_stop: 'पूर्ण म्यूट चालू: अब कोई C2FF साउंड नहीं', amb_on: 'माहौल: ON',
    amb_off: 'माहौल: OFF', amb_ok: 'जीवंत माहौल - रंग शांति से वर्गों के बीच बहता है (हरा, नीला, पीला...)',
    amb_stop: 'माहौल मूल हरे पर स्थिर', nt_on: 'सूचनाएं: ON',
    nt_off: 'सूचनाएं: OFF', nt_ok: 'ब्राउज़र सूचनाएं चालू - P1 और P2 पर बीप',
    nt_denied: 'सूचनाएं ब्राउज़र में ब्लॉक हैं: साइट सेटिंग्स में अनुमति दें', term_denied: 'टर्मिनल अस्वीकृत या अनुपलब्ध: localhost या एडमिन के रूप में खुला कमरा चाहिए',
    term_p: 'असली bash - तीर से हिस्ट्री, Ctrl+C रोकें, Ctrl+D बंद करें', term_restart: 'रीसेट',
    navtrm: 'टर्मिनल', term_h2: 'टर्मिनल - कंसोल में ही काम का शेल',
    fl_off: 'बेड़ा : बंद', fl_paused: 'बेड़ा : विराम',
    fl_active: 'बेड़ा : सक्रिय ({n} चक्र)', fl_last: 'अंतिम चक्र',
    fl_none: 'अभी कोई चक्र नहीं', fl_info: 'अंतराल {i} मिनट, बजट {b} अनुरोध/चक्र',
    sub_ttl: 'command & control framework', navt: 'सेशन',
    tm_h2: 'समूह सेशन - साथ शिकार, नेटवर्क हो या नहीं', tm_p: 'एक साझा कमरा खोलो: तुम्हारी टीम फ्लीट और निष्कर्ष देखेगी और लाइव ट्राइएज कर सकेगी। नीचे समर्पित सेशन चैट। तीन स्तर: लोकल (सोलो), LAN (नेटवर्क के लिए खोलें), और वर्ल्ड (दुनिया के लिए खोलें) - सार्वजनिक टनल (cloudflared यदि स्थापित है) निमंत्रण लिंक को किसी भी नेटवर्क से मान्य बनाता है, मशीन को सीधे उजागर किए बिना। सब कुछ रूम की से गुजरता है - इसे दोबारा बनाओ तो सब एक साथ बाहर।',
    tm_handle: 'तुम्हारा नाम (अधिकतम 16 अक्षर)', tm_save_h: 'चुनें',
    tm_room_ph: 'कमरे का नाम (जैसे: c2ff-core)', tm_save: 'लागू करें',
    tm_on: 'कमरा खुला: {r} - {n} ऑनलाइन', tm_off: 'टीम मोड बंद - लोकल सोलो सेशन',
    tm_room: 'कमरा', tm_key: 'रूम की',
    tm_regen: 'की दोबारा बनाओ', tm_regen_ok: 'नई की बनी - पुराने लिंक मर गए',
    tm_invite: 'निमंत्रण लिंक (टीम को कॉपी करो)', tm_copy: 'कॉपी',
    tm_copied: 'क्लिपबोर्ड में कॉपी हो गया', tm_members: 'सदस्य',
    tm_nobody: 'अभी कोई नहीं - टीम को लिंक भेजो', tm_you: '(तुम)',
    tm_here: 'मौजूद', tm_saved: 'नाम सेव हुआ',
    tm_no_handle: 'नाम खाली है', tm_cfg_ok: 'कमरा अपडेट हुआ',
    tm_cfg_no: 'विफल', tm_live: 'नेटवर्क के लिए खोलें',
    tm_shore: 'लोकल पर वापस', tm_need_on: 'पहले कमरा चालू करो (ON)',
    tm_bind_lan: 'नेटवर्क: {a}', tm_bind_lo: 'लोकल: केवल localhost',
    to_team_live: '[GO-LIVE] सर्वर नेटवर्क पहुंच के साथ फिर शुरू - LAN लिंक दिखा, 2 सेकंड में पुनःकनेक्ट', to_team_shore: 'सर्वर लोकल (127.0.0.1) पर फिर शुरू',
    tm_tun_open: 'दुनिया के लिए खोलें (टनल)', tm_tun_close: 'टनल बंद करें',
    tm_tun_wait: 'सार्वजनिक टनल खुल रहा है (कुछ सेकंड)…', tm_tun_on: 'सेशन दुनिया के लिए खुला: {u} - निमंत्रण लिंक किसी भी नेटवर्क से काम करता है, वही नेटवर्क जरूरी नहीं',
    tm_tun_closed: 'टनल बंद - LAN/लोकल पर वापस', tm_chat_empty: 'सेशन चैनल खुला - कमरे के सदस्य यहाँ बातें करते हैं',
    tm_chat_h2: 'सेशन चैट', tm_msg_ph: 'सेशन को संदेश…',
    tm_admin: 'एडमिन', tm_guest: 'अतिथि',
    tm_kick: 'निकालो', tm_kick_ok: 'सदस्य कमरे से निकाला गया (दोबारा क्लिक से अनब्लॉक)',
    tm_role_ok: 'भूमिका अपडेट हुई', tm_mic_on: 'माइक चालू करो',
    tm_mic_off: 'माइक बंद करो', tm_mic_denied: 'माइक अस्वीकृत या अनुपलब्ध: HTTPS जरूरी (वर्ल्ड टनल या localhost) और अनुमति देनी होगी',
    navf: 'बेड़ा', navfd: 'खोजें',
    navp: 'प्रोग्राम', navai: 'AI',
    navc: 'समन्वय', st_runs: 'Runs',
    st_beacons: 'सक्रिय बीकन', st_sig: 'संकेत',
    h2f: 'बेड़ा - सभी प्रोग्राम, चालू एजेंट पहले', h2fd: 'फाइंडिंग आधार - स्थायी ट्रायाज',
    h2eng: 'बेड़ा इंजन - बिना टोकन लोकल चक्र', h2prog: 'प्रोग्राम - स्कोप, आवश्यक हेडर, लॉन्च',
    h2new: 'नया प्रोग्राम', h2ai: 'AI एजेंट - 100% वैकल्पिक',
    h2c: 'समन्वय - निजी चैनल', fl_start: 'शुरू',
    fl_pause: 'विराम', fl_cycle: 'अभी चक्र',
    f_add: 'जोड़ें', f_none: 'अभी कोई संकेत नहीं',
    f_ph: 'मैन्युअल फाइंडिंग: एंडपॉइंट + प्रमाण + बचाव योग्य गंभीरता…', st_sig_off: 'सिग्नल',
    st_sig_an: 'विश्लेषण', st_sig_sub: 'सबमिट',
    st_sig_dup: 'डुप', st_sig_ref: 'अस्वीकृत',
    st_sig_cl: 'बंद', r_none: 'कोई रन नहीं मिला',
    r_live: '{n} चालू', r_done: 'पूर्ण',
    r_feed: '▽ फ़ीड ({n} घ)', r_close: '△ निचोड़ें',
    p_name_ph: 'प्रोग्राम का नाम (जैसे: PayPal)', p_hdr_ph: 'आवश्यक हेडर (जैसे: X-Bug-Bounty: xxx)',
    p_scope_ph: 'स्कोप : डोमेन1, डोमेन2, …', p_save: 'सहेजें',
    p_local: 'मॉड्यूल, 100% लोकल', ai_p: 'C2FF बिना AI चलता है: मोड नियतात्मक लोकल प्रोब हैं। यह गेटवे केवल <b>आपके</b> AI (सेल्फ-होस्टेड या API) को जोड़ता है ताकि किसी एक फाइंडिंग का तुरंत विश्लेषण हो: फाइंडिंग टैब में <span style="color:var(--green)">IA »</span> बटन, जवाब समन्वय टैब में। इन सेटिंग्स के बिना कोई डेटा आपकी मशीन से बाहर नहीं जाता।',
    ai_off: 'निष्क्रिय', ai_on: 'सक्रिय',
    ai_st_off: 'AI निष्क्रिय - फ्रेमवर्क बिना AI 100% लोकल चलता है', ai_st_ready: 'AI कनेक्टेड: {p} · {m}',
    ai_st_inc: 'AI सक्रिय लेकिन अधूरा: baseURL और model ज़रूरी', ai_url_ph: 'बेस URL - जैसे: http://localhost:11434 या https://api.MyAI.tld/v1',
    ai_model_ph: 'model - जैसे: llama3.1:8b', ai_key_ph: 'API कुंजी (लोकल सर्वर के लिए खाली)',
    ai_save: 'सहेजें', ai_test: 'कनेक्शन जाँचें',
    ai_testing: 'जाँच हो रही है…', ai_ok: 'ठीक - उत्तर: ',
    ai_fail: 'विफल: ', ai_note: 'कॉन्फ़िग data/ai.json में स्थानीय रूप से संग्रहीत - केवल आपके दिए एंडपॉइंट पर भेजी जाती है',
    ch_ph: 'root@c2ff:~# विश्लेषण एजेंट को संदेश…', ch_send: 'भेजें',
    ch_empty: 'चैनल खुला है। यहाँ लिखो, मॉनिटर मुझे तुरंत जगा देता है।', ft: '100% लोकल - नियतात्मक प्रोब, बिना टोकन बिना बाहरी निर्भरता - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE सक्रिय: हर 30 मिनट लोकल चक्र, 0 टोकन।', to_fl_pa: 'बेड़ा विराम पर - जब चाहो फिर से शुरू।',
    to_fl_cy: 'तुरंत चक्र लॉन्च (बजट 60 अनुरोध)।', to_launch: '[GO] मोड {m} (CWE {c}) → {p} - लोकल चक्र लॉन्च',
    to_ai_ok: 'कॉन्फ़िग सहेजी गई', to_ai_no: 'सहेजना विफल',
    to_ai_no_cfg: 'AI कॉन्फ़िगर नहीं - AI टैब में सेट करें', to_ai_head: 'AI विश्लेषण',
    to_ai_bad: 'AI विश्लेषण विफल', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ लॉन्च', navar: 'आर्सनल',
    ar_h2: 'ARSENAL - पहचानी गई सतह पर CVE, EPSS और एक्सप्लॉयट', ar_sync: 'SYNC डेटाबेस',
    ar_btn: 'चालें', ar_exec: 'EXEC',
    ar_none: 'कोई चाल नहीं: पहले RECON चलाएँ, फिर KEV/EPSS लोड करने के लिए SYNC', ar_loading: 'डेटाबेस का सारांश लोड हो रहा है...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'डेमो प्रोग्राम - स्कैन नहीं: अपना प्रोग्राम बनाएं', pip_noprog: 'कोई प्रोग्राम नहीं: प्रोग्राम टैब में अपना प्रोग्राम बनाएं',
    pip_next: 'अगला चरण:', fnd_n: 'फाइंडिंग्स: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  nl: {
    pl_title: 'Werkplan', pl_empty: 'nog geen plan : draai RECON in de kaart hierboven, hypotheses landen hier (statussen blijven bewaard)',
    pl_run: 'Start', pl_reflect: 'canary gereflecteerd',
    st_do: 'te doen', st_test: 'getest',
    st_signal: 'signaal', st_valid: 'geldig',
    st_void: 'niets', atk_btn: 'ATTACK',
    atk_start: 'attack op de surface : endpoints, blootgestelde docs, JWT, secrets...', atk_fail: 'attack onmogelijk : draai eerst RECON',
    atk_none: 'geen signaal', atk_findings: 'kandidaten',
    atk_done: 'ATTACK : {n} P1/P2 kandidaten met bewijs in de findings geinjecteerd', atk_empty: 'nog geen attack : draai RECON en dan ATTACK - kandidaten met req/res bewijs landen hier',
    navh: 'HUNT', h2hunt: 'HUNT - echte surface en bewijzen',
    h_ready: 'klaar', h_empty: 'geen surface bekend : draai RECON om pagina\'s, API endpoints, params, JS bundles en subdomeinen te mappen',
    h_fnd: 'Findings van het programma', h_nofnd: 'geen findings voor dit programma',
    rc_btn: 'RECON', rc_start: 'recon van de surface loopt : pagina\'s, JS bundles, endpoints, params...',
    rc_done: 'surface in kaart gebracht : endpoints, params en subdomeinen staan in de kaart van het programma', rc_fail: 'recon mislukt : host onbereikbaar of scope leeg',
    rc_surface: 'oppervlak:', snd_on: 'GELUID : AAN',
    snd_off: 'GELUID : UIT', snd_ok: 'interfacegeluid actief - bibliotheek : klik, tabblad, kopieer, alerts',
    snd_stop: 'volledige mute ingeschakeld : geen C2FF geluiden meer', amb_on: 'AMBIANCE: AAN',
    amb_off: 'AMBIANCE: UIT', amb_ok: 'levende ambiance - de tint glijdt zachtjes door de families (groen, blauw, geel...)',
    amb_stop: 'ambiance bevroren op het originele groen', nt_on: 'NOTIFS : AAN',
    nt_off: 'NOTIFS : UIT', nt_ok: 'browsermeldingen ingeschakeld - piepje bij P1 en P2',
    nt_denied: 'meldingen geblokkeerd door de browser : sta ze toe in de site-instellingen', term_denied: 'terminal geweigerd of onbeschikbaar : localhost vereist, of een OPEN kamer als admin',
    term_p: 'echte bash - geschiedenis met pijltjes, Ctrl+C onderbreekt, Ctrl+D sluit', term_restart: 'Herinitialiseren',
    navtrm: 'TERM', term_h2: 'Terminal - werkshell, direct in de console',
    fl_off: 'FLEET : GESTOPT', fl_paused: 'FLEET : GEPAUZEERD',
    fl_active: 'FLEET : ACTIEF ({n} cycles)', fl_last: 'laatste cycle',
    fl_none: 'nog geen cycle', fl_info: 'interval {i} min, budget {b} req/cycle',
    sub_ttl: 'command & control framework', navt: 'SESSIE',
    tm_h2: 'Sessies met z\'n meerderen - groepsjacht, ook buiten het netwerk', tm_p: 'Open een gedeelde kamer : je groep ziet de fleet en de findings en kan live triagen. Eigen sessiechat hieronder. Drie toegangsniveaus : LOCAL (solo), LAN via OPEN NAAR HET NETWERK en WERELD via OPEN NAAR DE WERELD - een publieke tunnel (cloudflared indien geinstalleerd) maakt de uitnodigingslink geldig vanuit elk netwerk, zonder je machine direct bloot te stellen. Alles gaat via de kamersleutel - genereer hem opnieuw om iedereen in een keer eruit te zetten.',
    tm_handle: 'Jouw nick (max 16 tekens)', tm_save_h: 'Kiezen',
    tm_room_ph: 'kamernaam (bv : c2ff-core)', tm_save: 'Toepassen',
    tm_on: 'KAMER OPEN : {r} - {n} online', tm_off: 'TEAM MODE UIT - lokale solo sessie',
    tm_room: 'Kamer', tm_key: 'Kamersleutel',
    tm_regen: 'Sleutel opnieuw genereren', tm_regen_ok: 'nieuwe sleutel gegenereerd - oude links zijn dood',
    tm_invite: 'Uitnodigingslink (kopieer naar je team)', tm_copy: 'Kopieer',
    tm_copied: 'gekopieerd naar het klembord', tm_members: 'Leden',
    tm_nobody: 'nog niemand - stuur de link naar je team', tm_you: '(jij)',
    tm_here: 'aanwezig', tm_saved: 'nick opgeslagen',
    tm_no_handle: 'nick leeg', tm_cfg_ok: 'kamer bijgewerkt',
    tm_cfg_no: 'mislukt', tm_live: 'OPEN NAAR HET NETWERK',
    tm_shore: 'TERUG LOKAAL', tm_need_on: 'zet eerst de kamer aan (ON)',
    tm_bind_lan: 'NETWERK : {a}', tm_bind_lo: 'LOKAAL : alleen localhost',
    to_team_live: '[GO-LIVE] server herstart met netwerktoegang - LAN link getoond, herverbinding over 2 s', to_team_shore: 'server lokaal herstart (127.0.0.1)',
    tm_tun_open: 'OPEN NAAR DE WERELD (tunnel)', tm_tun_close: 'SLUIT DE TUNNEL',
    tm_tun_wait: 'publieke tunnel wordt geopend (enkele seconden)…', tm_tun_on: 'SESSIE OPEN NAAR DE WERELD : {u} - de uitnodigingslink werkt overal, geen gedeeld netwerk nodig',
    tm_tun_closed: 'tunnel gesloten - terug naar LAN/lokaal', tm_chat_empty: 'sessiekanaal open - kamerleden lezen elkaar hier',
    tm_chat_h2: 'Sessiechat', tm_msg_ph: 'bericht naar de sessie…',
    tm_admin: 'admin', tm_guest: 'gast',
    tm_kick: 'KICK', tm_kick_ok: 'lid uit de kamer gezet (opnieuw klikken ontgrendelt)',
    tm_role_ok: 'rol bijgewerkt', tm_mic_on: 'MICROFOON AANZETTEN',
    tm_mic_off: 'MICROFOON UITZETTEN', tm_mic_denied: 'microfoon geweigerd of onbeschikbaar : HTTPS vereist (WERELD tunnel of localhost) en je moet de microfoon toestaan',
    navf: 'Vloot', navfd: 'Findings',
    navp: 'Programma\'s', navai: 'AI',
    navc: 'Coördinatie', st_runs: 'Runs',
    st_beacons: 'Actieve beacons', st_sig: 'Signalen',
    h2f: 'Fleet - alle programma\'s, lopende agents eerst', h2fd: 'Findingsdatabase - blijvende triage tags',
    h2eng: 'Fleet motor - lokale cycles zonder tokens', h2prog: 'Programma\'s - scope, verplichte header, launch',
    h2new: 'Nieuw programma', h2ai: 'AI agent - 100% optionele integratie',
    h2c: 'Coördinatie - privékanaal', fl_start: 'Starten',
    fl_pause: 'Pauze', fl_cycle: 'Cycle nu',
    f_add: 'Toevoegen', f_none: 'nog geen signaal',
    f_ph: 'handmatig finding : endpoint + bewijs + verdedigbare severity…', st_sig_off: 'signaal',
    st_sig_an: 'analyse', st_sig_sub: 'ingediend',
    st_sig_dup: 'dup', st_sig_ref: 'geweigerd',
    st_sig_cl: 'gesloten', r_none: 'geen run gedetecteerd',
    r_live: '{n} IN LOOP', r_done: 'KLAAR',
    r_feed: '▽ feed ({n} ev)', r_close: '△ inklappen',
    p_name_ph: 'Naam van het programma (bv : PayPal)', p_hdr_ph: 'verplichte researcher header (bv : X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domein1, domein2, …', p_save: 'Opslaan',
    p_local: 'module(s), 100% lokaal', ai_p: 'C2FF draait volledig zonder AI : de modes zijn deterministische lokale probes. Deze gateway dient alleen om <b>jouw</b> AI (self-hosted of API) aan te sluiten voor de durende analyse van een finding : knop <span style="color:var(--green)">AI »</span> in FINDINGS, antwoord getoond in COORDINATION. Geen data verlaat je machine zonder deze configuratie.',
    ai_off: 'uitgeschakeld', ai_on: 'ingeschakeld',
    ai_st_off: 'AI UITGESCHAKELD - het framework draait 100% lokaal zonder', ai_st_ready: 'AI VERBONDEN : {p} · {m}',
    ai_st_inc: 'AI AAN MAAR ONVOLLEDIG : baseURL en model vereist', ai_url_ph: 'base URL - bv : http://localhost:11434 of https://api.MijnAI.tld/v1',
    ai_model_ph: 'model - bv : llama3.1:8b', ai_key_ph: 'API sleutel (laag leeg voor lokale servers)',
    ai_save: 'Opslaan', ai_test: 'Verbinding testen',
    ai_testing: 'test loopt…', ai_ok: 'OK - antwoord : ',
    ai_fail: 'MISLUKT : ', ai_note: 'config lokaal opgeslagen in data/ai.json - nooit ergens heen gestuurd behalve naar de endpoint die je er invult',
    ch_ph: 'root@c2ff:~# bericht naar de analyse agent…', ch_send: 'Versturen',
    ch_empty: 'Het kanaal is open. Tik hier, de monitor wekt me direct.', ft: '100% lokaal - deterministische probes, geen tokens en geen externe dependencies - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ACTIEF : lokale cycles elke 30 min, 0 tokens.', to_fl_pa: 'FLEET GEPAUZEERD - hervat wanneer jij wil.',
    to_fl_cy: 'Directe cycle gestart (budget 60 req).', to_launch: '[GO] modus {m} (CWE {c}) op {p} - lokale cycle gestart',
    to_ai_ok: 'config opgeslagen', to_ai_no: 'opslaan mislukt',
    to_ai_no_cfg: 'AI niet geconfigureerd - regel het in het AI tabblad', to_ai_head: 'AI ANALYSE',
    to_ai_bad: 'AI ANALYSE mislukt', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ LANCEER', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS en exploits op het gedetecteerde oppervlak', ar_sync: 'SYNC DATABANKEN',
    ar_btn: 'BEWEGINGEN', ar_exec: 'EXEC',
    ar_none: 'geen bewegingen: voer eerst RECON uit, daarna SYNC om KEV/EPSS te laden', ar_loading: 'overzicht van databanken laden...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demoprogramma - geen scan: maak je eigen programma', pip_noprog: 'geen programma: maak je eigen programma onder programma\'s',
    pip_next: 'volgende stap:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  tr: {
    pl_title: 'Çalışma planı', pl_empty: 'henüz plan yok: yukarıdaki kartta RECON çalıştır, hipotezler buraya düşer (durumlar kalıcı)',
    pl_run: 'Çalıştır', pl_reflect: 'canary yansıtıldı',
    st_do: 'yapılacak', st_test: 'test edildi',
    st_signal: 'sinyal', st_valid: 'doğrulandı',
    st_void: 'boş', atk_btn: 'ATTACK',
    atk_start: 'surface\'a saldırı: endpointler, açık dokümanlar, JWT, secretlar...', atk_fail: 'saldırı imkansız: önce RECON çalıştır',
    atk_none: 'sinyal yok', atk_findings: 'adaylar',
    atk_done: 'ATTACK: {n} P1/P2 adayı kanıtla birlikte findings\'e enjekte edildi', atk_empty: 'henüz saldırı yok: RECON sonra ATTACK çalıştır - req/res kanıtlı adaylar buraya düşer',
    navh: 'HUNT', h2hunt: 'HUNT - gerçek surface ve kanıtlar',
    h_ready: 'hazır', h_empty: 'bilinen surface yok: sayfaları, API endpointlerini, parametreleri, JS bundle\'ları ve subdomainleri haritalamak için RECON çalıştır',
    h_fnd: 'Programın findings\'leri', h_nofnd: 'bu program için finding yok',
    rc_btn: 'RECON', rc_start: 'surface recon\'u sürüyor: sayfalar, JS bundle\'ları, endpointler, parametreler...',
    rc_done: 'surface haritalandı: endpointler, parametreler ve subdomainler program kartında listelendi', rc_fail: 'recon başarısız: host erişilemez veya scope boş',
    rc_surface: 'yüzey:', snd_on: 'SES: AÇIK',
    snd_off: 'SES: KAPALI', snd_ok: 'arayüz sesleri açık - kütüphane: tıklama, sekme, kopyalama, alarmlar',
    snd_stop: 'tam sessizlik açık: artık hiçbir C2FF sesi yok', amb_on: 'AMBIYANS: AÇIK',
    amb_off: 'AMBIYANS: KAPALI', amb_ok: 'canlı ambiyans - renk tonu aileler arasında yumuşakça kayar (yeşil, mavi, sarı...)',
    amb_stop: 'ambiyans orijinal yeşilde donduruldu', nt_on: 'BİLDİRİMLER: AÇIK',
    nt_off: 'BİLDİRİMLER: KAPALI', nt_ok: 'tarayıcı bildirimleri açıldı - P1 ve P2\'de bip',
    nt_denied: 'bildirimler tarayıcı tarafından engellendi: site ayarlarından izin ver', term_denied: 'terminal reddedildi veya yok: localhost gerekli, ya da admin olarak AÇIK bir oda',
    term_p: 'gerçek bash - oklarla geçmiş, Ctrl+C keser, Ctrl+D kapatır', term_restart: 'Sıfırla',
    navtrm: 'TERM', term_h2: 'Terminal - çalışma kabuğu, doğrudan konsolda',
    fl_off: 'FLEET: DURDURULDU', fl_paused: 'FLEET: DURAKLATILDI',
    fl_active: 'FLEET: AKTİF ({n} döngü)', fl_last: 'son döngü',
    fl_none: 'henüz döngü yok', fl_info: 'aralık {i} dk, bütçe {b} req/döngü',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Grup oturumları - birlikte avlan, aynı ağda olmasan bile', tm_p: 'Paylaşımlı bir oda aç: takımın filoyu ve findings\'leri görür, canlı triyaj yapabilir. Aşağıda özel oturum sohbeti var. Üç erişim seviyesi: YEREL (solo), LAN ile AĞA AÇ ve DÜNYA ile DÜNYAYA AÇ - herkese açık tünel (kuruluysa cloudflared) davet linkini her ağdan geçerli kılar, makineni doğrudan dışarı açmadan. Her şey oda anahtarına bağlı - herkesi tek seferde atmak için yenile.',
    tm_handle: 'Takma adın (en fazla 16 karakter)', tm_save_h: 'Ayarla',
    tm_room_ph: 'oda adı (örn. c2ff-core)', tm_save: 'Uygula',
    tm_on: 'ODA AÇIK: {r} - {n} çevrimiçi', tm_off: 'TAKİM MODU KAPALI - yerel solo oturum',
    tm_room: 'Oda', tm_key: 'Oda anahtarı',
    tm_regen: 'Anahtarı yenile', tm_regen_ok: 'yeni anahtar üretildi - eski linkler ölü',
    tm_invite: 'Davet linki (takımına kopyala)', tm_copy: 'Kopyala',
    tm_copied: 'panoya kopyalandı', tm_members: 'Üyeler',
    tm_nobody: 'henüz kimse yok - linki takımına gönder', tm_you: '(sen)',
    tm_here: 'burada', tm_saved: 'takma ad kaydedildi',
    tm_no_handle: 'takma ad boş', tm_cfg_ok: 'oda güncellendi',
    tm_cfg_no: 'başarısız', tm_live: 'AĞA AÇ',
    tm_shore: 'YERELE DÖN', tm_need_on: 'önce odayı aç (ON)',
    tm_bind_lan: 'AĞ: {a}', tm_bind_lo: 'YEREL: yalnızca localhost',
    to_team_live: '[GO-LIVE] sunucu ağ erişimiyle yeniden başlatıldı - LAN linki gösterildi, 2 sn içinde yeniden bağlanılıyor', to_team_shore: 'sunucu yerel olarak yeniden başlatıldı (127.0.0.1)',
    tm_tun_open: 'DÜNYAYA AÇ (tünel)', tm_tun_close: 'TÜNELİ KAPAT',
    tm_tun_wait: 'herkese açık tünel açılıyor (birkaç saniye)…', tm_tun_on: 'OTURUM DÜNYAYA AÇIK: {u} - davet linki her yerden çalışır, aynı ağa gerek yok',
    tm_tun_closed: 'tün kapatıldı - LAN/yerel\'e dön', tm_chat_empty: 'oturum kanalı açık - oda üyeleri birbirini burada okur',
    tm_chat_h2: 'Oturum sohbeti', tm_msg_ph: 'oturuma mesaj…',
    tm_admin: 'admin', tm_guest: 'misafir',
    tm_kick: 'KICK', tm_kick_ok: 'üye odadan çıkarıldı (tekrar tıklamak bloğu açar)',
    tm_role_ok: 'rol güncellendi', tm_mic_on: 'MİKROFONU AÇ',
    tm_mic_off: 'MİKROFONU KAPAT', tm_mic_denied: 'mikrofon reddedildi veya erişilemez: HTTPS gerekli (DÜNYA tüneli ya da localhost) ve mikrofona izin vermelisin',
    navf: 'Filo', navfd: 'Findings',
    navp: 'Programlar', navai: 'YZ',
    navc: 'Koordinasyon', st_runs: 'Runs',
    st_beacons: 'Aktif beaconlar', st_sig: 'Sinyaller',
    h2f: 'Filo - tüm programlar, koşan agentlar önce', h2fd: 'Findings tabanı - kalıcı triyaj etiketleme',
    h2eng: 'Filo motoru - tokensız yerel döngüler', h2prog: 'Programlar - scope, gerekli header, lansman',
    h2new: 'Yeni program', h2ai: 'YZ agentı - %100 isteğe bağlı entegrasyon',
    h2c: 'Koordinasyon - özel kanal', fl_start: 'Başlat',
    fl_pause: 'Duraklat', fl_cycle: 'Şimdi döngü',
    f_add: 'Ekle', f_none: 'henüz sinyal yok',
    f_ph: 'manuel finding: endpoint + kanıt + savunulabilir severity…', st_sig_off: 'sinyal',
    st_sig_an: 'analiz', st_sig_sub: 'gönderildi',
    st_sig_dup: 'mük', st_sig_ref: 'reddedildi',
    st_sig_cl: 'kapandı', r_none: 'run algılanmadı',
    r_live: '{n} KOŞUYOR', r_done: 'BİTTİ',
    r_feed: '▽ akış ({n} ev)', r_close: '△ daralt',
    p_name_ph: 'Program adı (örn. PayPal)', p_hdr_ph: 'gerekli researcher başlığı (örn. X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: alan1, alan2, …', p_save: 'Kaydet',
    p_local: 'modül(ler), %100 yerel', ai_p: 'C2FF tamamen YZ\'siz çalışır: modlar deterministik yerel probe\'lardır. Bu ağ geçidi yalnızca <b>senin</b> YZ\'ni (self-hosted veya API) tek bir finding\'in nokta analizi için bağlar: FINDINGS içindeki <span style="color:var(--green)">YZ »</span> butonu, yanıt COORDINATION\'da gösterilir. Bu yapılandırma olmadan makinenizden hiçbir veri çıkmaz.',
    ai_off: 'kapalı', ai_on: 'açık',
    ai_st_off: 'YZ KAPALI - framework onsuz %100 yerel çalışıyor', ai_st_ready: 'YZ BAĞLI: {p} · {m}',
    ai_st_inc: 'YZ AÇIK AMA EKSİK: baseURL ve model gerekli', ai_url_ph: 'base URL - örn. http://localhost:11434 veya https://api.BenimYZ.tld/v1',
    ai_model_ph: 'model - örn. llama3.1:8b', ai_key_ph: 'API anahtarı (yerel sunucularda boş bırak)',
    ai_save: 'Kaydet', ai_test: 'Bağlantıyı test et',
    ai_testing: 'test sürüyor…', ai_ok: 'TAMAM - yanıt: ',
    ai_fail: 'BAŞARISIZ: ', ai_note: 'config yerel olarak data/ai.json\'da saklanır - yalnızca senin yazdığın endpointe gönderilir, başka hiçbir yere',
    ch_ph: 'root@c2ff:~# analiz agentına mesaj…', ch_send: 'Gönder',
    ch_empty: 'Kanal açık. Buraya yaz, monitör beni anında uyandırır.', ft: '%100 yerel - deterministik probe\'lar, token yok harici bağımlılık yok - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE AKTİF: her 30 dakikada yerel döngüler, 0 token.', to_fl_pa: 'FLEET DURAKLATILDI - istediğinde kaldığı yerden sürdür.',
    to_fl_cy: 'Anında döngü başlatıldı (bütçe 60 req).', to_launch: '[GO] mod {m} (CWE {c}), hedef {p} - yerel döngü başlatıldı',
    to_ai_ok: 'config kaydedildi', to_ai_no: 'kaydetme başarısız',
    to_ai_no_cfg: 'YZ yapılandırılmadı - YZ sekmesinden ayarla', to_ai_head: 'YZ ANALİZİ',
    to_ai_bad: 'YZ ANALİZİ başarısız', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'YZ',
    w_launch: '⚡ FIRLAT', navar: 'Arsenal',
    ar_h2: 'ARSENAL - algilanan yuzeyde CVE, EPSS ve exploitler', ar_sync: 'SYNC VERITABANLARI',
    ar_btn: 'HAREKETLER', ar_exec: 'EXEC',
    ar_none: 'hareket yok: once RECON calistir, sonra KEV/EPSS yuklemek icin SYNC', ar_loading: 'veritabani ozeti yukleniyor...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demo program - tarama yok: kendi programini olustur', pip_noprog: 'program yok: Programlar sekmesinde kendinkini olustur',
    pip_next: 'sonraki adim:', fnd_n: 'bulgular: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  no: {
    pl_title: 'Arbeidsplan', pl_empty: 'ingen plan ennå: kjør RECON i kortet over, hypotesene lander her (statuser lagres)',
    pl_run: 'Kjør', pl_reflect: 'canary vurdert',
    st_do: 'å gjøre', st_test: 'testet',
    st_signal: 'signal', st_valid: 'bekreftet',
    st_void: 'intet', atk_btn: 'ATTACK',
    atk_start: 'attack på overflaten: endepunkter, eksponerte docs, JWT, secrets...', atk_fail: 'attack umulig: kjør RECON først',
    atk_none: 'intet signal', atk_findings: 'kandidater',
    atk_done: 'ATTACK: {n} P1/P2-kandidater injisert i findings med bevis', atk_empty: 'ingen attack ennå: kjør RECON så ATTACK - kandidater med req/res-bevis lander her',
    navh: 'HUNT', h2hunt: 'HUNT - ekte overflate og beviser',
    h_ready: 'klar', h_empty: 'ingen kjent overflate: kjør RECON for å kartlegge sider, API-endepunkter, parametre, JS-bundles og subdomener',
    h_fnd: 'Findings i programmet', h_nofnd: 'ingen finding på dette programmet',
    rc_btn: 'RECON', rc_start: 'recon av overflaten pågår: sider, JS-bundles, endepunkter, parametre...',
    rc_done: 'overflate kartlagt: endepunkter, parametre og subdomener listet i programkortet', rc_fail: 'recon mislyktes: host utilgjengelig eller scope tomt',
    rc_surface: 'overflate:', snd_on: 'LYD: PÅ',
    snd_off: 'LYD: AV', snd_ok: 'grensesnittlyder aktivert - bibliotek: klikk, fane, kopi, varsler',
    snd_stop: 'fullstendig demping aktivert: ingen flere C2FF-lyder', amb_on: 'AMBIANSE: PÅ',
    amb_off: 'AMBIANSE: AV', amb_ok: 'levende ambianse - tonen glir mykt gjennom familiene (grønn, blå, gul...)',
    amb_stop: 'ambianse frosset på originalgrønn', nt_on: 'VARSLER: PÅ',
    nt_off: 'VARSLER: AV', nt_ok: 'nettleservarsler aktivert - bip på P1 og P2',
    nt_denied: 'varsler blokkert av nettleseren: tillat dem i nettstedets innstillinger', term_denied: 'terminal nektet eller utilgjengelig: localhost kreves, eller et ÅPENT rom som admin',
    term_p: 'ekte bash - historikk med pil opp, Ctrl+C avbryter, Ctrl+D lukker', term_restart: 'Tilbakestill',
    navtrm: 'TERM', term_h2: 'Terminal - arbeidsshell, rett i konsollen',
    fl_off: 'FLEET: STOPPET', fl_paused: 'FLEET: PÅ PAUSE',
    fl_active: 'FLEET: AKTIV ({n} sykluser)', fl_last: 'siste syklus',
    fl_none: 'ingen syklus ennå', fl_info: 'intervall {i} min, budsjett {b} req/syklus',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Flerspillerøkter - gruppejakt, også utenfor nettverket', tm_p: 'Åpner et delt rom: gruppen din ser flåten, findings og kan triage live. Egen øktchat nedenfor. Tre tilgangsnivåer: LOKAL (solo), LAN via ÅPNE TIL NETTVERK, og VERDEN via ÅPNE TIL VERDEN - en offentlig tunnel (cloudflared hvis installert) gjør invitasjonslenken gyldig fra hvilket som helst nettverk, uten direkte eksponering av maskinen din. Alt går via romnøkkelen - regenerer den for å kaste ut alle samtidig.',
    tm_handle: 'Psevdonymet ditt (16 tegn maks)', tm_save_h: 'Velg',
    tm_room_ph: 'navn på rommet (f.eks.: c2ff-core)', tm_save: 'Bruk',
    tm_on: 'ROM ÅPENT: {r} - {n} pålogget', tm_off: 'TEAM-MODUS AV - lokal solo-økt',
    tm_room: 'Rom', tm_key: 'Romnøkkel',
    tm_regen: 'Regenerer nøkkelen', tm_regen_ok: 'ny nøkkel generert - de gamle lenkene er døde',
    tm_invite: 'Invitasjonslenke (kopier til laget ditt)', tm_copy: 'Kopier',
    tm_copied: 'kopiert til utklippstavlen', tm_members: 'Medlemmer',
    tm_nobody: 'ingen ennå - send lenken til laget ditt', tm_you: '(deg)',
    tm_here: 'til stede', tm_saved: 'psevdonym lagret',
    tm_no_handle: 'tomt psevdonym', tm_cfg_ok: 'rom oppdatert',
    tm_cfg_no: 'feilet', tm_live: 'ÅPNE TIL NETTVERK',
    tm_shore: 'TILBAKE TIL LOKAL', tm_need_on: 'aktiver rommet først (PÅ)',
    tm_bind_lan: 'NETTVERK: {a}', tm_bind_lo: 'LOKAL: bare localhost',
    to_team_live: '[GO-LIVE] server startet på nytt med nettverkstilgang - LAN-lenke vist, kobler til igjen om 2 s', to_team_shore: 'server startet på nytt lokalt (127.0.0.1)',
    tm_tun_open: 'ÅPNE TIL VERDEN (tunnel)', tm_tun_close: 'LUKK TUNNELEN',
    tm_tun_wait: 'offentlig tunnel åpner seg (noen sekunder)…', tm_tun_on: 'ØKT ÅPEN FOR VERDEN: {u} - invitasjonslenken fungerer overalt, ikke samme nettverk nødvendig',
    tm_tun_closed: 'tunnel lukket - tilbake til LAN/lokal', tm_chat_empty: 'øktkanal åpen - rommets medlemmer leser hverandre her',
    tm_chat_h2: 'Øktchat', tm_msg_ph: 'melding til økten…',
    tm_admin: 'admin', tm_guest: 'gjest',
    tm_kick: 'KICK', tm_kick_ok: 'medlem kastet ut av rommet (klikk igjen for å oppheve)',
    tm_role_ok: 'rolle oppdatert', tm_mic_on: 'AKTIVER MIKROFON',
    tm_mic_off: 'SLÅ AV MIKROFON', tm_mic_denied: 'mikrofon nektet eller utilgjengelig: HTTPS kreves (VERDEN-tunnel eller localhost) og mikrofonen må tillates',
    navf: 'Flåte', navfd: 'Findings',
    navp: 'Programmer', navai: 'KI',
    navc: 'Koordinering', st_runs: 'Kjøringer',
    st_beacons: 'Aktive beacons', st_sig: 'Signaler',
    h2f: 'Flåte - alle programmer, kjørende agenter først', h2fd: 'Findings-base - vedvarende triage-merking',
    h2eng: 'Flåtemotor - lokale sykluser uten tokens', h2prog: 'Programmer - scope, påkrevd header, lansering',
    h2new: 'Nytt program', h2ai: 'KI-agent - 100 % valgfri integrasjon',
    h2c: 'Koordinering - privat kanal', fl_start: 'Start flåten',
    fl_pause: 'Pause', fl_cycle: 'Syklus nå',
    f_add: 'Legg til', f_none: 'intet signal ennå',
    f_ph: 'manuelt finding: endepunkt + bevis + forsvarebar alvorlighetsgrad…', st_sig_off: 'signal',
    st_sig_an: 'analyse', st_sig_sub: 'innsendt',
    st_sig_dup: 'dup', st_sig_ref: 'avslått',
    st_sig_cl: 'lukket', r_none: 'ingen run oppdaget',
    r_live: '{n} PÅGÅR', r_done: 'FERDIG',
    r_feed: '▽ flyt ({n} ev)', r_close: '△ fold sammen',
    p_name_ph: 'Programnavn (f.eks: PayPal)', p_hdr_ph: 'påkrevd researcher-header (f.eks: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domene1, domene2, …', p_save: 'Lagre',
    p_local: 'modul(er), 100 % lokalt', ai_p: 'C2FF fungerer helt uten KI: modusene er lokale deterministiske probes. Denne gatewayen brukes kun til å koble til <b>din</b> KI (self-hosted eller API) for punktvis analyse av et finding: knappen <span style="color:var(--green)">KI »</span> i FINDINGS, svaret vises i COORDINATION. Ingen data forlater maskinen din uten denne konfigurasjonen.',
    ai_off: 'deaktivert', ai_on: 'aktivert',
    ai_st_off: 'KI DEAKTIVERT - rammeverket kjører 100 % lokalt uten den', ai_st_ready: 'KI TILKOBLET: {p} · {m}',
    ai_st_inc: 'KI AKTIVERT MEN UFULLSTENDIG: baseURL og model kreves', ai_url_ph: 'base URL - f.eks: http://localhost:11434 eller https://api.MinKI.tld/v1',
    ai_model_ph: 'model - f.eks: llama3.1:8b', ai_key_ph: 'API-nøkkel (la stå tom for lokale servere)',
    ai_save: 'Lagre', ai_test: 'Test tilkoblingen',
    ai_testing: 'tester…', ai_ok: 'OK - svar: ',
    ai_fail: 'MISLYKTES: ', ai_note: 'config lagres lokalt i data/ai.json - sendes aldri noe annet sted enn endepunktet du setter',
    ch_ph: 'root@c2ff:~# melding til analyse-agenten…', ch_send: 'Send',
    ch_empty: 'Kanalen er åpen. Skriv her, monitoren vekker meg øyeblikkelig.', ft: '100 % lokalt - deterministiske probes, uten tokens eller eksterne avhengigheter - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODUS AKTIV: lokale sykluser hver 30. min, 0 tokens.', to_fl_pa: 'FLEET PÅ PAUSE - fortsett når du vil.',
    to_fl_cy: 'Umiddelbar syklus startet (budsjett 60 req).', to_launch: '[GO] modus {m} (CWE {c}) på {p} - lokal syklus startet',
    to_ai_ok: 'config lagret', to_ai_no: 'lagring mislyktes',
    to_ai_no_cfg: 'KI ikke konfigurert - sett den opp i KI-fanen', to_ai_head: 'KI-ANALYSE',
    to_ai_bad: 'KI-ANALYSE feilet', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'KI',
    w_launch: '⚡ LANSERING', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS og exploits pa den oppdagede overflaten', ar_sync: 'SYNC BASER',
    ar_btn: 'TREKK', ar_exec: 'EXEC',
    ar_none: 'ingen trekk: kjor RECON forst, deretter SYNC for a laste KEV/EPSS', ar_loading: 'oppsummering av baser laster...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demoprogram - ingen skanning: opprett ditt eget program', pip_noprog: 'ingen programmer: opprett ditt eget under Programmer',
    pip_next: 'neste trinn:', fnd_n: 'funn: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  da: {
    pl_title: 'Arbejdsplan', pl_empty: 'ingen plan endnu: kør RECON i kortet ovenover, hypoteserne lander her (statuser gemmes)',
    pl_run: 'Kør', pl_reflect: 'canary vurderet',
    st_do: 'at gøre', st_test: 'testet',
    st_signal: 'signal', st_valid: 'bekræftet',
    st_void: 'intet', atk_btn: 'ATTACK',
    atk_start: 'attack på overfladen: endpoints, eksponerede docs, JWT, secrets...', atk_fail: 'attack ikke muligt: kør RECON først',
    atk_none: 'intet signal', atk_findings: 'kandidater',
    atk_done: 'ATTACK: {n} P1/P2-kandidater injiceret i findings med bevis', atk_empty: 'ingen attack endnu: kør RECON og derefter ATTACK - kandidater med req/res-bevis lander her',
    navh: 'HUNT', h2hunt: 'HUNT - ægte overflade og beviser',
    h_ready: 'klar', h_empty: 'ingen kendt overflade: kør RECON for at kortlægge sider, API-endpoints, params, JS-bundles og subdomener',
    h_fnd: 'Programmets findings', h_nofnd: 'ingen finding på dette program',
    rc_btn: 'RECON', rc_start: 'recon af overfladen i gang: sider, JS-bundles, endpoints, params...',
    rc_done: 'overflade kortlagt: endpoints, params og subdomener listet i programkortet', rc_fail: 'recon fejlede: host utilgængelig eller scope tomt',
    rc_surface: 'overflade:', snd_on: 'LYD: TÆNDT',
    snd_off: 'LYD: SLUKKET', snd_ok: 'grænsefladelyde aktive - bibliotek: klik, fane, kopi, alarmer',
    snd_stop: 'total dæmpning aktiveret: ikke flere C2FF-lyde', amb_on: 'STEMNING: TÆNDT',
    amb_off: 'STEMNING: SLUKKET', amb_ok: 'levende stemning - tonen glider blødt igennem familierne (grøn, blå, gul...)',
    amb_stop: 'stemning frosset på den oprindelige grønne', nt_on: 'NOTIFIKATIONER: TÆNDT',
    nt_off: 'NOTIFIKATIONER: SLUKKET', nt_ok: 'browsernotifikationer aktiveret - bip ved P1 og P2',
    nt_denied: 'notifikationer blokeret af browseren: tillad dem i sitets indstillinger', term_denied: 'terminal nægtet eller utilgængelig: localhost kræves, eller et ÅBENT rum som admin',
    term_p: 'ægte bash - historik med pil op, Ctrl+C afbryder, Ctrl+D lukker', term_restart: 'Nulstil',
    navtrm: 'TERM', term_h2: 'Terminal - arbejdsshell, direkte i konsollen',
    fl_off: 'FLEET: STOPPET', fl_paused: 'FLEET: PÅ PAUSE',
    fl_active: 'FLEET: AKTIV ({n} cyklusser)', fl_last: 'sidste cyklus',
    fl_none: 'ingen cyklus endnu', fl_info: 'interval {i} min, budget {b} req/cyklus',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Sessioner til flere - gruppejagt, også uden for netværket', tm_p: 'Åbn et delt rum: din gruppe ser flåden, findings og kan triage live. Egen sessionschat herunder. Tre adgangsniveauer: LOKAL (solo), LAN via ÅBN TIL NETVÆRK, og VERDEN via ÅBN TIL VERDEN - en offentlig tunnel (cloudflared hvis installeret) gør invitationslinket gyldigt fra ethvert netværk, uden direkte eksponering af din maskine. Alt går via rumnøglen - regenerer den for at smide alle ud på én gang.',
    tm_handle: 'Dit kaldenavn (16 tegn maks)', tm_save_h: 'Vælg',
    tm_room_ph: 'navn på rummet (f.eks.: c2ff-core)', tm_save: 'Anvend',
    tm_on: 'RUM ÅBENT: {r} - {n} online', tm_off: 'TEAM-TILSTAND SLÅET FRA - lokal solo-session',
    tm_room: 'Rum', tm_key: 'Rumnøgle',
    tm_regen: 'Regenerer nøglen', tm_regen_ok: 'ny nøgle genereret - de gamle links er døde',
    tm_invite: 'Invitationslink (kopier til dit team)', tm_copy: 'Kopier',
    tm_copied: 'kopieret til udklipsholderen', tm_members: 'Medlemmer',
    tm_nobody: 'ingen endnu - send linket til dit team', tm_you: '(dig)',
    tm_here: 'til stede', tm_saved: 'kaldenavn gemt',
    tm_no_handle: 'tomt kaldenavn', tm_cfg_ok: 'rum opdateret',
    tm_cfg_no: 'fejlede', tm_live: 'ÅBN TIL NETVÆRK',
    tm_shore: 'TILBAGE TIL LOKAL', tm_need_on: 'aktiver rummet først (TÆNDT)',
    tm_bind_lan: 'NETVÆRK: {a}', tm_bind_lo: 'LOKAL: kun localhost',
    to_team_live: '[GO-LIVE] server genstartet med netværksadgang - LAN-link vist, genforbinder om 2 s', to_team_shore: 'server genstartet lokalt (127.0.0.1)',
    tm_tun_open: 'ÅBN TIL VERDEN (tunnel)', tm_tun_close: 'LUK TUNNELLEN',
    tm_tun_wait: 'offentlig tunnel under åbning (nogle sekunder)…', tm_tun_on: 'SESSION ÅBEN FOR VERDEN: {u} - invitationslinket virker overalt, ikke samme netværk nødvendigt',
    tm_tun_closed: 'tunnel lukket - tilbage til LAN/lokal', tm_chat_empty: 'sessionskanal åben - rummets medlemmer læser hinanden her',
    tm_chat_h2: 'Sessionschat', tm_msg_ph: 'besked til sessionen…',
    tm_admin: 'admin', tm_guest: 'gæst',
    tm_kick: 'KICK', tm_kick_ok: 'medlem smidt ud af rummet (klik igen for at ophæve)',
    tm_role_ok: 'rolle opdateret', tm_mic_on: 'AKTIVER MIKROFON',
    tm_mic_off: 'SLÅ MIKROFON FRA', tm_mic_denied: 'mikrofon nægtet eller utilgængelig: HTTPS kræves (VERDEN-tunnel eller localhost) og mikrofonen skal tillades',
    navf: 'Flåde', navfd: 'Findings',
    navp: 'Programmer', navai: 'AI',
    navc: 'Koordinering', st_runs: 'Kørsler',
    st_beacons: 'Aktive beacons', st_sig: 'Signaler',
    h2f: 'Flåde - alle programmer, kørende agenter først', h2fd: 'Findings-base - vedvarende triage-mærkning',
    h2eng: 'Flådemotor - lokale cyklusser uden tokens', h2prog: 'Programmer - scope, påkrævet header, lancering',
    h2new: 'Nyt program', h2ai: 'AI-agent - 100 % valgfri integration',
    h2c: 'Koordinering - privat kanal', fl_start: 'Start flåden',
    fl_pause: 'Pause', fl_cycle: 'Cyklus nu',
    f_add: 'Tilføj', f_none: 'intet signal endnu',
    f_ph: 'manuelt finding: endpoint + bevis + forsvarelig sværhedsgrad…', st_sig_off: 'signal',
    st_sig_an: 'analyse', st_sig_sub: 'indsendt',
    st_sig_dup: 'dup', st_sig_ref: 'afvist',
    st_sig_cl: 'lukket', r_none: 'ingen run registreret',
    r_live: '{n} PÅGÅR', r_done: 'FÆRDIG',
    r_feed: '▽ strøm ({n} ev)', r_close: '△ sammenfold',
    p_name_ph: 'Programnavn (f.eks: PayPal)', p_hdr_ph: 'påkrævet researcher-header (f.eks: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domæne1, domæne2, …', p_save: 'Gem',
    p_local: 'modul(er), 100 % lokalt', ai_p: 'C2FF fungerer 100 % uden AI: tilstandene er lokale deterministiske probes. Denne gateway bruges kun til at tilslutte <b>din</b> AI (self-hosted eller API) til punktvis analyse af et finding: knappen <span style="color:var(--green)">AI »</span> i FINDINGS, svaret vises i COORDINATION. Ingen data forlader din maskine uden denne konfiguration.',
    ai_off: 'deaktiveret', ai_on: 'aktiveret',
    ai_st_off: 'AI DEAKTIVERET - frameworket kører 100 % lokalt uden den', ai_st_ready: 'AI FORBINDET: {p} · {m}',
    ai_st_inc: 'AI AKTIVERET MEN UFULDKOMMEN: baseURL og model kræves', ai_url_ph: 'base URL - f.eks: http://localhost:11434 eller https://api.MinAI.tld/v1',
    ai_model_ph: 'model - f.eks: llama3.1:8b', ai_key_ph: 'API-nøgle (lad den tom ved lokale servere)',
    ai_save: 'Gem', ai_test: 'Test forbindelsen',
    ai_testing: 'tester…', ai_ok: 'OK - svar: ',
    ai_fail: 'FEJLEDE: ', ai_note: 'config gemmes lokalt i data/ai.json - sendes aldrig et andet sted hen end endpointet du sætter',
    ch_ph: 'root@c2ff:~# besked til analyse-agenten…', ch_send: 'Send',
    ch_empty: 'Kanalen er åben. Skriv her, monitoren vækker mig øjeblikkeligt.', ft: '100 % lokalt - deterministiske probes, uden tokens eller eksterne afhængigheder - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-TILSTAND AKTIV: lokale cyklusser hver 30. min, 0 tokens.', to_fl_pa: 'FLEET PÅ PAUSE - fortsæt når du vil.',
    to_fl_cy: 'Øjeblikkelig cyklus startet (budget 60 req).', to_launch: '[GO] tilstand {m} (CWE {c}) på {p} - lokal cyklus startet',
    to_ai_ok: 'config gemt', to_ai_no: 'kunne ikke gemme',
    to_ai_no_cfg: 'AI ikke konfigureret - sæt den op under fanen AI', to_ai_head: 'AI-ANALYSE',
    to_ai_bad: 'AI-ANALYSE fejlede', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ LANCERING', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS og exploits pa den detekterede overflade', ar_sync: 'SYNC BASER',
    ar_btn: 'TRAEK', ar_exec: 'EXEC',
    ar_none: 'ingen traek: kor RECON forst, derefter SYNC for at indlaese KEV/EPSS', ar_loading: 'oversigt over baser indlaeser...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demoprogram - ingen scanning: opret dit eget program', pip_noprog: 'ingen programmer: opret dit eget under Programmer',
    pip_next: 'naeste trin:', fnd_n: 'fund: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  fa: {
    pl_title: 'برنامه کاری', pl_empty: 'هنوز برنامه‌ای نیست : RECON را در کارت بالای صفحه اجرا کن، فرضیه‌ها همین‌جا می‌افتند (وضعیت‌ها ذخیره می‌مانند)',
    pl_run: 'اجرا', pl_reflect: 'canary بازتابیده شد',
    st_do: 'باقی‌مانده', st_test: 'تست‌شده',
    st_signal: 'سیگنال', st_valid: 'تأییدشده',
    st_void: 'هیچی', atk_btn: 'ATTACK',
    atk_start: 'حمله به سطح حمله : اندپوینت‌ها، مستندات باز، JWT، اسرار...', atk_fail: 'حمله ممکن نیست : اول RECON را اجرا کن',
    atk_none: 'هیچ سیگنالی نیست', atk_findings: 'کاندیدها',
    atk_done: 'ATTACK : {n} کاندید P1/P2 همراه با مدرک به یافته‌ها تزریق شد', atk_empty: 'هنوز حمله‌ای نیست : اول RECON بعد ATTACK - کاندیدهای دارای مدرک req/res همین‌جا می‌افتند',
    navh: 'HUNT', h2hunt: 'HUNT - سطح واقعی و مدارک',
    h_ready: 'آماده', h_empty: 'هیچ سطحی شناخته نشده : RECON را اجرا کن تا صفحه‌ها، اندپوینت‌های API، پارامترها، باندل‌های JS و زیردامنه‌ها نقشه‌برداری شوند',
    h_fnd: 'یافته‌های برنامه', h_nofnd: 'هیچ یافته‌ای برای این برنامه نیست',
    rc_btn: 'RECON', rc_start: 'شناسایی سطح حمله در جریان است : صفحه‌ها، باندل‌های JS، اندپوینت‌ها، پارامترها...',
    rc_done: 'سطح نقشه‌برداری شد : اندپوینت‌ها، پارامترها و زیردامنه‌ها در کارت برنامه فهرست شده‌اند', rc_fail: 'recon شکست خورد : هاست در دسترس نیست یا scope خالی است',
    rc_surface: 'سطح :', snd_on: 'صدا : روشن',
    snd_off: 'صدا : خاموش', snd_ok: 'صداهای رابط فعال شد - کتابخانه : کلیک، تب، کپی، هشدارها',
    snd_stop: 'بی‌صدا کردن کامل فعال شد : دیگر هیچ صدایی از C2FF نیست', amb_on: 'اتمسفر: روشن',
    amb_off: 'اتمسفر: خاموش', amb_ok: 'اتمسفر زنده - رنگ آرام میان خانواده‌ها سُر می‌خورد (سبز، آبی، زرد...)',
    amb_stop: 'اتمسفر روی سبز اصلی ثابت ماند', nt_on: 'نوتیف‌ها : روشن',
    nt_off: 'نوتیف‌ها : خاموش', nt_ok: 'نوتیفیکیشن‌های مرورگر فعال شد - روی P1 و P2 بوق می‌خورد',
    nt_denied: 'نوتیفیکیشن‌ها توسط مرورگر مسدود شده : در تنظیمات سایت مجازشان کن', term_denied: 'ترمینال رد شد یا در دسترس نیست : localhost لازم است، یا اتاقِ باز در نقش ادمین',
    term_p: 'bash واقعی - تاریخچه با فلش بالا، Ctrl+C قطع می‌کند، Ctrl+D می‌بندد', term_restart: 'ریست',
    navtrm: 'TERM', term_h2: 'ترمینال - شل کاری، مستقیم در کنسول',
    fl_off: 'FLEET : متوقف', fl_paused: 'FLEET : در توقف موقت',
    fl_active: 'FLEET : فعال ({n} چرخه)', fl_last: 'آخرین چرخه',
    fl_none: 'هنوز هیچ چرخه‌ای نیست', fl_info: 'بازه {i} دقیقه، بودجه {b} req/چرخه',
    sub_ttl: 'فریم‌ورک فرماندهی و کنترل', navt: 'نشست',
    tm_h2: 'نشست‌های گروهی - شکار دسته‌جمعی، حتی بیرون از شبکه', tm_p: 'یک اتاق مشترک باز کن : گروهت ناوگان و یافته‌ها را می‌بیند و می‌تواند زنده تریاژ کند. چت اختصاصی نشست پایین است. سه سطح دسترسی : LOCAL (تکی)، LAN با «باز به شبکه»، و WORLD با «باز به دنیا» - یک تونل عمومی (اگر cloudflared نصب باشد) لینک دعوت را از هر شبکه‌ای معتبر نگه می‌دارد، بدون قرار گرفتن مستقیم دستگاهت. همه‌چیز با کلید اتاق کنترل می‌شود - آن را دوباره بساز تا همه یک‌جا بیرون بیفتند.',
    tm_handle: 'اسم مستعار تو (حداکثر 16 کاراکتر)', tm_save_h: 'انتخاب',
    tm_room_ph: 'نام اتاق (مثلاً c2ff-core)', tm_save: 'اعمال',
    tm_on: 'اتاق باز : {r} - {n} آنلاین', tm_off: 'حالت TEAM خاموش - نشست محلی تکی',
    tm_room: 'اتاق', tm_key: 'کلید اتاق',
    tm_regen: 'دوباره‌سازی کلید', tm_regen_ok: 'کلید تازه ساخته شد - لینک‌های قدیمی مُردند',
    tm_invite: 'لینک دعوت (برای تیم‌ت کپی کن)', tm_copy: 'کپی',
    tm_copied: 'در کلیپ‌بورد کپی شد', tm_members: 'اعضا',
    tm_nobody: 'هنوز هیچ‌کس نیست - لینک را برای تیم‌ت بفرست', tm_you: '(تو)',
    tm_here: 'حاضر', tm_saved: 'اسم مستعار ذخیره شد',
    tm_no_handle: 'اسم مستعار خالی است', tm_cfg_ok: 'اتاق به‌روز شد',
    tm_cfg_no: 'شکست خورد', tm_live: 'باز به شبکه',
    tm_shore: 'برگشت به محلی', tm_need_on: 'اول اتاق را روشن کن (ON)',
    tm_bind_lan: 'شبکه : {a}', tm_bind_lo: 'محلی : فقط localhost',
    to_team_live: '[GO-LIVE] سرور با دسترسی شبکه دوباره راه افتاد - لینک LAN نمایش داده شد، اتصال دوباره در 2 ثانیه', to_team_shore: 'سرور به‌صورت محلی دوباره راه افتاد (127.0.0.1)',
    tm_tun_open: 'باز به دنیا (تونل)', tm_tun_close: 'بستن تونل',
    tm_tun_wait: 'تونل عمومی در حال بالا آمدن است (چند ثانیه)…', tm_tun_on: 'نشست باز به دنیا : {u} - لینک دعوت همه‌جا کار می‌کند، شبکه مشترک لازم نیست',
    tm_tun_closed: 'تونل بسته شد - برگشت به LAN/محلی', tm_chat_empty: 'کانال نشست باز شد - اعضای اتاق اینجا همدیگر را می‌خوانند',
    tm_chat_h2: 'چت نشست', tm_msg_ph: 'پیام به نشست…',
    tm_admin: 'ادمین', tm_guest: 'مهمان',
    tm_kick: 'KICK', tm_kick_ok: 'عضو از اتاق اخراج شد (کلیک دوباره رفع انسداد می‌کند)',
    tm_role_ok: 'نقش به‌روز شد', tm_mic_on: 'روشن کردن میکروفون',
    tm_mic_off: 'قطع میکروفون', tm_mic_denied: 'میکروفون رد شد یا در دسترس نیست : HTTPS لازم است (تونل جهانی یا localhost) و باید اجازه بدهی',
    navf: 'ناوگان', navfd: 'یافته‌ها',
    navp: 'برنامه‌ها', navai: 'هوش مصنوعی',
    navc: 'هماهنگی', st_runs: 'اجراها',
    st_beacons: 'بیکن‌های فعال', st_sig: 'سیگنال‌ها',
    h2f: 'ناوگان - همه برنامه‌ها، ایجنت‌های در حال اجرا اول', h2fd: 'پایگاه یافته‌ها - برچسب‌گذاری تریاژ ماندگار',
    h2eng: 'موتور ناوگان - چرخه‌های محلی بدون توکن', h2prog: 'برنامه‌ها - scope، هدر لازم، اجرا',
    h2new: 'برنامه جدید', h2ai: 'ایجنت هوش مصنوعی - اتصال 100% اختیاری',
    h2c: 'هماهنگی - کانال خصوصی', fl_start: 'شروع',
    fl_pause: 'توقف موقت', fl_cycle: 'چرخه فوری',
    f_add: 'افزودن', f_none: 'هنوز هیچ سیگنالی نیست',
    f_ph: 'یافته دستی : اندپوینت + مدرک + شدت قابل دفاع…', st_sig_off: 'سیگنال',
    st_sig_an: 'تحلیل', st_sig_sub: 'ارسال‌شده',
    st_sig_dup: 'تکراری', st_sig_ref: 'ردشده',
    st_sig_cl: 'بسته', r_none: 'هیچ اجرایی شناسایی نشد',
    r_live: '{n} در حال اجرا', r_done: 'پایان',
    r_feed: '▽ جریان ({n} رویداد)', r_close: '△ جمع کردن',
    p_name_ph: 'نام برنامه (مثلاً PayPal)', p_hdr_ph: 'هدر لازم پژوهشگر (مثلاً X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : دامنه۱، دامنه۲، …', p_save: 'ذخیره',
    p_local: 'ماژول(ها)، 100% محلی', ai_p: 'C2FF کاملاً بدون هوش مصنوعی کار می‌کند : حالت‌ها پروب‌های قطعی محلی هستند. این دروازه فقط برای وصل کردن <b>هوش مصنوعی خودت</b> (self-hosted یا API) است تا یک یافته را به‌صورت موردی تحلیل کند : دکمه <span style="color:var(--green)">هوش مصنوعی »</span> در یافته‌ها، پاسخ در هماهنگی رندر می‌شود. بدون این تنظیم هیچ داده‌ای از دستگاهت بیرون نمی‌رود.',
    ai_off: 'غیرفعال', ai_on: 'فعال',
    ai_st_off: 'هوش مصنوعی خاموش - فریم‌ورک 100% محلی بدون آن کار می‌کند', ai_st_ready: 'هوش مصنوعی متصل : {p} · {m}',
    ai_st_inc: 'هوش مصنوعی فعال اما ناقص : baseURL و model لازم است', ai_url_ph: 'base URL - مثلاً http://localhost:11434 یا https://api.MyAI.tld/v1',
    ai_model_ph: 'model - مثلاً llama3.1:8b', ai_key_ph: 'کلید API (برای سرور محلی خالی بگذار)',
    ai_save: 'ذخیره', ai_test: 'تست اتصال',
    ai_testing: 'تست در جریان…', ai_ok: 'OK - پاسخ : ',
    ai_fail: 'شکست : ', ai_note: 'تنظیمات به‌صورت محلی در data/ai.json ذخیره می‌شود - هرگز به جایی جز اندپوینتی که خودت می‌گذاری فرستاده نمی‌شود',
    ch_ph: 'root@c2ff:~# پیام به ایجنت تحلیل…', ch_send: 'ارسال',
    ch_empty: 'کانال باز است. اینجا تایپ کن، مانیتور همان لحظه بیدارم می‌کند.', ft: '100% محلی - پروب‌های قطعی، بدون توکن و بدون وابستگی بیرونی - unrestricted · undetected · unstoppable',
    to_fl_on: 'حالت FLEET فعال : چرخه‌های محلی هر 30 دقیقه، 0 توکن.', to_fl_pa: 'FLEET در توقف موقت - هر وقت خواستی ادامه بده.',
    to_fl_cy: 'چرخه فوری اجرا شد (بودجه 60 req).', to_launch: '[GO] حالت {m} (CWE {c}) روی {p} - چرخه محلی اجرا شد',
    to_ai_ok: 'تنظیمات ذخیره شد', to_ai_no: 'ذخیره شکست خورد',
    to_ai_no_cfg: 'هوش مصنوعی تنظیم نشده - در تب هوش مصنوعی تنظیمش کن', to_ai_head: 'تحلیل هوش مصنوعی',
    to_ai_bad: 'تحلیل هوش مصنوعی شکست خورد', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'هوش مصنوعی',
    w_launch: '⚡ شروع', navar: 'ارسنال',
    ar_h2: 'ARSENAL - CVE، EPSS واکسپلویت‌ها روی سطح شناسایی‌شده', ar_sync: 'SYNC پایگاه‌ها',
    ar_btn: 'حرکت‌ها', ar_exec: 'EXEC',
    ar_none: 'حرکتی نیست: اول RECON را اجرا کن، بعد SYNC برای بارگذاری KEV/EPSS', ar_loading: 'خلاصه پایگاه‌ها در حال بارگذاری...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'برنامه نمایشی - اسکن ممکن نیست: برنامه خودت را بساز', pip_noprog: 'هیچ برنامه‌ای وجود ندارد: برنامه خودت را در تب برنامه‌ها بساز',
    pip_next: 'مرحله بعدی:', fnd_n: 'یافته‌ها: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  ur: {
    pl_title: 'ورک پلان', pl_empty: 'ابھی کوئی پلان نہیں: اوپر والے کارڈ میں RECON چلاؤ، مفروضے یہاں آتے ہیں (اسٹیٹس محفوظ رہتے ہیں)',
    pl_run: 'چلاؤ', pl_reflect: 'canary منعکس ہو گیا',
    st_do: 'کرنا ہے', st_test: 'ٹیسٹ شدہ',
    st_signal: 'سگنل', st_valid: 'تصدیق شدہ',
    st_void: 'کچھ نہیں', atk_btn: 'ATTACK',
    atk_start: 'سرفیس پر اٹیک: اینڈ پوائنٹس، کھلی دستاویزات، JWT، سیکریٹس...', atk_fail: 'اٹیک ممکن نہیں: پہلے RECON چلاؤ',
    atk_none: 'کوئی سگنل نہیں', atk_findings: 'کینڈیڈیٹس',
    atk_done: 'ATTACK: اثبات کے ساتھ {n} کینڈیڈیٹس P1/P2 findings میں داخل کر دیے', atk_empty: 'ابھی کوئی اٹیک نہیں: RECON چلاؤ پھر ATTACK - req/res اثبات والے کینڈیڈیٹس یہاں آتے ہیں',
    navh: 'HUNT', h2hunt: 'HUNT - اصل سرفیس اور ثبوت',
    h_ready: 'تیار', h_empty: 'کوئی سرفیس معلوم نہیں: RECON چلاؤ تاکہ صفحات، API اینڈ پوائنٹس، پیرامیٹرز، JS بنڈلز اور سب ڈومینز میپ ہو جائیں',
    h_fnd: 'پروگرام کے Findings', h_nofnd: 'اس پروگرام کا کوئی finding نہیں',
    rc_btn: 'RECON', rc_start: 'سرفیس کا recon جاری: صفحات، JS بنڈلز، اینڈ پوائنٹس، پیرامیٹرز...',
    rc_done: 'سرفیس میپ ہو گئی: اینڈ پوائنٹس، پیرامیٹرز اور سب ڈومینز پروگرام کارڈ میں لسٹ ہیں', rc_fail: 'recon ناکام: ہوسٹ پہنچ سے باہر یا scope خالی',
    rc_surface: 'سرفیس:', snd_on: 'آواز: چالو',
    snd_off: 'آواز: بند', snd_ok: 'انٹرفیس کی آوازیں فعال - لائبریری: کلک، ٹیب، کاپی، الرٹس',
    snd_stop: 'مکمل خاموشی فعال: اب C2FF کی کوئی آواز نہیں', amb_on: 'ماحول: چالو',
    amb_off: 'ماحول: بند', amb_ok: 'زندہ ماحول - رنگ خاندانوں کے درمیان نرمی سے پھرتا ہے (سبز، نیلا، پیلا...)',
    amb_stop: 'ماحول اصل سبز پر جم گیا', nt_on: 'نوٹیفیکیشنز: چالو',
    nt_off: 'نوٹیفیکیشنز: بند', nt_ok: 'براؤزر نوٹیفیکیشنز فعال - P1 اور P2 پر بین',
    nt_denied: 'براؤزر نے نوٹیفیکیشنز بلاک کر دیں: سائٹ کی سیٹنگز میں اجازت دو', term_denied: 'ٹرمینل مسترد یا دستیاب نہیں: localhost لازم ہے، یا ایڈمن کے طور پر OPEN روم',
    term_p: 'حقیقی bash - تیر اوپر سے ہسٹری، Ctrl+C توڑتا ہے، Ctrl+D بند کرتا ہے', term_restart: 'ری سیٹ',
    navtrm: 'TERM', term_h2: 'ٹرمینل - ورک شیل، سیدھا کنسول میں',
    fl_off: 'FLEET: رکا ہوا', fl_paused: 'FLEET: وقفے پر',
    fl_active: 'FLEET: فعال ({n} سائیکل)', fl_last: 'آخری سائیکل',
    fl_none: 'ابھی کوئی سائیکل نہیں', fl_info: 'وقفہ {i} منٹ، بجٹ {b} req/سائیکل',
    sub_ttl: 'کمانڈ اینڈ کنٹرول framework', navt: 'سیشن',
    tm_h2: 'گروپ سیشنز - مل کر ہنٹ، بغیر ایک جیسے نیٹ ورک بھی', tm_p: 'شیئرڈ روم کھولو: آپ کا گروپ بیڑا اور findings دیکھتا ہے اور لائیو ٹرائیج کر سکتا ہے. مخصوص سیشن چیٹ نیچے ہے. رسائی کی تین سطحیں: LOCAL (اکیلا)، LAN «نیٹ ورک پر کھولو» سے، اور دنیا «دنیا پر کھولو» سے - ایک پبلک ٹنل (cloudflared اگر انسٹال ہو) انوائٹ لنک کو کسی بھی نیٹ ورک سے چلتا رکھتا ہے، بغیر آپ کی مشین کے براہ راست ایکسپوز کیے. سب کچھ روم کی clave... روم کی کلید سے محفوظ ہے - اسے دوبارہ جنریٹ کرو تاکہ سب ایک ساتھ باہر ہو جائیں.',
    tm_handle: 'آپ کا ہینڈل (حدود ۱۶ حروف)', tm_save_h: 'سیٹ کرو',
    tm_room_ph: 'روم کا نام (مثلاً: c2ff-core)', tm_save: 'لاگو کرو',
    tm_on: 'روم کھلی ہے: {r} - {n} آن لائن', tm_off: 'ٹیم موڈ آف - لوکل سولو سیشن',
    tm_room: 'روم', tm_key: 'روم کی کلید',
    tm_regen: 'کلید دوبارہ جنریٹ کرو', tm_regen_ok: 'نئی کلید بن گئی - پرانے لنکس مر چکے',
    tm_invite: 'انوائٹ لنک (اپنی ٹیم کو کاپی کرو)', tm_copy: 'کاپی',
    tm_copied: 'کلپ بورڈ پر کاپی ہو گیا', tm_members: 'ارکان',
    tm_nobody: 'ابھی کوئی نہیں - انوائٹ لنک ٹیم کو بھیجو', tm_you: '(آپ)',
    tm_here: 'موجود', tm_saved: 'ہینڈل محفوظ ہو گیا',
    tm_no_handle: 'ہینڈل خالی', tm_cfg_ok: 'روم اپ ڈیٹ ہو گئی',
    tm_cfg_no: 'ناکام', tm_live: 'نیٹ ورک پر کھولو',
    tm_shore: 'واپس لوکل', tm_need_on: 'پہلے روم آن کرو (ON)',
    tm_bind_lan: 'نیٹ ورک: {a}', tm_bind_lo: 'لوکل: صرف localhost',
    to_team_live: '[GO-LIVE] سرور نیٹ ورک رسائی کے ساتھ دوبارہ چل پڑا - LAN لنک دکھایا گیا، 2 سیکنڈ میں دوبارہ جڑنا', to_team_shore: 'سرور لوکل پر دوبارہ چل پڑا (127.0.0.1)',
    tm_tun_open: 'دنیا پر کھولو (ٹنل)', tm_tun_close: 'ٹنل بند کرو',
    tm_tun_wait: 'پبلک ٹنل کھل رہا ہے (چند سیکنڈ)…', tm_tun_on: 'سیشن دنیا پر کھلا: {u} - انوائٹ لنک ہر جگہ چلتا ہے، ایک جیسے نیٹ ورک کی ضرورت نہیں',
    tm_tun_closed: 'ٹنل بند - واپس LAN/لوکل', tm_chat_empty: 'سیشن چینل کھلا - روم کے ارکان یہاں ایک دوسرے کو پڑھتے ہیں',
    tm_chat_h2: 'سیشن چیٹ', tm_msg_ph: 'سیشن کے لیے پیغام…',
    tm_admin: 'ایڈمن', tm_guest: 'مہمان',
    tm_kick: 'KICK', tm_kick_ok: 'روم کا رکن نکال دیا گیا (دوبارہ کلک سے کھل جاتا ہے)',
    tm_role_ok: 'رول اپ ڈیٹ ہو گیا', tm_mic_on: 'مائیکروفون چالو کرو',
    tm_mic_off: 'مائیکروفون بند کرو', tm_mic_denied: 'مائیکروفون مسترد یا دستیاب نہیں: HTTPS لازم ہے (WORLD ٹنل یا localhost) اور اجازت دینی ہوگی',
    navf: 'بیڑا', navfd: 'Findings',
    navp: 'پروگرامز', navai: 'ہوش مصنوعی',
    navc: 'ہم آہنگی', st_runs: 'رنز',
    st_beacons: 'فعال بیکنز', st_sig: 'سگنلز',
    h2f: 'بیڑا - تمام پروگرامز، چل رہے ایجنٹس پہلے', h2fd: 'Findings بیس - مستقل ٹرائیج ٹیگنگ',
    h2eng: 'بیڑا انجن - لوکل سائیکلز، بغیر ٹوکنز', h2prog: 'پروگرامز - scope، مطلوبہ ہیڈر، لانچ',
    h2new: 'نیا پروگرام', h2ai: 'ہوش مصنوعی ایجنٹ - 100% اختیاری انٹیگریشن',
    h2c: 'ہم آہنگی - پرائیویٹ چینل', fl_start: 'شروع',
    fl_pause: 'وقفہ', fl_cycle: 'ابھی سائیکل',
    f_add: 'شامل کرو', f_none: 'ابھی کوئی سگنل نہیں',
    f_ph: 'دستی finding: اینڈ پوائنٹ + اثبات + قابل دفاع شدت…', st_sig_off: 'سگنل',
    st_sig_an: 'تجزیہ', st_sig_sub: 'جمع شدہ',
    st_sig_dup: 'ڈپ', st_sig_ref: 'مسترد',
    st_sig_cl: 'بند', r_none: 'کوئی رن نہیں ملا',
    r_live: '{n} چل رہے ہیں', r_done: 'مکمل',
    r_feed: '▽ فیڈ ({n} واقعہ)', r_close: '△ سمیٹو',
    p_name_ph: 'پروگرام کا نام (مثال: PayPal)', p_hdr_ph: 'مطلوبہ ریسرچر ہیڈر (مثال: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: ڈومین1، ڈومین2، …', p_save: 'محفوظ کرو',
    p_local: 'ماڈیولز، 100% لوکل', ai_p: 'C2FF ہوش مصنوعی کے بغیر پورا چلتا ہے: موڈز مقامی طے شدہ پروبز ہیں. یہ گیٹ وے صرف آپ کی <b>اپنی</b> ہوش مصنوعی (self-hosted یا API) جوڑنے کے لیے ہے تاکہ کسی finding کا وقفے پر تجزیہ ہو: FINDINGS میں <span style="color:var(--green)">ہوش مصنوعی »</span> بٹن، جواب COORDINATION میں رینڈر ہوتا ہے. اس ترتیب کے بغیر آپ کی مشین سے کوئی ڈیٹا باہر نہیں جاتا.',
    ai_off: 'بند', ai_on: 'چالو',
    ai_st_off: 'ہوش مصنوعی بند - framework اس کے بغیر 100% لوکل چلتا ہے', ai_st_ready: 'ہوش مصنوعی جڑا ہوا: {p} · {m}',
    ai_st_inc: 'ہوش مصنوعی چالو مگر نامکمل: baseURL اور model درکار', ai_url_ph: 'base URL - مثال: http://localhost:11434 یا https://api.MyAI.tld/v1',
    ai_model_ph: 'model - مثال: llama3.1:8b', ai_key_ph: 'API کی کلید (لوکل سرور کے لیے خالی چھوڑو)',
    ai_save: 'محفوظ کرو', ai_test: 'کنکشن ٹیسٹ',
    ai_testing: 'ٹیسٹ جاری…', ai_ok: 'OK - جواب: ',
    ai_fail: 'ناکام: ', ai_note: 'config لوکل طور پر data/ai.json میں محفوظ - سواے اسی اینڈ پوائنٹ کے جہاں آپ خود رکھیں کہیں نہیں جاتی',
    ch_ph: 'root@c2ff:~# تجزیہ ایجنٹ کے لیے پیغام…', ch_send: 'بھیجو',
    ch_empty: 'چینل کھلا ہے. یہاں لکھو، مانیٹر مجھے فوراً جگا دیتا ہے.', ft: '100% لوکل - طے شدہ پروبز، بغیر ٹوکن اور بغیر بیرونی ڈیپینڈنسی - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE فعال: ہر 30 منٹ لوکل سائیکلز، 0 ٹوکنز.', to_fl_pa: 'FLEET وقفے پر - جب چاہو دوبارہ شروع.',
    to_fl_cy: 'فوری سائیکل چل پڑا (بجٹ 60 req).', to_launch: '[GO] mode {m} (CWE {c}) بر {p} - لوکل سائیکل چل پڑا',
    to_ai_ok: 'config محفوظ ہو گئی', to_ai_no: 'محفوظ کرنے میں ناکامی',
    to_ai_no_cfg: 'ہوش مصنوعی تشکیل شدہ نہیں - ہوش مصنوعی ٹیب میں سیٹ کرو', to_ai_head: 'ہوش مصنوعی تجزیہ',
    to_ai_bad: 'ہوش مصنوعی تجزیہ ناکام', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'ہوش مصنوعی',
    w_launch: '⚡ لانچ', navar: 'ارسنل',
    ar_h2: 'ARSENAL - شناختی گئی سطح پر CVE، EPSS اور ایکسپلوئٹس', ar_sync: 'SYNC ڈیٹا بیس',
    ar_btn: 'چالیں', ar_exec: 'EXEC',
    ar_none: 'کوئی چال نہیں: پہلے RECON چلائیں، پھر KEV/EPSS لوڈ کرنے کے لیے SYNC', ar_loading: 'ڈیٹا بیس کا خلاصہ لوڈ ہو رہا ہے...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'ڈیمو پروگرام - سکین نہیں ہو سکتا: اپنا پروگرام بنائیں', pip_noprog: 'کوئی پروگرام نہیں: پروگرامز ٹیب میں اپنا پروگرام بنائیں',
    pip_next: 'اگلا مرحلہ:', fnd_n: 'فائنڈنگز: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  ro: {
    pl_title: 'Plan de lucru', pl_empty: 'încă niciun plan: rulează RECON în cardul de sus, ipotezele ajung aici (stările se salvează)',
    pl_run: 'Rulează', pl_reflect: 'canary reflectat',
    st_do: 'de făcut', st_test: 'testat',
    st_signal: 'semnal', st_valid: 'valid',
    st_void: 'nimic', atk_btn: 'ATTACK',
    atk_start: 'atac asupra suprafeței: endpoint-uri, documente expuse, JWT, secrets...', atk_fail: 'atacul eșuat: rulează mai întâi RECON',
    atk_none: 'niciun semnal', atk_findings: 'candidați',
    atk_done: 'ATTACK: {n} candidați P1/P2 injectați în findings cu dovadă', atk_empty: 'încă niciun atac: rulează RECON apoi ATTACK - candidații cu dovadă req/res ajung aici',
    navh: 'HUNT', h2hunt: 'HUNT - suprafață reală și dovezi',
    h_ready: 'gata', h_empty: 'nicio suprafață cunoscută: rulează RECON pentru a cartografia pagini, endpoint-uri API, parametri, bundle-uri JS și subdomenii',
    h_fnd: 'Findings ale programului', h_nofnd: 'niciun finding pentru acest program',
    rc_btn: 'RECON', rc_start: 'recon al suprafeței în desfășurare: pagini, bundle-uri JS, endpoint-uri, parametri...',
    rc_done: 'suprafață cartografiată: endpoint-uri, parametri și subdomenii listate în cardul programului', rc_fail: 'recon eșuat: host inaccesibil sau scope gol',
    rc_surface: 'suprafață:', snd_on: 'SUNET: ON',
    snd_off: 'SUNET: OFF', snd_ok: 'sunete de interfață active - bibliotecă: click, tab, copiere, alerte',
    snd_stop: 'mute total activat: niciun sunet C2FF', amb_on: 'AMBIENT: ON',
    amb_off: 'AMBIENT: OFF', amb_ok: 'ambient viu - nuanța alunecă încet prin familii (verde, albastru, galben...)',
    amb_stop: 'ambient înghețat pe verdele original', nt_on: 'NOTIFICĂRI: ON',
    nt_off: 'NOTIFICĂRI: OFF', nt_ok: 'notificări browser activate - bip la P1 și P2',
    nt_denied: 'notificări blocate de browser: permite-le din setările site-ului', term_denied: 'terminal refuzat sau indisponibil: e necesar localhost, sau o sală DESCHISĂ ca admin',
    term_p: 'bash real - istorie cu săgeți, Ctrl+C întrerupe, Ctrl+D închide', term_restart: 'Resetează',
    navtrm: 'TERM', term_h2: 'Terminal - shell de lucru, direct în consolă',
    fl_off: 'FLEET: OPRIT', fl_paused: 'FLEET: ÎN PAUZĂ',
    fl_active: 'FLEET: ACTIV ({n} cicluri)', fl_last: 'ultimul ciclu',
    fl_none: 'încă niciun ciclu', fl_info: 'interval {i} min, buget {b} req/ciclu',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Sesiuni în grup - vânătoare în echipă, chiar și din rețele diferite', tm_p: 'Deschide o sală partajată: grupul tău vede flota, findings-urile și poate tria live. Chat de sesiune dedicat mai jos. Trei niveluri de acces: LOCAL (solo), LAN prin DESCHIDE ÎN RETEAUĂ și LUME prin DESCHIDE CĂTRE LUME - un tunel public (cloudflared dacă e instalat) face linkul de invitație valid din orice rețea, fără expunerea directă a mașinii tale. Totul trece prin cheia sălii - regenereaz-o pentru a da pe toți afară dintr-o singură mișcare.',
    tm_handle: 'Pseudonimul tău (16 caractere max)', tm_save_h: 'Alege',
    tm_room_ph: 'numele sălii (ex: c2ff-core)', tm_save: 'Aplică',
    tm_on: 'SALĂ DESCHISĂ: {r} - {n} online', tm_off: 'MOD TEAM DEZACTIVAT - sesiune locală solo',
    tm_room: 'Sală', tm_key: 'Cheia sălii',
    tm_regen: 'Regenerează cheia', tm_regen_ok: 'cheie nouă generată - linkurile vechi sunt moarte',
    tm_invite: 'Link de invitație (de copiat către echipa ta)', tm_copy: 'Copiază',
    tm_copied: 'copiat în clipboard', tm_members: 'Membri',
    tm_nobody: 'încă nimeni - trimite linkul echipei tale', tm_you: '(tu)',
    tm_here: 'prezent', tm_saved: 'pseudonim salvat',
    tm_no_handle: 'pseudonim gol', tm_cfg_ok: 'sală actualizată',
    tm_cfg_no: 'eșec', tm_live: 'DESCHIDE ÎN RETEAUĂ',
    tm_shore: 'ÎNTOARCE LA LOCAL', tm_need_on: 'activează mai întâi sala (ON)',
    tm_bind_lan: 'REȚEA: {a}', tm_bind_lo: 'LOCAL: doar localhost',
    to_team_live: '[GO-LIVE] server repornit cu acces în rețea - link LAN afișat, reconectare în 2 s', to_team_shore: 'server repornit local (127.0.0.1)',
    tm_tun_open: 'DESCHIDE CĂTRE LUME (tunel)', tm_tun_close: 'ÎNCHIDE TUNELUL',
    tm_tun_wait: 'tunel public în curs de deschidere (câteva secunde)…', tm_tun_on: 'SESIUNE DESCHISĂ CĂTRE LUME: {u} - linkul de invitație merge oriunde, nu ai nevoie de aceeași rețea',
    tm_tun_closed: 'tunel închis - înapoi la LAN/local', tm_chat_empty: 'canal de sesiune deschis - membrii sălii comunică aici',
    tm_chat_h2: 'Chat de sesiune', tm_msg_ph: 'mesaj către sesiune…',
    tm_admin: 'admin', tm_guest: 'invitat',
    tm_kick: 'KICK', tm_kick_ok: 'membru dat afară din sală (mai apasă o dată pentru deblocare)',
    tm_role_ok: 'rol actualizat', tm_mic_on: 'ACTIVEAZĂ MICROFONUL',
    tm_mic_off: 'OPREȘTE MICROFONUL', tm_mic_denied: 'microfon refuzat sau inaccesibil: e necesar HTTPS (tunel LUME sau localhost) și trebuie să permiți microfonul',
    navf: 'Flotă', navfd: 'Findings',
    navp: 'Programe', navai: 'IA',
    navc: 'Coordonare', st_runs: 'Rulări',
    st_beacons: 'Beacons active', st_sig: 'Semnale',
    h2f: 'Flotă - toate programele, agenții rulează primele', h2fd: 'Bază de findings - etichetare triaj persistentă',
    h2eng: 'Motor de flotă - cicluri locale fără tokenuri', h2prog: 'Programe - scope, header obligatoriu, lansare',
    h2new: 'Program nou', h2ai: 'Agent IA - integrare 100% opțională',
    h2c: 'Coordonare - canal privat', fl_start: 'Pornește',
    fl_pause: 'Pauză', fl_cycle: 'Ciclu acum',
    f_add: 'Adaugă', f_none: 'încă niciun semnal',
    f_ph: 'finding manual: endpoint + dovadă + severitate apărabilă…', st_sig_off: 'semnal',
    st_sig_an: 'analiză', st_sig_sub: 'trimis',
    st_sig_dup: 'dup', st_sig_ref: 'refuzat',
    st_sig_cl: 'închis', r_none: 'niciun run detectat',
    r_live: '{n} ÎN CURS', r_done: 'TERMINAT',
    r_feed: '▽ flux ({n} evenimente)', r_close: '△ restrânge',
    p_name_ph: 'Numele programului (ex: PayPal)', p_hdr_ph: 'header de cercetător obligatoriu (ex: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domeniu1, domeniu2, …', p_save: 'Salvează',
    p_local: 'module, 100% local', ai_p: 'C2FF funcționează integral fără IA: modurile sunt sonde deterministe locale. Acest gateway servește doar la conectarea <b>IA</b>-ului <b>tău</b> (self-hosted sau API) pentru analiza punctuală a unui finding: butonul <span style="color:var(--green)">IA »</span> în FINDINGS, răspunsul randat în COORDINATION. Nicio dată nu iese din mașina ta fără această configurație.',
    ai_off: 'dezactivată', ai_on: 'activată',
    ai_st_off: 'IA DEZACTIVATĂ - framework-ul rulează 100% local fără ea', ai_st_ready: 'IA CONECTATĂ: {p} · {m}',
    ai_st_inc: 'IA ACTIVATĂ DAR INCOMPLETĂ: baseURL și model obligatorii', ai_url_ph: 'base URL - ex: http://localhost:11434 sau https://api.IAMea.tld/v1',
    ai_model_ph: 'model - ex: llama3.1:8b', ai_key_ph: 'cheie API (lasă gol pentru server local)',
    ai_save: 'Salvează', ai_test: 'Testează conexiunea',
    ai_testing: 'test în curs…', ai_ok: 'OK - răspuns: ',
    ai_fail: 'EȘEC: ', ai_note: 'config salvat local în data/ai.json - niciodată trimis altundeva decât către endpoint-ul pe care îl setezi',
    ch_ph: 'root@c2ff:~# mesaj către agentul de analiză…', ch_send: 'Trimite',
    ch_empty: 'Canalul e deschis. Scrie aici, monitorul mă trezește instant.', ft: '100% local - sonde deterministe, fără tokenuri și fără dependențe externe - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ACTIV: cicluri locale la fiecare 30 min, 0 tokenuri.', to_fl_pa: 'FLEET ÎN PAUZĂ - reia când vrei.',
    to_fl_cy: 'Ciclu imediat lansat (buget 60 req).', to_launch: '[GO] mod {m} (CWE {c}) pe {p} - ciclu local lansat',
    to_ai_ok: 'config salvat', to_ai_no: 'salvare eșuată',
    to_ai_no_cfg: 'IA neconfigurată - configureaz-o în tabul IA', to_ai_head: 'ANALIZĂ IA',
    to_ai_bad: 'ANALIZĂ IA eșuată', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'IA',
    w_launch: '⚡ LANSARE', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS si exploituri pe suprafata detectata', ar_sync: 'SYNC BAZE DE DATE',
    ar_btn: 'MISCARI', ar_exec: 'EXEC',
    ar_none: 'nicio miscare: ruleaza mai intai RECON, apoi SYNC pentru a incarca KEV/EPSS', ar_loading: 'rezumatul bazelor se incarca...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'program demonstrativ - fara scanare: creeaza-ti programul', pip_noprog: 'niciun program: creeaza-ti programul la Programe',
    pip_next: 'pasul urmator:', fnd_n: 'descoperiri: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  bg: {
    pl_title: 'Работен план', pl_empty: 'още няма план: стартирай RECON в картата отгоре, хипотезите падат тук (статусите се запазват)',
    pl_run: 'Стартирай', pl_reflect: 'canary отражен',
    st_do: 'за правене', st_test: 'тестиран',
    st_signal: 'сигнал', st_valid: 'валиден',
    st_void: 'нищо', atk_btn: 'ATTACK',
    atk_start: 'атака на повърхността: endpoints, отворени документации, JWT, секрети...', atk_fail: 'атака невъзможна: първо стартирай RECON',
    atk_none: 'няма сигнал', atk_findings: 'кандидати',
    atk_done: 'ATTACK: {n} кандидата P1/P2 инжектирани в findings с доказателство', atk_empty: 'още няма атака: стартирай RECON, после ATTACK - кандидатите с доказателство req/res падат тук',
    navh: 'HUNT', h2hunt: 'HUNT - реална повърхност и доказателства',
    h_ready: 'готов', h_empty: 'няма известна повърхност: стартирай RECON, за да картографираш страници, API endpoints, параметри, JS bundles и поддомейни',
    h_fnd: 'Findings на програмата', h_nofnd: 'няма findings за тази програма',
    rc_btn: 'RECON', rc_start: 'recon на повърхността е в ход: страници, JS bundles, endpoints, параметри...',
    rc_done: 'повърхността е картографирана: endpoints, параметри и поддомейни са изброени в картата на програмата', rc_fail: 'recon се провали: host недостъпен или празен scope',
    rc_surface: 'повърхност:', snd_on: 'ЗВУК: ON',
    snd_off: 'ЗВУК: OFF', snd_ok: 'звуци на интерфейса активни - библиотека: клик, таб, копиране, аларми',
    snd_stop: 'пълно заглушаване включено: никакви звуци на C2FF', amb_on: 'АМБИЕНТ: ON',
    amb_off: 'АМБИЕНТ: OFF', amb_ok: 'жив амбиент - нюансът се плъзга плавно през семействата (зелен, син, жълт...)',
    amb_stop: 'амбиентът е закован на оригиналното зелено', nt_on: 'ИЗВЕСТИЯ: ON',
    nt_off: 'ИЗВЕСТИЯ: OFF', nt_ok: 'известия в браузъра активирани - бип при P1 и P2',
    nt_denied: 'известията са блокирани от браузъра: разреши ги в настройките на сайта', term_denied: 'терминалът е отказан или недостъпен: нужен е localhost, или ОТВОРЕНА стая като админ',
    term_p: 'истински bash - история със стрелки, Ctrl+C прекъсва, Ctrl+D затваря', term_restart: 'Рестартирай',
    navtrm: 'TERM', term_h2: 'Терминал - работен shell, директно в конзолата',
    fl_off: 'FLEET: СПРЯН', fl_paused: 'FLEET: НА ПАУЗА',
    fl_active: 'FLEET: АКТИВЕН ({n} цикъла)', fl_last: 'последен цикъл',
    fl_none: 'още няма цикъл', fl_info: 'интервал {i} мин, бюджет {b} req/cycle',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Групови сесии - лов в екип, дори извън мрежата', tm_p: 'Отвори споделена стая: групата ти вижда флота, findings и може да триажва на живо. Отделен чат за сесията е отдолу. Три нива на достъп: LOCAL (соло), LAN чрез ОТВОРИ КЪМ МРЕЖАТА и СВЯТ чрез ОТВОРИ КЪМ СВЕТА - публичен тунел (cloudflared, ако е инсталиран) прави линка за покана валиден от която и да е мрежа, без директно излагане на машината ти. Всичко минава през ключа на стаята - регенерирай го, за да изхвърлиш всички наведнъж.',
    tm_handle: 'Твоят псевдоним (16 символа max)', tm_save_h: 'Избери',
    tm_room_ph: 'име на стаята (напр. c2ff-core)', tm_save: 'Приложи',
    tm_on: 'СТАЯТА Е ОТВОРЕНА: {r} - {n} онлайн', tm_off: 'TEAM MODE ИЗКЛЮЧЕН - локална соло сесия',
    tm_room: 'Стая', tm_key: 'Ключ на стаята',
    tm_regen: 'Регенерирай ключа', tm_regen_ok: 'нов ключ е генериран - старите линкове са мъртви',
    tm_invite: 'Линк за покана (за копиране към твоя отбор)', tm_copy: 'Копирай',
    tm_copied: 'копирано в клипборда', tm_members: 'Членове',
    tm_nobody: 'още никой - изпрати линка на екипа си', tm_you: '(ти)',
    tm_here: 'тук', tm_saved: 'псевдонимът е записан',
    tm_no_handle: 'празен псевдоним', tm_cfg_ok: 'стаята е обновена',
    tm_cfg_no: 'неуспех', tm_live: 'ОТВОРИ КЪМ МРЕЖАТА',
    tm_shore: 'ВЪРНИ ЛОКАЛНО', tm_need_on: 'първо включи стаята (ON)',
    tm_bind_lan: 'МРЕЖА: {a}', tm_bind_lo: 'ЛОКАЛНО: само localhost',
    to_team_live: '[GO-LIVE] сървърът е рестартиран с достъп към мрежата - LAN линк е показан, свързване отново след 2 с', to_team_shore: 'сървърът е рестартиран локално (127.0.0.1)',
    tm_tun_open: 'ОТВОРИ КЪМ СВЕТА (тунел)', tm_tun_close: 'ЗАТВОРИ ТУНЕЛА',
    tm_tun_wait: 'публичен тунел се отваря (няколко секунди)…', tm_tun_on: 'СЕСИЯТА Е ОТВОРЕНА КЪМ СВЕТА: {u} - линкът за покана работи отвсякъде, не е нужна една и съща мрежа',
    tm_tun_closed: 'тунелът е затворен - обратно към LAN/local', tm_chat_empty: 'каналът на сесията е отворен - членовете на стаята се четат тук',
    tm_chat_h2: 'Чат на сесията', tm_msg_ph: 'съобщение към сесията…',
    tm_admin: 'админ', tm_guest: 'гост',
    tm_kick: 'KICK', tm_kick_ok: 'членът е изгонен от стаята (повторен клик отключва)',
    tm_role_ok: 'ролята е обновена', tm_mic_on: 'ВКЛЮЧИ МИКРОФОНА',
    tm_mic_off: 'ЗАГЛУШИ МИКРОФОНА', tm_mic_denied: 'микрофонът е отказан или недостъпен: нужен е HTTPS (СВЕТОВЕН тунел или localhost) и трябва да разрешиш микрофона',
    navf: 'Флота', navfd: 'Findings',
    navp: 'Програми', navai: 'ИИ',
    navc: 'Координация', st_runs: 'Изпълнения',
    st_beacons: 'Активни beacons', st_sig: 'Сигнали',
    h2f: 'Флота - всички програми, агентите в ход най-отпред', h2fd: 'База findings - постоянна триаж маркировка',
    h2eng: 'Двигател на флота - локални цикли без токени', h2prog: 'Програми - scope, задължителен header, стартиране',
    h2new: 'Нова програма', h2ai: 'ИИ агент - интеграция 100% по желание',
    h2c: 'Координация - частен канал', fl_start: 'Старт',
    fl_pause: 'Пауза', fl_cycle: 'Цикъл сега',
    f_add: 'Добави', f_none: 'още няма сигнал',
    f_ph: 'ръчен finding: endpoint + доказателство + защитима тежест…', st_sig_off: 'сигнал',
    st_sig_an: 'анализ', st_sig_sub: 'изпратено',
    st_sig_dup: 'dup', st_sig_ref: 'отказано',
    st_sig_cl: 'затворено', r_none: 'няма открит run',
    r_live: '{n} В ХОД', r_done: 'ГОТОВО',
    r_feed: '▽ поток ({n} съб)', r_close: '△ свий',
    p_name_ph: 'Име на програмата (напр. PayPal)', p_hdr_ph: 'задължителен изследователски header (напр. X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: домейн1, домейн2, …', p_save: 'Запази',
    p_local: 'модул(и), 100% локално', ai_p: 'C2FF работи изцяло без ИИ: режимите са локални детерминирани сонди. Този gateway служи само за закачане на <b>твоя</b> ИИ (self-hosted или API) за еднократен анализ на finding: бутонът <span style="color:var(--green)">ИИ »</span> в FINDINGS, отговорът се показва в COORDINATION. Без тази настройка никакви данни не напускат машината ти.',
    ai_off: 'изключен', ai_on: 'включен',
    ai_st_off: 'ИИ ИЗКЛЮЧЕН - framework-ът върви 100% локално без него', ai_st_ready: 'ИИ СВЪРЗАН: {p} · {m}',
    ai_st_inc: 'ИИ ВКЛЮЧЕН НО НЕПЪЛЕН: baseURL и model са задължителни', ai_url_ph: 'base URL - напр. http://localhost:11434 или https://api.MoqIA.tld/v1',
    ai_model_ph: 'model - напр. llama3.1:8b', ai_key_ph: 'API ключ (остави празно за локален сървър)',
    ai_save: 'Запази', ai_test: 'Тествай връзката',
    ai_testing: 'тест в ход…', ai_ok: 'OK - отговор: ',
    ai_fail: 'ПРОВАЛ: ', ai_note: 'config се пази локално в data/ai.json - никога не се праща другаде, освен към endpoint-а, който сам си задал',
    ch_ph: 'root@c2ff:~# съобщение към агента за анализ…', ch_send: 'Изпрати',
    ch_empty: 'Каналът е отворен. Пиши тук, мониторът ме събужда мигновено.', ft: '100% локално - детерминирани проби, без токени и външни зависимости - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE АКТИВЕН: локални цикли на всеки 30 мин, 0 токена.', to_fl_pa: 'FLEET НА ПАУЗА - продължи когато искаш.',
    to_fl_cy: 'Незабавен цикъл стартиран (бюджет 60 req).', to_launch: '[GO] режим {m} (CWE {c}) върху {p} - локален цикъл стартиран',
    to_ai_ok: 'config записан', to_ai_no: 'запазването се провали',
    to_ai_no_cfg: 'ИИ не е настроен - настрой го в таба ИИ', to_ai_head: 'ИИ АНАЛИЗ',
    to_ai_bad: 'ИИ АНАЛИЗ се провали', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'ИИ',
    w_launch: '⚡ СТАРТ', navar: 'Арсенал',
    ar_h2: 'ARSENAL - CVE, EPSS и експлойти на откритата повърхност', ar_sync: 'SYNC БАЗИ ДАННИ',
    ar_btn: 'ХОДОВЕ', ar_exec: 'EXEC',
    ar_none: 'няма ходове: пусни първо RECON, след това SYNC за зареждане на KEV/EPSS', ar_loading: 'обобщение на базите се зарежда...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'демо програма - без сканиране: създай своя програма', pip_noprog: 'няма програми: създай своя в раздел Програми',
    pip_next: 'следваща стъпка:', fnd_n: 'находки: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  sl: {
    pl_title: 'Delovni načrt', pl_empty: 'š še ni načrta: poženi RECON v kartici zgoraj, hipoteze pristanejo tukaj (statusi se ohranijo)',
    pl_run: 'Zaženi', pl_reflect: 'reflektirani canary',
    st_do: 'za narediti', st_test: 'testirano',
    st_signal: 'signal', st_valid: 'veljavno',
    st_void: 'nič', atk_btn: 'ATTACK',
    atk_start: 'napad na površino: endpointi, izpostavljena dokumentacija, JWT, skrivnosti...', atk_fail: 'napad ni mogoč: najprej poženi RECON',
    atk_none: 'brez signala', atk_findings: 'kandidati',
    atk_done: 'ATTACK: {n} kandidatov P1/P2 vstavljenih v findings z dokazom', atk_empty: 'š še ni napada: poženi RECON, nato ATTACK - kandidati z dokazom req/res pristanejo tukaj',
    navh: 'HUNT', h2hunt: 'HUNT - prava površina in dokazi',
    h_ready: 'pripravljen', h_empty: 'nobene znane površine: poženi RECON za preslikavo strani, API endpointov, parametrov, JS paketov in poddomen',
    h_fnd: 'Findings programa', h_nofnd: 'brez findingov za ta program',
    rc_btn: 'RECON', rc_start: 'recon površine v teku: strani, JS paketi, endpointi, parametri...',
    rc_done: 'površina preslikana: endpointi, parametri in poddomene navedeni v kartici programa', rc_fail: 'recon ni uspel: gostitelj nedosegljiv ali prazen scope',
    rc_surface: 'površina:', snd_on: 'ZVOK: VKLOPLJEN',
    snd_off: 'ZVOK: IZKLOPLJEN', snd_ok: 'zvoki vmesnika vklopljeni - knjižnica: klik, zavihek, kopiranje, opozorila',
    snd_stop: 'popolna tišina aktivirana: več nobenih zvokov C2FF', amb_on: 'AMBIENT: VKLOPLJEN',
    amb_off: 'AMBIENT: IZKLOPLJEN', amb_ok: 'živ ambient - odtenek se mehko pomika skozi družine (zelena, modra, rumena...)',
    amb_stop: 'ambient zamrznjen na izvirni zeleni', nt_on: 'OBVESTILA: VKLOPLJENA',
    nt_off: 'OBVESTILA: IZKLOPLJENA', nt_ok: 'obvestila brskalnika vklopljena - pisk pri P1 in P2',
    nt_denied: 'obvestila blokirana s strani brskalnika: dovoli jih v nastavitvah strani', term_denied: 'terminal zavrnjen ali nedosegljiv: potreben localhost, ali ODPRTA soba kot admin',
    term_p: 'pravi bash - zgodovina s puščicami, Ctrl+C prekine, Ctrl+D zapre', term_restart: 'Ponastavi',
    navtrm: 'TERM', term_h2: 'Terminal - delovna lupina, neposredno v konzoli',
    fl_off: 'FLEET: USTAVLJEN', fl_paused: 'FLEET: V PAUZI',
    fl_active: 'FLEET: AKTIVEN ({n} ciklov)', fl_last: 'zadnji cikel',
    fl_none: 'š ni ciklov', fl_info: 'intervalem {i} min, proračun {b} req/cikel',
    sub_ttl: 'command & control framework', navt: 'SEJA',
    tm_h2: 'Skupinske seje - lov v skupini, tudi brez istega omrežja', tm_p: 'Odpri deljeno sobo: tvoja ekipa vidi floto, findings in lahko triažira v živo. Posvešen klepet seje spodaj. Trije nivoji dostopa: LOKALNO (solo), LAN prek ODPIRI V OMREŽJE in SVET prek ODPIRI V SVET - javni tunel (cloudflared, če je nameščen) naredi povezavo za povabilo veljavno iz katerega koli omrežja, brez neposredne izpostavitve tvoje naprave. Vse je zaščiteno s ključem sobe - ponovno ga generiraj, da vse naenkrat vržeš ven.',
    tm_handle: 'Tvoj vzdevek (največ 16 znakov)', tm_save_h: 'Nastavi',
    tm_room_ph: 'ime sobe (npr: c2ff-core)', tm_save: 'Uporabi',
    tm_on: 'SOBA ODPRTA: {r} - {n} povezanih', tm_off: 'TEAM NAČIN IZKLOPLJEN - lokalna solo seja',
    tm_room: 'Soba', tm_key: 'Ključ sobe',
    tm_regen: 'Ponovno generiraj ključ', tm_regen_ok: 'nove ključ generirana - stari povezave so mrtev',
    tm_invite: 'Povezava za povabilo (kopiraj svoji ekipi)', tm_copy: 'Kopiraj',
    tm_copied: 'kopirano v odložišče', tm_members: 'Člani',
    tm_nobody: 'š še nihče - pošlji povezavo svoji ekipi', tm_you: '(ti)',
    tm_here: 'prisoten', tm_saved: 'vzdevek shranjen',
    tm_no_handle: 'prazen vzdevek', tm_cfg_ok: 'soba posodobljena',
    tm_cfg_no: 'napaka', tm_live: 'ODPRI V OMREŽJE',
    tm_shore: 'NAZAJ LOKALNO', tm_need_on: 'najprej vklopi sobo (ON)',
    tm_bind_lan: 'OMREŽJE: {a}', tm_bind_lo: 'LOKALNO: samo localhost',
    to_team_live: '[GO-LIVE] strežnik ponovno zagnan z omrežnim dostopom - LAN povezava prikazana, ponovna povezava v 2 s', to_team_shore: 'strežnik ponovno zagnan lokalno (127.0.0.1)',
    tm_tun_open: 'ODPRI V SVET (tunel)', tm_tun_close: 'ZAPRI TUNEL',
    tm_tun_wait: 'javni tunel se odpira (nekaj sekund)…', tm_tun_on: 'SEJA ODPRTA V SVET: {u} - povezava za povabilo deluje od kjer koli, brez istega omrežja',
    tm_tun_closed: 'tunel zaprt - nazaj na LAN/lokalno', tm_chat_empty: 'kanal seje odprt - člani sobe se berejo tukaj',
    tm_chat_h2: 'Klepet seje', tm_msg_ph: 'sporočilo v sejo…',
    tm_admin: 'admin', tm_guest: 'gost',
    tm_kick: 'KICK', tm_kick_ok: 'član izvržen iz sobe (ponovni klik odblokuje)',
    tm_role_ok: 'vloga posodobljena', tm_mic_on: 'VKLOPI MIKROFON',
    tm_mic_off: 'IZKLOPI MIKROFON', tm_mic_denied: 'mikrofon zavrnjen ali nedostopen: potreben je HTTPS (svetovni tunel ali localhost) in dovoliti je treba mikrofon',
    navf: 'Flota', navfd: 'Findings',
    navp: 'Programi', navai: 'AI',
    navc: 'Koordinacija', st_runs: 'Izvajanja',
    st_beacons: 'Aktivni beaconi', st_sig: 'Signali',
    h2f: 'Flota - vsi programi, agenti v teku najprej', h2fd: 'Baza findings - trajno označevanje triaže',
    h2eng: 'Motor flote - lokalni cikli brez tokenov', h2prog: 'Programi - scope, obvezen header, zagon',
    h2new: 'Nov program', h2ai: 'AI agent - popolnoma neobvezen vključek',
    h2c: 'Koordinacija - zasebni kanal', fl_start: 'Zaženi',
    fl_pause: 'Pavza', fl_cycle: 'Cikel zdaj',
    f_add: 'Dodaj', f_none: 'š še ni signala',
    f_ph: 'ročni finding: endpoint + dokaz + branljiva resnost…', st_sig_off: 'signal',
    st_sig_an: 'analiza', st_sig_sub: 'poslano',
    st_sig_dup: 'dup', st_sig_ref: 'zavrnjeno',
    st_sig_cl: 'zaprt', r_none: 'brez zaznanih izvajanj',
    r_live: '{n} V TEKU', r_done: 'DOKONČANO',
    r_feed: '▽ tok ({n} ev)', r_close: '△ zvij',
    p_name_ph: 'Ime programa (npr: PayPal)', p_hdr_ph: 'obvezen researcher header (npr: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domena1, domena2, …', p_save: 'Shrani',
    p_local: 'modul(i), 100 % lokalno', ai_p: 'C2FF deluje v celoti brez AI: načini so deterministične lokalne sonde. Ta prehod služi samo za povezavo <b>tvoje</b> AI (self-hosted ali API) za občasno analizo enega findinga: gumb <span style="color:var(--green)">AI »</span> v FINDINGS, odgovor prikazan v COORDINATION. Brez te nastavitve nič podatkov ne zapusti tvoje naprave.',
    ai_off: 'izklopljena', ai_on: 'vklopljena',
    ai_st_off: 'AI IZKLOPLJENA - framework teče 100 % lokalno brez nje', ai_st_ready: 'AI POVEZANA: {p} · {m}',
    ai_st_inc: 'AI VKLOPLJENA, VENDAR NEPOPOLNA: potrebna sta baseURL in model', ai_url_ph: 'base URL - npr: http://localhost:11434 ali https://api.MojaAI.tld/v1',
    ai_model_ph: 'model - npr: llama3.1:8b', ai_key_ph: 'API ključ (pusti prazno za lokalne strežnike)',
    ai_save: 'Shrani', ai_test: 'Preveri povezavo',
    ai_testing: 'preizkus v teku…', ai_ok: 'OK - odgovor: ',
    ai_fail: 'NEUSPEŠNO: ', ai_note: 'konfiguracija shranjena lokalno v data/ai.json - nikoli poslana nikamor drugam kot na endpoint, ki ga nastaviš',
    ch_ph: 'root@c2ff:~# sporočilo agentu za analizo…', ch_send: 'Pošlji',
    ch_empty: 'Kanal je odprt. Piši tukaj, monitor me takoj zbudi.', ft: '100 % lokalno - deterministične sonde, brez tokenov in zunanjih odvisnosti - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET NAČIN AKTIVEN: lokalni cikli vsakih 30 min, 0 tokenov.', to_fl_pa: 'FLEET V PAUZI - nadaljuj, kadar hočeš.',
    to_fl_cy: 'Takojšnji cikel zagnan (proračun 60 req).', to_launch: '[GO] način {m} (CWE {c}) na {p} - lokalni cikel zagnan',
    to_ai_ok: 'konfiguracija shranjena', to_ai_no: 'shranjevanje ni uspelo',
    to_ai_no_cfg: 'AI ni nastavljena - nastavi jo v zavihku AI', to_ai_head: 'AI ANALIZA',
    to_ai_bad: 'AI ANALIZA neuspešna', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ ZAGON', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS in exploit na odkriti površini', ar_sync: 'SYNC BAZ',
    ar_btn: 'POTEZE', ar_exec: 'EXEC',
    ar_none: 'ni potez: najprej poženi RECON, nato SYNC za nalaganje KEV/EPSS', ar_loading: 'povzetek baz se nalaga...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demo program - brez skeniranja: ustvari svoj program', pip_noprog: 'ni programov: ustvari svojega pod Programi',
    pip_next: 'naslednji korak:', fnd_n: 'najdbe: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  lt: {
    pl_title: 'Darbo planas', pl_empty: 'dar nėra plano: paleisk RECON aukščiau esančioje kortelėje, hipotezės atkeliauja čia (būsenos išlieka)',
    pl_run: 'Vykdyti', pl_reflect: 'atspindėtas canary',
    st_do: 'daryti', st_test: 'išbandyta',
    st_signal: 'signalas', st_valid: 'patvirtinta',
    st_void: 'nieko', atk_btn: 'ATTACK',
    atk_start: 'puolamas paviršius: endpointai, atvira dokumentacija, JWT, slapti duomenys...', atk_fail: 'puolimas neįmanomas: pirmiausia paleisk RECON',
    atk_none: 'jokio signalo', atk_findings: 'kandidatai',
    atk_done: 'ATTACK: {n} P1/P2 kandidatų įrašyta į findings su įrodymu', atk_empty: 'dar nėra atakos: paleisk RECON, paskui ATTACK - kandidatai su req/res įrodymu atkeliauja čia',
    navh: 'HUNT', h2hunt: 'HUNT - tikras paviršius ir įrodymai',
    h_ready: 'paruošta', h_empty: 'jokio žinomo paviršiaus: paleisk RECON, kad susimapytum puslapius, API endpointus, parametrus, JS paketus ir subdomenus',
    h_fnd: 'Programos findings', h_nofnd: 'šios programos findings nėra',
    rc_btn: 'RECON', rc_start: 'tęsiasi paviršiaus recon: puslapiai, JS paketai, endpointai, parametrai...',
    rc_done: 'paviršius susimapytas: endpointai, parametrai ir subdomenai išvardyti programos kortelėje', rc_fail: 'recon nepavyko: serveris nepasiekiamas arba tuščias scope',
    rc_surface: 'paviršius:', snd_on: 'GARSAS: ĮJUNGTAS',
    snd_off: 'GARSAS: IŠJUNGTAS', snd_ok: 'sąsajos garsai įjungti - biblioteka: paspaudimas, skirtukas, kopijavimas, įspėjimai',
    snd_stop: 'įjungtas visiškas nutildymas: daugiau jokių C2FF garsų', amb_on: 'AMBIENTAS: ĮJUNGTAS',
    amb_off: 'AMBIENTAS: IŠJUNGTAS', amb_ok: 'gyvas ambientas - atspalvis švelniai slenka per spalvų šeimas (žalia, mėlyna, geltona...)',
    amb_stop: 'ambientas užfiksuotas ties originalia žalia', nt_on: 'PRANEŠIMAI: ĮJUNGTI',
    nt_off: 'PRANEŠIMAI: IŠJUNGTI', nt_ok: 'naršyklės pranešimai įjungti - pyptelėjimas ties P1 ir P2',
    nt_denied: 'pranešimus užblokavo naršyklė: leisk juos svetainės nustatymuose', term_denied: 'terminalas atmestas arba neprieinamas: reikalingas localhost, arba ATIDARYTA patalpa kaip admin',
    term_p: 'tikras bash - istorija su strėlytėmis, Ctrl+C nutraukia, Ctrl+D uždaro', term_restart: 'Atstatyti',
    navtrm: 'TERM', term_h2: 'Terminalas - darbo shell, tiesiai konsolėje',
    fl_off: 'FLEET: SUSTABDYTAS', fl_paused: 'FLEET: PAUZĖJE',
    fl_active: 'FLEET: AKTYVUS ({n} ciklų)', fl_last: 'paskutinis ciklas',
    fl_none: 'dar nėra ciklų', fl_info: 'intervalas {i} min, biudžetas {b} req/ciklą',
    sub_ttl: 'command & control framework', navt: 'SEANSAS',
    tm_h2: 'Grupiniai seansai - medžioklė komandoje, net skirtinguose tinkluose', tm_p: 'Atidaryk bendrą kambarį: tavo komanda mato flotilę, findings ir gali triažuoti tiesiogiai. Žemiau - atskiras seanso pokalbis. Trys prieigos lygiai: VIETINIS (solo), LAN per ATIDARYTI TINKLUI ir PASAULIS per ATIDARYTI PASAULIUI - viešas tunelis (cloudflared, jei įdiegtas) padaro pakvietimo nuorodą galiojančią iš bet kurio tinklo, be tiesioginio tavo mašinos atvėrimo. Viskas paremta kambario raktu - perkurk jį, kad visus išmestum vienu ypu.',
    tm_handle: 'Tavo slapyvardis (iki 16 simbolių)', tm_save_h: 'Nustatyti',
    tm_room_ph: 'kambario pavadinimas (pvz: c2ff-core)', tm_save: 'Taikyti',
    tm_on: 'KAMBARYS ATIDARYTAS: {r} - {n} prisijungę', tm_off: 'TEAM REŽIMAS IŠJUNGTAS - vietinis solo seansas',
    tm_room: 'Kambarys', tm_key: 'Kambario raktas',
    tm_regen: 'Perkurti raktą', tm_regen_ok: 'sugeneruotas naujas raktas - senos nuorodos nebegalioja',
    tm_invite: 'Pakvietimo nuoroda (nukopijuok savo komandai)', tm_copy: 'Kopijuoti',
    tm_copied: 'nukopijuota į iškarpinę', tm_members: 'Nariai',
    tm_nobody: 'dar nieko - atsiųsk nuorodą savo komandai', tm_you: '(tu)',
    tm_here: 'čia', tm_saved: 'slapyvardis išsaugotas',
    tm_no_handle: 'tuščias slapyvardis', tm_cfg_ok: 'kambarys atnaujintas',
    tm_cfg_no: 'nepavyko', tm_live: 'ATIDARYTI TINKLUI',
    tm_shore: 'GRĮŽTI Į VIETINĮ', tm_need_on: 'pirma įjunk kambarį (ON)',
    tm_bind_lan: 'TINKLAS: {a}', tm_bind_lo: 'VIETINIS: tik localhost',
    to_team_live: '[GO-LIVE] serveris paleistas iš naujo su tinklo prieiga - rodoma LAN nuoroda, pakartotinis prisijungimas po 2 s', to_team_shore: 'serveris paleistas iš naujo vietiškai (127.0.0.1)',
    tm_tun_open: 'ATIDARYTI PASAULIUI (tunelis)', tm_tun_close: 'UŽDARYTI TUNELĮ',
    tm_tun_wait: 'viešas tunelis kuriasi (kelios sekundės)…', tm_tun_on: 'SEANSAS ATIDARYTAS PASAULIUI: {u} - pakvietimo nuoroda veikia iš bet kur, to paties tinklo nereikia',
    tm_tun_closed: 'tunelis uždarytas - grįžtama į LAN/vietinį', tm_chat_empty: 'seanso kanalas atidarytas - kambario nariai rašosi čia',
    tm_chat_h2: 'Seanso pokalbis', tm_msg_ph: 'žinutė į seansą…',
    tm_admin: 'admin', tm_guest: 'svečias',
    tm_kick: 'KICK', tm_kick_ok: 'narys pašalintas iš kambario (pakartotinis spustelėjimas atblokuoja)',
    tm_role_ok: 'rolė atnaujinta', tm_mic_on: 'ĮJUNGTI MIKROFONĄ',
    tm_mic_off: 'IŠJUNGTI MIKROFONĄ', tm_mic_denied: 'mikrofonas atmestas arba neprieinamas: reikalingas HTTPS (pasaulio tunelis arba localhost) ir reikia leisti mikrofoną',
    navf: 'Flotilė', navfd: 'Findings',
    navp: 'Programos', navai: 'AI',
    navc: 'Koordinacija', st_runs: 'Vykdymai',
    st_beacons: 'Aktyvūs beaconai', st_sig: 'Signalai',
    h2f: 'Flotilė - visos programos, besileidžiantys agentai pirmiausia', h2fd: 'Findings bazė - nuolatinis triažo žymėjimas',
    h2eng: 'Flotilės variklis - vietiniai ciklai be tokenų', h2prog: 'Programos - scope, būtinas header, paleidimas',
    h2new: 'Nauja programa', h2ai: 'AI agentas - 100 % neprivaloma integracija',
    h2c: 'Koordinacija - privatus kanalas', fl_start: 'Paleisti',
    fl_pause: 'Pauzė', fl_cycle: 'Ciklas dabar',
    f_add: 'Pridėti', f_none: 'dar nėra signalo',
    f_ph: 'rankinis finding: endpoint + įrodymas + pagrįstas rimtumas…', st_sig_off: 'signalas',
    st_sig_an: 'analizė', st_sig_sub: 'pateikta',
    st_sig_dup: 'dup', st_sig_ref: 'atmesta',
    st_sig_cl: 'uždaryta', r_none: 'neaptikta jokių vykdymų',
    r_live: '{n} VYKSTA', r_done: 'BAIGTA',
    r_feed: '▽ srautas ({n} ev)', r_close: '△ suskleisti',
    p_name_ph: 'Programos pavadinimas (pvz: PayPal)', p_hdr_ph: 'būtinas researcher header (pvz: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domena1, domena2, …', p_save: 'Išsaugoti',
    p_local: 'modulis(-iai), 100 % vietoje', ai_p: 'C2FF veikia visiškai be AI: režimai yra deterministiniai vietiniai zondai. Ši prieiga skirta tik prijungti <b>savo</b> AI (self-hosted arba API) pavienio finding analizei on demand: mygtukas <span style="color:var(--green)">AI »</span> FINDINGS skiltyje, atsakymas rodomas COORDINATION. Be šios konfigūracijos iš tavo mašinos neišeina jokie duomenys.',
    ai_off: 'išjungta', ai_on: 'įjungta',
    ai_st_off: 'AI IŠJUNGTA - framework veikia 100 % vietoje be jos', ai_st_ready: 'AI PRIJUNGTA: {p} · {m}',
    ai_st_inc: 'AI ĮJUNGTA, BET NEPILNA: reikalingi baseURL ir model', ai_url_ph: 'base URL - pvz: http://localhost:11434 arba https://api.ManoAI.tld/v1',
    ai_model_ph: 'model - pvz: llama3.1:8b', ai_key_ph: 'API raktas (palik tuščią vietiniams serveriams)',
    ai_save: 'Išsaugoti', ai_test: 'Išbandyti ryšį',
    ai_testing: 'bandoma…', ai_ok: 'OK - atsakymas: ',
    ai_fail: 'NESĖKMĖ: ', ai_note: 'konfigūracija saugoma vietoje data/ai.json - niekada nesiunčiama niekur kitur, tik į endpointą, kurį nustatysi',
    ch_ph: 'root@c2ff:~# žinutė analizuojančiam agentui…', ch_send: 'Siųsti',
    ch_empty: 'Kanalas atidarytas. Rašyk čia, monitorius mane pažadina akimirksniu.', ft: '100 % vietoje - deterministiniai zondai, be tokenų ir išorinių priklausomybių - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET REŽIMAS AKTYVUS: vietiniai ciklai kas 30 min, 0 tokenų.', to_fl_pa: 'FLEET PAUZĖJE - tęsk kada nori.',
    to_fl_cy: 'Paleistas nedelsiamas ciklas (biudžetas 60 req).', to_launch: '[GO] režimas {m} (CWE {c}) ant {p} - vietinis ciklas paleistas',
    to_ai_ok: 'konfigūracija išsaugota', to_ai_no: 'išsaugoti nepavyko',
    to_ai_no_cfg: 'AI nesukonfigūruota - nustatyk AI skirtuke', to_ai_head: 'AI ANALIZĖ',
    to_ai_bad: 'AI ANALIZĖ nepavyko', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ PALEIDIMAS', navar: 'Arsenalas',
    ar_h2: 'ARSENAL - CVE, EPSS ir exploitai aptiktame paviršiuje', ar_sync: 'SYNC BAZĖS',
    ar_btn: 'ĖJIMAI', ar_exec: 'EXEC',
    ar_none: 'jokių ėjimų: pirmiausia paleisk RECON, tada SYNC, kad įkeliamas KEV/EPSS', ar_loading: 'bazių santrauka kraunasi...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demo programa - neskenuoja: sukurk savo programa', pip_noprog: 'programu nera: sukurk savo skirtuke Programos',
    pip_next: 'kitas etapas:', fnd_n: 'radiniai: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  vi: {
    pl_title: 'Kế hoạch làm việc', pl_empty: 'chưa có kế hoạch : chạy RECON trong thẻ phía trên, các giả thuyết sẽ rơi vào đây (trạng thái được lưu lại)',
    pl_run: 'Chạy', pl_reflect: 'canary đã phản chiếu',
    st_do: 'cần làm', st_test: 'đã thử',
    st_signal: 'tín hiệu', st_valid: 'xác nhận',
    st_void: 'không có gì', atk_btn: 'ATTACK',
    atk_start: 'đang attack bề mặt : endpoint, docs bị lộ, JWT, secrets...', atk_fail: 'không thể attack : chạy RECON trước đã',
    atk_none: 'không có tín hiệu', atk_findings: 'ứng cử',
    atk_done: 'ATTACK : {n} ứng cử P1/P2 đã đưa vào findings kèm bằng chứng', atk_empty: 'chưa attack : chạy RECON rồi ATTACK - các ứng cử kèm bằng chứng req/res sẽ rơi vào đây',
    navh: 'HUNT', h2hunt: 'HUNT - bề mặt thực và bằng chứng',
    h_ready: 'sẵn sàng', h_empty: 'chưa có bề mặt nào : chạy RECON để vẽ bản đồ trang, endpoint API, params, bundle JS và subdomain',
    h_fnd: 'Findings của chương trình', h_nofnd: 'không có finding nào cho chương trình này',
    rc_btn: 'RECON', rc_start: 'đang recon bề mặt : trang, bundle JS, endpoint, params...',
    rc_done: 'bề mặt đã được vẽ bản đồ : endpoint, params và subdomain được liệt kê trong thẻ chương trình', rc_fail: 'recon thất bại : host không truy cập được hoặc scope trống',
    rc_surface: 'bề mặt :', snd_on: 'ÂM THANH : BẬT',
    snd_off: 'ÂM THANH : TẮT', snd_ok: 'đã bật âm thanh giao diện - bộ : click, tab, copy, cảnh báo',
    snd_stop: 'đã tắt tiếng hoàn toàn : không còn âm thanh C2FF nào', amb_on: 'KHÔNG KHÍ : BẬT',
    amb_off: 'KHÔNG KHÍ : TẮT', amb_ok: 'không khí sống động - sắc màu trôi nhẹ qua các tông (xanh lá, xanh dương, vàng...)',
    amb_stop: 'không khí đóng băng ở màu xanh lá gốc', nt_on: 'THÔNG BÁO : BẬT',
    nt_off: 'THÔNG BÁO : TẮT', nt_ok: 'đã bật thông báo trình duyệt - tiếng bíp khi có P1 và P2',
    nt_denied: 'thông báo bị trình duyệt chặn : cho phép chúng trong cài đặt của trang', term_denied: 'terminal bị từ chối hoặc không khả dụng : cần localhost, hoặc phòng ĐANG MỞ với vai trò admin',
    term_p: 'bash thật - history bằng phím mũi tên, Ctrl+C ngắt, Ctrl+D đóng', term_restart: 'Đặt lại',
    navtrm: 'TERM', term_h2: 'Terminal - shell làm việc, ngay trong console',
    fl_off: 'FLEET : ĐÃ DỪNG', fl_paused: 'FLEET : TẠM DỪNG',
    fl_active: 'FLEET : ĐANG CHẠY ({n} chu kỳ)', fl_last: 'chu kỳ gần nhất',
    fl_none: 'chưa có chu kỳ nào', fl_info: 'khoảng cách {i} phút, ngân sách {b} req/chu kỳ',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Session nhiều người - săn cùng nhau, kể cả ngoài mạng', tm_p: 'Mở phòng chia sẻ : nhóm của bạn thấy đội, findings và có thể triage trực tiếp. Chat session riêng ở bên dưới. Ba cấp truy cập : LOCAL (solo), LAN qua MỞ RA MẠNG, và THẾ GIỚI qua MỞ RA THẾ GIỚI - một tunnel công khai (cloudflared nếu đã cài) làm link mời hợp lệ từ bất kỳ mạng nào, không lộ trực tiếp máy của bạn. Mọi thứ được kiểm soát bằng khóa phòng - tạo lại khóa để đuổi tất cả cùng lúc.',
    tm_handle: 'Biệt danh của bạn (tối đa 16 ký tự)', tm_save_h: 'Chọn',
    tm_room_ph: 'tên phòng (vd : c2ff-core)', tm_save: 'Áp dụng',
    tm_on: 'PHÒNG ĐANG MỞ : {r} - {n} đang online', tm_off: 'CHẾ ĐỘ TEAM ĐÃ TẮT - session local solo',
    tm_room: 'Phòng', tm_key: 'Khóa phòng',
    tm_regen: 'Tạo lại khóa', tm_regen_ok: 'khóa mới đã tạo - các link cũ đã chết',
    tm_invite: 'Link mời (copy cho team của bạn)', tm_copy: 'Sao chép',
    tm_copied: 'đã copy vào clipboard', tm_members: 'Thành viên',
    tm_nobody: 'chưa có ai - gửi link cho team của bạn', tm_you: '(bạn)',
    tm_here: 'có mặt', tm_saved: 'đã lưu biệt danh',
    tm_no_handle: 'biệt danh trống', tm_cfg_ok: 'phòng đã cập nhật',
    tm_cfg_no: 'thất bại', tm_live: 'MỞ RA MẠNG',
    tm_shore: 'QUAY LẠI LOCAL', tm_need_on: 'bật phòng trước đã (BẬT)',
    tm_bind_lan: 'MẠNG : {a}', tm_bind_lo: 'LOCAL : chỉ localhost',
    to_team_live: '[GO-LIVE] server khởi động lại với truy cập mạng - link LAN được hiển thị, kết nối lại sau 2 s', to_team_shore: 'server khởi động lại local (127.0.0.1)',
    tm_tun_open: 'MỞ RA THẾ GIỚI (tunnel)', tm_tun_close: 'ĐÓNG TUNNEL',
    tm_tun_wait: 'đang mở tunnel công khai (vài giây)…', tm_tun_on: 'SESSION MỞ RA THẾ GIỚI : {u} - link mời chạy ở mọi nơi, không cần cùng mạng',
    tm_tun_closed: 'tunnel đã đóng - quay lại LAN/local', tm_chat_empty: 'kênh session đã mở - các thành viên phòng đọc nhau ở đây',
    tm_chat_h2: 'Chat session', tm_msg_ph: 'tin nhắn tới session…',
    tm_admin: 'admin', tm_guest: 'khách',
    tm_kick: 'KICK', tm_kick_ok: 'đã đuổi thành viên khỏi phòng (bấm lại để mở khóa)',
    tm_role_ok: 'đã cập nhật vai trò', tm_mic_on: 'BẬT MICRO',
    tm_mic_off: 'TẮT MICRO', tm_mic_denied: 'micro bị từ chối hoặc không truy cập được : cần HTTPS (tunnel THẾ GIỚI hoặc localhost) và phải cấp quyền micro',
    navf: 'Đội', navfd: 'Findings',
    navp: 'Chương trình', navai: 'AI',
    navc: 'Phối hợp', st_runs: 'Runs',
    st_beacons: 'Beacon đang chạy', st_sig: 'Tín hiệu',
    h2f: 'Đội - mọi chương trình, agent đang chạy lên trước', h2fd: 'Kho findings - gắn nhãn triage bền vững',
    h2eng: 'Bộ máy đội - chu kỳ local, không token', h2prog: 'Chương trình - scope, header bắt buộc, khởi chạy',
    h2new: 'Chương trình mới', h2ai: 'Agent AI - tích hợp 100% tùy chọn',
    h2c: 'Phối hợp - kênh riêng', fl_start: 'Khởi động',
    fl_pause: 'Tạm dừng', fl_cycle: 'Chạy chu kỳ ngay',
    f_add: 'Thêm', f_none: 'chưa có tín hiệu nào',
    f_ph: 'finding thủ công : endpoint + bằng chứng + severity bảo vệ được…', st_sig_off: 'tín hiệu',
    st_sig_an: 'phân tích', st_sig_sub: 'đã nộp',
    st_sig_dup: 'trùng', st_sig_ref: 'bị từ chối',
    st_sig_cl: 'đã đóng', r_none: 'không phát hiện run nào',
    r_live: '{n} ĐANG CHẠY', r_done: 'HOÀN TẤT',
    r_feed: '▽ luồng ({n} sk)', r_close: '△ thu gọn',
    p_name_ph: 'Tên chương trình (vd : PayPal)', p_hdr_ph: 'header researcher bắt buộc (vd : X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domain1, domain2, …', p_save: 'Lưu',
    p_local: 'module, 100% local', ai_p: 'C2FF chạy trọn vẹn không cần AI : các mode là probe xác định chạy local. Cổng này chỉ để nối <b>AI của bạn</b> (self-hosted hoặc API) nhằm phân tích một finding theo yêu cầu : nút <span style="color:var(--green)">AI »</span> trong FINDINGS, câu trả lời hiển thị trong COORDINATION. Không một dữ liệu nào rời khỏi máy của bạn nếu không có cấu hình này.',
    ai_off: 'đã tắt', ai_on: 'đã bật',
    ai_st_off: 'AI ĐÃ TẮT - framework chạy 100% local không cần nó', ai_st_ready: 'AI ĐÃ KẾT NỐI : {p} · {m}',
    ai_st_inc: 'AI ĐÃ BẬT NHƯNG CHƯA ĐỦ : cần baseURL và model', ai_url_ph: 'base URL - vd : http://localhost:11434 hoặc https://api.MyAI.tld/v1',
    ai_model_ph: 'model - vd : llama3.1:8b', ai_key_ph: 'khóa API (để trống nếu server local)',
    ai_save: 'Lưu', ai_test: 'Kiểm tra kết nối',
    ai_testing: 'đang kiểm tra…', ai_ok: 'OK - phản hồi : ',
    ai_fail: 'THẤT BẠI : ', ai_note: 'config lưu local trong data/ai.json - không bao giờ gửi đi đâu ngoài endpoint bạn khai báo',
    ch_ph: 'root@c2ff:~# tin nhắn tới agent phân tích…', ch_send: 'Gửi',
    ch_empty: 'Kênh đã mở. Gõ ở đây, monitor đánh thức tôi ngay lập tức.', ft: '100% local - probe xác định, không token không phụ thuộc ngoài - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ĐANG CHẠY : chu kỳ local mỗi 30 phút, 0 token.', to_fl_pa: 'FLEET TẠM DỪNG - tiếp tục khi bạn muốn.',
    to_fl_cy: 'Đã chạy chu kỳ ngay lập tức (ngân sách 60 req).', to_launch: '[GO] mode {m} (CWE {c}) trên {p} - đã chạy chu kỳ local',
    to_ai_ok: 'đã lưu config', to_ai_no: 'lưu thất bại',
    to_ai_no_cfg: 'AI chưa cấu hình - cài trong tab AI', to_ai_head: 'PHÂN TÍCH AI',
    to_ai_bad: 'PHÂN TÍCH AI thất bại', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ KHỞI CHẠY', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS và exploit trên bề mặt đã phát hiện', ar_sync: 'SYNC CƠ SỞ DỮ LIỆU',
    ar_btn: 'NƯỚC ĐI', ar_exec: 'EXEC',
    ar_none: 'chưa có nước đi: chạy RECON trước, rồi SYNC để tải KEV/EPSS', ar_loading: 'tóm tắt cơ sở dữ liệu đang tải...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'chương trình demo - không quét được: hãy tạo chương trình của bạn', pip_noprog: 'chưa có chương trình: hãy tạo chương trình của bạn trong tab Programs',
    pip_next: 'bước tiếp theo:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  pl: {
    pl_title: 'Plan pracy', pl_empty: 'brak planu: uruchom RECON w karcie wyżej, hipotezy lądują tutaj (statusy są zapisywane)',
    pl_run: 'Uruchom', pl_reflect: 'canary odbity',
    st_do: 'do zrobienia', st_test: 'przetestowane',
    st_signal: 'sygnał', st_valid: 'potwierdzone',
    st_void: 'nic', atk_btn: 'ATTACK',
    atk_start: 'atak na powierzchnię: endpointy, wystawione dokumentacje, JWT, sekrety...', atk_fail: 'atak niemożliwy: najpierw uruchom RECON',
    atk_none: 'brak sygnału', atk_findings: 'kandydaci',
    atk_done: 'ATTACK: {n} kandydatów P1/P2 wstrzykniętych do findings z dowodem', atk_empty: 'brak ataku: uruchom RECON, potem ATTACK - kandydaci z dowodem req/res lądują tutaj',
    navh: 'HUNT', h2hunt: 'HUNT - realna powierzchnia i dowody',
    h_ready: 'gotowy', h_empty: 'brak znanej powierzchni: uruchom RECON, żeby zmapować strony, endpointy API, parametry, bundlki JS i subdomeny',
    h_fnd: 'Findings programu', h_nofnd: 'brak findings w tym programie',
    rc_btn: 'RECON', rc_start: 'recon powierzchni w toku: strony, bundlki JS, endpointy, parametry...',
    rc_done: 'powierzchnia zmapowana: endpointy, parametry i subdomeny wypisane w karcie programu', rc_fail: 'recon nieudany: host nieosiągalny lub pusty scope',
    rc_surface: 'powierzchnia:', snd_on: 'DŹWIĘK: ON',
    snd_off: 'DŹWIĘK: OFF', snd_ok: 'dźwięki interfejsu aktywne - biblioteka: klik, karta, kopiowanie, alerty',
    snd_stop: 'całkowite wyciszenie włączone: koniec dźwięków C2FF', amb_on: 'AMBIANS: ON',
    amb_off: 'AMBIANS: OFF', amb_ok: 'żywy ambians - odcień płynnie przesuwa się po rodzinach (zieleń, błękit, żółć...)',
    amb_stop: 'ambians zamrożony na pierwotnej zieleni', nt_on: 'NOTIFIKACJE: ON',
    nt_off: 'NOTIFIKACJE: OFF', nt_ok: 'notyfikacje przeglądarki włączone - bip na P1 i P2',
    nt_denied: 'notyfikacje zablokowane przez przeglądarkę: zezwól na nie w ustawieniach strony', term_denied: 'terminal odmówiony lub niedostępny: wymagany localhost, albo sala OTWARTA jako admin',
    term_p: 'prawdziwy bash - historia strzałkami, Ctrl+C przerywa, Ctrl+D zamyka', term_restart: 'Zresetuj',
    navtrm: 'TERM', term_h2: 'Terminal - shell roboczy, prosto w konsoli',
    fl_off: 'FLEET: ZATRZYMANY', fl_paused: 'FLEET: PAUZA',
    fl_active: 'FLEET: AKTYWNY ({n} cykli)', fl_last: 'ostatni cykl',
    fl_none: 'jeszcze żadnego cyklu', fl_info: 'interwał {i} min, budżet {b} req/cykl',
    sub_ttl: 'command & control framework', navt: 'SESJA',
    tm_h2: 'Sesje grupowe - polowanie zespołowe, nawet poza siecią', tm_p: 'Otwórz współdzieloną salę: twoja grupa widzi flotę, findings i może triage\'ować na żywo. Dedykowany czat sesji poniżej. Trzy poziomy dostępu: LOCAL (solo), LAN przez UDOSTĘPNIJ W SIECI i ŚWIAT przez UDOSTĘPNIJ ŚWIATU - publiczny tunel (cloudflared, jeśli zainstalowany) sprawia, że link zaproszenia działa z każdej sieci, bez bezpośredniego wystawiania twojej maszyny. Wszystko chroni klucz sali - wygeneruj go od nowa, żeby wyrzucić wszystkich jednym ruchem.',
    tm_handle: 'Twój nick (16 znaków max)', tm_save_h: 'Ustaw',
    tm_room_ph: 'nazwa sali (np. c2ff-core)', tm_save: 'Zastosuj',
    tm_on: 'SALA OTWARTA: {r} - {n} online', tm_off: 'TRYB TEAM WYŁĄCZONY - lokalna sesja solo',
    tm_room: 'Sala', tm_key: 'Klucz sali',
    tm_regen: 'Wygeneruj klucz ponownie', tm_regen_ok: 'nowy klucz wygenerowany - stare linki są martwe',
    tm_invite: 'Link zaproszenia (skopiuj swojemu zespołowi)', tm_copy: 'Kopiuj',
    tm_copied: 'skopiowano do schowka', tm_members: 'Członkowie',
    tm_nobody: 'jeszcze nikt - wyślij link zespołowi', tm_you: '(ty)',
    tm_here: 'obecny', tm_saved: 'nick zapisany',
    tm_no_handle: 'pusty nick', tm_cfg_ok: 'sala zaktualizowana',
    tm_cfg_no: 'niepowodzenie', tm_live: 'UDOSTĘPNIJ W SIECI',
    tm_shore: 'WRÓĆ DO LOKALNEGO', tm_need_on: 'najpierw włącz salę (ON)',
    tm_bind_lan: 'SIEĆ: {a}', tm_bind_lo: 'LOCAL: tylko localhost',
    to_team_live: '[GO-LIVE] serwer zrestartowany z dostępem sieciowym - link LAN wyświetlony, ponowne połączenie za 2 s', to_team_shore: 'serwer zrestartowany lokalnie (127.0.0.1)',
    tm_tun_open: 'UDOSTĘPNIJ ŚWIATU (tunel)', tm_tun_close: 'ZAMKNIJ TUNEL',
    tm_tun_wait: 'publiczny tunel się otwiera (kilka sekund)…', tm_tun_on: 'SESJA OTWARTA NA ŚWIAT: {u} - link zaproszenia działa wszędzie, bez wspólnej sieci',
    tm_tun_closed: 'tunel zamknięty - powrót do LAN/local', tm_chat_empty: 'kanał sesji otwarty - członkowie sali czytają się tu nawzajem',
    tm_chat_h2: 'Czat sesji', tm_msg_ph: 'wiadomość do sesji…',
    tm_admin: 'admin', tm_guest: 'gość',
    tm_kick: 'KICK', tm_kick_ok: 'członek wyrzucony z sali (kliknij ponownie, żeby odblokować)',
    tm_role_ok: 'rola zaktualizowana', tm_mic_on: 'WŁĄCZ MIKROFON',
    tm_mic_off: 'WYCISZ MIKROFON', tm_mic_denied: 'mikrofon odmówiony lub niedostępny: wymagany HTTPS (tunel ŚWIAT albo localhost) i trzeba zezwolić na mikrofon',
    navf: 'Flota', navfd: 'Findings',
    navp: 'Programy', navai: 'AI',
    navc: 'Koordynacja', st_runs: 'Runy',
    st_beacons: 'Aktywne beacony', st_sig: 'Sygnały',
    h2f: 'Flota - wszystkie programy, agenci w biegu pierwsi', h2fd: 'Baza findings - trwałe tagowanie triage',
    h2eng: 'Silnik floty - lokalne cykle bez tokenów', h2prog: 'Programy - scope, wymagany header, lansowanie',
    h2new: 'Nowy program', h2ai: 'Agent AI - integracja w 100% opcjonalna',
    h2c: 'Koordynacja - prywatny kanał', fl_start: 'Start',
    fl_pause: 'Pauza', fl_cycle: 'Cykl teraz',
    f_add: 'Dodaj', f_none: 'jeszcze żaden sygnał',
    f_ph: 'ręczny finding: endpoint + dowód + defensywna severita…', st_sig_off: 'sygnał',
    st_sig_an: 'analiza', st_sig_sub: 'wysłane',
    st_sig_dup: 'dup', st_sig_ref: 'odrzucone',
    st_sig_cl: 'zamknięte', r_none: 'brak wykrytych runów',
    r_live: '{n} W BIEGU', r_done: 'ZAKOŃCZONE',
    r_feed: '▽ strumień ({n} zd.)', r_close: '△ zwiń',
    p_name_ph: 'Nazwa programu (np. PayPal)', p_hdr_ph: 'wymagany header badacza (np. X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domena1, domena2, …', p_save: 'Zapisz',
    p_local: 'moduł(y), 100% lokalnie', ai_p: 'C2FF działa w całości bez AI: tryby to deterministyczne lokalne proby. Ta bramka służy tylko do podłączenia <b>twojego</b> AI (self-hosted lub API) do punktowej analizy findingu: przycisk <span style="color:var(--green)">AI »</span> w FINDINGS, odpowiedź renderowana w KOORDYNACJI. Żadne dane nie opuszczają twojej maszyny bez tej konfiguracji.',
    ai_off: 'wyłączona', ai_on: 'włączona',
    ai_st_off: 'AI WYŁĄCZONE - framework działa w 100% lokalnie bez niego', ai_st_ready: 'AI PODŁĄCZONE: {p} · {m}',
    ai_st_inc: 'AI WŁĄCZONE, ALE NIEKOMPLETNE: wymagane baseURL i model', ai_url_ph: 'base URL - np. http://localhost:11434 lub https://api.MojeAI.tld/v1',
    ai_model_ph: 'model - np. llama3.1:8b', ai_key_ph: 'klucz API (zostaw puste dla serwerów lokalnych)',
    ai_save: 'Zapisz', ai_test: 'Testuj połączenie',
    ai_testing: 'test w toku…', ai_ok: 'OK - odpowiedź: ',
    ai_fail: 'PORAŻKA: ', ai_note: 'konfiguracja zapisana lokalnie w data/ai.json - nigdy nie wysyłana nikąd poza endpoint, który tam ustawisz',
    ch_ph: 'root@c2ff:~# wiadomość do agenta analizy…', ch_send: 'Wyślij',
    ch_empty: 'Kanał otwarty. Pisz tutaj, monitor budzi mnie natychmiast.', ft: '100% lokalne - deterministyczne proby, bez tokenów i zewnętrznych zależności - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE AKTYWNY: lokalne cykle co 30 min, 0 tokenów.', to_fl_pa: 'FLEET NA PAUZIE - wznów kiedy chcesz.',
    to_fl_cy: 'Natychmiastowy cykl uruchomiony (budżet 60 req).', to_launch: '[GO] tryb {m} (CWE {c}) na {p} - lokalny cykl uruchomiony',
    to_ai_ok: 'konfiguracja zapisana', to_ai_no: 'zapis nieudany',
    to_ai_no_cfg: 'AI nieskonfigurowane - ustaw je w karcie AI', to_ai_head: 'ANALIZA AI',
    to_ai_bad: 'ANALIZA AI nieudana', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ START', navar: 'Arsenał',
    ar_h2: 'ARSENAL - CVE, EPSS i exploity na wykrytej powierzchni', ar_sync: 'SYNC BAZ',
    ar_btn: 'RUCHY', ar_exec: 'EXEC',
    ar_none: 'brak ruchów: najpierw uruchom RECON, potem SYNC, aby załadować KEV/EPSS', ar_loading: 'podsumowanie baz się ładuje...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'program demo - brak skanowania: utwórz własny program', pip_noprog: 'brak programów: utwórz swój w zakładce Programy',
    pip_next: 'następny etap:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  id: {
    pl_title: 'Rencana kerja', pl_empty: 'belum ada rencana: jalankan RECON di kartu di atas, hipotesis mendarat di sini (status tersimpan)',
    pl_run: 'Jalankan', pl_reflect: 'canary terpantul',
    st_do: 'harus dilakukan', st_test: 'sudah dites',
    st_signal: 'sinyal', st_valid: 'valid',
    st_void: 'kosong', atk_btn: 'ATTACK',
    atk_start: 'menyerang permukaan: endpoint, docs yang terekspos, JWT, secrets...', atk_fail: 'serangan gagal: jalankan RECON dulu',
    atk_none: 'tidak ada sinyal', atk_findings: 'kandidat',
    atk_done: 'ATTACK: {n} kandidat P1/P2 disuntikkan ke findings dengan bukti', atk_empty: 'belum ada serangan: jalankan RECON lalu ATTACK - kandidat dengan bukti req/res mendarat di sini',
    navh: 'HUNT', h2hunt: 'HUNT - permukaan nyata dan bukti',
    h_ready: 'siap', h_empty: 'belum ada permukaan: jalankan RECON untuk memetakan halaman, endpoint API, parameter, bundle JS dan subdomain',
    h_fnd: 'Findings program', h_nofnd: 'tidak ada findings di program ini',
    rc_btn: 'RECON', rc_start: 'recon permukaan berjalan: halaman, bundle JS, endpoint, parameter...',
    rc_done: 'permukaan terpetakan: endpoint, parameter dan subdomain terdaftar di kartu program', rc_fail: 'recon gagal: host tak terjangkau atau scope kosong',
    rc_surface: 'permukaan:', snd_on: 'SUARA: ON',
    snd_off: 'SUARA: OFF', snd_ok: 'suara antarmuka aktif - pustaka: klik, tab, salin, alarm',
    snd_stop: 'bisu total aktif: tak ada suara C2FF lagi', amb_on: 'SUASANA: ON',
    amb_off: 'SUASANA: OFF', amb_ok: 'suasana hidup - rona meluncur halus melewati keluarga warna (hijau, biru, kuning...)',
    amb_stop: 'suasana beku pada hijau asli', nt_on: 'NOTIF: ON',
    nt_off: 'NOTIF: OFF', nt_ok: 'notifikasi browser aktif - bip saat P1 dan P2',
    nt_denied: 'notifikasi diblokir browser: izinkan di pengaturan situs', term_denied: 'terminal ditolak atau tak tersedia: localhost wajib, atau ruangan TERBUKA sebagai admin',
    term_p: 'bash asli - riwayat pakai panah, Ctrl+C menghentikan, Ctrl+D menutup', term_restart: 'Reset',
    navtrm: 'TERM', term_h2: 'Terminal - shell kerja, langsung di konsol',
    fl_off: 'FLEET: BERHENTI', fl_paused: 'FLEET: JEDA',
    fl_active: 'FLEET: AKTIF ({n} siklus)', fl_last: 'siklus terakhir',
    fl_none: 'belum ada siklus', fl_info: 'interval {i} menit, anggaran {b} req/siklus',
    sub_ttl: 'command & control framework', navt: 'SESI',
    tm_h2: 'Sesi bersama - berburu rombongan, bahkan di luar jaringan', tm_p: 'Buka ruangan bersama: grupmu melihat armada, findings dan bisa triage langsung. Chat sesi khusus di bawah. Tiga tingkat akses: LOCAL (solo), LAN lewat BUKA KE JARINGAN, dan DUNIA lewat BUKA KE DUNIA - tunnel publik (cloudflared jika terpasang) membuat link undangan berlaku dari jaringan mana pun, tanpa mengekspos mesinmu langsung. Semuanya dikunci kunci ruangan - regenerasi untuk mengusir semua orang sekaligus.',
    tm_handle: 'Nama panggilanmu (maks 16 karakter)', tm_save_h: 'Atur',
    tm_room_ph: 'nama ruangan (mis. c2ff-core)', tm_save: 'Terapkan',
    tm_on: 'RUANGAN TERBUKA: {r} - {n} online', tm_off: 'MODE TEAM MATI - sesi lokal solo',
    tm_room: 'Ruangan', tm_key: 'Kunci ruangan',
    tm_regen: 'Regenerasi kunci', tm_regen_ok: 'kunci baru dibuat - link lama mati',
    tm_invite: 'Link undangan (salin ke timmu)', tm_copy: 'Salin',
    tm_copied: 'disalin ke clipboard', tm_members: 'Anggota',
    tm_nobody: 'belum ada siapa pun - kirim link ke timmu', tm_you: '(kamu)',
    tm_here: 'hadir', tm_saved: 'nama panggilan tersimpan',
    tm_no_handle: 'nama panggilan kosong', tm_cfg_ok: 'ruangan diperbarui',
    tm_cfg_no: 'gagal', tm_live: 'BUKA KE JARINGAN',
    tm_shore: 'KEMBALI LOKAL', tm_need_on: 'aktifkan ruangan dulu (ON)',
    tm_bind_lan: 'JARINGAN: {a}', tm_bind_lo: 'LOCAL: hanya localhost',
    to_team_live: '[GO-LIVE] server di-restart dengan akses jaringan - link LAN ditampilkan, sambung ulang dalam 2 s', to_team_shore: 'server di-restart lokal (127.0.0.1)',
    tm_tun_open: 'BUKA KE DUNIA (tunnel)', tm_tun_close: 'TUTUP TUNNEL',
    tm_tun_wait: 'tunnel publik sedang dibuka (beberapa detik)…', tm_tun_on: 'SESI TERBUKA KE DUNIA: {u} - link undangan bekerja di mana saja, tak perlu jaringan yang sama',
    tm_tun_closed: 'tunnel ditutup - kembali ke LAN/lokal', tm_chat_empty: 'kanal sesi terbuka - anggota ruangan saling membaca di sini',
    tm_chat_h2: 'Chat sesi', tm_msg_ph: 'pesan ke sesi…',
    tm_admin: 'admin', tm_guest: 'tamu',
    tm_kick: 'KICK', tm_kick_ok: 'anggota dikeluarkan dari ruangan (klik lagi untuk membuka blokir)',
    tm_role_ok: 'peran diperbarui', tm_mic_on: 'AKTIFKAN MIKROFON',
    tm_mic_off: 'MATIKAN MIKROFON', tm_mic_denied: 'mikrofon ditolak atau tak tersedia: HTTPS wajib (tunnel DUNIA atau localhost) dan izin mikrofon harus diberikan',
    navf: 'Armada', navfd: 'Findings',
    navp: 'Program', navai: 'AI',
    navc: 'Koordinasi', st_runs: 'Run',
    st_beacons: 'Beacon aktif', st_sig: 'Sinyal',
    h2f: 'Armada - semua program, agen yang berlari di atas', h2fd: 'Basis findings - penandaan triage permanen',
    h2eng: 'Mesin armada - siklus lokal tanpa token', h2prog: 'Program - scope, header wajib, peluncuran',
    h2new: 'Program baru', h2ai: 'Agen AI - integrasi 100% opsional',
    h2c: 'Koordinasi - kanal privat', fl_start: 'Mulai',
    fl_pause: 'Jeda', fl_cycle: 'Siklus sekarang',
    f_add: 'Tambah', f_none: 'belum ada sinyal',
    f_ph: 'finding manual: endpoint + bukti + severity yang bisa dipertahankan…', st_sig_off: 'sinyal',
    st_sig_an: 'analisis', st_sig_sub: 'terkirim',
    st_sig_dup: 'dup', st_sig_ref: 'ditolak',
    st_sig_cl: 'ditutup', r_none: 'tidak ada run terdeteksi',
    r_live: '{n} SEDANG BERLARI', r_done: 'SELESAI',
    r_feed: '▽ umpan ({n} ev)', r_close: '△ lipat',
    p_name_ph: 'Nama program (mis. PayPal)', p_hdr_ph: 'header peneliti wajib (mis. X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domain1, domain2, …', p_save: 'Simpan',
    p_local: 'modul, 100% lokal', ai_p: 'C2FF berjalan sepenuhnya tanpa AI: mode-nya adalah probe deterministik lokal. Gerbang ini hanya untuk menyambungkan <b>AI milikmu</b> (self-hosted atau API) untuk analisis satu finding sesuai permintaan: tombol <span style="color:var(--green)">AI »</span> di FINDINGS, jawaban ditampilkan di KOORDINASI. Tak ada data keluar dari mesinmu tanpa konfigurasi ini.',
    ai_off: 'nonaktif', ai_on: 'aktif',
    ai_st_off: 'AI NONAKTIF - framework berjalan 100% lokal tanpanya', ai_st_ready: 'AI TERHUBUNG: {p} · {m}',
    ai_st_inc: 'AI AKTIF TAPI TIDAK LENGKAP: baseURL dan model wajib', ai_url_ph: 'base URL - mis. http://localhost:11434 atau https://api.AIKu.tld/v1',
    ai_model_ph: 'model - mis. llama3.1:8b', ai_key_ph: 'kunci API (kosongkan untuk server lokal)',
    ai_save: 'Simpan', ai_test: 'Tes koneksi',
    ai_testing: 'pengujian berjalan…', ai_ok: 'OK - jawaban: ',
    ai_fail: 'GAGAL: ', ai_note: 'konfigurasi disimpan lokal di data/ai.json - tak pernah dikirim ke mana pun selain endpoint yang kamu isikan',
    ch_ph: 'root@c2ff:~# pesan ke agen analisis…', ch_send: 'Kirim',
    ch_empty: 'Kanal terbuka. Ketik di sini, monitor membangunkanku seketika.', ft: '100% lokal - probe deterministik, tanpa token dan dependensi eksternal - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE AKTIF: siklus lokal tiap 30 menit, 0 token.', to_fl_pa: 'FLEET DIJEDA - lanjutkan kapan pun kau mau.',
    to_fl_cy: 'Siklus segera diluncurkan (anggaran 60 req).', to_launch: '[GO] mode {m} (CWE {c}) di {p} - siklus lokal diluncurkan',
    to_ai_ok: 'konfigurasi tersimpan', to_ai_no: 'penyimpanan gagal',
    to_ai_no_cfg: 'AI belum dikonfigurasi - atur di tab AI', to_ai_head: 'ANALISIS AI',
    to_ai_bad: 'ANALISIS AI gagal', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ LUNCURKAN', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS dan exploit pada permukaan yang terdeteksi', ar_sync: 'SYNC BASIS DATA',
    ar_btn: 'LANGKAH', ar_exec: 'EXEC',
    ar_none: 'belum ada langkah: jalankan RECON dulu, lalu SYNC untuk memuat KEV/EPSS', ar_loading: 'ringkasan basis data sedang dimuat...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'program demo - tidak bisa scan: buat programmu sendiri', pip_noprog: 'belum ada program: buat milikmu di tab Program',
    pip_next: 'tahap berikutnya:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  sv: {
    pl_title: 'Arbetsplan', pl_empty: 'ingen plan ännu: kör RECON i kortet ovan, hypoteser landar här (statusar sparas)',
    pl_run: 'Kör', pl_reflect: 'canary reflekterad',
    st_do: 'att göra', st_test: 'testad',
    st_signal: 'signal', st_valid: 'validerad',
    st_void: 'inget', atk_btn: 'ATTACK',
    atk_start: 'attack mot ytan: endpoints, exponerad docs, JWT, hemligheter...', atk_fail: 'attack omöjlig: kör RECON först',
    atk_none: 'ingen signal', atk_findings: 'kandidater',
    atk_done: 'ATTACK: {n} P1/P2-kandidater injicerade i findings med bevis', atk_empty: 'ingen attack ännu: kör RECON sedan ATTACK - kandidater med req/res-bevis landar här',
    navh: 'HUNT', h2hunt: 'HUNT - riktig yta och bevis',
    h_ready: 'redo', h_empty: 'ingen yta känd: kör RECON för att mappa sidor, API-endpoints, parametrar, JS-bundels och subdomäner',
    h_fnd: 'Programmets findings', h_nofnd: 'inga findings för detta program',
    rc_btn: 'RECON', rc_start: 'recon av ytan pågår: sidor, JS-bundels, endpoints, parametrar...',
    rc_done: 'ytan karterad: endpoints, parametrar och subdomäner listade i programkortet', rc_fail: 'recon misslyckades: värden onåbar eller tomt scope',
    rc_surface: 'yta:', snd_on: 'LJUD: PÅ',
    snd_off: 'LJUD: AV', snd_ok: 'interaktionsljud aktiva - bibliotek: klick, flik, kopiera, larm',
    snd_stop: 'total tystning aktiverad: inga fler C2FF-ljud', amb_on: 'STÄMNING: PÅ',
    amb_off: 'STÄMNING: AV', amb_ok: 'levande stämning - tonen glider mjukt genom familjerna (grönt, blått, gult...)',
    amb_stop: 'stämningen fryst på ursprungsgrönt', nt_on: 'NOTISER: PÅ',
    nt_off: 'NOTISER: AV', nt_ok: 'webbläsarnotiser aktiverade - pip vid P1 och P2',
    nt_denied: 'notiser blockerade av webbläsaren: tillåt dem i webbplatsens inställningar', term_denied: 'terminal nekad eller otillgänglig: localhost krävs, eller ett ÖPPET rum som admin',
    term_p: 'riktig bash - historik med pilar, Ctrl+C avbryter, Ctrl+D stänger', term_restart: 'Återställ',
    navtrm: 'TERM', term_h2: 'Terminal - arbetsskal, direkt i konsolen',
    fl_off: 'FLEET: STOPPAD', fl_paused: 'FLEET: PAUSAD',
    fl_active: 'FLEET: AKTIV ({n} cykler)', fl_last: 'senaste cykeln',
    fl_none: 'ingen cykel ännu', fl_info: 'intervall {i} min, budget {b} req/cykel',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Gruppsessioner - jaga tillsammans, även utanför nätverket', tm_p: 'Öppna ett delat rum: din grupp ser flottan, findings och kan triage:a live. Egen sessionschatt nedan. Tre åtkomstnivåer: LOCAL (solo), LAN via ÖPPNA FÖR NÄTVERK och VÄRLDEN via ÖPPNA FÖR VÄRLDEN - en publik tunnel (cloudflared om installerad) gör att inbjudningslänken fungerar från vilket nätverk som helst, utan att exponera din maskin direkt. Allt låses av rumsnyckeln - generera om den för att sparka ut alla på en gång.',
    tm_handle: 'Ditt nick (16 tecken max)', tm_save_h: 'Sätt',
    tm_room_ph: 'rumsnamn (t.ex. c2ff-core)', tm_save: 'Verkställ',
    tm_on: 'RUM ÖPPET: {r} - {n} online', tm_off: 'TEAM-LÄGE AV - lokal solosession',
    tm_room: 'Rum', tm_key: 'Rumsnyckel',
    tm_regen: 'Generera om nyckeln', tm_regen_ok: 'ny nyckel skapad - gamla länkar är döda',
    tm_invite: 'Inbjudningslänk (kopiera till ditt team)', tm_copy: 'Kopiera',
    tm_copied: 'kopierad till urklipp', tm_members: 'Medlemmar',
    tm_nobody: 'ingen ännu - skicka länken till ditt team', tm_you: '(du)',
    tm_here: 'här', tm_saved: 'nick sparat',
    tm_no_handle: 'tomt nick', tm_cfg_ok: 'rum uppdaterat',
    tm_cfg_no: 'misslyckades', tm_live: 'ÖPPNA FÖR NÄTVERK',
    tm_shore: 'TILLBAKA LOKALT', tm_need_on: 'aktivera rummet först (PÅ)',
    tm_bind_lan: 'NÄTVERK: {a}', tm_bind_lo: 'LOCAL: endast localhost',
    to_team_live: '[GO-LIVE] servern startad om med nätverksåtkomst - LAN-länk visas, återanslutning om 2 s', to_team_shore: 'servern startad om lokalt (127.0.0.1)',
    tm_tun_open: 'ÖPPNA FÖR VÄRLDEN (tunnel)', tm_tun_close: 'STÄNG TUNNELN',
    tm_tun_wait: 'publik tunnel öppnas (några sekunder)…', tm_tun_on: 'SESSION ÖPPEN FÖR VÄRLDEN: {u} - inbjudningslänken fungerar var som helst, inget gemensamt nätverk behövs',
    tm_tun_closed: 'tunnel stängd - tillbaka till LAN/lokal', tm_chat_empty: 'sessionskanal öppen - rumsmedlemmarna läser varandra här',
    tm_chat_h2: 'Sessionschatt', tm_msg_ph: 'meddelande till sessionen…',
    tm_admin: 'admin', tm_guest: 'gäst',
    tm_kick: 'KICK', tm_kick_ok: 'medlem utkastad från rummet (klicka igen för att häva)',
    tm_role_ok: 'roll uppdaterad', tm_mic_on: 'AKTIVERA MIKROFON',
    tm_mic_off: 'STÄNG AV MIKROFONEN', tm_mic_denied: 'mikrofon nekad eller otillgänglig: HTTPS krävs (VÄRLDS-tunnel eller localhost) och mikrofonen måste tillåtas',
    navf: 'Flotta', navfd: 'Findings',
    navp: 'Program', navai: 'AI',
    navc: 'Koordination', st_runs: 'Runs',
    st_beacons: 'Aktiva beacons', st_sig: 'Signaler',
    h2f: 'Flotta - alla program, agenter i löp först', h2fd: 'Findings-bas - beständig triage-märkning',
    h2eng: 'Flottmotor - lokala cykler utan tokens', h2prog: 'Program - scope, krävd header, start',
    h2new: 'Nytt program', h2ai: 'AI-agent - helt valfri integration',
    h2c: 'Koordination - privat kanal', fl_start: 'Starta',
    fl_pause: 'Paus', fl_cycle: 'Cykla nu',
    f_add: 'Lägg till', f_none: 'ingen signal ännu',
    f_ph: 'manuell finding: endpoint + bevis + försvarbar severitet…', st_sig_off: 'signal',
    st_sig_an: 'analys', st_sig_sub: 'inskickad',
    st_sig_dup: 'dup', st_sig_ref: 'avslagen',
    st_sig_cl: 'stängd', r_none: 'ingen run upptäckt',
    r_live: '{n} PÅ GÅNG', r_done: 'KLAR',
    r_feed: '▽ flöde ({n} ev)', r_close: '△ fäll ihop',
    p_name_ph: 'Programnamn (t.ex. PayPal)', p_hdr_ph: 'krävd forskarheader (t.ex. X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domän1, domän2, …', p_save: 'Spara',
    p_local: 'modul(er), 100% lokal', ai_p: 'C2FF kör helt utan AI: lägena är deterministiska lokala prober. Denna gateway finns bara för att koppla in <b>din</b> AI (self-hosted eller API) för punktanalys av en finding: knappen <span style="color:var(--green)">IA »</span> i FINDINGS, svaret renderas i KOORDINATION. Ingen data lämnar din maskin utan denna konfiguration.',
    ai_off: 'avstängd', ai_on: 'aktiverad',
    ai_st_off: 'AI AVSTÄNGD - ramverket kör 100% lokalt utan den', ai_st_ready: 'AI ANSLUTEN: {p} · {m}',
    ai_st_inc: 'AI PÅSLAGEN MEN OFULLSTÄNDIG: baseURL och modell krävs', ai_url_ph: 'base URL - t.ex. http://localhost:11434 eller https://api.MinAI.tld/v1',
    ai_model_ph: 'modell - t.ex. llama3.1:8b', ai_key_ph: 'API-nyckel (lämna tom för lokala servrar)',
    ai_save: 'Spara', ai_test: 'Testa anslutningen',
    ai_testing: 'test pågår…', ai_ok: 'OK - svar: ',
    ai_fail: 'MISSLYCKAT: ', ai_note: 'konfig sparas lokalt i data/ai.json - skickas aldrig någon annanstans än till endpointen du ställer in',
    ch_ph: 'root@c2ff:~# meddelande till analysagenten…', ch_send: 'Skicka',
    ch_empty: 'Kanalen är öppen. Skriv här, monitorn väcker mig ögonblickligen.', ft: '100% lokal - deterministiska prober, inga tokens eller externa beroenden - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-LÄGE AKTIVT: lokala cykler var 30:e min, 0 tokens.', to_fl_pa: 'FLEET PAUSAD - fortsätt när du vill.',
    to_fl_cy: 'Omedelbar cykel startad (budget 60 req).', to_launch: '[GO] läge {m} (CWE {c}) på {p} - lokal cykel startad',
    to_ai_ok: 'konfig sparad', to_ai_no: 'spara misslyckades',
    to_ai_no_cfg: 'AI ej konfigurerad - ställ in den i AI-fliken', to_ai_head: 'AI-ANALYS',
    to_ai_bad: 'AI-ANALYS misslyckades', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'IA',
    w_launch: '⚡ UPPSKJUTNING', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS och exploits på den upptäckta ytan', ar_sync: 'SYNC BASER',
    ar_btn: 'DRAG', ar_exec: 'EXEC',
    ar_none: 'inga drag: kör RECON först, sedan SYNC för att ladda KEV/EPSS', ar_loading: 'sammanfattning av baser laddas...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demoprogram - ingen skanning: skapa ditt eget program', pip_noprog: 'inget program ännu: skapa ditt eget under Program',
    pip_next: 'nästa steg:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  el: {
    pl_title: 'Πλάνο εργασίας', pl_empty: 'ακόμα δεν υπάρχει πλάνο: τρέξε RECON στην κάρτα από πάνω, οι υποθέσεις γράφονται εδώ (οι καταστάσεις μένουν αποθηκευμένες)',
    pl_run: 'Εκτέλεση', pl_reflect: 'canary αντανακλάστηκε',
    st_do: 'προς διεκπεραίωση', st_test: 'δοκιμασμένο',
    st_signal: 'σήμα', st_valid: 'έγκυρο',
    st_void: 'τίποτα', atk_btn: 'ATTACK',
    atk_start: 'επίθεση στην επιφάνεια: endpoints, εκτεθειμένα docs, JWT, μυστικά...', atk_fail: 'αδύνατη επίθεση: τρέξε πρώτα RECON',
    atk_none: 'κανένα σήμα', atk_findings: 'υποψήφιοι',
    atk_done: 'ATTACK: {n} υποψήφια P1/P2 εγχυμένα στα findings με απόδειξη', atk_empty: 'ακόμα καμία επίθεση: τρέξε RECON και μετά ATTACK - οι υποψήφιοι με απόδειξη req/res γράφονται εδώ',
    navh: 'HUNT', h2hunt: 'HUNT - πραγματική επιφάνεια και αποδείξεις',
    h_ready: 'έτοιμος', h_empty: 'καμία γνωστή επιφάνεια: τρέξε RECON για να χαρτογραφήσεις σελίδες, endpoints API, παραμέτρους, bundles JS και subdomains',
    h_fnd: 'Findings του προγράμματος', h_nofnd: 'κανένα finding σε αυτό το πρόγραμμα',
    rc_btn: 'RECON', rc_start: 'recon της επιφάνειας σε εξέλιξη: σελίδες, bundles JS, endpoints, παράμετροι...',
    rc_done: 'επιφάνεια χαρτογραφημένη: endpoints, παράμετροι και subdomains απαριθμημένα στην κάρτα του προγράμματος', rc_fail: 'το recon απέτυχε: απροσπέλαστος host ή κενό scope',
    rc_surface: 'επιφάνεια:', snd_on: 'ΗΧΟΣ: ON',
    snd_off: 'ΗΧΟΣ: OFF', snd_ok: 'ενεργοί ήχοι διεπαφής - βιβλιοθήκη: κλικ, καρτέλα, αντιγραφή, ειδοποιήσεις',
    snd_stop: 'ολική σίγαση ενεργή: τέλος των ήχων C2FF', amb_on: 'ΑΤΜΟΣΦΑΙΡΑ: ON',
    amb_off: 'ΑΤΜΟΣΦΑΙΡΑ: OFF', amb_ok: 'ζωντανή ατμόσφαιρα - η απόχρωση γλιστρά απαλά μέσα στις οικογένειες (πράσινο, μπλε, κίτρινο...)',
    amb_stop: 'ατμόσφαιρα παγωμένη στο αρχικό πράσινο', nt_on: 'ΕΙΔΟΠΟΙΗΣΕΙΣ: ON',
    nt_off: 'ΕΙΔΟΠΟΙΗΣΕΙΣ: OFF', nt_ok: 'ενεργοποιημένες ειδοποιήσεις browser - μπιπ σε P1 και P2',
    nt_denied: 'ειδοποιήσεις μπλοκαρισμένες από τον browser: δώσε άδεια στις ρυθμίσεις του site', term_denied: 'το terminal απορρίφθηκε ή δεν είναι διαθέσιμο: απαιτείται localhost, ή ανοιχτό δωμάτιο ως admin',
    term_p: 'πραγματικό bash - ιστορικό με βέλη, το Ctrl+C διακόπτει, το Ctrl+D κλείνει', term_restart: 'Επαναφορά',
    navtrm: 'TERM', term_h2: 'Terminal - κέλυφος εργασίας, μέσα στην κονσόλα',
    fl_off: 'FLEET: ΣΤΑΜΑΤΗΜΕΝΟ', fl_paused: 'FLEET: ΣΕ ΠΑΥΣΗ',
    fl_active: 'FLEET: ΕΝΕΡΓΟ ({n} κύκλοι)', fl_last: 'τελευταίος κύκλος',
    fl_none: 'ακόμα κανένας κύκλος', fl_info: 'διάστημα {i} λεπτά, προϋπολογισμός {b} req/κύκλο',
    sub_ttl: 'command & control framework', navt: 'ΣΥΝΕΔΡΙΑ',
    tm_h2: 'Ομαδικές συνεδρίες - κυνήγι σε ομάδα, ακόμα κι εκτός δικτύου', tm_p: 'Άνοιξε κοινόχρηστο δωμάτιο: η ομάδα σου βλέπει τον στόλο, τα findings και μπορεί να κάνει triage ζωντανά. Αφιερωμένο chat συνεδρίας παρακάτω. Τρία επίπεδα πρόσβασης: LOCAL (μόνος), LAN μέσω ΑΝΟΙΓΜΑ ΣΤΟ ΔΙΚΤΥΟ, και ΚΟΣΜΟΣ μέσω ΑΝΟΙΓΜΑ ΣΤΟΝ ΚΟΣΜΟ - δημόσιο tunnel (cloudflared αν είναι εγκατεστημένο) κάνει τον σύνδεσμο πρόσκλησης έγκυρο από οποιοδήποτε δίκτυο, χωρίς άμεση έκθεση της μηχανής σου. Τα όλα κλειδώνουν με το κλειδί δωματίου - ανανέωσέ το για να πετάξεις όλους έξω με μια κίνηση.',
    tm_handle: 'Το ψευδώνυμό σου (16 χαρακτήρες max)', tm_save_h: 'Ορισμός',
    tm_room_ph: 'όνομα δωματίου (π.χ. c2ff-core)', tm_save: 'Εφαρμογή',
    tm_on: 'ΔΩΜΑΤΙΟ ΑΝΟΙΧΤΟ: {r} - {n} online', tm_off: 'ΤΟ TEAM MODE ΕΙΝΑΙ ΑΝΕΝΕΡΓΟ - τοπική συνεδρία solo',
    tm_room: 'Δωμάτιο', tm_key: 'Κλειδί δωματίου',
    tm_regen: 'Ανανέωση κλειδιού', tm_regen_ok: 'νέο κλειδί δημιουργήθηκε - οι παλιοί σύνδεσμοι είναι νεκροί',
    tm_invite: 'Σύνδεσμος πρόσκλησης (αντίγραψέ τον στην ομάδα σου)', tm_copy: 'Αντιγραφή',
    tm_copied: 'αντιγράφηκε στο πρόχειρο', tm_members: 'Μέλη',
    tm_nobody: 'ακόμα κανείς - στείλε τον σύνδεσμο στην ομάδα σου', tm_you: '(εσύ)',
    tm_here: 'παρών', tm_saved: 'ψευδώνυμο αποθηκεύτηκε',
    tm_no_handle: 'κενο ψευδώνυμο', tm_cfg_ok: 'το δωμάτιο ενημερώθηκε',
    tm_cfg_no: 'αποτυχία', tm_live: 'ΑΝΟΙΓΜΑ ΣΤΟ ΔΙΚΤΥΟ',
    tm_shore: 'ΕΠΙΣΤΡΟΦΗ ΣΕ ΤΟΠΙΚΟ', tm_need_on: 'ενεργοποίησε πρώτα το δωμάτιο (ON)',
    tm_bind_lan: 'ΔΙΚΤΥΟ: {a}', tm_bind_lo: 'LOCAL: μόνο localhost',
    to_team_live: '[GO-LIVE] ο server επανεκκινήθηκε με πρόσβαση δικτύου - ο σύνδεσμος LAN εμφανίζεται, επανασύδεση σε 2 δ', to_team_shore: 'ο server επανεκκινήθηκε τοπικά (127.0.0.1)',
    tm_tun_open: 'ΑΝΟΙΓΜΑ ΣΤΟΝ ΚΟΣΜΟ (tunnel)', tm_tun_close: 'ΚΛΕΙΣΙΜΟ TUNNEL',
    tm_tun_wait: 'δημόσιο tunnel ανοίγει (λίγα δευτερόλεπτα)…', tm_tun_on: 'ΣΥΝΕΔΡΙΑ ΑΝΟΙΧΤΗ ΣΤΟΝ ΚΟΣΜΟ: {u} - ο σύνδεσμος πρόσκλησης δουλεύει παντού, δεν χρειάζεται κοινό δίκτυο',
    tm_tun_closed: 'tunnel έκλεισε - πίσω σε LAN/τοπικό', tm_chat_empty: 'κανάλι συνεδρίας ανοιχτό - τα μέλη του δωματίου διαβάζονται εδώ μεταξύ τους',
    tm_chat_h2: 'Chat συνεδρίας', tm_msg_ph: 'μήνυμα προς τη συνεδρία…',
    tm_admin: 'admin', tm_guest: 'καλεσμένος',
    tm_kick: 'KICK', tm_kick_ok: 'μέλος πετάχτηκε έξω από το δωμάτιο (ξανακλίκαρε για να λύσεις)',
    tm_role_ok: 'ο ρόλος ενημερώθηκε', tm_mic_on: 'ΕΝΕΡΓΟΠΟΙΗΣΗ ΜΙΚΡΟΦΩΝΟΥ',
    tm_mic_off: 'ΑΠΕΝΕΡΓΟΠΟΙΗΣΗ ΜΙΚΡΟΦΩΝΟΥ', tm_mic_denied: 'το μικρόφωνο απορρίφθηκε ή δεν είναι διαθέσιμο: απαιτείται HTTPS (tunnel ΚΟΣΜΟΣ ή localhost) και πρέπει να δώσεις άδεια μικροφώνου',
    navf: 'Στόλος', navfd: 'Findings',
    navp: 'Προγράμματα', navai: 'AI',
    navc: 'Συντονισμός', st_runs: 'Runs',
    st_beacons: 'Ενεργά beacons', st_sig: 'Σήματα',
    h2f: 'Στόλος - όλα τα προγράμματα, πράκτορες σε δρόμο πρώτα', h2fd: 'Βάση findings - μόνιμη σήμανση triage',
    h2eng: 'Μηχανή στόλου - τοπικοί κύκλοι χωρίς tokens', h2prog: 'Προγράμματα - scope, απαιτούμενο header, εκτόξευση',
    h2new: 'Νέο πρόγραμμα', h2ai: 'Πράκτορας AI - ολικά προαιρετική ενσωμάτωση',
    h2c: 'Συντονισμός - ιδιωτικό κανάλι', fl_start: 'Εκκίνηση',
    fl_pause: 'Παύση', fl_cycle: 'Κύκλος τώρα',
    f_add: 'Προσθήκη', f_none: 'ακόμα κανένα σήμα',
    f_ph: 'χειροκίνητο finding: endpoint + απόδειξη + υποστηρίξιμη σοβαρότητα…', st_sig_off: 'σήμα',
    st_sig_an: 'ανάλυση', st_sig_sub: 'υποβλήθηκε',
    st_sig_dup: 'διπλότυπο', st_sig_ref: 'απορρίφθηκε',
    st_sig_cl: 'έκλεισε', r_none: 'κανένα run εντοπίστηκε',
    r_live: '{n} ΣΕ ΔΡΟΜΟ', r_done: 'ΤΕΛΟΣ',
    r_feed: '▽ ροή ({n} εκ.)', r_close: '△ αναδίπλωση',
    p_name_ph: 'Όνομα προγράμματος (π.χ. PayPal)', p_hdr_ph: 'απαιτούμενο header ερευνητή (π.χ. X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domain1, domain2, …', p_save: 'Αποθήκευση',
    p_local: 'module(s), 100% τοπικά', ai_p: 'Το C2FF δουλεύει πλήρως χωρίς AI: οι τρόποι είναι ντετερμινιστικές τοπικές δοκιμές. Αυτή η πύλη υπάρχει μόνο για να συνδέσεις <b>το</b> AI σου (self-hosted ή API) για επιμέρους ανάλυση ενός finding: το κουμπί <span style="color:var(--green)">AI »</span> στα FINDINGS, η απάντηση εμφανίζεται στον ΣΥΝΤΟΝΙΣΜΟ. Κανένα δεδομένο δεν φεύγει από τη μηχανή σου χωρίς αυτή τη ρύθμιση.',
    ai_off: 'ανενεργό', ai_on: 'ενεργό',
    ai_st_off: 'AI ΑΝΕΝΕΡΓΟ - το framework τρέχει 100% τοπικά χωρίς αυτό', ai_st_ready: 'AI ΣΥΝΔΕΔΕΜΕΝΟ: {p} · {m}',
    ai_st_inc: 'AI ΕΝΕΡΓΟ ΑΛΛΑ ΗΜΙΤΕΛΕΣ: απαιτούνται baseURL και model', ai_url_ph: 'base URL - π.χ. http://localhost:11434 ή https://api.AITou.tld/v1',
    ai_model_ph: 'model - π.χ. llama3.1:8b', ai_key_ph: 'κλειδί API (άφησε κενό για τοπικούς servers)',
    ai_save: 'Αποθήκευση', ai_test: 'Τεστ σύνδεσης',
    ai_testing: 'τέστ σε εξέλιξη…', ai_ok: 'ΟΚ - απάντηση: ',
    ai_fail: 'ΑΠΟΤΥΧΙΑ: ', ai_note: 'η ρύθμιση αποθηκεύεται τοπικά στο data/ai.json - δεν στέλνεται ποτέ πουθενά αλλού, μόνο στον endpoint που ορίζεις',
    ch_ph: 'root@c2ff:~# μήνυμα προς τον πράκτορα ανάλυσης…', ch_send: 'Αποστολή',
    ch_empty: 'Το κανάλι είναι ανοιχτό. Γράψε εδώ, ο monitor με ξυπνά άμεσα.', ft: '100% τοπικά - ντετερμινιστικές δοκιμές, χωρίς tokens ή εξωτερικές εξαρτήσεις - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ΕΝΕΡΓΟΣ: τοπικοί κύκλοι κάθε 30 λεπτά, 0 tokens.', to_fl_pa: 'FLEET ΣΕ ΠΑΥΣΗ - συνέχισε όποτε θέλεις.',
    to_fl_cy: 'Άμεσος κύκλος εκτοξεύτηκε (προϋπολογισμός 60 req).', to_launch: '[GO] λειτουργία {m} (CWE {c}) σε {p} - τοπικός κύκλος εκτοξεύτηκε',
    to_ai_ok: 'η ρύθμιση αποθηκεύτηκε', to_ai_no: 'η αποθήκευση απέτυχε',
    to_ai_no_cfg: 'AI μη ρυθμισμένο - ρύθμισέ το στη καρτέλα AI', to_ai_head: 'ΑΝΑΛΥΣΗ AI',
    to_ai_bad: 'ΑΝΑΛΥΣΗ AI απέτυχε', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ ΕΚΤΟΞΕΥΣΗ', navar: 'Αρσεναλ',
    ar_h2: 'ARSENAL - CVE, EPSS και exploits στην ανιχνευμένη επιφάνεια', ar_sync: 'SYNC ΒΑΣΕΩΝ',
    ar_btn: 'ΚΙΝΗΣΕΙΣ', ar_exec: 'EXEC',
    ar_none: 'καμία κίνηση: εκτέλεσε πρώτα RECON, μετά SYNC για φόρτωση KEV/EPSS', ar_loading: 'φόρτωση σύνοψης βάσεων...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'πρόγραμμα demo - χωρίς σάρωση: δημιούργησε το πρόγραμμά σου', pip_noprog: 'κανένα πρόγραμμα: δημιούργησε το δικό σου στα Προγράμματα',
    pip_next: 'επόμενο βήμα:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  he: {
    pl_title: 'תוכנית עבודה', pl_empty: 'אין עדיין תוכנית: הפעל RECON בכרטיס למעלה, ההשערות נופלות לכאן (הסטטוסים נשמרים)',
    pl_run: 'הרץ', pl_reflect: 'canary הוחזר',
    st_do: 'לביצוע', st_test: 'נבדק',
    st_signal: 'אות', st_valid: 'תקף',
    st_void: 'כלום', atk_btn: 'ATTACK',
    atk_start: 'תקיפת המשטח: endpoints, מסמכים חשופים, JWT, סודות...', atk_fail: 'תקיפה בלתי אפשרית: הפעל קודם RECON',
    atk_none: 'אין אות', atk_findings: 'מועמדים',
    atk_done: 'ATTACK: {n} מועמדי P1/P2 הוזרקו ל-findings עם הוכחה', atk_empty: 'אין עדיין תקיפה: הפעל RECON ואז ATTACK - מועמדים עם הוכחת req/res נופלים לכאן',
    navh: 'HUNT', h2hunt: 'HUNT - משטח אמיתי והוכחות',
    h_ready: 'מוכן', h_empty: 'אין משטח מוכר: הפעל RECON כדי למפות דפים, endpoints של API, פרמטרים, חבילות JS וסאבדומיינים',
    h_fnd: 'Findings של התוכנית', h_nofnd: 'אין findings בתוכנית הזו',
    rc_btn: 'RECON', rc_start: 'recon של המשטח מתבצע: דפים, חבילות JS, endpoints, פרמטרים...',
    rc_done: 'המשטח מופה: endpoints, פרמטרים וסאבדומיינים רשומים בכרטיס התוכנית', rc_fail: 'ה-recon נכשל: מארח לא נגיש או scope ריק',
    rc_surface: 'משטח:', snd_on: 'צליל: ON',
    snd_off: 'צליל: OFF', snd_ok: 'צלילי ממשק פעילים - ספרייה: קליק, טאב, העתקה, התראות',
    snd_stop: 'השתקה מוחלטת הופעלה: אין עוד צלילי C2FF', amb_on: 'אווירה: ON',
    amb_off: 'אווירה: OFF', amb_ok: 'אווירה חיה - הגוון גולש בעדינות בין המשפחות (ירוק, כחול, צהוב...)',
    amb_stop: 'האווירה קפואה על הירוק המקורי', nt_on: 'נוטיפיקציות : ON',
    nt_off: 'נוטיפיקציות : OFF', nt_ok: 'נוטיפיקציות דפדפן הופעלו - ביפ על P1 ו-P2',
    nt_denied: 'הנוטיפיקציות נחסמו על ידי הדפדפן: אפשר אותן בהגדרות האתר', term_denied: 'הטרמינל נדחה או לא זמין: נדרש localhost, או חדר פתוח כ-admin',
    term_p: 'bash אמיתי - היסטוריה עם חצים, Ctrl+C מפריע, Ctrl+D סוגר', term_restart: 'איפוס',
    navtrm: 'TERM', term_h2: 'טרמינל - מעטפת עבודה, ישירות בקונסולה',
    fl_off: 'FLEET: עצור', fl_paused: 'FLEET: בהשהיה',
    fl_active: 'FLEET: פעיל ({n} מחזורים)', fl_last: 'המחזור האחרון',
    fl_none: 'אין עדיין מחזור', fl_info: 'מרווח {i} דק, תקציב {b} req למחזור',
    sub_ttl: 'command & control framework', navt: 'סשן',
    tm_h2: 'סשנים קבוצתיים - צייד בקבוצה, גם מחוץ לרשת', tm_p: 'פתח חדר משותף: הקבוצה שלך רואה את הצי, את ה-findings ויכולה לעשות טרייז\' לייב. צ\'אט סשן ייעודי למטה. שלוש רמות גישה: LOCAL (עצמאי), LAN דרך פתח לרשת, ועולם דרך פתח לעולם - מנהרה ציבורית (cloudflared אם מותקן) הופכת את לינק ההזמנה תקף מכל רשת, בלי לחשוף ישירות את המחשב שלך. הכל נשלט על ידי מפתח החדר - חדש אותו כדי לזרוק את כולם בבת אחת.',
    tm_handle: 'הכינוי שלך (16 תווים מקס)', tm_save_h: 'בחר',
    tm_room_ph: 'שם החדר (למשל : c2ff-core)', tm_save: 'החל',
    tm_on: 'חדר פתוח: {r} - {n} מחוברים', tm_off: 'מצב TEAM כבוי - סשן לוקאלי סולו',
    tm_room: 'חדר', tm_key: 'מפתח החדר',
    tm_regen: 'צור מפתח מחדש', tm_regen_ok: 'מפתח חדש נוצר - כל הלינקים הישנים מתים',
    tm_invite: 'לינק הזמנה (העתק לקבוצה שלך)', tm_copy: 'העתק',
    tm_copied: 'הועתק ללוח', tm_members: 'חברים',
    tm_nobody: 'אף אחד עדיין - שלח את הלינק לקבוצה שלך', tm_you: '(אתה)',
    tm_here: 'נוכח', tm_saved: 'הכינוי נשמר',
    tm_no_handle: 'כינוי ריק', tm_cfg_ok: 'החדר עודכן',
    tm_cfg_no: 'נכשל', tm_live: 'פתח לרשת',
    tm_shore: 'חזור ללוקאלי', tm_need_on: 'הפעל קודם את החדר (ON)',
    tm_bind_lan: 'רשת: {a}', tm_bind_lo: 'LOCAL: localhost בלבד',
    to_team_live: '[GO-LIVE] השרת הופעל מחדש עם גישת רשת - לינק LAN מוצג, התחברות מחדש בעוד 2 שניות', to_team_shore: 'השרת הופעל מחדש לוקאלית (127.0.0.1)',
    tm_tun_open: 'פתח לעולם (מנהרה)', tm_tun_close: 'סגור את המנהרה',
    tm_tun_wait: 'מנהרה ציבורית נפתחת (כמה שניות)…', tm_tun_on: 'סשן פתוח לעולם: {u} - לינק ההזמנה עובד מכל מקום, אין צורך באותה רשת',
    tm_tun_closed: 'המנהרה נסגרה - חזרה ל-LAN/לוקאלי', tm_chat_empty: 'ערוץ סשן נפתח - חברי החדר קוראים זה את זה כאן',
    tm_chat_h2: 'צ\'אט סשן', tm_msg_ph: 'הודעה לסשן…',
    tm_admin: 'מנהל', tm_guest: 'אורח',
    tm_kick: 'KICK', tm_kick_ok: 'החבר הוצא מהחדר (לחיצה נוספת מבטלת את הבלוק)',
    tm_role_ok: 'התפקיד עודכן', tm_mic_on: 'הפעל מיקרופון',
    tm_mic_off: 'כבה מיקרופון', tm_mic_denied: 'המיקרופון נדחה או לא זמין: נדרש HTTPS (מנהרת עולם או localhost) וצריך לאשר את המיקרופון',
    navf: 'צי', navfd: 'Findings',
    navp: 'תוכניות', navai: 'AI',
    navc: 'תיאום', st_runs: 'Runs',
    st_beacons: 'Beacons פעילים', st_sig: 'אותות',
    h2f: 'צי - כל התוכניות, סוכנים שרצים קודם', h2fd: 'בסיס findings - תיוג טריינד מתמשך',
    h2eng: 'מנוע הצי - מחזורים לוקאליים ללא טוקנים', h2prog: 'תוכניות - scope, הדר נדרש, שיגור',
    h2new: 'תוכנית חדשה', h2ai: 'סוכן AI - אינטגרציה אופציונלית במאה אחוז',
    h2c: 'תיאום - ערוץ פרטי', fl_start: 'התחל',
    fl_pause: 'השהה', fl_cycle: 'מחזור עכשיו',
    f_add: 'הוסף', f_none: 'אין עדיין אות',
    f_ph: 'finding ידני: endpoint + הוכחה + דרגת חומרה שאפשר להגן עליה…', st_sig_off: 'אות',
    st_sig_an: 'אנליזה', st_sig_sub: 'הוגש',
    st_sig_dup: 'כפילות', st_sig_ref: 'נדחה',
    st_sig_cl: 'נסגר', r_none: 'לא זוהה run',
    r_live: '{n} בריצה', r_done: 'הושלם',
    r_feed: '▽ פיד ({n} אירועים)', r_close: '△ כווץ',
    p_name_ph: 'שם התוכנית (למשל : PayPal)', p_hdr_ph: 'הדר חוקר נדרש (למשל : X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domain1, domain2, …', p_save: 'שמור',
    p_local: 'מודול אחד או יותר, מאה אחוז לוקאלי', ai_p: 'C2FF עובד במלואו בלי AI: המצבים הם חיישנים דטרמיניסטיים מקומיים. השער הזה קיים רק כדי לחבר <b>את ה-AI</b> שלך (self-hosted או API) לאנליזת נקודה של finding בודד: כפתור <span style="color:var(--green)">AI »</span> ב-FINDINGS, התשובה מוצגת בתיאום. אף נתון לא יוצא מהמחשב שלך בלי ההגדרה הזו.',
    ai_off: 'כבוי', ai_on: 'מופעל',
    ai_st_off: 'AI כבוי - הפריימוורק רץ מאה אחוז לוקאלי בלעדיו', ai_st_ready: 'AI מחובר: {p} · {m}',
    ai_st_inc: 'AI מופעל אך לא הושלם: דרושים baseURL ו-model', ai_url_ph: 'בסיס URL - למשל : http://localhost:11434 או https://api.AISheli.tld/v1',
    ai_model_ph: 'model - למשל : llama3.1:8b', ai_key_ph: 'מפתח API (השאר ריק לשרת לוקאלי)',
    ai_save: 'שמור', ai_test: 'בדוק חיבור',
    ai_testing: 'בדיקה מתבצעת…', ai_ok: 'OK - תשובה: ',
    ai_fail: 'נכשל: ', ai_note: 'ההגדרה נשמרת מקומית ב-data/ai.json - לעולם לא נשלחת לשום מקום מלבד ה-endpoint שתגדיר שם',
    ch_ph: 'root@c2ff:~# הודעה לסוכן האנליזה…', ch_send: 'שלח',
    ch_empty: 'הערוץ פתוח. כתוב כאן, המוניטור מעיר אותי מיד.', ft: 'חיישנים דטרמיניסטיים, בלי טוקנים ותלות חיצונית - unrestricted · undetected · unstoppable',
    to_fl_on: 'מצב FLEET פעיל: מחזורים לוקאליים כל 30 דק, 0 טוקנים.', to_fl_pa: 'FLEET בהשהיה - המשך מתי שתרצה.',
    to_fl_cy: 'מחזור מיידי שוגר (תקציב 60 req).', to_launch: '[GO] מצב {m} (CWE {c}) על {p} - מחזור לוקאלי שוגר',
    to_ai_ok: 'ההגדרה נשמרה', to_ai_no: 'השמירה נכשלה',
    to_ai_no_cfg: 'AI לא מוגדר - הגדר אותו בטאב AI', to_ai_head: 'אנליזת AI',
    to_ai_bad: 'אנליזת AI נכשלה', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ שיגור', navar: 'ארסנל',
    ar_h2: 'ARSENAL - CVE, EPSS ו-exploits על משטח שזוהה', ar_sync: 'SYNC בסיסים',
    ar_btn: 'מהלכים', ar_exec: 'EXEC',
    ar_none: 'אין מהלכים: הרץ RECON קודם, ואז SYNC לטעינת KEV/EPSS', ar_loading: 'סיכום הבסיסים בטעינה...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'תוכנית דמו - אין סריקה: צור תוכנית משלך', pip_noprog: 'אין תוכנית: צור את שלך בלשונית תוכניות',
    pip_next: 'השלב הבא:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  hu: {
    pl_title: 'Munkaterv', pl_empty: 'még nincs terv: futtasd a RECON-t a fenti kártyán, a hipotézisek ide hullanak (az állapotok megmaradnak)',
    pl_run: 'Futtatás', pl_reflect: 'canary visszaverődött',
    st_do: 'teendő', st_test: 'tesztelt',
    st_signal: 'jel', st_valid: 'érvényes',
    st_void: 'semmi', atk_btn: 'ATTACK',
    atk_start: 'támadás a felszínre: endpointok, kiteett docik, JWT, titoktok...', atk_fail: 'támadás lehetetlen: először futtasd a RECON-t',
    atk_none: 'semmi jel', atk_findings: 'jelöltek',
    atk_done: 'ATTACK: {n} P1/P2 jelölt beinjektálva a findings-be bizonyítékkal', atk_empty: 'még nincs támadás: futtasd a RECON-t, aztán az ATTACK-ot - req/res bizonyítékos jelöltek ide hullanak',
    navh: 'HUNT', h2hunt: 'HUNT - valós felület és bizonyítékok',
    h_ready: 'kész', h_empty: 'ismert felület nincs: futtasd a RECON-t, hogy feltérképezd az oldalakat, API endpointokat, paramétereket, JS csomagokat és szubdoméneket',
    h_fnd: 'A program findings-ei', h_nofnd: 'ebben a programban nincs findings',
    rc_btn: 'RECON', rc_start: 'a felület reconja zajlik: oldalak, JS csomagok, endpointok, paraméterek...',
    rc_done: 'felület feltérképezve: endpointok, paraméterek és szubdomének felsorolva a programkártyán', rc_fail: 'recon meghiúsult: a host nem elérhető vagy üres a scope',
    rc_surface: 'felület:', snd_on: 'HANG: ON',
    snd_off: 'HANG: OFF', snd_ok: 'felületi hangok aktívak - tárház: katt, fül, másolás, riasztások',
    snd_stop: 'teljes némítás bekapcsolva: több C2FF hang nincs', amb_on: 'HANGULAT: ON',
    amb_off: 'HANGULAT: OFF', amb_ok: 'élő hangulat - az árnyalat finoman siklik végig a családokon (zöld, kék, sárga...)',
    amb_stop: 'hangulat befagyasztva az eredeti zöldre', nt_on: 'ÉRTESÍTÉSEK: ON',
    nt_off: 'ÉRTESÍTÉSEK: OFF', nt_ok: 'böngésző értesítések engedélyezve - pitty P1-re és P2-re',
    nt_denied: 'a böngésző blokkolja az értesítéseket: engedélyezd a weboldal beállításainál', term_denied: 'terminál megtagadva vagy nem elérhető: localhost kell, vagy NYITOTT szoba adminként',
    term_p: 'valódi bash - history nyilakkal, a Ctrl+C megszakít, a Ctrl+D bezár', term_restart: 'Alaphelyzet',
    navtrm: 'TERM', term_h2: 'Terminál - munkagép, egyenesen a konzolban',
    fl_off: 'FLEET: LEÁLLÍTVA', fl_paused: 'FLEET: SZÜNETEL',
    fl_active: 'FLEET: AKTÍV ({n} ciklus)', fl_last: 'utolsó ciklus',
    fl_none: 'még egy ciklus sincs', fl_info: 'intervallum {i} perc, keret {b} req/ciklus',
    sub_ttl: 'command & control framework', navt: 'MEGBESZÉLÉS',
    tm_h2: 'Csoportos szekciók - közös vadászat, akár hálózaton kívül is', tm_p: 'Nyiss meg egy osztott szobát: a csapatod látja a flottát, a findings-eket és élőben triázhat. Külön szekciós chat lent. Három hozzáférési szint: LOCAL (solo), LAN hálózatra nyitás útján, és VILÁG a világ felé nyitás útján - a nyilvános tunel (ha telepített cloudflared van) érvényessé teszi a meghívó linket bármely hálózatról, a géped közvetlen kitevése nélkül. Mindent a szoba kulcsa zár - regeneráld, és egy mozdulattal kidobod mindet.',
    tm_handle: 'A beceneved (legfeljebb 16 karakter)', tm_save_h: 'Beállít',
    tm_room_ph: 'szoba neve (pl. c2ff-core)', tm_save: 'Alkalmaz',
    tm_on: 'SZOBA NYITVA: {r} - {n} online', tm_off: 'TEAM MÓD KIKAPCSOLVA - lokális solo szekció',
    tm_room: 'Szoba', tm_key: 'Szobakulcs',
    tm_regen: 'Kulcs újratermelése', tm_regen_ok: 'új kulcs legyártva - régi linkek halottak',
    tm_invite: 'Meghívó link (másold a csapatodnak)', tm_copy: 'Másolás',
    tm_copied: 'vágólapra másolva', tm_members: 'Tagok',
    tm_nobody: 'még senki - küldd el a linket a csapatodnak', tm_you: '(ti)',
    tm_here: 'itt', tm_saved: 'becenév elmentve',
    tm_no_handle: 'üres becenév', tm_cfg_ok: 'szoba frissítve',
    tm_cfg_no: 'meghiúsult', tm_live: 'NYITÁS A HÁLÓZATRA',
    tm_shore: 'VISSZA A LOKÁLISRA', tm_need_on: 'először kapcsold be a szobát (ON)',
    tm_bind_lan: 'HÁLÓ: {a}', tm_bind_lo: 'LOCAL: csak localhost',
    to_team_live: '[GO-LIVE] kiszolgáló újraindítva hálózati hozzáféréssel - LAN link kirakva, újrakapcsolódás 2 mp múlva', to_team_shore: 'kiszolgáló újraindítva lokálisan (127.0.0.1)',
    tm_tun_open: 'NYITÁS A VILÁGNAK (tunel)', tm_tun_close: 'TUNEL BEZÁRÁSA',
    tm_tun_wait: 'nyilvános tunel nyílik (néhány másodperc)…', tm_tun_on: 'SZEKCIÓ A VILÁGNAK NYITVA: {u} - a meghívó link mindenhol működik, nem kell közös háló',
    tm_tun_closed: 'tunel bezárva - vissza LAN/lokálra', tm_chat_empty: 'szekciós csatorna nyitva - a szoba tagjai itt olvassák egymást',
    tm_chat_h2: 'Szekciós csevegés', tm_msg_ph: 'üzenet a szekcióba…',
    tm_admin: 'admin', tm_guest: 'vendég',
    tm_kick: 'KICK', tm_kick_ok: 'tag kirúgva a szobából (kattints újra a zárfeloldáshoz)',
    tm_role_ok: 'szerep frissítve', tm_mic_on: 'MIKROFON BEKAPCSOLÁSA',
    tm_mic_off: 'MIKROFON LEKAPCSOLÁSA', tm_mic_denied: 'mikrofon megtagadva vagy nem elérhető: HTTPS kell (VILÁG tunel vagy localhost) és engedélyezni kell a mikrofont',
    navf: 'Flotta', navfd: 'Findings',
    navp: 'Programok', navai: 'MI',
    navc: 'Együttdolgozás', st_runs: 'Runok',
    st_beacons: 'Aktív beaconok', st_sig: 'Jelek',
    h2f: 'Flotta - minden program, futó agentok elöl', h2fd: 'Findings bázis - tartós triage címkézés',
    h2eng: 'Flottamotor - lokális cikliklik, token nélkül', h2prog: 'Programok - scope, szikséges header, kilövés',
    h2new: 'Új program', h2ai: 'MI-Ágnes - integráció tíznulla százalékban opcionális',
    h2c: 'Együttműködés - privát csatorna', fl_start: 'Indítás',
    fl_pause: 'Szünet', fl_cycle: 'Ciklus most',
    f_add: 'Hozzáadás', f_none: 'még egy jel sincs',
    f_ph: 'kézi finding: endpoint + bizonyíték + megvédhető súly…', st_sig_off: 'jel',
    st_sig_an: 'analízis', st_sig_sub: 'beküldt',
    st_sig_dup: 'dup', st_sig_ref: 'elutasított',
    st_sig_cl: 'zárva', r_none: 'egy run sem volt észlelni',
    r_live: '{n} SZALAD', r_done: 'KÉSZ',
    r_feed: '▽ csörge ({n} ev)', r_close: '△ becsuk',
    p_name_ph: 'Program neve (pl. PayPal)', p_hdr_ph: 'közvetlen kutatóheader (pl. X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domén1, domén2, …', p_save: 'Mentés',
    p_local: 'modul, tíznulla százalékban lokális', ai_p: 'A C2FF teljesen MI nélkül dolgozik: a módok determinista lokális szondák. Ez a kapu csak arra való, hogy <b>a te</b> MI-det (self-hosted vagy API) egyetlen finding eseti elemzéséhez kösd rá: az <span style="color:var(--green)">IA »</span> gomb a FINDINGS-ben, a válasz az EGYÜTTMŰKÖDÉS-ben jelenik meg. Ennek a beállításnak a híján egyetlen adat sem hagyja el a gépet.',
    ai_off: 'kikapcsolva', ai_on: 'bekapcsolva',
    ai_st_off: 'MI KI - a keretrendszer tíznulla százalékban lokálisan fut nélküle', ai_st_ready: 'MI RÁKÖTVE: {p} · {m}',
    ai_st_inc: 'MI BEKAPCSOLVA, DE HIÁNYOS: baseURL és model kell', ai_url_ph: 'bázis URL - pl. http://localhost:11434 vagy https://api.AzEnMI.tld/v1',
    ai_model_ph: 'model - pl. llama3.1:8b', ai_key_ph: 'API kulcs (lokális kiszolgálóknál hagyd üresen)',
    ai_save: 'Mentés', ai_test: 'Kapcsolat tesztelése',
    ai_testing: 'vizsgálat zajlik…', ai_ok: 'OK - válasz: ',
    ai_fail: 'MEGHIÚSULT: ', ai_note: 'a beállítás lokálisan tárolt a data/ai.json-ban - soha nem küldődik máshová, mint arra az endpointra, amelyet beleraksz',
    ch_ph: 'root@c2ff:~# üzenet az analízis ágensnek…', ch_send: 'Küldés',
    ch_empty: 'A csatorna nyitva van. Írj ide, a monitor engem azonnal felébreszt.', ft: 'tíznulla százalékban lokális - determinista szondák, token és külső függőség nélkül - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE AKTÍV: lokális cikliklik félóránként, 0 token.', to_fl_pa: 'FLEET SZÜNETEL - folytasd amikor akarod.',
    to_fl_cy: 'Azonnali ciklus kilőve (60 req keret).', to_launch: '[GO] mód {m} (CWE {c}) a {p}-n - lokális ciklus kilőve',
    to_ai_ok: 'beállítás elmentve', to_ai_no: 'mentés meghiúsult',
    to_ai_no_cfg: 'MI nincs beállítva - állítsd be az MI fülön', to_ai_head: 'MI ELEMZÉS',
    to_ai_bad: 'MI ELEMZÉS meghiúsult', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'MI',
    w_launch: '⚡ KILÖVÉS', navar: 'Arzenál',
    ar_h2: 'ARSENAL - CVE, EPSS és exploitok az észlelt felületen', ar_sync: 'SYNC ADATBÁZISOK',
    ar_btn: 'LÉPÉSEK', ar_exec: 'EXEC',
    ar_none: 'nincs lépés: futtasd előbb a RECON-t, majd SYNC a KEV/EPSS betöltéséhez', ar_loading: 'adatbázis-összefoglaló betöltése...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demóprogram - nincs szkennelés: hozd létre a saját programod', pip_noprog: 'nincs még program: hozd létre a sajátodat a Programok fülön',
    pip_next: 'következő lépés:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  cs: {
    pl_title: 'Pracovní plán', pl_empty: 'zatím žádný plán: spusť RECON v kartě nahoře, hypotezy padají sem (stavy se ukládají)',
    pl_run: 'Spustit', pl_reflect: 'kanárek se odrazil',
    st_do: 'k udělání', st_test: 'otestováno',
    st_signal: 'signál', st_valid: 'platné',
    st_void: 'nic', atk_btn: 'ATTACK',
    atk_start: 'útok na povrch: endpointy, vystavené dokumentace, JWT, tajemství...', atk_fail: 'útok nemožný: nejdřív pusť RECON',
    atk_none: 'žádný signál', atk_findings: 'kandidáti',
    atk_done: 'ATTACK: {n} kandidátů P1/P2 vstříknuto do findings s důkazem', atk_empty: 'zatím žádný útok: pusť RECON a pak ATTACK - kandidáti s důkazem req/res padají sem',
    navh: 'HUNT', h2hunt: 'HUNT - reálná plocha a důkazy',
    h_ready: 'připraveno', h_empty: 'žádná známá plocha: pusť RECON a zmapuj stránky, endpointy API, parametry, JS bundly a subdomény',
    h_fnd: 'Findings programu', h_nofnd: 'v tomhle programu žádné findings',
    rc_btn: 'RECON', rc_start: 'recon plochy probíhá: stránky, JS bundly, endpointy, parametry...',
    rc_done: 'plocha zmapována: endpointy, parametry a subdomény vypsané v kartě programu', rc_fail: 'recon selhal: host nedosážitelný nebo prázdný scope',
    rc_surface: 'plocha:', snd_on: 'ZVUK: ON',
    snd_off: 'ZVUK: OFF', snd_ok: 'zvuky rozhraní aktivní - knihovna: klik, panel, kopírování, výstrahy',
    snd_stop: 'úplné ztišení zapnuto: žádné zvuky C2FF', amb_on: 'PROSTŘEDÍ: ON',
    amb_off: 'PROSTŘEDÍ: OFF', amb_ok: 'živé prostředí - odstín jemně klouže rodinami (zelená, modrá, žlutá...)',
    amb_stop: 'prostředí zafrozené na původní zelené', nt_on: 'NOTIFIKACE: ON',
    nt_off: 'NOTIFIKACE: OFF', nt_ok: 'notifikace prohlížeče povoleny - pípne na P1 a P2',
    nt_denied: 'notifikace zablokované prohlížečem: povol je v nastavení webu', term_denied: 'terminál odepřen nebo nedostupný: potřeba localhost, nebo OTEVŘENÁ místnost jako admin',
    term_p: 'skutečný bash - historie šipkami, Ctrl+C přeruší, Ctrl+D zavře', term_restart: 'Resetovat',
    navtrm: 'TERM', term_h2: 'Terminál - pracovní shell, přímo v konzoli',
    fl_off: 'FLEET: ZASTAVEN', fl_paused: 'FLEET: V PAUZE',
    fl_active: 'FLEET: AKTIVNÍ ({n} cyklů)', fl_last: 'poslední cyklus',
    fl_none: 'zatím žádný cyklus', fl_info: 'interval {i} min, rozpočet {b} req/cykl',
    sub_ttl: 'command & control framework', navt: 'SEZNÁNÍ',
    tm_h2: 'Skupinové sezení - lov v partě, i mimo síť', tm_p: 'Otevři sdílenou místnost: tvoje parta vidí flotilu, findings a může třídit živě. Samostatný chat sezení níž. Tři úrovně přístupu: LOCAL (solo), LAN přes OTEVŘÍT DO SÍTĚ a SVĚT přes OTEVŘÍT SVĚTU - veřejný tunel (cloudflared, je-li nainstalovaný) udělá z pozvánky platnou z jakékoliv sítě, bez přímého vystavení tvojí mašiny. Vše střeží klíč místnosti - přegeneruj ho a shodíš všechny najednou.',
    tm_handle: 'Tvoje přezdívka (max 16 znaků)', tm_save_h: 'Nastavit',
    tm_room_ph: 'název místnosti (např. c2ff-core)', tm_save: 'Použít',
    tm_on: 'MÍSTNOST OTEVŘENÁ: {r} - {n} online', tm_off: 'TEAM REŽIM VYPNUTÝ - lokální session solo',
    tm_room: 'Místnost', tm_key: 'Klíč místnosti',
    tm_regen: 'Přegenerovat klíč', tm_regen_ok: 'nový klíč vygenerován - staré linky jsou mrtvé',
    tm_invite: 'Pozvánka (zkopíruj svému týmu)', tm_copy: 'Kopírovat',
    tm_copied: 'zkopírováno do schránky', tm_members: 'Členové',
    tm_nobody: 'zatím nikdo - pošli link týmu', tm_you: '(ty)',
    tm_here: 'přítomen', tm_saved: 'přezdívka uložena',
    tm_no_handle: 'prázdná přezdívka', tm_cfg_ok: 'místnost upravena',
    tm_cfg_no: 'selhalo', tm_live: 'OTEVŘÍT DO SÍTĚ',
    tm_shore: 'ZPĚT K LOKÁLNÍMU', tm_need_on: 'nejdřív zapni místnost (ON)',
    tm_bind_lan: 'SÍŤ: {a}', tm_bind_lo: 'LOCAL: jen localhost',
    to_team_live: '[GO-LIVE] server restartován se síťovým přístupem - LAN link zobrazen, znovupřipojení za 2 s', to_team_shore: 'server restartován lokálně (127.0.0.1)',
    tm_tun_open: 'OTEVŘÍT SVĚTU (tunel)', tm_tun_close: 'ZAVŘÍT TUNEL',
    tm_tun_wait: 'veřejný tunel se otevírá (několik sekund)…', tm_tun_on: 'SESSION OTEVŘENÁ SVĚTU: {u} - pozvánka funguje odkudkoliv, netřeba stejnou síť',
    tm_tun_closed: 'tunel zavřen - zpátky na LAN/lokál', tm_chat_empty: 'kanál session otevřen - členové místnosti se tu čtou navzájem',
    tm_chat_h2: 'Chat session', tm_msg_ph: 'zpráva do session…',
    tm_admin: 'admin', tm_guest: 'host',
    tm_kick: 'KICK', tm_kick_ok: 'člen vyhozen z místnosti (klikni znovu na odblokování)',
    tm_role_ok: 'role upravena', tm_mic_on: 'ZAPNOUT MIKROFON',
    tm_mic_off: 'VYPNOUT MIKROFON', tm_mic_denied: 'mikrofon odepřen nebo nedostupný: vyžadován HTTPS (tunel SVĚT nebo localhost) a mikrofon musíš povolit',
    navf: 'Flotila', navfd: 'Findings',
    navp: 'Programy', navai: 'AI',
    navc: 'Koordinace', st_runs: 'Runy',
    st_beacons: 'Aktivní beacony', st_sig: 'Signály',
    h2f: 'Flotila - všechny programy, běžící agenti navrchu', h2fd: 'Základna findings - trvalé triáže značení',
    h2eng: 'Motor flotily - lokální cykly bez tokenů', h2prog: 'Programy - scope, vyžadovaný header, odpalení',
    h2new: 'Nový program', h2ai: 'AI agent - integrace zcela volitelná',
    h2c: 'Koordinace - soukromý kanál', fl_start: 'Spustit',
    fl_pause: 'Pauza', fl_cycle: 'Cyklus teď',
    f_add: 'Přidat', f_none: 'zatím žádný signál',
    f_ph: 'manuální finding: endpoint + důkaz + hájitelná závažnost…', st_sig_off: 'signál',
    st_sig_an: 'analýza', st_sig_sub: 'odesláno',
    st_sig_dup: 'dup', st_sig_ref: 'odmítnuto',
    st_sig_cl: 'uzavřeno', r_none: 'nezjištěn žádný run',
    r_live: '{n} V BĚHU', r_done: 'HOTOVO',
    r_feed: '▽ proud ({n} ud.)', r_close: '△ složit',
    p_name_ph: 'Název programu (např. PayPal)', p_hdr_ph: 'vyžadovaný header výzkumníka (např. X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: doména1, doména2, …', p_save: 'Uložit',
    p_local: 'modul(ů), na sto procent lokálně', ai_p: 'C2FF funguje naprosto bez AI: režimy jsou deterministické lokální sondy. Tato brána slouží jen k připojení <b>tvého</b> AI (self-hosted nebo API) k bodové analýze findingu: tlačítko <span style="color:var(--green)">IA »</span> ve FINDINGS, odpověď se vykreslí v KOORDINACI. Bez téhle konfigurace neodejde z tvé mašiny žádná data.',
    ai_off: 'vypnuto', ai_on: 'zapnuto',
    ai_st_off: 'AI VYPNUTO - framework běží na sto procent lokálně bez něj', ai_st_ready: 'AI PŘIPOJENO: {p} · {m}',
    ai_st_inc: 'AI ZAPNUTO, ALE NEKOMPLETNÍ: nutné baseURL a model', ai_url_ph: 'base URL - např. http://localhost:11434 nebo https://api.MojeAI.tld/v1',
    ai_model_ph: 'model - např. llama3.1:8b', ai_key_ph: 'API klíč (ponech prázdné u lokálních serverů)',
    ai_save: 'Uložit', ai_test: 'Otestovat spojení',
    ai_testing: 'test běží…', ai_ok: 'OK - odpověď: ',
    ai_fail: 'SELHÁNÍ: ', ai_note: 'nastavení je uložené lokálně v data/ai.json - nikdy se neposílá nikam jinam než na endpoint, který tam nastavíš',
    ch_ph: 'root@c2ff:~# zpráva agentovi analýzy…', ch_send: 'Poslat',
    ch_empty: 'Kanál je otevřený. Piš sem, monitor mě probouzí okamžitě.', ft: 'na sto procent lokální - deterministické sondy, bez tokenů a externích závislostí - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE AKTIVNÍ: lokální cykly každých 30 min, 0 tokenů.', to_fl_pa: 'FLEET V PAUZE - obnov, kdy chceš.',
    to_fl_cy: 'Okamžitý cyklus odpačen (rozpočet 60 req).', to_launch: '[GO] režim {m} (CWE {c}) na {p} - lokální cyklus odpálen',
    to_ai_ok: 'nastavení uloženo', to_ai_no: 'ukládání selhalo',
    to_ai_no_cfg: 'AI nenastavené - doladěj ho v záložce AI', to_ai_head: 'ANALÝZA AI',
    to_ai_bad: 'ANALÝZA AI selhala', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'IA',
    w_launch: '⚡ VÝSTŘEL', navar: 'Arzenál',
    ar_h2: 'ARSENAL - CVE, EPSS a exploity na zjištěné ploše', ar_sync: 'SYNC DATABÁZ',
    ar_btn: 'TAHY', ar_exec: 'EXEC',
    ar_none: 'žádné tahy: nejprve spusť RECON, pak SYNC pro načtení KEV/EPSS', ar_loading: 'přehled databází se načítá...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demo program - bez skenování: vytvoř si vlastní program', pip_noprog: 'žádný program: vytvoř si vlastní v záložce Programy',
    pip_next: 'další krok:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  sk: {
    pl_title: 'Pracovný plán', pl_empty: 'zatiaľ žiadny plán: spusti RECON v karte vyššie, hypotézy padajú sem (stavy sa ukladajú)',
    pl_run: 'Spustiť', pl_reflect: 'kanárik sa odrazil',
    st_do: 'na urobene', st_test: 'otestované',
    st_signal: 'signál', st_valid: 'platné',
    st_void: 'nič', atk_btn: 'ATTACK',
    atk_start: 'útok na povrch: endpointy, vystavené dokumentácie, JWT, tajomstvá...', atk_fail: 'útok nemožný: najprv pusti RECON',
    atk_none: 'žiadny signál', atk_findings: 'kandidáti',
    atk_done: 'ATTACK: {n} kandidátov P1/P2 vstriečených do findings s dôkazom', atk_empty: 'zatiaľ žiadny útok: pusti RECON a potom ATTACK - kandidáti s dôkazom req/res padajú sem',
    navh: 'HUNT', h2hunt: 'HUNT - reálna plocha a dôkazy',
    h_ready: 'pripravené', h_empty: 'žiadna známa plocha: pusti RECON a zmapuj stránky, endpointy API, parametre, JS bundy a subdomény',
    h_fnd: 'Findings programu', h_nofnd: 'v tomto programe žiadne findings',
    rc_btn: 'RECON', rc_start: 'recon povrchu prebieha: stránky, JS bundy, endpointy, parametre...',
    rc_done: 'povrch zmapovaný: endpointy, parametre a subdomény vypísané v karte programu', rc_fail: 'recon zlyhal: host nedostupný alebo prázdny scope',
    rc_surface: 'povrch:', snd_on: 'ZVUK: ON',
    snd_off: 'ZVUK: OFF', snd_ok: 'zvuky rozhrania aktívne - knižnica: klik, panel, kopírovanie, výstrahy',
    snd_stop: 'úplné stlmenie zapnuté: žiadne zvuky C2FF', amb_on: 'PROSTREDIE: ON',
    amb_off: 'PROSTREDIE: OFF', amb_ok: 'živé prostredie - odtieň jemne kĺže rodinami (zelená, modrá, žltá...)',
    amb_stop: 'prostredie zmrazené na pôvodnej zelenej', nt_on: 'NOTIFIKÁCIE: ON',
    nt_off: 'NOTIFIKÁCIE: OFF', nt_ok: 'notifikácie prehliadača povolené - pípne na P1 a P2',
    nt_denied: 'notifikácie zablokované prehliadačom: povoľ ich v nastavení webu', term_denied: 'terminál odmietnutý alebo nedostupný: potrebný localhost, alebo OTVORENÁ miestnosť ako admin',
    term_p: 'skutočný bash - história šípkami, Ctrl+C preruší, Ctrl+D zavrie', term_restart: 'Resetovať',
    navtrm: 'TERM', term_h2: 'Terminál - pracovný shell, priamo v konzole',
    fl_off: 'FLEET: ZASTAVENÝ', fl_paused: 'FLEET: V PAUZE',
    fl_active: 'FLEET: AKTÍVNY ({n} cyklov)', fl_last: 'posledný cyklus',
    fl_none: 'zatiaľ žiadny cyklus', fl_info: 'interval {i} min, rozpočet {b} req/cyklus',
    sub_ttl: 'command & control framework', navt: 'SEDENIE',
    tm_h2: 'Skupinové sedenia - lov v party, aj mimo siete', tm_p: 'Otvor zdieľanú miestnosť: tvoja parta vidí flotilu, findings a môže triediť naživo. Vlastný chat sezení nižšie. Tri úrovne prístupu: LOCAL (solo), LAN cez OTVORIŤ DO SIETE a SVET cez OTVORIŤ SVETU - verejný tunel (cloudflared, ak je nainštalovaný) spraví z pozvánky platnú z akejkoľvek siete, bez priameho vystavenia tvojej mašiny. Všetko stráži kľúč miestnosti - pregeneruj ho a zhodíš všetkých naraz.',
    tm_handle: 'Tvoja prezývka (max 16 znakov)', tm_save_h: 'Nastaviť',
    tm_room_ph: 'názov miestnosti (napr. c2ff-core)', tm_save: 'Použiť',
    tm_on: 'MIESTNOSŤ OTVORENÁ: {r} - {n} online', tm_off: 'TEAM REŽIM VYPNUTÝ - lokálna session solo',
    tm_room: 'Miestnosť', tm_key: 'Kľúč miestnosti',
    tm_regen: 'Pregenerovať kľúč', tm_regen_ok: 'nový kľúč vygenerovaný - staré linky sú mŕtve',
    tm_invite: 'Pozvánka (skopíruj svojmu tímu)', tm_copy: 'Kopírovať',
    tm_copied: 'skopírované do schránky', tm_members: 'Členovia',
    tm_nobody: 'zatiaľ nikto - pošli link tímu', tm_you: '(ty)',
    tm_here: 'prítomný', tm_saved: 'prezývka uložená',
    tm_no_handle: 'prázdna prezývka', tm_cfg_ok: 'miestnosť upravená',
    tm_cfg_no: 'zlyhalo', tm_live: 'OTVORIŤ DO SIETE',
    tm_shore: 'SPÄŤ K LOKÁLNEMU', tm_need_on: 'najprv zapni miestnosť (ON)',
    tm_bind_lan: 'SIEŤ: {a}', tm_bind_lo: 'LOCAL: len localhost',
    to_team_live: '[GO-LIVE] server reštartovaný so sieťovým prístupom - LAN link zobrazený, znovupripojenie za 2 s', to_team_shore: 'server reštartovaný lokálne (127.0.0.1)',
    tm_tun_open: 'OTVORIŤ SVETU (tunel)', tm_tun_close: 'ZAVRIEŤ TUNEL',
    tm_tun_wait: 'verejný tunel sa otvára (niekoľko sekúnd)…', tm_tun_on: 'SESSION OTVORENÁ SVETU: {u} - pozvánka funguje odkiaľkoľvek, netreba rovnakú sieť',
    tm_tun_closed: 'tunel zatvorený - späť na LAN/lokál', tm_chat_empty: 'kanál session otvorený - členovia miestnosti sa tu čítajú navzájom',
    tm_chat_h2: 'Chat session', tm_msg_ph: 'správa do session…',
    tm_admin: 'admin', tm_guest: 'hosť',
    tm_kick: 'KICK', tm_kick_ok: 'člen vyhodený z miestnosti (klikni znovu na odblokovanie)',
    tm_role_ok: 'rola upravená', tm_mic_on: 'ZAPNÚŤ MIKROFÓN',
    tm_mic_off: 'VYPNÚŤ MIKROFÓN', tm_mic_denied: 'mikrofón odmietnutý alebo nedostupný: vyžaduje sa HTTPS (tunel SVET alebo localhost) a mikrofón musíš povoliť',
    navf: 'Flotila', navfd: 'Findings',
    navp: 'Programy', navai: 'AI',
    navc: 'Koordinácia', st_runs: 'Runy',
    st_beacons: 'Aktívne beacony', st_sig: 'Signály',
    h2f: 'Flotila - všetky programy, bežiaci agenti navrchu', h2fd: 'Základňa findings - trvalé označenie triáže',
    h2eng: 'Motor flotily - lokálne cykly bez tokenov', h2prog: 'Programy - scope, vyžadovaný header, odpálenie',
    h2new: 'Nový program', h2ai: 'AI agent - integrácia úplne voliteľná',
    h2c: 'Koordinácia - súkromný kanál', fl_start: 'Spustiť',
    fl_pause: 'Pauza', fl_cycle: 'Cyklus teraz',
    f_add: 'Pridať', f_none: 'zatiaľ žiadny signál',
    f_ph: 'manuálny finding: endpoint + dôkaz + obhájiteľná závažnosť…', st_sig_off: 'signál',
    st_sig_an: 'analýza', st_sig_sub: 'odoslané',
    st_sig_dup: 'dup', st_sig_ref: 'odmietnuté',
    st_sig_cl: 'uzavreté', r_none: 'nezistený žiadny run',
    r_live: '{n} V BEHU', r_done: 'HOTOVO',
    r_feed: '▽ prúd ({n} ud.)', r_close: '△ zložiť',
    p_name_ph: 'Názov programu (napr. PayPal)', p_hdr_ph: 'vyžadovaný header výskumníka (napr. X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: doména1, doména2, …', p_save: 'Uložiť',
    p_local: 'modul(ov), na sto percent lokálne', ai_p: 'C2FF funguje úplne bez AI: režimy sú deterministické lokálne sondy. Táto brána slúži len na pripojenie <b>tvojho</b> AI (self-hosted alebo API) k bodovej analýze findingu: tlačidlo <span style="color:var(--green)">AI »</span> vo FINDINGS, odpoveď sa vykreslí v KOORDINÁCII. Bez tejto konfigurácie neodíde z tvojej mašiny žiadne dáta.',
    ai_off: 'vypnuté', ai_on: 'zapnuté',
    ai_st_off: 'AI VYPNUTÉ - framework beží na sto percent lokálne bez neho', ai_st_ready: 'AI PRIPOJENÉ: {p} · {m}',
    ai_st_inc: 'AI ZAPNUTÉ, ALE NEKOMPLETNÉ: nutné baseURL a model', ai_url_ph: 'base URL - napr. http://localhost:11434 alebo https://api.MojeAI.tld/v1',
    ai_model_ph: 'model - napr. llama3.1:8b', ai_key_ph: 'API kľúč (ponechaj prázdne pri lokálnych serveroch)',
    ai_save: 'Uložiť', ai_test: 'Otestovať spojenie',
    ai_testing: 'test prebieha…', ai_ok: 'OK - odpoveď: ',
    ai_fail: 'ZLYHANIE: ', ai_note: 'konfigurácia uložená lokálne v data/ai.json - nikdy sa neposiela nikam inam než na endpoint, ktorý tam nastavíš',
    ch_ph: 'root@c2ff:~# správa agentovi analýzy…', ch_send: 'Poslať',
    ch_empty: 'Kanál je otvorený. Píš sem, monitor ma budí okamžite.', ft: 'na sto percent lokálne - deterministické sondy, bez tokenov a externých závislostí - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE AKTÍVNY: lokálne cykly každých 30 min, 0 tokenov.', to_fl_pa: 'FLEET V PAUZE - obnov, kedy chceš.',
    to_fl_cy: 'Okamžitý cyklus odpálený (rozpočet 60 req).', to_launch: '[GO] režim {m} (CWE {c}) na {p} - lokálny cyklus odpálený',
    to_ai_ok: 'konfigurácia uložená', to_ai_no: 'ukladanie zlyhalo',
    to_ai_no_cfg: 'AI nenastavené - dolad ho v záložke AI', to_ai_head: 'ANALÝZA AI',
    to_ai_bad: 'ANALÝZA AI zlyhala', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'IA',
    w_launch: '⚡ VYPÚŠŤANIE', navar: 'Arzenál',
    ar_h2: 'ARSENAL - CVE, EPSS a exploity na zistenej ploche', ar_sync: 'SYNC DATABÁZ',
    ar_btn: 'TAHY', ar_exec: 'EXEC',
    ar_none: 'žiadne tahy: najprv spusti RECON, potom SYNC na načítanie KEV/EPSS', ar_loading: 'prehľad databáz sa načítava...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demo program - bez skenovania: vytvor si vlastný program', pip_noprog: 'žiadny program: vytvor si vlastný na karte Programy',
    pip_next: 'ďalší krok:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  uk: {
    pl_title: 'Робочий план', pl_empty: 'плану ще немає: запусти RECON в картці вище, гіпотези падають сюди (статуси зберігаються)',
    pl_run: 'Запустити', pl_reflect: 'canary відбито',
    st_do: 'до виконання', st_test: 'протестовано',
    st_signal: 'сигнал', st_valid: 'валідне',
    st_void: 'нічого', atk_btn: 'ATTACK',
    atk_start: 'атака на поверхню: ендпоінти, відкрита документація, JWT, секрети...', atk_fail: 'атака неможлива: спершу запусти RECON',
    atk_none: 'немає сигналу', atk_findings: 'кандидати',
    atk_done: 'ATTACK: {n} кандидатів P1/P2 впорскнуто в findings з доказом', atk_empty: 'атаки ще не було: запусти RECON, потім ATTACK - кандидати з доказом req/res падають сюди',
    navh: 'HUNT', h2hunt: 'HUNT - реальна поверхня і докази',
    h_ready: 'готовий', h_empty: 'відомої поверхні немає: запусти RECON, щоб змапувати сторінки, ендпоінти API, параметри, JS-бандли і сабдомени',
    h_fnd: 'Знахідки програми', h_nofnd: 'у цій програмі немає findings',
    rc_btn: 'RECON', rc_start: 'recon поверхні триває: сторінки, JS-бандли, ендпоінти, параметри...',
    rc_done: 'поверхню змаповано: ендпоінти, параметри і сабдомени перелічені в картці програми', rc_fail: 'recon провалився: хост недосяжний або порожній scope',
    rc_surface: 'поверхня:', snd_on: 'ЗВУК: ON',
    snd_off: 'ЗВУК: OFF', snd_ok: 'звуки інтерфейсу активні - бібліотека: клік, вкладка, копіювання, сповіщення',
    snd_stop: 'повне приглушення увімкнено: жодних звуків C2FF', amb_on: 'АТМОСФЕРА: ON',
    amb_off: 'АТМОСФЕРА: OFF', amb_ok: 'жива атмосфера - відтінок плавно ковзає родинами (зелений, синій, жовтий...)',
    amb_stop: 'атмосфера заморожена на початковому зеленому', nt_on: 'Сповіщення : ON',
    nt_off: 'Сповіщення : OFF', nt_ok: 'сповіщення браузера увімкнено - піп на P1 і P2',
    nt_denied: 'сповіщення заблоковані браузером: дозволь їх у налаштуваннях сайту', term_denied: 'термінал відхилено або недоступний: потрібен localhost, або ВІДКРИТА кімната як адмін',
    term_p: 'справжній bash - історія стрілками, Ctrl+C перериває, Ctrl+D закриває', term_restart: 'Скинути',
    navtrm: 'TERM', term_h2: 'Термінал - робоча оболонка, просто в консолі',
    fl_off: 'FLEET: ЗУПИНЕНО', fl_paused: 'FLEET: НА ПАУЗІ',
    fl_active: 'FLEET: АКТИВНИЙ ({n} циклів)', fl_last: 'останній цикл',
    fl_none: 'циклів ще не було', fl_info: 'інтервал {i} хв, бюджет {b} req/цикл',
    sub_ttl: 'command & control framework', navt: 'СЕСІЯ',
    tm_h2: 'Групові сесії - полювання командою, навіть поза мережею', tm_p: 'Відкрий спільну кімнату: твоя банда бачить флот, знахідки і може тріажити наживо. Окремий чат сесії нижче. Три рівні доступу: LOCAL (соло), LAN через ВІДКРИТИ ДО МЕРЕЖІ та СВІТ через ВІДКРИТИ ДО СВІТУ - публічний тунель (cloudflared, якщо встановлено) робить посилання-запрошення чинним з будь-якої мережі, без прямого виставляння твоєї машини. Все захищено ключем кімнати - перегенеруй його, щоб викинути всіх одним рухом.',
    tm_handle: 'Твій нік (макс 16 символів)', tm_save_h: 'Обрати',
    tm_room_ph: 'назва кімнати (напр. c2ff-core)', tm_save: 'Застосувати',
    tm_on: 'КІМНАТА ВІДКРИТА: {r} - {n} онлайн', tm_off: 'РЕЖИМ КОМАНДИ ВИКЛЮЧЕНО - локальна сольна сесія',
    tm_room: 'Кімната', tm_key: 'Ключ кімнати',
    tm_regen: 'Перегенерувати ключ', tm_regen_ok: 'новий ключ згенеровано - старі лінки мертві',
    tm_invite: 'Посилання-запрошення (скопіюй своїй команді)', tm_copy: 'Копіювати',
    tm_copied: 'скопійовано в буфер', tm_members: 'Учасники',
    tm_nobody: 'поки нікого - надішли лінк команді', tm_you: '(ти)',
    tm_here: 'присутній', tm_saved: 'нік збережено',
    tm_no_handle: 'порожній нік', tm_cfg_ok: 'кімнату оновлено',
    tm_cfg_no: 'не вдалося', tm_live: 'ВІДКРИТИ ДО МЕРЕЖІ',
    tm_shore: 'ПОВЕРНУТИСЬ ДО ЛОКАЛЬНОГО', tm_need_on: 'спершу увімкни кімнату (ON)',
    tm_bind_lan: 'МЕРЕЖА: {a}', tm_bind_lo: 'LOCAL: лише localhost',
    to_team_live: '[GO-LIVE] сервер перезапущено з мережевим доступом - LAN-лінк показано, перепідключення за 2 с', to_team_shore: 'сервер перезапущено локально (127.0.0.1)',
    tm_tun_open: 'ВІДКРИТИ ДО СВІТУ (тунель)', tm_tun_close: 'ЗАКРИТИ ТУНЕЛЬ',
    tm_tun_wait: 'публічний тунель відкривається (кілька секунд)…', tm_tun_on: 'СЕСІЯ ВІДКРИТА ДО СВІТУ: {u} - запрошення працює звідусіль, спільна мережа не потрібна',
    tm_tun_closed: 'тунель закрито - назад до LAN/локал', tm_chat_empty: 'канал сесії відкрито - учасники кімнати читають одне одного тут',
    tm_chat_h2: 'Чат сесії', tm_msg_ph: 'повідомлення у сесію…',
    tm_admin: 'адмін', tm_guest: 'гість',
    tm_kick: 'KICK', tm_kick_ok: 'учасника викинуто з кімнати (клацни ще раз, щоб розблокувати)',
    tm_role_ok: 'роль оновлено', tm_mic_on: 'УВІМКНУТИ МІКРОФОН',
    tm_mic_off: 'ВИКЛЮЧИТИ МІКРОФОН', tm_mic_denied: 'мікрофон відхилено або недоступний: потрібен HTTPS (тунель СВІТ або localhost) і треба дозволити мікрофон',
    navf: 'Флот', navfd: 'Findings',
    navp: 'Програми', navai: 'ШІ',
    navc: 'Координація', st_runs: 'Runи',
    st_beacons: 'Активні бекони', st_sig: 'Сигнали',
    h2f: 'Флот - усі програми, агенти в бігу вище', h2fd: 'База знахідок - постійне тріаж-маркування',
    h2eng: 'Двигун флоту - локальні цикли без токенів', h2prog: 'Програми - scope, обов\'язковий заголовок, запуск',
    h2new: 'Нова програма', h2ai: 'ШІ-агент - інтеграція на ціло сто процентів необов\'язкова',
    h2c: 'Координація - приватний канал', fl_start: 'Запустити',
    fl_pause: 'Пауза', fl_cycle: 'Цикл зараз',
    f_add: 'Додати', f_none: 'сигналів ще немає',
    f_ph: 'ручна знахідка: ендпоінт + доказ + захищувана критичність…', st_sig_off: 'сигнал',
    st_sig_an: 'аналіз', st_sig_sub: 'надіслано',
    st_sig_dup: 'дубль', st_sig_ref: 'відхилено',
    st_sig_cl: 'закрито', r_none: 'не виявлено жодного run',
    r_live: '{n} В РОЗБІГУ', r_done: 'ЗАВЕРШЕНО',
    r_feed: '▽ потік ({n} под.)', r_close: '△ згорнути',
    p_name_ph: 'Назва програми (напр. PayPal)', p_hdr_ph: 'обов\'язковий заголовок дослідника (напр. X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: домен1, домен2, …', p_save: 'Зберегти',
    p_local: 'модулів, на сто процентів локально', ai_p: 'C2FF працює повністю без ШІ: режими - детерміністичні локальні проби. Ця брама існує лише щоб підключити <b>твій</b> ШІ (self-hosted або API) до точкового аналізу одного finding: кнопка <span style="color:var(--green)">AI »</span> у FINDINGS, відповідь малюється в КООРДИНАЦІЇ. Жодні дані не покидають твою машину без цієї конфігурації.',
    ai_off: 'вимкнено', ai_on: 'увімкнено',
    ai_st_off: 'ШІ ВИМКНЕНО - фреймворк працює на сто процентів локально без нього', ai_st_ready: 'ШІ ПІД\'ЄДНАНО: {p} · {m}',
    ai_st_inc: 'ШІ УВІМКНЕНО, АЛЕ НЕПОВНЕ: потрібні baseURL і model', ai_url_ph: 'base URL - напр. http://localhost:11434 або https://api.МійШІ.tld/v1',
    ai_model_ph: 'model - напр. llama3.1:8b', ai_key_ph: 'API-ключ (залиш порожнім для локальних серверів)',
    ai_save: 'Зберегти', ai_test: 'Перевірити з\'єднання',
    ai_testing: 'тест триває…', ai_ok: 'OK - відповідь: ',
    ai_fail: 'ПРОВАЛ: ', ai_note: 'конфіг зберігається локально у data/ai.json - ніколи не надсилається нікуди, окрім ендпоінта, який там задаш',
    ch_ph: 'root@c2ff:~# повідомлення агенту аналізу…', ch_send: 'Надіслати',
    ch_empty: 'Канал відкрито. Пиши тут, монітор розбудить мене миттю.', ft: 'на сто процентів локально - детерміністичні проби, без токенів чи зовнішніх залежностей - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE АКТИВНИЙ: локальні цикли щопівгодини, 0 токенів.', to_fl_pa: 'FLEET НА ПАУЗІ - продовжуй коли захочеш.',
    to_fl_cy: 'Негайний цикл запущено (бюджет 60 req).', to_launch: '[GO] режим {m} (CWE {c}) на {p} - локальний цикл запущено',
    to_ai_ok: 'конфіг збережено', to_ai_no: 'збереження провалилося',
    to_ai_no_cfg: 'ШІ не налаштовано - задай його у вкладці ШІ', to_ai_head: 'АНАЛІЗ ШІ',
    to_ai_bad: 'АНАЛІЗ ШІ провалився', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'ШІ',
    w_launch: '⚡ ЗАПУСК', navar: 'Арсенал',
    ar_h2: 'ARSENAL - CVE, EPSS та експлойти на виявленій поверхні', ar_sync: 'SYNC БАЗ',
    ar_btn: 'ХОДИ', ar_exec: 'EXEC',
    ar_none: 'немає ходів: спочатку запусти RECON, потім SYNC для завантаження KEV/EPSS', ar_loading: 'зведення баз завантажується...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'демо програма - без сканування: створи свою програму', pip_noprog: 'жодної програми: створи свою у вкладці Програми',
    pip_next: 'наступний крок:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  hr: {
    pl_title: 'Radni plan', pl_empty: 'još nema plana: pokreni RECON u kartici gore, hipoteze padaju ovdje (statusi se spremaju)',
    pl_run: 'Pokreni', pl_reflect: 'kanarinac odražen',
    st_do: 'za napraviti', st_test: 'testirano',
    st_signal: 'signal', st_valid: 'valjano',
    st_void: 'ništa', atk_btn: 'ATTACK',
    atk_start: 'napad na površinu: endpointovi, izložena dokumentacija, JWT, tajne...', atk_fail: 'napad nemoguć: prvo pokreni RECON',
    atk_none: 'bez signala', atk_findings: 'kandidati',
    atk_done: 'ATTACK: {n} P1/P2 kandidata ubačeno u findings s dokazom', atk_empty: 'još nema napada: pokreni RECON pa ATTACK - kandidati s dokazom req/res padaju ovdje',
    navh: 'HUNT', h2hunt: 'HUNT - prava površina i dokazi',
    h_ready: 'spremno', h_empty: 'nema poznate površine: pokreni RECON da mapiraš stranice, endpointove API-ja, parametre, JS pakete i poddomene',
    h_fnd: 'Findings programa', h_nofnd: 'nema findings u ovom programu',
    rc_btn: 'RECON', rc_start: 'recon površine u toku: stranice, JS paketi, endpointovi, parametri...',
    rc_done: 'površina mapirana: endpointovi, parametri i poddomene izlistani u kartici programa', rc_fail: 'recon nije uspio: host nedostižan ili prazan scope',
    rc_surface: 'površina:', snd_on: 'ZVUK: ON',
    snd_off: 'ZVUK: OFF', snd_ok: 'zvuci sučelja aktivni - knjižnica: klik, kartica, kopiranje, alarmi',
    snd_stop: 'potpuno utišavanje uključeno: više nikakvih C2FF zvukova', amb_on: 'AMBIJENT: ON',
    amb_off: 'AMBIJENT: OFF', amb_ok: 'živi ambijent - nijansa glatko klizi kroz obitelji (zelena, plava, žuta...)',
    amb_stop: 'ambijent zamrznut na izvornoj zelenoj', nt_on: 'OBAVIJEŠTENJA: ON',
    nt_off: 'OBAVIJEŠTENJA: OFF', nt_ok: 'obavijesti preglednika omogućene - pip na P1 i P2',
    nt_denied: 'obavijesti blokirane od preglednika: dopusti ih u postavkama weba', term_denied: 'terminal odbijen ili nedostupan: traži se localhost, ili OTVORENA soba kao admin',
    term_p: 'pravi bash - povijest strelicama, Ctrl+C prekida, Ctrl+D zatvara', term_restart: 'Resetiraj',
    navtrm: 'TERM', term_h2: 'Terminal - radna ljuska, ravno u konzolu',
    fl_off: 'FLEET: ZAUSTAVLJEN', fl_paused: 'FLEET: U PAUSI',
    fl_active: 'FLEET: AKTIVAN ({n} ciklusa)', fl_last: 'posljednji ciklus',
    fl_none: 'još nikakav ciklus', fl_info: 'interval {i} min, proračun {b} req/ciklus',
    sub_ttl: 'command & control framework', navt: 'SESIJA',
    tm_h2: 'Grupne sjednice - lov u družini, čak i izvan mreže', tm_p: 'Otvori dijeljenu sobu: tvoja družina vidi flotu, findings i može razvrstavati uživo. Zasebni chat sesije dolje. Tri razine pristupa: LOCAL (solo), LAN preko OTVORI NA MREŽU i SVIJET preko OTVORI SVIJETU - javni tunel (cloudflared ako je instaliran) čini pozivni link valjanim s bilo koje mreže, bez izravne izloženosti tvoje mašine. Sve stvar čuva ključ sobe - regeneriraj ga da sve izbaciš jednim potezom.',
    tm_handle: 'Tvoj nadimak (16 znakova najviše)', tm_save_h: 'Postavi',
    tm_room_ph: 'ime sobe (npr. c2ff-core)', tm_save: 'Primijeni',
    tm_on: 'SOBA OTVORENA: {r} - {n} online', tm_off: 'TEAM NAČIN ISKLJUČEN - lokalna sjednica solo',
    tm_room: 'Soba', tm_key: 'Ključ sobe',
    tm_regen: 'Regeneriraj ključ', tm_regen_ok: 'novi ključ generiran - stari linkovi mrtvi',
    tm_invite: 'Pozivni link (kopiraj svom timu)', tm_copy: 'Kopiraj',
    tm_copied: 'kopirano u međuspremnik', tm_members: 'Članovi',
    tm_nobody: 'još nikog - pošalji link timu', tm_you: '(ti)',
    tm_here: 'prisutan', tm_saved: 'nadimak spremljen',
    tm_no_handle: 'prazan nadimak', tm_cfg_ok: 'soba ažurirana',
    tm_cfg_no: 'nije uspjelo', tm_live: 'OTVORI NA MREŽU',
    tm_shore: 'VRATI SE NA LOKALNO', tm_need_on: 'prvo uključi sobu (ON)',
    tm_bind_lan: 'MREŽA: {a}', tm_bind_lo: 'LOCAL: samo localhost',
    to_team_live: '[GO-LIVE] server ponovno pokrenut s mrežnim pristupom - LAN link prikazan, ponovno spajanje za 2 s', to_team_shore: 'server ponovno pokrenut lokalno (127.0.0.1)',
    tm_tun_open: 'OTVORI SVIJETU (tunel)', tm_tun_close: 'ZATVORI TUNEL',
    tm_tun_wait: 'javni tunel se otvara (nekoliko sekundi)…', tm_tun_on: 'SESIJA OTVORENA SVIJETU: {u} - pozivni link radi od svuda, ne treba ista mreža',
    tm_tun_closed: 'tunel zatvoren - natrag na LAN/lokalno', tm_chat_empty: 'kanal sjednice otvoren - članovi sobe ovdje se međusobno čitaju',
    tm_chat_h2: 'Chat sjednice', tm_msg_ph: 'poruka u sjednicu…',
    tm_admin: 'admin', tm_guest: 'gost',
    tm_kick: 'KICK', tm_kick_ok: 'član izbačen iz sobe (klikni ponovno za deblokadu)',
    tm_role_ok: 'uloga ažurirana', tm_mic_on: 'UKLJUČI MIKROFON',
    tm_mic_off: 'ISKLJUČI MIKROFON', tm_mic_denied: 'mikrofon odbijen ili nedostupan: traži se HTTPS (tunel SVIJET ili localhost) i mikrofon trebaš dopustiti',
    navf: 'Flota', navfd: 'Findings',
    navp: 'Programi', navai: 'AI',
    navc: 'Usklađivanje', st_runs: 'Runovi',
    st_beacons: 'Aktivni beaconovi', st_sig: 'Signali',
    h2f: 'Flota - svi programi, agenti u utrci prije svih', h2fd: 'Baza findings - trajno označavanje trijaže',
    h2eng: 'Motor flote - lokalni ciklusi bez tokena', h2prog: 'Programi - scope, traženi header, lansiranje',
    h2new: 'Novi program', h2ai: 'AI agent - povezivanje sto posto opcionalno',
    h2c: 'Usklađivanje - privatni kanal', fl_start: 'Pokreni',
    fl_pause: 'Pauza', fl_cycle: 'Ciklus sad',
    f_add: 'Dodaj', f_none: 'još bez signala',
    f_ph: 'ručni finding: endpoint + dokaz + obranjiva ozbiljnost…', st_sig_off: 'signal',
    st_sig_an: 'analiza', st_sig_sub: 'predano',
    st_sig_dup: 'dup', st_sig_ref: 'odbijeno',
    st_sig_cl: 'zatvoreno', r_none: 'nijedan run nije otkriven',
    r_live: '{n} U TRKU', r_done: 'GOTOVO',
    r_feed: '▽ tok ({n} događaj(a))', r_close: '△ preklopi',
    p_name_ph: 'Ime programa (npr. PayPal)', p_hdr_ph: 'traženi header istraživača (npr. X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domena1, domena2, …', p_save: 'Spremi',
    p_local: 'module, sto posto lokalno', ai_p: 'C2FF radi sto posto bez AI: načini su deterministike lokalne probe. Ova kapija postoji samo da priključiš <b>tvoj</b> AI (self-hosted ili API) za analizu jednog findinga po potrebi: tipka <span style="color:var(--green)">AI »</span> u FINDINGS, odgovor se prikaže u usklađivanju. Nijedan podatak ne izlazi s tvoje mašine bez te postavke.',
    ai_off: 'isključeno', ai_on: 'uključeno',
    ai_st_off: 'AI ISKLJUČEN - okvir radi sto posto lokalno bez njega', ai_st_ready: 'AI SPOJEN: {p} · {m}',
    ai_st_inc: 'AI UKLJUČEN ALI NEPOTPUN: traže se baseURL i model', ai_url_ph: 'osnovni URL - npr. http://localhost:11434 ili https://api.MojAI.tld/v1',
    ai_model_ph: 'model - npr. llama3.1:8b', ai_key_ph: 'API ključ (ostavi prazno za lokalne servere)',
    ai_save: 'Spremi', ai_test: 'Ispitaj vezu',
    ai_testing: 'ispitivanje u toku…', ai_ok: 'OK - odgovor: ',
    ai_fail: 'NEUSPIJEH: ', ai_note: 'postava čuvana lokalno u data/ai.json - nikad slana nikud drugamo nego na endpoint koji tamo navedeš',
    ch_ph: 'root@c2ff:~# poruka agentu analize…', ch_send: 'Pošalji',
    ch_empty: 'Kanal je otvoren. Piši ovdje, monitor me budi odmah.', ft: 'sto posto lokalno - deterministike probe, bez tokena i vanjskih ovisnosti - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE AKTIVAN: lokalni ciklusi svakih 30 min, 0 tokena.', to_fl_pa: 'FLEET U PAUSI - nastavi kada hoćeš.',
    to_fl_cy: 'Trenutačni ciklus lansiran (proračun 60 req).', to_launch: '[GO] način {m} (CWE {c}) na {p} - lokalni ciklus lansiran',
    to_ai_ok: 'postava spremljena', to_ai_no: 'spremanje nije uspjelo',
    to_ai_no_cfg: 'AI nije postavljen - namjesti ga u kartici AI', to_ai_head: 'AI ANALIZA',
    to_ai_bad: 'AI ANALIZA nije uspjela', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ LANSIRANJE', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS i eksploiti na otkrivenoj površini', ar_sync: 'SYNC BAZA',
    ar_btn: 'POTEZI', ar_exec: 'EXEC',
    ar_none: 'nema poteza: prvo pokreni RECON, zatim SYNC za učitavanje KEV/EPSS', ar_loading: 'pregled baza se učitava...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demo program - bez skeniranja: stvori svoj program', pip_noprog: 'nema programa: stvori svoj u kartici Programi',
    pip_next: 'sljedeći korak:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  sr: {
    pl_title: 'Радни план', pl_empty: 'још нема плана: покрени RECON у картици горе, хипотезе падају овде (статуси се чувају)',
    pl_run: 'Покрени', pl_reflect: 'канаринач одреаговао',
    st_do: 'за спровођење', st_test: 'тестирано',
    st_signal: 'сигнал', st_valid: 'утврђено',
    st_void: 'ништа', atk_btn: 'ATTACK',
    atk_start: 'напад на површину: ендпоинтови, изложена документа, JWT, тајне...', atk_fail: 'напад немогућ: прво покрени RECON',
    atk_none: 'никакав сигнал', atk_findings: 'кандидати',
    atk_done: 'ATTACK: {n} кандидата P1/P2 убачено у findings с доказом', atk_empty: 'још нема напада: покрени RECON па ATTACK - кандидати с доказом req/res падају овде',
    navh: 'HUNT', h2hunt: 'HUNT - права површина и докази',
    h_ready: 'спремно', h_empty: 'нема познате површине: покрени RECON да мапираш странице, ендпоинтове API-ја, параметре, JS бандле и поддомене',
    h_fnd: 'Findings програма', h_nofnd: 'у овом програму нема findings',
    rc_btn: 'RECON', rc_start: 'recon површине у току: странице, JS бандле, ендпоинтови, параметри...',
    rc_done: 'површина мапирана: ендпоинтови, параметри и поддомене излистани у картици програма', rc_fail: 'recon није успео: хост недостижан или празан scope',
    rc_surface: 'површина:', snd_on: 'ЗВУК: ON',
    snd_off: 'ЗВУК: OFF', snd_ok: 'звучи интерфејса активни - библиотека: клик, картица, копирање, аларми',
    snd_stop: 'потпуно ућуткавање укључено: више никаквих C2FF звукова', amb_on: 'АМБИЈЕНТ: ON',
    amb_off: 'АМБИЈЕНТ: OFF', amb_ok: 'живи амбијент - нијанса глатко клизи кроз породице (зелена, плава, жута...)',
    amb_stop: 'амбијент замрзнут на првобитној зеленој', nt_on: 'ОБАВЕШТЕЊА: ON',
    nt_off: 'ОБАВЕШТЕЊА: OFF', nt_ok: 'обавештења прегледача омогућена - пип на P1 и P2',
    nt_denied: 'обавештења блокирана од прегледача: дозволи их у подешавањима сајта', term_denied: 'терминал одбијен или недоступан: тражи се localhost, или ОТВОРЕНА соба као админ',
    term_p: 'прави баш - историја стрелицама, Ctrl+C прекида, Ctrl+D затвара', term_restart: 'Ресетуј',
    navtrm: 'TERM', term_h2: 'Терминал - радна љуска, право у конзолу',
    fl_off: 'FLEET: ЗАУСТАВЉЕН', fl_paused: 'FLEET: НА ПАУЗИ',
    fl_active: 'FLEET: АКТИВАН ({n} циклуса)', fl_last: 'последњи циклус',
    fl_none: 'још никакав циклус', fl_info: 'интервал {i} мин, буџет {b} req/циклус',
    sub_ttl: 'command & control framework', navt: 'СЕСИЈА',
    tm_h2: 'Групне сесије - лов у дружини, чак и ван мреже', tm_p: 'Отвори дељену собу: твоја дружина види флот, findings и може вршити тријажу уживо. Посебно ћаскање сесије доле. Три нивоа приступа: LOCAL (соло), LAN преко ОТВОРИ НА МРЕЖУ и СВЕТ преко ОТВОРИ СВЕТУ - јавни тунел (cloudflared ако је инсталиран) чини позивни линк важећим из било које мреже, без директне изложености твоје машине. Све чува кључ собе - регенериши га да све избациш једним потезом.',
    tm_handle: 'Твој надимак (највише 16 знакова)', tm_save_h: 'Постави',
    tm_room_ph: 'име собе (нпр. c2ff-core)', tm_save: 'Примијени',
    tm_on: 'СОБА ОТВОРЕНА: {r} - {n} online', tm_off: 'TEAM РЕЖИМ ИСКЉУЧЕН - локална сесија соло',
    tm_room: 'Соба', tm_key: 'Кључ собе',
    tm_regen: 'Регенериши кључ', tm_regen_ok: 'нови кључ генерисан - стари линки мртви',
    tm_invite: 'Позивни линк (копирај свом тиму)', tm_copy: 'Копирај',
    tm_copied: 'копирано у оставу', tm_members: 'Чланови',
    tm_nobody: 'још никог - пошаљи линк тиму', tm_you: '(ти)',
    tm_here: 'присутан', tm_saved: 'надимак сачуван',
    tm_no_handle: 'празан надимак', tm_cfg_ok: 'соба ажурирана',
    tm_cfg_no: 'није успело', tm_live: 'ОТВОРИ НА МРЕЖУ',
    tm_shore: 'ВРАТИ СЕ НА ЛОКАЛНО', tm_need_on: 'прво укључи собу (ON)',
    tm_bind_lan: 'МРЕЖА: {a}', tm_bind_lo: 'LOCAL: само localhost',
    to_team_live: '[GO-LIVE] сервер поново покренут с мрежним приступом - LAN линк приказан, поновно спајање за 2 с', to_team_shore: 'сервер поново покренут локално (127.0.0.1)',
    tm_tun_open: 'ОТВОРИ СВЕТУ (тунел)', tm_tun_close: 'ЗАТВОРИ ТУНЕЛ',
    tm_tun_wait: 'јавни тунел се отвара (неколико секунди)…', tm_tun_on: 'СЕСИЈА ОТВОРЕНА СВЕТУ: {u} - позивни линк ради одасвуд, не треба иста мрежа',
    tm_tun_closed: 'тунел затворен - натраг на LAN/локално', tm_chat_empty: 'канал сесије отворен - чланови собе овде се међусобно читају',
    tm_chat_h2: 'Ћаскање сесије', tm_msg_ph: 'порука у сесију…',
    tm_admin: 'админ', tm_guest: 'гост',
    tm_kick: 'KICK', tm_kick_ok: 'члан избачен из собе (кликни поново за деблокаду)',
    tm_role_ok: 'улога ажурирана', tm_mic_on: 'УКЉУЧИ МИКРОФОН',
    tm_mic_off: 'ИСКЉУЧИ МИКРОФОН', tm_mic_denied: 'микрофон одбијен или недоступан: тражи се HTTPS (тунел СВЕТ или localhost) и микрофон требаш дозволити',
    navf: 'Флота', navfd: 'Findings',
    navp: 'Програми', navai: 'УИ',
    navc: 'Усклађивање', st_runs: 'Runови',
    st_beacons: 'Активни беаконови', st_sig: 'Сигнали',
    h2f: 'Флота - сви програми, агенти у трци пред свима', h2fd: 'База findings - трајно означавање тријаже',
    h2eng: 'Мотор флоте - локални циклуси без токена', h2prog: 'Програми - scope, тражени header, лансирање',
    h2new: 'Нови програм', h2ai: 'УИ агент - повезивање сто посто необавезно',
    h2c: 'Усклађивање - приватни канал', fl_start: 'Покрени',
    fl_pause: 'Пауза', fl_cycle: 'Циклус сад',
    f_add: 'Додај', f_none: 'још без сигнала',
    f_ph: 'ручно налаз: ендпоинт + доказ + бранљива озбиљност…', st_sig_off: 'сигнал',
    st_sig_an: 'анализа', st_sig_sub: 'предато',
    st_sig_dup: 'dup', st_sig_ref: 'одбијено',
    st_sig_cl: 'затворено', r_none: 'ниједан run није откривен',
    r_live: '{n} У ТРКУ', r_done: 'ГОТОВО',
    r_feed: '▽ ток ({n} догађај(а))', r_close: '△ преклопи',
    p_name_ph: 'Име програма (нпр. PayPal)', p_hdr_ph: 'тражени header истраживача (нпр. X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: домен1, домен2, …', p_save: 'Сачувај',
    p_local: 'модул(а), сто посто локално', ai_p: 'C2FF ради сто посто без УИ: режими су детерминистичке локалне пробе. Ова капија постоји само да прикључиш <b>твој</b> УИ (self-hosted или API) за анализу једног finding по потреби: тастер <span style="color:var(--green)">AI »</span> у FINDINGS, одговор се приказује у УСКЛАЂИВАЊУ. Никаки податак не излази с твоје машине без те поставке.',
    ai_off: 'искључено', ai_on: 'укључено',
    ai_st_off: 'УИ ИСКЉУЧЕН - оквир ради сто посто локално без њега', ai_st_ready: 'УИ СПОЈЕН: {p} · {m}',
    ai_st_inc: 'УИ УКЉУЧЕН АЛИ НЕПОТПУН: траже се baseURL и model', ai_url_ph: 'основни URL - нпр. http://localhost:11434 или https://api.МојУИ.tld/v1',
    ai_model_ph: 'model - нпр. llama3.1:8b', ai_key_ph: 'API кључ (остави празно за локалне сервере)',
    ai_save: 'Сачувај', ai_test: 'Испитај везу',
    ai_testing: 'испитивање у току…', ai_ok: 'OK - одговор: ',
    ai_fail: 'НЕУСПЕХ: ', ai_note: 'поставка чувана локално у data/ai.json - никад се не шаље никуда друго нег на ендпоинт који тамо наведеш',
    ch_ph: 'root@c2ff:~# порука агенту анализе…', ch_send: 'Пошаљи',
    ch_empty: 'Канал је отворен. Пиши овде, монитор ме пробуђава одмах.', ft: 'сто посто локално - детерминистичке пробе, без токена и спољних зависности - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE АКТИВАН: локални циклуси сваких 30 мин, 0 токена.', to_fl_pa: 'FLEET НА ПАУЗИ - настави кад хоћеш.',
    to_fl_cy: 'Тренутни циклус лансиран (буџет 60 req).', to_launch: '[GO] режим {m} (CWE {c}) на {p} - локални циклус лансиран',
    to_ai_ok: 'поставка сачувана', to_ai_no: 'чување није успело',
    to_ai_no_cfg: 'УИ није постављен - намести га у картици УИ', to_ai_head: 'УИ АНАЛИЗА',
    to_ai_bad: 'УИ АНАЛИЗА није успела', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'УИ',
    w_launch: '⚡ ЛАНСИРАЊЕ', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS i eksploiti na otkrivenoj površini', ar_sync: 'SYNC BAZA',
    ar_btn: 'POTEZI', ar_exec: 'EXEC',
    ar_none: 'nema poteza: prvo pokreni RECON, zatim SYNC za učitavanje KEV/EPSS', ar_loading: 'pregled baza se učitava...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demo program - bez skeniranja: napravi svoj program', pip_noprog: 'nema programa: napravi svoj u kartici Programi',
    pip_next: 'sledeći korak:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  lv: {
    pl_title: 'Darba plāns', pl_empty: 'plāna vēl nav: palaid RECON kartītē augstāk, hipotēzes šeit uzkritīs (statusi tiek saglabāti)',
    pl_run: 'Palaist', pl_reflect: 'canary atstarots',
    st_do: 'darāmais', st_test: 'pārbaudīts',
    st_signal: 'signāls', st_valid: 'derīgs',
    st_void: 'nekas', atk_btn: 'ATTACK',
    atk_start: 'uzbrukums virsmai: endpointi, atklātā dokumentācija, JWT, noslēpumi...', atk_fail: 'uzbrukums nav iespējams: vispirms palaid RECON',
    atk_none: 'nav signāla', atk_findings: 'kandidāti',
    atk_done: 'ATTACK: {n} P1/P2 kandidāti iesprausti findings ar pierādījumiem', atk_empty: 'uzbrukuma vēl nav: palaid RECON, tad ATTACK - kandidāti ar req/res pierādījumu uzkritīs šeit',
    navh: 'HUNT', h2hunt: 'HUNT - patiesā virsma un pierādījumi',
    h_ready: 'gatavs', h_empty: 'nav zināmas virsmas: palaid RECON, lai uzmērētu lapas, API endpointus, parametrus, JS pakas un apakšdomēnus',
    h_fnd: 'Programmas findings', h_nofnd: 'šajā programmā nav findings',
    rc_btn: 'RECON', rc_start: 'virsmas recon norisinās: lapas, JS pakas, endpointi, parametri...',
    rc_done: 'virsma uzmērīta: endpointi, parametri un apakšdomēni uzskaitīti programmas kartītē', rc_fail: 'recon neizdevās: host nesasniedzams vai tukšs scope',
    rc_surface: 'virsmas:', snd_on: 'SKAŅA: ON',
    snd_off: 'SKAŅA: OFF', snd_ok: 'saskarnes skaņas aktīvi - bibliotēka: klik, cilne, kopēšana, trauksmes',
    snd_stop: 'pilnīga izslēgšana ieslēgta: vairs nekādu C2FF skaņu', amb_on: 'AMBIENCE: ON',
    amb_off: 'AMBIENCE: OFF', amb_ok: 'dzīvā gaisotne - tonis gludi slīd caur saimēm (zaļa, zila, dzeltena...)',
    amb_stop: 'gaisotne sastingusi uz sākotnējās zaļās', nt_on: 'PAZIŅOJUMI: ON',
    nt_off: 'PAZIŅOJUMI: OFF', nt_ok: 'pārlūka paziņojumi ieslēgti - pip uz P1 un P2',
    nt_denied: 'paziņojumus bloķē pārluks: atļauj tos vietnes iestatījumos', term_denied: 'termināls atteikts vai nav pieejams: vajag localhost, vai ATVĒRTU istabu kā adminam',
    term_p: 'īsts bash - vēsture ar bultām, Ctrl+C pārtrauc, Ctrl+D aizver', term_restart: 'Atstatīt',
    navtrm: 'TERM', term_h2: 'Termināls - darba čaula, taisni konsolē',
    fl_off: 'FLEET: APSTĀDINĀTS', fl_paused: 'FLEET: PAUZĒ',
    fl_active: 'FLEET: AKTĪVS ({n} cikli)', fl_last: 'pēdējais cikls',
    fl_none: 'vēl nekāds cikls', fl_info: 'intervāls {i} min, budžets {b} req/cikls',
    sub_ttl: 'command & control framework', navt: 'SESIJA',
    tm_h2: 'Grupu sesijas - medības draugos, pat ārpus tīkla', tm_p: 'Atver koplietošanas istabu: tava komanda saskata floti, findings un var kārtot dzīvē. Atsevišķa sesijas tērzētava zemāk. Trīs pieejas līmeņi: LOCAL (solo), LAN caur ATVĒRT TĪKLAM un PASAULE caur ATVĒRT PASAULEI - publiskais tunelis (cloudflared, ja ieinstalēts) padara ielūguma saiti derīgu no jebkura tīkla, bez tava aparāta tiešas izcelšanas. Visu apsargā istabas atslēga - pārģenerē to, lai vienā kustībā izmestu visus.',
    tm_handle: 'Tavs segvārds (nekas vairāk par 16 rakstzīmēm)', tm_save_h: 'Uzstādīt',
    tm_room_ph: 'istabas nosaukums (piem., c2ff-core)', tm_save: 'Pielietot',
    tm_on: 'ISTABA ATVĒRTA: {r} - {n} online', tm_off: 'TEAM REŽĪMS IZSLĒGTS - lokālā sesija solo',
    tm_room: 'Istaba', tm_key: 'Istabas atslēga',
    tm_regen: 'Pārģenerēt atslēgu', tm_regen_ok: 'jauna atslēga izveidota - vecās saites ir mirušas',
    tm_invite: 'Ielūguma saite (nokopē savai komandai)', tm_copy: 'Kopēt',
    tm_copied: 'nokopēts starpliktuvē', tm_members: 'Biedri',
    tm_nobody: 'vēl neviens - sūti saiti komandai', tm_you: '(tu)',
    tm_here: 'klāt', tm_saved: 'segvārds saglabāts',
    tm_no_handle: 'tukšs segvārds', tm_cfg_ok: 'istaba atjaunināta',
    tm_cfg_no: 'neizdevās', tm_live: 'ATVĒRT TĪKLAM',
    tm_shore: 'ATPAKAL UZ LOKĀLO', tm_need_on: 'vispirms ieslēdz istabu (ON)',
    tm_bind_lan: 'TĪKLS: {a}', tm_bind_lo: 'LOCAL: tikai localhost',
    to_team_live: '[GO-LIVE] serveris pārstartēts ar tīkla pieeju - LAN saite parādīta, atkārtota savienošanās 2 s laikā', to_team_shore: 'serveris pārstartēts lokāli (127.0.0.1)',
    tm_tun_open: 'ATVĒRT PASAULEI (tunelis)', tm_tun_close: 'AIZVĒRT TUNELI',
    tm_tun_wait: 'publiskais tunelis atveras (dažas sekundes)…', tm_tun_on: 'SESIJA ATVĒRTA PASAULEI: {u} - ielūguma saite darbojas no visur, nav vajadzīgs viens tīkls',
    tm_tun_closed: 'tunelis aizvērts - atpakaļ uz LAN/lokālo', tm_chat_empty: 'sesijas kanāls atvērts - istabas biedri šeit lasa viens otru',
    tm_chat_h2: 'Sesijas tērzētava', tm_msg_ph: 'ziņa sesijā…',
    tm_admin: 'admin', tm_guest: 'viesis',
    tm_kick: 'KICK', tm_kick_ok: 'biedrs izmests no istabas (klikšķini vēlreiz, lai atbloķētu)',
    tm_role_ok: 'loma atjaunināta', tm_mic_on: 'IESLĒGT MIKROFONU',
    tm_mic_off: 'IZSLĒGT MIKROFONU', tm_mic_denied: 'mikrofons atteikts vai nav pieejams: vajag HTTPS (PASAULES tuneli vai localhost) un jāatļauj mikrofons',
    navf: 'Flote', navfd: 'Findings',
    navp: 'Programmas', navai: 'MI',
    navc: 'Koordinācija', st_runs: 'Runi',
    st_beacons: 'Aktīvie beaconi', st_sig: 'Signāli',
    h2f: 'Flote - visas programmas, skrienošie aģenti priekšgalā', h2fd: 'Findings pamats - pastāvīga triāžas zīmēšana',
    h2eng: 'Flotes dzinējs - lokāli cikli bez marķieriem', h2prog: 'Programmas - scope, vajadzīgā galvene, palaišana',
    h2new: 'Jauna programma', h2ai: 'MI aģents - pieslēgums pilnībā neobligāts',
    h2c: 'Koordinācija - privāts kanāls', fl_start: 'Sākt',
    fl_pause: 'Pauze', fl_cycle: 'Cikls tagad',
    f_add: 'Pievienot', f_none: 'vēl nav signāla',
    f_ph: 'manuāls findings: endpoints + pierādījums + aizsargājama nopietnība…', st_sig_off: 'signāls',
    st_sig_an: 'analīze', st_sig_sub: 'iesniegts',
    st_sig_dup: 'dub', st_sig_ref: 'noraidīts',
    st_sig_cl: 'aizvērts', r_none: 'nav atrasts neviens run',
    r_live: '{n} SKRIEN', r_done: 'PABEIGTS',
    r_feed: '▽ plūsma ({n} ev)', r_close: '△ salocīt',
    p_name_ph: 'Programmas nosaukums (piem., PayPal)', p_hdr_ph: 'vajadzīgā pētnieka galvene (piem., X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domēns1, domēns2, …', p_save: 'Saglabāt',
    p_local: 'moduļi, pilnībā lokāli', ai_p: 'C2FF darbojas pilnībā bez MI: režīmi ir deterministiskas lokālas zondas. Šie vārti ir tikai tāpēc, lai pieslēgtu <b>tavu</b> MI (self-hosted vai API) viena finding punktveida analīzei: poga <span style="color:var(--green)">IA »</span> FINDINGS sadaļā, atbilde parādās Koordinācijā. Nekādi dati neiziet no tava aparāta bez šīs iestatības.',
    ai_off: 'izslēgts', ai_on: 'ieslēgts',
    ai_st_off: 'MI IZSLĒGTS - struktūra darbojas pilnībā lokāli bez tā', ai_st_ready: 'MI PIEVĒRSTS: {p} · {m}',
    ai_st_inc: 'MI IESLĒGTS, BET NEPILNĪGS: vajag baseURL un model', ai_url_ph: 'bāzes URL - piem., http://localhost:11434 vai https://api.ManaMI.tld/v1',
    ai_model_ph: 'model - piem., llama3.1:8b', ai_key_ph: 'API atslēga (atstāj tukšu lokālajiem serveriem)',
    ai_save: 'Saglabāt', ai_test: 'Pārbaudīt sakari',
    ai_testing: 'pārbaude norisinās…', ai_ok: 'Labi - atbilde: ',
    ai_fail: 'NEIZDEVĀS: ', ai_note: 'iestatība saglabāta lokāli failā data/ai.json - nekad netiek sūtīta nekur citur, kā uz endpointu, ko tur ieliks',
    ch_ph: 'root@c2ff:~# ziņa analīzes aģentam…', ch_send: 'Sūtīt',
    ch_empty: 'Kanāls atvērts. Raksti šeit, monitors mani pamodina acumirklī.', ft: 'pilnībā lokāli - deterministiskas zondas, bez marķieriem un ārējām atkarībām - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE AKTĪVS: lokāli cikli ik pēc 30 min, 0 marķieru.', to_fl_pa: 'FLEET PAUZĒ - turpini, kad gribi.',
    to_fl_cy: 'Tūlītējs cikls palaists (60 req budžets).', to_launch: '[GO] režīms {m} (CWE {c}) uz {p} - lokāls cikls palaists',
    to_ai_ok: 'iestatība saglabāta', to_ai_no: 'saglabāšana neizdevās',
    to_ai_no_cfg: 'MI nav iestatīts - piekārto to MI cilnē', to_ai_head: 'MI ANALĪZE',
    to_ai_bad: 'MI ANALĪZE neizdevās', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'MI',
    w_launch: '⚡ PALAIŠANA', navar: 'Arsenāls',
    ar_h2: 'ARSENAL - CVE, EPSS un eksploiti konstatētajā virsmā', ar_sync: 'SYNC BĀZES',
    ar_btn: 'GĀJIENI', ar_exec: 'EXEC',
    ar_none: 'nav gājienu: vispirms palaid RECON, tad SYNC, lai ielādētu KEV/EPSS', ar_loading: 'bāzu kopsavilkums tiek ielādēts...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demo programma - bez skenēšanas: izveido savu programmu', pip_noprog: 'nav programmu: izveido savu sadaļā Programmas',
    pip_next: 'nākamais solis:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  et: {
    pl_title: 'Tööplaan', pl_empty: 'plaani veel pole: käivita RECON ülaloleval kaardil, hüpoteesid langevad siia (olekusid hoitakse alles)',
    pl_run: 'Käivita', pl_reflect: 'kanaripeegeldus tehtud',
    st_do: 'teha', st_test: 'katsetatud',
    st_signal: 'signaal', st_valid: 'kehtiv',
    st_void: 'midagi ei ole', atk_btn: 'ATTACK',
    atk_start: 'rünnak pinnale: otspunktid, paljastatud dokid, JWT, saladused...', atk_fail: 'rünnak võimatu: käivita kõigepealt RECON',
    atk_none: 'signaali pole', atk_findings: 'kandidaadid',
    atk_done: 'ATTACK: {n} P1/P2 kandidaati süstitud findings-itesse tõendiga', atk_empty: 'rünnakut veel pole: käivita RECON, siis ATTACK - tõendiga req/res kandidaadid langevad siia',
    navh: 'HUNT', h2hunt: 'HUNT - tõeline pind ja tõendid',
    h_ready: 'valmis', h_empty: 'tuntud pinda pole: käivita RECON, et kaardistada lehekülgi, API otspunkte, parameetreid, JS-kogumeid ja alamdomääne',
    h_fnd: 'Programmi findings-id', h_nofnd: 'selles programmis findings-eid pole',
    rc_btn: 'RECON', rc_start: 'pinna recon käib: leheküljed, JS-kogumid, otspunktid, parameetrid...',
    rc_done: 'pind kaardistatud: otspunktid, parameetrid ja alamdomäänid loetletud programmi kaardil', rc_fail: 'recon ebaõnnestus: host kättesaamatu või scope tühi',
    rc_surface: 'pind:', snd_on: 'HELI: SEES',
    snd_off: 'HELI: VÄLJAS', snd_ok: 'liidese helid aktiivsed - kogu: klõps, kaart, kopeerimine, häired',
    snd_stop: 'täielik vaigistus sisse lülitatud: rohkem C2FF hääli ei ole', amb_on: 'KAUNISUSE: SEES',
    amb_off: 'KAAUNUSE: VÄLJAS', amb_ok: 'elav kaunisus - toon libiseb pehme perekondade vahel (roheline, sinine, kollane...)',
    amb_stop: 'kaunisus jäätunud algsele rohelisele', nt_on: 'TEATED: SEES',
    nt_off: 'TEATED: VÄLJAS', nt_ok: 'brauseri teated sisse lülitatud - piiks P1 ja P2 peale',
    nt_denied: 'teated on brauseri poolt blokeeritud: luba need saidi seadetes', term_denied: 'terminal keeldus või pole saadaval: vajalik localhost, või AVATUD tuba adminina',
    term_p: 'ehtne bash - ajalugu nooltega, Ctrl+C katkestab, Ctrl+D sulgeb', term_restart: 'Taastada',
    navtrm: 'TERM', term_h2: 'Terminal - töökest, otse konsoolis',
    fl_off: 'FLEET: SEISKUNUD', fl_paused: 'FLEET: PAUSIL',
    fl_active: 'FLEET: AKTIIVNE ({n} tsüklit)', fl_last: 'viimane tsükkel',
    fl_none: 'tsüklit veel ei ole', fl_info: 'intervall {i} min, eelarve {b} req/tsükkel',
    sub_ttl: 'command & control framework', navt: 'SESSIOON',
    tm_h2: 'Rühma sessioonid - jaht seltskonnas, isegi võrgust väljas', tm_p: 'Ava jagatud tuba: sinu seltskond näeb laevastikku, findings-eid ja saab sorteerida otse. Eraldi sessioonivestlus allpool. Kolm ligipääsu taset: LOCAL (solo), LAN üle AVA VÕRGULE ja MAAILM üle AVA MAAILMALE - avalik tunnel (kui cloudflared on paigaldatud) teeb kutse lingi kehtivaks igast võrgust, ilma sinu masinat otse paljastamata. Kõike valvab toa võti - taasgenereri see, et ühe liigutusega kõik välja visata.',
    tm_handle: 'Sinu hüüdnimi (kõige rohkem 16 tähemärki)', tm_save_h: 'Määrata',
    tm_room_ph: 'toa nimi (nt c2ff-core)', tm_save: 'Rakenda',
    tm_on: 'TOA AVATUD: {r} - {n} online', tm_off: 'TEAM REŽIIM VÄLJAS - kohalik solo sessioon',
    tm_room: 'Tuba', tm_key: 'Toa võti',
    tm_regen: 'Taasgenereri võti', tm_regen_ok: 'uus võti tehtud - vanad lingid on surnud',
    tm_invite: 'Kutse link (kopeeri oma tiimile)', tm_copy: 'Kopeeri',
    tm_copied: 'kopeeritud lõikepuhvrisse', tm_members: 'Liikmed',
    tm_nobody: 'keegi veel ei ole - saada link tiimile', tm_you: '(sina)',
    tm_here: 'kohal', tm_saved: 'hüüdnimi salvestatud',
    tm_no_handle: 'tühi hüüdnimi', tm_cfg_ok: 'tuba uuendatud',
    tm_cfg_no: 'ebaõnnestus', tm_live: 'AVA VÕRGULE',
    tm_shore: 'TAGASI LOKAALSE JUURDE', tm_need_on: 'lülita tuba kõigepealt sisse (ON)',
    tm_bind_lan: 'VÕRK: {a}', tm_bind_lo: 'LOCAL: ainult localhost',
    to_team_live: '[GO-LIVE] server taaskäivitatud võrgupääsuga - LAN link nähtaval, uuesti ühendamine 2 s jooksul', to_team_shore: 'server taaskäivitatud lokaalselt (127.0.0.1)',
    tm_tun_open: 'AVA MAAILMALE (tunnel)', tm_tun_close: 'SULGE TUNNEL',
    tm_tun_wait: 'avalik tunnel avaneb (mõned sekundid)…', tm_tun_on: 'SESSIOON AVATUD MAAILMALE: {u} - kutse link töötab kõikjalt, ühist võrku ei vaja',
    tm_tun_closed: 'tunnel suletud - tagasi LAN/lokaalse juurde', tm_chat_empty: 'sessiooni kanal avatud - toa liikmed loevad teineteist siin',
    tm_chat_h2: 'Sessioonivestlus', tm_msg_ph: 'sõnum sessiooni…',
    tm_admin: 'admin', tm_guest: 'külaline',
    tm_kick: 'KICK', tm_kick_ok: 'liige välja visatud toast (klõpsi uuesti, et blokist lahti teha)',
    tm_role_ok: 'roll uuendatud', tm_mic_on: 'SISSE LÜLITA MIKROFON',
    tm_mic_off: 'VÄLJA LÜLITA MIKROFON', tm_mic_denied: 'mikrofon keeldus või pole saadaval: vajalik on HTTPS (MAAILMA tunnel või localhost) ja mikrofon tuleb lubada',
    navf: 'Laevastik', navfd: 'Findings',
    navp: 'Programmid', navai: 'AI',
    navc: 'Koordinatsioon', st_runs: 'Runid',
    st_beacons: 'Aktiivsed beaconid', st_sig: 'Signaalid',
    h2f: 'Laevastik - kõik programmid, jooksvad agendid esirinnas', h2fd: 'Findings baas - püsiv triage märgendus',
    h2eng: 'Laevastiku mootor - lokaalsed tsüklid ilma tokeniteta', h2prog: 'Programmid - scope, tarvilik päis, käivitamine',
    h2new: 'Uus programm', h2ai: 'AI agent - sidumus täiesti valikuline',
    h2c: 'Koordinatsioon - privaatne kanal', fl_start: 'Alusta',
    fl_pause: 'Paus', fl_cycle: 'Tsükkel kohe',
    f_add: 'Lisa', f_none: 'signaali veel ei ole',
    f_ph: 'käsitsi finding: otspunkt + tõend + kaitstav tõsidus…', st_sig_off: 'signaal',
    st_sig_an: 'analüüs', st_sig_sub: 'esitatud',
    st_sig_dup: 'dup', st_sig_ref: 'tagasi lükatud',
    st_sig_cl: 'suletud', r_none: 'ükstegi run-ei pole märgatud',
    r_live: '{n} JOOKSEB', r_done: 'VALMIS',
    r_feed: '▽ voog ({n} ev)', r_close: '△ kokku sulgeda',
    p_name_ph: 'Programmi nimi (nt PayPal)', p_hdr_ph: 'tarvilik uurija päis (nt X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domään1, domään2, …', p_save: 'Salvesta',
    p_local: 'moodulit, täiesti lokaalne', ai_p: 'C2FF töötab täiesti ilma AI-ta: režiimid on deterministlikud lokaalsed sondid. See värav on ainult selleks, et ühendada <b>sinu</b> AI (self-hosted või API) ühe finding punktilise analüüsiga: nupp <span style="color:var(--green)">IA »</span> FINDINGS-ites, vastus esitatakse Koordinatsioonis. Ilma selle seadeta ei välju sinu masinast ükski andmepükk.',
    ai_off: 'välja lülitatud', ai_on: 'sisse lülitatud',
    ai_st_off: 'AI VÄLJAS - raamistik töötab täiesti lokaalselt ilma selleta', ai_st_ready: 'AI ÜHENDATUD: {p} · {m}',
    ai_st_inc: 'AI SEES, KUID POLE TÄIELIK: vajalikud on baseURL ja model', ai_url_ph: 'baas URL - nt http://localhost:11434 või https://api.MinuAI.tld/v1',
    ai_model_ph: 'model - nt llama3.1:8b', ai_key_ph: 'API võti (jäta tühjaks lokaalsete serverite jaoks)',
    ai_save: 'Salvesta', ai_test: 'Katseta ühendust',
    ai_testing: 'katsetamine käib…', ai_ok: 'OK - vastus: ',
    ai_fail: 'ebaõnnestus: ', ai_note: 'seadistus hoitakse lokaalselt data/ai.json sees - kunagi ei saadeta kuhugi mujale kui endpointile, mille sinna paned',
    ch_ph: 'root@c2ff:~# sõnum analüüsi agendile…', ch_send: 'Saada',
    ch_empty: 'Kanal on avatud. Kirjuta siia, monitor äratab mind kohe.', ft: 'täiesti lokaalne - deterministlikud sondid, ilma tokeniteta ja väliste sõltuvusteta - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE AKTIIVNE: lokaalsed tsüklid iga 30 min järel, 0 tokenit.', to_fl_pa: 'FLEET PAUSIL - järga, kui sulle sobib.',
    to_fl_cy: 'Kohene tsükkel käivitatud (60 req eelarve).', to_launch: '[GO] režiim {m} (CWE {c}) peal {p} - lokaalne tsükkel käivitatud',
    to_ai_ok: 'seadistus salvestatud', to_ai_no: 'salvestamine ebaõnnestus',
    to_ai_no_cfg: 'AI ei ole seadistatud - seadista see AI kaardil', to_ai_head: 'AI ANALÜÜS',
    to_ai_bad: 'AI ANALÜÜS ebaõnnestus', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ KÄIVITUS', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS ja exploitid tuvastatud pinnal', ar_sync: 'SYNC ANDMEBAASID',
    ar_btn: 'KÄIGUD', ar_exec: 'EXEC',
    ar_none: 'käike pole: käivita esmalt RECON, seejärel SYNC KEV/EPSS laadimiseks', ar_loading: 'andmebaaside kokkuvõte laaditakse...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demoprogram - skannimine puudub: loo oma programm', pip_noprog: 'programmi pole: loo oma Programmide vahekaardil',
    pip_next: 'järgmine etapp:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  th: {
    pl_title: 'แผนงาน', pl_empty: 'ยังไม่มีแผน: รัน RECON ในการ์ดด้านบน สมมติฐานจะตกลงมาที่นี่ (สถานะถูกเก็บไว้)',
    pl_run: 'รัน', pl_reflect: 'canary สะท้อนกลับแล้ว',
    st_do: 'ต้องทำ', st_test: 'ทดสอบแล้ว',
    st_signal: 'สัญญาณ', st_valid: 'ตรวจสอบแล้ว',
    st_void: 'ว่างเปล่า', atk_btn: 'ATTACK',
    atk_start: 'โจมตีพื้นผิว: เอนด์พอยต์ เอกสารที่เปิดเผย JWT ความลับ...', atk_fail: 'โจมตีไม่ได้: รัน RECON ก่อน',
    atk_none: 'ไม่มีสัญญาณ', atk_findings: 'ผู้เข้ารอบ',
    atk_done: 'ATTACK: ฉีด {n} ผู้เข้ารอบ P1/P2 เข้า findings พร้อมหลักฐาน', atk_empty: 'ยังไม่มีการโจมตี: รัน RECON แล้ว ATTACK - ผู้เข้ารอบที่มีหลักฐาน req/res จะตกมาที่นี่',
    navh: 'HUNT', h2hunt: 'HUNT - พื้นผิวจริงและหลักฐาน',
    h_ready: 'พร้อม', h_empty: 'ยังไม่มีพื้นผิวที่รู้จัก: รัน RECON เพื่อแม็ปหน้าเว็บ เอนด์พอยต์ API พารามิเตอร์ บันเดิล JS และซับโดเมน',
    h_fnd: 'ผลของโปรแกรม', h_nofnd: 'ไม่มีผลของโปรแกรมนี้',
    rc_btn: 'RECON', rc_start: 'ค้นพื้นผิวกำลังทำงาน: หน้าเว็บ บันเดิล JS เอนด์พอยต์ พารามิเตอร์...',
    rc_done: 'พื้นผิวถูกแม็ปแล้ว: เอนด์พอยต์ พารามิเตอร์ และซับโดเมนถูกแสดงในการ์ดโปรแกรม', rc_fail: 'ค้นล้มเหลว: โฮสต์เข้าไม่ถึงหรือขอบเขตว่าง',
    rc_surface: 'พื้นผิว:', snd_on: 'เสียง : เปิด',
    snd_off: 'เสียง : ปิด', snd_ok: 'เสียงของส่วนติดต่อทำงาน - ชุด: คลิก แท็บ คัดลอก แจ้งเตือน',
    snd_stop: 'ปิดเสียงทั้งหมดแล้ว: ไม่มีเสียง C2FF อีกต่อไป', amb_on: 'บรรยากาศ : เปิด',
    amb_off: 'บรรยากาศ : ปิด', amb_ok: 'บรรยากาศมีชีวิต - เฉดสีไหลผ่านตระกูลอย่างนุ่มนวล (เขียว น้ำเงิน เหลือง...)',
    amb_stop: 'บรรยากาศแข็งค้างบนสีเขียวดั้งเดิม', nt_on: 'แจ้งเตือน : เปิด',
    nt_off: 'แจ้งเตือน : ปิด', nt_ok: 'เปิดการแจ้งเตือนของเบราว์เซอร์แล้ว - บีบเมื่อ P1 และ P2',
    nt_denied: 'เบราว์เซอร์บล็อกการแจ้งเตือน: อนุญาตในการตั้งค่าเว็บไซต์', term_denied: 'เทอร์มินัลถูกปฏิเสธหรือใช้ไม่ได้: ต้องใช้ localhost หรือห้องเปิดอยู่ในฐานะแอดมิน',
    term_p: 'แบชจริง - ประวัติด้วยลูกศร Ctrl+C ขัดจังหวะ Ctrl+D ปิด', term_restart: 'รีเซ็ต',
    navtrm: 'TERM', term_h2: 'เทอร์มินัล - เชลล์ทำงาน ตรงในคอนโซล',
    fl_off: 'FLEET: หยุดแล้ว', fl_paused: 'FLEET: พัก',
    fl_active: 'FLEET: ทำงาน ({n} รอบ)', fl_last: 'รอบล่าสุด',
    fl_none: 'ยังไม่มีรอบใด', fl_info: 'ระยะห่าง {i} นาที วงเงิน {b} req/รอบ',
    sub_ttl: 'command & control framework', navt: 'เซสชัน',
    tm_h2: 'เซสชันกลุ่ม - ล่าพร้อมกัน แม้ออกไปนอกเครือข่าย', tm_p: 'เปิดห้องใช้ร่วมกัน: กลุ่มของคุณมองเห็นฟลีต ผลลัพธ์ และคัดกรองได้สดๆ แชทเฉพาะเซสชันอยู่ด้านล่าง สามระดับการเข้าถึง: LOCAL (เดี่ยว) LAN ผ่านเปิดสู่เครือข่าย และโลกผ่านเปิดสู่โลก - อุโมงค์สาธารณะ (cloudflared ถ้าติดตั้งไว้) ทำให้ลิงก์เชิญใช้ได้จากทุกเครือข่าย โดยไม่ต้องเปิดเครื่องของคุณออกโดยตรง ทุกอย่างถูกยึดด้วยกุญแจห้อง - สร้างใหม่เพื่อเตะทุกคนออกในครั้งเดียว',
    tm_handle: 'ชื่อเล่นของคุณ (ไม่เกิน 16 ตัวอักษร)', tm_save_h: 'ตั้ง',
    tm_room_ph: 'ชื่อห้อง (เช่น c2ff-core)', tm_save: 'นำไปใช้',
    tm_on: 'ห้องเปิด: {r} - {n} ออนไลน์', tm_off: 'โหมดทีมปิดอยู่ - เซสชันเดี่ยวในเครื่อง',
    tm_room: 'ห้อง', tm_key: 'กุญแจห้อง',
    tm_regen: 'สร้างกุญแจใหม่', tm_regen_ok: 'กุญแจใหม่ถูกสร้าง - ลิงก์เก่าตายหมด',
    tm_invite: 'ลิงก์เชิญ (ก๊อปไปให้ทีมของคุณ)', tm_copy: 'คัดลอก',
    tm_copied: 'คัดลอกไปยังคลิปบอร์ดแล้ว', tm_members: 'สมาชิก',
    tm_nobody: 'ยังไม่มีใคร - ส่งลิงก์ให้ทีมของคุณ', tm_you: '(คุณ)',
    tm_here: 'อยู่ที่นี่', tm_saved: 'บันทึกชื่อเล่นแล้ว',
    tm_no_handle: 'ชื่อเล่นว่าง', tm_cfg_ok: 'อัปเดตห้องแล้ว',
    tm_cfg_no: 'ล้มเหลว', tm_live: 'เปิดสู่เครือข่าย',
    tm_shore: 'กลับสู่โหมดเครื่องตน', tm_need_on: 'เปิดห้องก่อน (เปิด)',
    tm_bind_lan: 'เครือข่าย : {a}', tm_bind_lo: 'LOCAL: localhost เท่านั้น',
    to_team_live: '[GO-LIVE] เซิร์ฟเวอร์รีสตาร์ทใหม่พร้อมการเข้าถึงเครือข่าย - แสดงลิงก์ LAN เชื่อมใหม่ใน 2 วินาที', to_team_shore: 'เซิร์ฟเวอร์รีสตาร์ทใหม่ในเครื่อง (127.0.0.1)',
    tm_tun_open: 'เปิดสู่โลก (อุโมงค์)', tm_tun_close: 'ปิดอุโมงค์',
    tm_tun_wait: 'กำลังเปิดอุโมงค์สาธารณะ (ไม่กี่วินาที)…', tm_tun_on: 'เซสชันเปิดสู่โลก: {u} - ลิงก์เชิญใช้ได้ทุกที่ ไม่ต้องอยู่เครือข่ายเดียวกัน',
    tm_tun_closed: 'ปิดอุโมงค์แล้ว - กลับสู่ LAN/ในเครื่อง', tm_chat_empty: 'ช่องทางเซสชันเปิดอยู่ - สมาชิกห้องอ่านกันเองที่นี่',
    tm_chat_h2: 'แชทเซสชัน', tm_msg_ph: 'ข้อความถึงเซสชัน…',
    tm_admin: 'แอดมิน', tm_guest: 'แขก',
    tm_kick: 'KICK', tm_kick_ok: 'เตะสมาชิกออกจากห้องแล้ว (กดอีกครั้งเพื่อปลดล็อก)',
    tm_role_ok: 'อัปเดตบทบาทแล้ว', tm_mic_on: 'เปิดไมโครโฟน',
    tm_mic_off: 'ปิดไมโครโฟน', tm_mic_denied: 'ไมโครโฟนถูกปฏิเสธหรือใช้ไม่ได้: จำเป็นต้องมี HTTPS (อุโมงค์โลกหรือ localhost) และต้องอนุญาตไมโครโฟน',
    navf: 'ฟลีต', navfd: 'ผลงาน',
    navp: 'โปรแกรม', navai: 'AI',
    navc: 'ประสานงาน', st_runs: 'รัน',
    st_beacons: 'บีคอนที่ทำงาน', st_sig: 'สัญญาณ',
    h2f: 'ฟลีต - ทุกโปรแกรม ตัวแทนที่กำลังวิ่งขึ้นก่อน', h2fd: 'ฐานผลงาน - ติดแท็กคัดกรองแบบคงอยู่',
    h2eng: 'เครื่องยนต์ฟลีต - รอบในเครื่อง ไม่ใช้โทเคน', h2prog: 'โปรแกรม - ขอบเขต ส่วนหัวที่ต้องมี การยิงออก',
    h2new: 'โปรแกรมใหม่', h2ai: 'ตัวแทน AI - ผนวกเป็นตัวเลือกทั้งหมด',
    h2c: 'ประสานงาน - ช่องทางส่วนตัว', fl_start: 'เริ่ม',
    fl_pause: 'พัก', fl_cycle: 'รอบเดี๋ยวนี้',
    f_add: 'เพิ่ม', f_none: 'ยังไม่มีสัญญาณ',
    f_ph: 'ผลงานเขียนมือ: เอนด์พอยต์ + หลักฐาน + ความรุนแรงที่ป้องกันได้…', st_sig_off: 'สัญญาณ',
    st_sig_an: 'วิเคราะห์', st_sig_sub: 'ส่งแล้ว',
    st_sig_dup: 'ซ้ำ', st_sig_ref: 'ถูกปฏิเสธ',
    st_sig_cl: 'ปิดแล้ว', r_none: 'ไม่พบรันใด',
    r_live: '{n} กำลังวิ่ง', r_done: 'เสร็จสิ้น',
    r_feed: '▽ กระแส ({n} เหตุการณ์)', r_close: '△ พับเก็บ',
    p_name_ph: 'ชื่อโปรแกรม (เช่น PayPal)', p_hdr_ph: 'ส่วนหัวที่นักวิจัยต้องมี (เช่น X-Bug-Bounty: xxx)',
    p_scope_ph: 'ขอบเขต : โดเมน1, โดเมน2, …', p_save: 'บันทึก',
    p_local: 'โมดูล ทำงานในเครื่องทั้งหมด', ai_p: 'C2FF ทำงานได้เต็มรูปแบบโดยไม่มี AI: โหมดต่างๆ เป็นโพรบดีเทอร์มินิสติกในเครื่อง ประตูนี้มีไว้เท่านั้นเพื่อเสียบ <b>AI ของคุณ</b> (self-hosted หรือ API) เข้ามาวิเคราะห์ผลรายกรณี: ปุ่ม <span style="color:var(--green)">IA »</span> ใน FINDINGS คำตอบแสดงในการประสานงาน ข้อมูลไม่หลุดออกจากเครื่องของคุณถ้าไม่ตั้งค่านี้',
    ai_off: 'ปิดอยู่', ai_on: 'เปิดอยู่',
    ai_st_off: 'AI ปิดอยู่ - เฟรมเวิร์กทำงานในเครื่องเต็มร้อยโดยไม่ต้องมีมัน', ai_st_ready: 'AI เชื่อมต่อแล้ว: {p} · {m}',
    ai_st_inc: 'AI เปิดอยู่แต่ไม่ครบ: ต้องมี baseURL และ model', ai_url_ph: 'URL พื้นฐาน - เช่น http://localhost:11434 หรือ https://api.AIKhongKhom.tld/v1',
    ai_model_ph: 'โมเดล - เช่น llama3.1:8b', ai_key_ph: 'กุญแจ API (ทิ้งว่างไว้สำหรับเซิร์ฟเวอร์ในเครื่อง)',
    ai_save: 'บันทึก', ai_test: 'ทดสอบการเชื่อมต่อ',
    ai_testing: 'กำลังทดสอบ…', ai_ok: 'โอเค - คำตอบ: ',
    ai_fail: 'ล้มเหลว: ', ai_note: 'ตั้งค่าถูกเก็บในเครื่องที่ data/ai.json - ไม่เคยส่งไปที่อื่นนอกจากเอนด์พอยต์ที่คุณใส่ไว้',
    ch_ph: 'root@c2ff:~# ข้อความถึงตัวแทนวิเคราะห์…', ch_send: 'ส่ง',
    ch_empty: 'ช่องทางเปิดอยู่ พิมพ์ที่นี่ มอนิเตอร์ปลุกฉันทันที', ft: 'ทำงานในเครื่องทั้งหมด - โพรบดีเทอร์มินิสติก ไร้โทเคนและการพึ่งพาภายนอก - unrestricted · undetected · unstoppable',
    to_fl_on: 'โหมด FLEET ทำงาน: รอบในเครื่องทุกครึ่งชั่วโมง โทเคนเป็นศูนย์', to_fl_pa: 'FLEET กำลังพัก - กลับมาเมื่อไหร่ก็ได้',
    to_fl_cy: 'สั่งรอบทันทีแล้ว (วงเงิน 60 คำขอ)', to_launch: '[GO] โหมด {m} (CWE {c}) บน {p} - ยิงรอบในเครื่องออกไปแล้ว',
    to_ai_ok: 'บันทึกการตั้งค่าแล้ว', to_ai_no: 'การบันทึกล้มเหลว',
    to_ai_no_cfg: 'ยังไม่ได้ตั้งค่า AI - ไปตั้งในแท็บ AI', to_ai_head: 'การวิเคราะห์ AI',
    to_ai_bad: 'การวิเคราะห์ AI ล้มเหลว', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ ยิงออก', navar: 'อาร์เซนอล',
    ar_h2: 'ARSENAL - CVE, EPSS และ exploit บนพื้นผิวที่ตรวจพบ', ar_sync: 'SYNC ฐานข้อมูล',
    ar_btn: 'การเดิน', ar_exec: 'EXEC',
    ar_none: 'ยังไม่มีการเดิน: รัน RECON ก่อน แล้ว SYNC เพื่อโหลด KEV/EPSS', ar_loading: 'กำลังโหลดสรุปฐานข้อมูล...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'โปรแกรมสาธิต - สแกนไม่ได้: สร้างโปรแกรมของคุณ', pip_noprog: 'ยังไม่มีโปรแกรม: สร้างของคุณในแท็บ Programs',
    pip_next: 'ขั้นตอนถัดไป:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  ms: {
    pl_title: 'Pelan kerja', pl_empty: 'belum ada pelan: jalankan RECON dalam kad di atas, hipotesis mendarat di sini (status kekal disimpan)',
    pl_run: 'Jalankan', pl_reflect: 'canary dipantulkan',
    st_do: 'perlu dilakukan', st_test: 'telah diuji',
    st_signal: 'isyarat', st_valid: 'sah',
    st_void: 'tiada', atk_btn: 'ATTACK',
    atk_start: 'menyerang permukaan: endpoint, dokumentasi terdedah, JWT, rahsia...', atk_fail: 'serangan tidak dapat dilakukan: jalankan RECON dahulu',
    atk_none: 'tiada isyarat', atk_findings: 'calon',
    atk_done: 'ATTACK: {n} calon P1/P2 disuntik ke dalam findings bersama bukti', atk_empty: 'belum ada serangan: jalankan RECON kemudian ATTACK - calon dengan bukti req/res mendarat di sini',
    navh: 'HUNT', h2hunt: 'HUNT - permukaan sebenar dan bukti',
    h_ready: 'sedia', h_empty: 'belum ada permukaan yang diketahui: jalankan RECON untuk memetakan halaman, endpoint API, parameter, buntel JS dan subdomain',
    h_fnd: 'Findings program', h_nofnd: 'tiada findings untuk program ini',
    rc_btn: 'RECON', rc_start: 'recon permukaan sedang berjalan: halaman, buntel JS, endpoint, parameter...',
    rc_done: 'permukaan sudah dipetakan: endpoint, parameter dan subdomain tersenarai dalam kad program', rc_fail: 'recon gagal: hos tidak capaian atau skop kosong',
    rc_surface: 'permukaan:', snd_on: 'BUNYI: HIDUP',
    snd_off: 'BUNYI: MATI', snd_ok: 'bunyi antara muka aktif - pustaka: klik, tab, salin, amaran',
    snd_stop: 'senyap penuh diaktifkan: tiada lagi bunyi C2FF', amb_on: 'SUASANA: HIDUP',
    amb_off: 'SUASANA: MATI', amb_ok: 'suasana hidup - rona meluncur lembut merentasi rumpun (hijau, biru, kuning...)',
    amb_stop: 'suasana beku pada hijau asal', nt_on: 'NOTIFIKASI: HIDUP',
    nt_off: 'NOTIFIKASI: MATI', nt_ok: 'notifikasi pelayar diaktifkan - bip pada P1 dan P2',
    nt_denied: 'notifikasi disekat oleh pelayar: benarkan dalam tetapan laman', term_denied: 'terminal ditolak atau tidak tersedia: diperlukan localhost, atau bilik TERBUKA selaku admin',
    term_p: 'bash sebenar - sejarah dengan anak panah, Ctrl+C menghentikan, Ctrl+D menutup', term_restart: 'Tetap semula',
    navtrm: 'TERM', term_h2: 'Terminal - cengkeraman kerja, terus di dalam konsol',
    fl_off: 'FLEET: TERHENTI', fl_paused: 'FLEET: DIHENTIKAN SEMENTARA',
    fl_active: 'FLEET: AKTIF ({n} kitaran)', fl_last: 'kitaran terakhir',
    fl_none: 'belum ada kitaran', fl_info: 'selang {i} min, bajet {b} req/kitaran',
    sub_ttl: 'command & control framework', navt: 'SESI',
    tm_h2: 'Sesi berkumpulan - memburu bersama, walaupun luar rangkaian', tm_p: 'Buka bilik kongsi: kumpulan anda melihat armada, findings dan boleh mengasing secara langsung. Sesi sembang khusus di bawah. Tiga tahap akses: LOCAL (solo), LAN melalui BUKA KEPADA RANGKAIAN, dan DUNIA melalui BUKA KEPADA DUNIA - terowong awam (cloudflared jika dipasang) menjadikan pautan jemputan sah dari mana-mana rangkaian, tanpa mendedahkan mesin anda secara langsung. Semua terkunci dengan kunci bilik - jana semula untuk menendang semua orang sekaligus.',
    tm_handle: 'Nama panggilan anda (paling banyak 16 aksara)', tm_save_h: 'Tetapkan',
    tm_room_ph: 'nama bilik (cth: c2ff-core)', tm_save: 'Laksanakan',
    tm_on: 'BILIK TERBUKA: {r} - {n} dalam talian', tm_off: 'MOD TEAM DIMATIKAN - sesi tempatan solo',
    tm_room: 'Bilik', tm_key: 'Kunci bilik',
    tm_regen: 'Jana semula kunci', tm_regen_ok: 'kunci baru dijana - pautan lama sudah mati',
    tm_invite: 'Pautan jemputan (salin kepada pasukan anda)', tm_copy: 'Salin',
    tm_copied: 'disalin ke papanklip', tm_members: 'Ahli',
    tm_nobody: 'belum ada sesiapa - hantar pautan kepada pasukan anda', tm_you: '(anda)',
    tm_here: 'hadir', tm_saved: 'nama panggilan disimpan',
    tm_no_handle: 'nama panggilan kosong', tm_cfg_ok: 'bilik dikemas kini',
    tm_cfg_no: 'gagal', tm_live: 'BUKA KEPADA RANGKAIAN',
    tm_shore: 'KEMBALI KE TEMPATAN', tm_need_on: 'hidupkan bilik dahulu (HIDUP)',
    tm_bind_lan: 'RANGKAIAN: {a}', tm_bind_lo: 'LOCAL: localhost sahaja',
    to_team_live: '[GO-LIVE] pelayan dimulakan semula dengan akses rangkaian - pautan LAN dipaparkan, sambung semula dalam 2 s', to_team_shore: 'pelayan dimulakan semula secara tempatan (127.0.0.1)',
    tm_tun_open: 'BUKA KEPADA DUNIA (terowong)', tm_tun_close: 'TUTUP TEROWONG',
    tm_tun_wait: 'terowong awam sedang dibuka (beberapa saat)…', tm_tun_on: 'SESI TERBUKA KEPADA DUNIA: {u} - pautan jemputan berfungsi dari mana sahaja, tidak perlu rangkaian sama',
    tm_tun_closed: 'terowong ditutup - kembali ke LAN/tempatan', tm_chat_empty: 'saluran sesi dibuka - ahli bilik membaca satu sama lain di sini',
    tm_chat_h2: 'Sembang sesi', tm_msg_ph: 'mesej ke sesi…',
    tm_admin: 'admin', tm_guest: 'tetamu',
    tm_kick: 'KICK', tm_kick_ok: 'ahli ditendang keluar dari bilik (klik semula untuk membuka blok)',
    tm_role_ok: 'peranan dikemas kini', tm_mic_on: 'AKTIFKAN MIKROFON',
    tm_mic_off: 'MATIKAN MIKROFON', tm_mic_denied: 'mikrofon ditolak atau tidak tersedia: diperlukan HTTPS (terowong DUNIA atau localhost) dan mikrofon perlu dibenarkan',
    navf: 'Armada', navfd: 'Findings',
    navp: 'Program', navai: 'AI',
    navc: 'Penyelarasan', st_runs: 'Larian',
    st_beacons: 'Beacon aktif', st_sig: 'Isyarat',
    h2f: 'Armada - semua program, ejen yang sedang berlari lebih dulu', h2fd: 'Pangkalan findings - penyisipan tanda triage kekal',
    h2eng: 'Enjin armada - kitaran tempatan tanpa token', h2prog: 'Program - skop, kepala diperlukan, pelancaran',
    h2new: 'Program baharu', h2ai: 'Ejen AI - penyepaduan pilihan sepenuhnya',
    h2c: 'Penyelarasan - saluran peribadi', fl_start: 'Mula',
    fl_pause: 'Jeda', fl_cycle: 'Kitaran sekarang',
    f_add: 'Tambah', f_none: 'belum ada isyarat',
    f_ph: 'finding manual: endpoint + bukti + tahap parah yang boleh dipertahankan…', st_sig_off: 'isyarat',
    st_sig_an: 'analisis', st_sig_sub: 'dihantar',
    st_sig_dup: 'dup', st_sig_ref: 'ditolak',
    st_sig_cl: 'ditutup', r_none: 'tiada larian dikesan',
    r_live: '{n} SEDANG BERLARI', r_done: 'SIAP',
    r_feed: '▽ aliran ({n} ev)', r_close: '△ lipat masuk',
    p_name_ph: 'Nama program (cth: PayPal)', p_hdr_ph: 'kepala penyelidik diperlukan (cth: X-Bug-Bounty: xxx)',
    p_scope_ph: 'skop: domain1, domain2, …', p_save: 'Simpan',
    p_local: 'modul, 100% tempatan', ai_p: 'C2FF berjalan sepenuhnya tanpa AI: mod adalah peneroka deterministik tempatan. Gerbang ini hanya untuk menyambungkan <b>AI anda</b> (self-hosted atau API) untuk analisis satu finding dengan keperluan: butang <span style="color:var(--green)">IA »</span> dalam FINDINGS, jawaban dipaparkan dalam PENYELARASAN. Tiada data keluar dari mesin anda tanpa konfigurasi ini.',
    ai_off: 'dimatikan', ai_on: 'dihidupkan',
    ai_st_off: 'AI DIMATIKAN - rangka kerja berjalan 100% tempatan tanpanya', ai_st_ready: 'AI BERSAMBUNG: {p} · {m}',
    ai_st_inc: 'AI DIHIDUPKAN TAPI TIDAK LENGKAP: diperlukan baseURL dan model', ai_url_ph: 'URL pangkalan - cth: http://localhost:11434 atau https://api.AISaya.tld/v1',
    ai_model_ph: 'model - cth: llama3.1:8b', ai_key_ph: 'kunci API (biarkan kosong untuk pelayan tempatan)',
    ai_save: 'Simpan', ai_test: 'Uji sambungan',
    ai_testing: 'ujian sedang berjalan…', ai_ok: 'OK - jawab: ',
    ai_fail: 'GAGAL: ', ai_note: 'konfigurasi disimpan tempatan dalam data/ai.json - tidak pernah dihantar ke mana pun kecuali endpoint yang anda letakkan',
    ch_ph: 'root@c2ff:~# mesej kepada ejen analisis…', ch_send: 'Hantar',
    ch_empty: 'Saluran terbuka. Taip di sini, monitor membangunkan saya serta-merta.', ft: '100% tempatan - peneroka deterministik, tanpa token dan kebergantungan luar - unrestricted · undetected · unstoppable',
    to_fl_on: 'MOD FLEET AKTIF: kitaran tempatan setiap 30 min, 0 token.', to_fl_pa: 'FLEET DITANGGUHKAN - sambung semula bila-bila masa anda mahu.',
    to_fl_cy: 'Kitaran segera dilancarkan (bajet 60 permintaan).', to_launch: '[GO] mod {m} (CWE {c}) pada {p} - kitaran tempatan dilancarkan',
    to_ai_ok: 'konfigurasi disimpan', to_ai_no: 'penyimpanan gagal',
    to_ai_no_cfg: 'AI tidak dikonfigurasi - tetapkannya dalam tab AI', to_ai_head: 'ANALISIS AI',
    to_ai_bad: 'ANALISIS AI gagal', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ PELANCARAN', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS dan exploit pada permukaan yang dikesan', ar_sync: 'SYNC PANGKALAN DATA',
    ar_btn: 'LANGKAH', ar_exec: 'EXEC',
    ar_none: 'tiada langkah: jalankan RECON dahulu, kemudian SYNC untuk memuatkan KEV/EPSS', ar_loading: 'ringkasan pangkalan data sedang dimuatkan...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'program demo - tiada imbasan: buat program anda sendiri', pip_noprog: 'tiada program lagi: buat milik anda dalam tab Program',
    pip_next: 'langkah seterusnya:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  tl: {
    pl_title: 'Plano ng trabaho', pl_empty: 'wala pang plano : patakbuhin ang RECON sa card sa itaas, dito bumabagsak ang mga hypothesis (nananatili ang mga status)',
    pl_run: 'Patakbuhin', pl_reflect: 'reflektado ang canary',
    st_do: 'gagawin', st_test: 'nasubok',
    st_signal: 'signal', st_valid: 'kumpirmado',
    st_void: 'wala', atk_btn: 'ATTACK',
    atk_start: 'inaatake ang surface : mga endpoint, exposed docs, JWT, secrets...', atk_fail: 'hindi ma-attack : patakbuhin muna ang RECON',
    atk_none: 'walang signal', atk_findings: 'mga kandidato',
    atk_done: 'ATTACK : {n} kandidatong P1/P2 naipasok sa findings na may ebidensya', atk_empty: 'wala pang attack : patakbuhin ang RECON tapos ATTACK - dito bumabagsak ang mga kandidatong may ebidensyang req/res',
    navh: 'HUNT', h2hunt: 'HUNT - tunay na surface at mga ebidensya',
    h_ready: 'handa', h_empty: 'walang kilalang surface : patakbuhin ang RECON para i-map ang mga page, API endpoint, param, JS bundle at subdomain',
    h_fnd: 'Mga finding ng programa', h_nofnd: 'walang finding sa programang ito',
    rc_btn: 'RECON', rc_start: 'isinasagawa ang recon ng surface : mga page, JS bundle, endpoint, param...',
    rc_done: 'na-map ang surface : nakalista sa card ng programa ang mga endpoint, param at subdomain', rc_fail: 'nabigo ang recon : hindi maabot ang host o walang laman ang scope',
    rc_surface: 'surface :', snd_on: 'TUNOG : ON',
    snd_off: 'TUNOG : OFF', snd_ok: 'naka-on ang mga tunog ng interface - library : click, tab, copy, mga alerto',
    snd_stop: 'naka-aktibo ang buong mute : wala nang tunog mula sa C2FF', amb_on: 'ATMOSPERA : ON',
    amb_off: 'ATMOSPERA : OFF', amb_ok: 'buhay na atmospera - dahan-dahang dumadaloy ang tint sa mga pamilya (berde, asul, dilaw...)',
    amb_stop: 'naka-freeze ang atmospera sa orihinal na berde', nt_on: 'NOTIFIKASYON : ON',
    nt_off: 'NOTIFIKASYON : OFF', nt_ok: 'naka-enable ang mga notification ng browser - may bip sa P1 at P2',
    nt_denied: 'hinaharang ng browser ang mga notification : paganahin ang mga ito sa settings ng site', term_denied: 'tinanggihan o hindi available ang terminal : kailangan ng localhost, o BUKAS na kuwarto bilang admin',
    term_p: 'totoong bash - history gamit ang arrows, pinuputol ng Ctrl+C, isinasara ng Ctrl+D', term_restart: 'I-reset',
    navtrm: 'TERM', term_h2: 'Terminal - working shell, diretso sa console',
    fl_off: 'FLEET : TIGIL', fl_paused: 'FLEET : NAKA-PAUSE',
    fl_active: 'FLEET : AKTIBO ({n} cycle)', fl_last: 'huling cycle',
    fl_none: 'wala pang cycle', fl_info: 'interyal na {i} min, budget na {b} req/cycle',
    sub_ttl: 'command & control framework', navt: 'SESYON',
    tm_h2: 'Mga grupong sesyon - sabay-sabay manhunting, kahit wala sa parehong network', tm_p: 'Bumukas ng shared room : nakikita ng grupo mo ang fleet, ang mga finding, at puwedeng mag-triage nang live. May nakalaang session chat sa ibaba. Tatlong antas ng access : LOCAL (solo), LAN sa pamamagitan ng BUKAS SA NETWORK, at MUNDO sa pamamagitan ng BUKAS SA MUNDO - ginagawang balido ang invite link ng isang pampublikong tunnel (cloudflared kung naka-install) mula sa anumang network, nang hindi direktang nailalantad ang makina mo. Lahat ay pinapagates ng room key - i-regenerate ito para isang bagsak na mailabas lahat.',
    tm_handle: 'Handle mo (16 characters max)', tm_save_h: 'Itakda',
    tm_room_ph: 'pangalan ng kuwarto (hal : c2ff-core)', tm_save: 'I-apply',
    tm_on: 'BUKAS ANG KUWARTO : {r} - {n} online', tm_off: 'TEAM MODE OFF - lokal na solo session',
    tm_room: 'Kuwarto', tm_key: 'Susi ng kuwarto',
    tm_regen: 'I-regenerate ang susi', tm_regen_ok: 'bagong susi na-generate - patay na ang mga lumang link',
    tm_invite: 'Invite link (kopyahin sa team mo)', tm_copy: 'Kopyahin',
    tm_copied: 'nakopya sa clipboard', tm_members: 'Mga miyembro',
    tm_nobody: 'walang tao pa - ipasa ang link sa team mo', tm_you: '(ikaw)',
    tm_here: 'nandito', tm_saved: 'naka-save ang handle',
    tm_no_handle: 'walang laman ang handle', tm_cfg_ok: 'na-update ang kuwarto',
    tm_cfg_no: 'nabigo', tm_live: 'BUKAS SA NETWORK',
    tm_shore: 'BALIK SA LOCAL', tm_need_on: 'buksan muna ang kuwarto (ON)',
    tm_bind_lan: 'NETWORK : {a}', tm_bind_lo: 'LOCAL : localhost lang',
    to_team_live: '[GO-LIVE] muling inilunsad ang server na may network access - ipinapakita ang LAN link, muling kokonekta sa loob ng 2 s', to_team_shore: 'muling inilunsad ang server nang lokal (127.0.0.1)',
    tm_tun_open: 'BUKAS SA MUNDO (tunnel)', tm_tun_close: 'ISARA ANG TUNNEL',
    tm_tun_wait: 'bubuksan na ang pampublikong tunnel (ilang segundo)…', tm_tun_on: 'BUKAS ANG SESSION SA MUNDO : {u} - gumagana ang invite link kahit saan, hindi kailangan ng parehong network',
    tm_tun_closed: 'isinarang tunnel - balik sa LAN/local', tm_chat_empty: 'bukas ang session channel - dito nagbabasaan ang mga miyembro ng kuwarto',
    tm_chat_h2: 'Session chat', tm_msg_ph: 'mensahe papuntang session…',
    tm_admin: 'admin', tm_guest: 'bisita',
    tm_kick: 'KICK', tm_kick_ok: 'naalis sa kuwarto ang miyembro (i-click muli para i-unlock)',
    tm_role_ok: 'na-update ang role', tm_mic_on: 'BUKSAN ANG MIKROPONO',
    tm_mic_off: 'PATAYIN ANG MIKROPONO', tm_mic_denied: 'tinanggihan o hindi maabot ang mikropono : kailangan ng HTTPS (WORLD tunnel o localhost) at kailangang bigyan ng pahintulot ang mikropono',
    navf: 'Fleet', navfd: 'Findings',
    navp: 'Programa', navai: 'AI',
    navc: 'Koordinasyon', st_runs: 'Runs',
    st_beacons: 'Mga aktibong beacon', st_sig: 'Mga signal',
    h2f: 'Fleet - lahat ng programa, unahin ang mga agent na nasa takbo', h2fd: 'Base ng findings - pananatilihin ang triage tagging',
    h2eng: 'Engine ng fleet - lokal na cycle, walang token', h2prog: 'Mga programa - scope, kinakailangang header, paglulunsad',
    h2new: 'Bagong programa', h2ai: 'AI agent - opsyonal na integration',
    h2c: 'Koordinasyon - pribadong channel', fl_start: 'Simulan',
    fl_pause: 'Pause', fl_cycle: 'Cycle ngayon',
    f_add: 'Idagdag', f_none: 'wala pang signal',
    f_ph: 'manual na finding : endpoint + ebidensya + mapipigilang severity…', st_sig_off: 'signal',
    st_sig_an: 'pagsusuri', st_sig_sub: 'naisumite',
    st_sig_dup: 'dup', st_sig_ref: 'tinanggihan',
    st_sig_cl: 'sinara', r_none: 'walang nadetect na run',
    r_live: '{n} TUMATAKBO', r_done: 'TAPOS',
    r_feed: '▽ daloy ({n} ev)', r_close: '△ i-collapse',
    p_name_ph: 'Pangalan ng programa (hal : PayPal)', p_hdr_ph: 'kinakailangang header ng researcher (hal : X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domain1, domain2, …', p_save: 'I-save',
    p_local: 'module(s), 100% lokal', ai_p: 'Tumatakbo ang C2FF nang buo nang walang AI : ang mga mode ay deterministic at lokal na probes. Ang gateway na ito ay para lang sa pagkabit ng <b>AI mo</b> (self-hosted o API) para sa pagsusuri ng isang finding on demand : ang button na <span style="color:var(--green)">AI »</span> sa FINDINGS, ipapakita ang sagot sa COORDINATION. Walang data na aalis sa makina mo nang wala ang configuration na ito.',
    ai_off: 'naka-off', ai_on: 'naka-on',
    ai_st_off: 'NAKA-OFF ANG AI - 100% lokal na tumatakbo ang framework nang wala ito', ai_st_ready: 'NAKAKONEKTA ANG AI : {p} · {m}',
    ai_st_inc: 'NAKA-ON ANG AI PERO KULANG : kailangan ng baseURL at model', ai_url_ph: 'base URL - hal : http://localhost:11434 o https://api.MyAI.tld/v1',
    ai_model_ph: 'model - hal : llama3.1:8b', ai_key_ph: 'API key (iwanang blangko kung lokal na server)',
    ai_save: 'I-save', ai_test: 'Subukan ang koneksyon',
    ai_testing: 'sinusubok…', ai_ok: 'OK - sagot : ',
    ai_fail: 'NABIGO : ', ai_note: 'naka-store nang lokal ang config sa data/ai.json - hindi kailanman ipapadala kundi sa endpoint na itinakda mo',
    ch_ph: 'root@c2ff:~# mensahe sa analysis agent…', ch_send: 'Ipadala',
    ch_empty: 'Bukas ang channel. Mag-type dito, ginigising ako agad ng monitor.', ft: '100% lokal - deterministic probes, walang token at external deps - unrestricted · undetected · unstoppable',
    to_fl_on: 'AKTIBO ANG FLEET-MODE : lokal na cycle kada 30 min, 0 token.', to_fl_pa: 'NAKA-PAUSE ANG FLEET - ipagpatuloy anumang oras mo gusto.',
    to_fl_cy: 'Inilunsad ang agarang cycle (budget 60 req).', to_launch: '[GO] mode {m} (CWE {c}) sa {p} - inilunsad ang lokal na cycle',
    to_ai_ok: 'naka-save ang config', to_ai_no: 'nabigo ang pag-save',
    to_ai_no_cfg: 'hindi pa na-configure ang AI - itakda ito sa AI tab', to_ai_head: 'ANALYSIS NG AI',
    to_ai_bad: 'NABIGO ANG ANALYSIS NG AI', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ ILUNSAD', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS at exploits sa nadiskubreng surface', ar_sync: 'SYNC MGA BASE',
    ar_btn: 'MGA GALAW', ar_exec: 'EXEC',
    ar_none: 'walang galaw: patakbuhin muna ang RECON, tapos SYNC para i-load ang KEV/EPSS', ar_loading: 'buod ng mga base ay naglo-load...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demo program - walang scan: gumawa ng sarili mong program', pip_noprog: 'walang program pa: gumawa ng sa iyo sa tab na Programs',
    pip_next: 'susunod na hakbang:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  bn: {
    pl_title: 'কাজের পরিকল্পনা', pl_empty: 'এখনও কোনো পরিকল্পনা নেই : উপরের কার্ডে RECON চালাও, অনুমানগুলো এখানে জমা হবে (স্ট্যাটাস সংরক্ষিত থাকে)',
    pl_run: 'চালাও', pl_reflect: 'canary প্রতিফলিত',
    st_do: 'করণীয়', st_test: 'পরীক্ষিত',
    st_signal: 'সিগন্যাল', st_valid: 'নিশ্চিত',
    st_void: 'কিছু নেই', atk_btn: 'ATTACK',
    atk_start: 'সারফেস আক্রমণ চলছে : endpoint, উন্মুক্ত ডকুমেন্ট, JWT, সিক্রেট...', atk_fail: 'আক্রমণ সম্ভব নয় : আগে RECON চালাও',
    atk_none: 'কোনো সিগন্যাল নেই', atk_findings: 'প্রার্থী',
    atk_done: 'ATTACK : {n} টি P1/P2 প্রার্থী প্রমাণসহ findings-এ ঢুকেছে', atk_empty: 'এখনও কোনো attack নেই : আগে RECON তারপর ATTACK চালাও - req/res প্রমাণসহ প্রার্থীরা এখানে জমা হবে',
    navh: 'HUNT', h2hunt: 'HUNT - সত্যিকারের সারফেস ও প্রমাণ',
    h_ready: 'প্রস্তুত', h_empty: 'এখনও কোনো সারফেস নেই : পেজ, API endpoint, প্যারাম, JS bundle ও সাবডোমেইন ম্যাপ করতে RECON চালাও',
    h_fnd: 'প্রোগ্রামের findings', h_nofnd: 'এই প্রোগ্রামে কোনো finding নেই',
    rc_btn: 'RECON', rc_start: 'সারফেসের recon চলছে : পেজ, JS bundle, endpoint, প্যারাম...',
    rc_done: 'সারফেস ম্যাপ হয়ে গেছে : endpoint, প্যারাম ও সাবডোমেইন প্রোগ্রামের কার্ডে তালিকাভুক্ত', rc_fail: 'recon ব্যর্থ : হোস্টে পৌঁছানো যায়নি বা scope খালি',
    rc_surface: 'সারফেস :', snd_on: 'সাউন্ড : ON',
    snd_off: 'সাউন্ড : OFF', snd_ok: 'ইন্টারফেসের সাউন্ড চালু - লাইব্রেরি : click, tab, copy, অ্যালার্ট',
    snd_stop: 'সম্পূর্ণ মিউট চালু : আর কোনো C2FF সাউন্ড নেই', amb_on: 'পরিবেশ : ON',
    amb_off: 'পরিবেশ : OFF', amb_ok: 'জীবন্ত পরিবেশ - রঙের আভা ধীরে ধীরে পরিবারগুলোর মধ্যে ঘোরে (সবুজ, নীল, হলুদ...)',
    amb_stop: 'পরিবেশ আসল সবুজে স্থির', nt_on: 'নোটিফ : ON',
    nt_off: 'নোটিফ : OFF', nt_ok: 'ব্রাউজারের নোটিফিকেশন চালু - P1 ও P2-তে বিপ হবে',
    nt_denied: 'ব্রাউজার নোটিফিকেশন আটকে দিয়েছে : সাইটের সেটিংসে অনুমতি দাও', term_denied: 'টার্মিনাল অস্বীকৃত বা অনুপস্থিত : localhost দরকার, অথবা অ্যাডমিন হিসেবে খোলা রুম',
    term_p: 'আসল bash - তীর দিয়ে history, Ctrl+C থামায়, Ctrl+D বন্ধ করে', term_restart: 'রিসেট',
    navtrm: 'TERM', term_h2: 'টার্মিনাল - কাজের শেল, সরাসরি কনসোলে',
    fl_off: 'FLEET : বন্ধ', fl_paused: 'FLEET : PAUSE',
    fl_active: 'FLEET : সক্রিয় ({n} সাইকেল)', fl_last: 'শেষ সাইকেল',
    fl_none: 'এখনও কোনো সাইকেল নেই', fl_info: 'প্রতি {i} মিনিট, {b} req/সাইকেল',
    sub_ttl: 'command & control framework', navt: 'সেশন',
    tm_h2: 'দলীয় সেশন - একসাথে শিকার, নেটওয়ার্কের বাইরেও', tm_p: 'শেয়ার্ড রুম খোলো : তোমার দল fleet ও findings দেখবে এবং লাইভ ট্রায়াজ করতে পারবে। নিচে আলাদা সেশন চ্যাট। তিন ধরনের অ্যাক্সেস : LOCAL (একা), নেটওয়ার্কে খোলার মাধ্যমে LAN, এবং বিশ্বের জন্য খোলার মাধ্যমে WORLD - একটি পাবলিক টানেল (cloudflared ইনস্টল থাকলে) ইনভাইট লিংককে যেকোনো নেটওয়ার্ক থেকে বৈধ করে, তোমার মেশিন সরাসরি উন্মুক্ত না হয়ে। সবকিছুর গেট রুম কী - এক কলাকে সবাইকে বাদ দিতে এটি আবার তৈরি করো।',
    tm_handle: 'তোমার হ্যান্ডেল (সর্বোচ্চ ১৬ অক্ষর)', tm_save_h: 'সেট',
    tm_room_ph: 'রুমের নাম (যেমন : c2ff-core)', tm_save: 'প্রয়োগ',
    tm_on: 'রুম খোলা : {r} - {n} অনলাইন', tm_off: 'TEAM MODE বন্ধ - লোকাল একা সেশন',
    tm_room: 'রুম', tm_key: 'রুম কী',
    tm_regen: 'কী আবার তৈরি করো', tm_regen_ok: 'নতুন কী তৈরি হয়েছে - পুরনো লিংক মৃত',
    tm_invite: 'ইনভাইট লিংক (দলের সাথে শেয়ার করো)', tm_copy: 'কপি',
    tm_copied: 'ক্লিপবোর্ডে কপি হয়েছে', tm_members: 'সদস্য',
    tm_nobody: 'এখনও কেউ নেই - দলকে লিংক পাঠাও', tm_you: '(তুমি)',
    tm_here: 'এখানে', tm_saved: 'হ্যান্ডেল সংরক্ষিত',
    tm_no_handle: 'হ্যান্ডেল খালি', tm_cfg_ok: 'রুম আপডেট হয়েছে',
    tm_cfg_no: 'ব্যর্থ', tm_live: 'নেটওয়ার্কে খোলো',
    tm_shore: 'লোকালে ফিরে যাও', tm_need_on: 'প্রথমে রুম চালু করো (ON)',
    tm_bind_lan: 'NETWORK : {a}', tm_bind_lo: 'LOCAL : শুধু localhost',
    to_team_live: '[GO-LIVE] নেটওয়ার্ক অ্যাক্সেসসহ সার্ভার আবার চালু - LAN লিংক দেখানো হচ্ছে, 2 সেতে পুনঃসংযোগ', to_team_shore: 'সার্ভার লোকালে (127.0.0.1) আবার চালু',
    tm_tun_open: 'বিশ্বের জন্য খোলো (টানেল)', tm_tun_close: 'টানেল বন্ধ করো',
    tm_tun_wait: 'পাবলিক টানেল খুলছে (কয়েক সেকেন্ড)…', tm_tun_on: 'সেশন বিশ্বের জন্য খোলা : {u} - ইনভাইট লিংক সব জায়গা থেকে কাজ করে, একই নেটওয়ার্ক লাগবে না',
    tm_tun_closed: 'টানেল বন্ধ - ফিরে গেল LAN/লোকাল', tm_chat_empty: 'সেশন চ্যানেল খোলা - রুমের সদস্যরা এখানে একে অপরকে পড়ে',
    tm_chat_h2: 'সেশন চ্যাট', tm_msg_ph: 'সেশনে বার্তা…',
    tm_admin: 'অ্যাডমিন', tm_guest: 'অতিথি',
    tm_kick: 'KICK', tm_kick_ok: 'সদস্য রুম থেকে বাদ (আবার ক্লিক করলে আনব্লক)',
    tm_role_ok: 'রোল আপডেট হয়েছে', tm_mic_on: 'মাইক্রোফোন চালু করো',
    tm_mic_off: 'মাইক্রোফোন বন্ধ করো', tm_mic_denied: 'মাইক্রোফোন অস্বীকৃত বা অনুপস্থিত : HTTPS দরকার (WORLD টানেল বা localhost) এবং মাইক্রোফোনের অনুমতি দিতে হবে',
    navf: 'ফ্লিট', navfd: 'Findings',
    navp: 'প্রোগ্রাম', navai: 'AI',
    navc: 'কোর্ডিনেশন', st_runs: 'রান',
    st_beacons: 'সক্রিয় বীকন', st_sig: 'সিগন্যাল',
    h2f: 'ফ্লিট - সব প্রোগ্রাম, চলমান এজেন্ট আগে', h2fd: 'Findings বেস - স্থায়ী ট্রায়াজ ট্যাগিং',
    h2eng: 'ফ্লিট ইঞ্জিন - লোকাল সাইকেল, টোকেন ছাড়া', h2prog: 'প্রোগ্রাম - scope, প্রয়োজনীয় হেডার, লঞ্চ',
    h2new: 'নতুন প্রোগ্রাম', h2ai: 'AI এজেন্ট - ১০০% ঐচ্ছিক ইন্টিগ্রেশন',
    h2c: 'কোর্ডিনেশন - প্রাইভেট চ্যানেল', fl_start: 'শুরু করো',
    fl_pause: 'Pause', fl_cycle: 'এখনই সাইকেল',
    f_add: 'যোগ করো', f_none: 'এখনও কোনো সিগন্যাল নেই',
    f_ph: 'ম্যানুয়াল finding : endpoint + প্রমাণ + রক্ষণযোগ্য sev…', st_sig_off: 'সিগন্যাল',
    st_sig_an: 'বিশ্লেষণ', st_sig_sub: 'জমা হয়েছে',
    st_sig_dup: 'dup', st_sig_ref: 'প্রত্যাখ্যাত',
    st_sig_cl: 'বন্ধ', r_none: 'কোনো রান শনাক্ত হয়নি',
    r_live: '{n} চলছে', r_done: 'শেষ',
    r_feed: '▽ ফিড ({n} ev)', r_close: '△ ভাঁজ করো',
    p_name_ph: 'প্রোগ্রামের নাম (যেমন : PayPal)', p_hdr_ph: 'রিসার্চার হেডার আবশ্যক (যেমন : X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domain1, domain2, …', p_save: 'সংরক্ষণ',
    p_local: 'মডিউল, ১০০% লোকাল', ai_p: 'C2FF সম্পূর্ণভাবে AI ছাড়া চলে : মোডগুলো ডিটারমিনিস্টিক লোকাল প্রোব। এই গেটওয়ে শুধু তোমার <b>নিজের</b> AI (self-hosted বা API) লাগানোর জন্য, একটি finding-এর সময়ে বিশ্লেষণের জন্য : FINDINGS-এর <span style="color:var(--green)">AI »</span> বোতাম, উত্তর COORDINATION-এ দেখাবে। এই কনফিগারেশন ছাড়া তোমার মেশিন থেকে কোনো ডেটা বেরোয় না।',
    ai_off: 'বন্ধ', ai_on: 'চালু',
    ai_st_off: 'AI বন্ধ - ফ্রেমওয়ার্ক ১০০% লোকালে চলে, এটি ছাড়া', ai_st_ready: 'AI সংযুক্ত : {p} · {m}',
    ai_st_inc: 'AI চালু কিন্তু অসম্পূর্ণ : baseURL ও model আবশ্যক', ai_url_ph: 'base URL - যেমন : http://localhost:11434 বা https://api.MyAI.tld/v1',
    ai_model_ph: 'model - যেমন : llama3.1:8b', ai_key_ph: 'API key (লোকাল সার্ভার হলে খালি রাখো)',
    ai_save: 'সংরক্ষণ', ai_test: 'সংযোগ পরীক্ষা',
    ai_testing: 'পরীক্ষা চলছে…', ai_ok: 'OK - উত্তর : ',
    ai_fail: 'ব্যর্থ : ', ai_note: 'কনফিগ লোকালে data/ai.json-এ সংরক্ষিত - শুধু তুমি যে endpoint দেবে সেখানেই যাবে, অন্য কোথাও নয়',
    ch_ph: 'root@c2ff:~# বিশ্লেষণ এজেন্টের কাছে বার্তা…', ch_send: 'পাঠাও',
    ch_empty: 'চ্যানেল খোলা। এখানে লেখো, মনিটর আমাকে তাৎক্ষণিক জাগায়।', ft: '১০০% লোকাল - ডিটারমিনিস্টিক প্রোব, টোকেন বা এক্সটার্নাল ডিপেন্ডেন্সি ছাড়া - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE সক্রিয় : প্রতি 30 মিনিটে লোকাল সাইকেল, 0 টোকেন।', to_fl_pa: 'FLEET PAUSE - যখন চাও আবার চালাও।',
    to_fl_cy: 'তাৎক্ষণিক সাইকেল চালু (বাজেট 60 req)।', to_launch: '[GO] {p}-এ mode {m} (CWE {c}) - লোকাল সাইকেল চালু',
    to_ai_ok: 'কনফিগ সংরক্ষিত', to_ai_no: 'সংরক্ষণ ব্যর্থ',
    to_ai_no_cfg: 'AI কনফিগার করা নেই - AI ট্যাবে সেট করো', to_ai_head: 'AI বিশ্লেষণ',
    to_ai_bad: 'AI বিশ্লেষণ ব্যর্থ', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ লঞ্চ', navar: 'আর্সেনাল',
    ar_h2: 'ARSENAL - সনাক্ত পৃষ্ঠে CVE, EPSS এবং exploit', ar_sync: 'SYNC বেস',
    ar_btn: 'চাল', ar_exec: 'EXEC',
    ar_none: 'কোনো চাল নেই: প্রথমে RECON চালান, তারপর KEV/EPSS লোড করতে SYNC', ar_loading: 'বেসগুলোর সারসংক্ষেপ লোড হচ্ছে...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'ডেমো প্রোগ্রাম - স্ক্যান নেই: নিজের প্রোগ্রাম তৈরি করো', pip_noprog: 'কোনো প্রোগ্রাম নেই: Programs ট্যাবে নিজের প্রোগ্রাম তৈরি করো',
    pip_next: 'পরবর্তী ধাপ:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  ta: {
    pl_title: 'வேலைத் திட்டம்', pl_empty: 'இன்னும் திட்டம் இல்லை : மேலே உள்ள கார்டில் RECON இயக்கு, கருதுகோள்கள் இங்கே விழும் (நிலைகள் சேமிக்கப்படும்)',
    pl_run: 'இயக்கு', pl_reflect: 'canary பிரதிபலித்தது',
    st_do: 'செய்ய வேண்டியது', st_test: 'சோதிக்கப்பட்டது',
    st_signal: 'சிக்னல்', st_valid: 'உறுதிப்படுத்தப்பட்டது',
    st_void: 'ஒன்றுமில்லை', atk_btn: 'ATTACK',
    atk_start: 'மேற்பரப்பு தாக்கப்படுகிறது : endpoints, திறந்த docs, JWT, secrets...', atk_fail: 'தாக்க முடியவில்லை : முதலில் RECON இயக்கு',
    atk_none: 'சிக்னல் இல்லை', atk_findings: 'வேட்பாளர்கள்',
    atk_done: 'ATTACK : ஆதாரத்துடன் {n} P1/P2 வேட்பாளர்கள் findings-ல் சேர்க்கப்பட்டனர்', atk_empty: 'இன்னும் attack இல்லை : RECON இயக்கி பிறகு ATTACK - req/res ஆதாரத்துடன் வேட்பாளர்கள் இங்கே விழுவார்கள்',
    navh: 'HUNT', h2hunt: 'HUNT - உண்மையான மேற்பரப்பு மற்றும் ஆதாரங்கள்',
    h_ready: 'தயார்', h_empty: 'அறியப்பட்ட மேற்பரப்பு இல்லை : பக்கங்கள், API endpoints, பாராம்கள், JS bundles மற்றும் சப்டொமைன்களை வரைய RECON இயக்கு',
    h_fnd: 'ப்ரோகிராமின் findings', h_nofnd: 'இந்த ப்ரோகிராமில் finding இல்லை',
    rc_btn: 'RECON', rc_start: 'மேற்பரப்பின் recon நடக்கிறது : பக்கங்கள், JS bundles, endpoints, பாராம்கள்...',
    rc_done: 'மேற்பரப்பு வரையப்பட்டது : endpoints, பாராம்கள் மற்றும் சப்டொமைன்கள் ப்ரோகிராம் கார்டில் பட்டியலிடப்பட்டுள்ளன', rc_fail: 'recon தோல்வி : host அணுக முடியவில்லை அல்லது scope காலி',
    rc_surface: 'மேற்பரப்பு :', snd_on: 'ஒலி : ON',
    snd_off: 'ஒலி : OFF', snd_ok: 'இன்டர்ஃபேஸ் ஒலிகள் இயக்கப்பட்டன - லைப்ரரி : click, tab, copy, எச்சரிக்கைகள்',
    snd_stop: 'முழு மவுட் இயக்கப்பட்டது : இனி C2FF ஒலி எதுவும் இல்லை', amb_on: 'சூழல் : ON',
    amb_off: 'சூழல் : OFF', amb_ok: 'உயிருள்ள சூழல் - நிறத்தின் நிழல் மெதுவாக குடும்பங்களுக்கிடையே நகர்கிறது (பச்சை, நீலம், மஞ்சள்...)',
    amb_stop: 'சூழல் அசல் பச்சையில் உறைந்தது', nt_on: 'அறிவிப்புகள் : ON',
    nt_off: 'அறிவிப்புகள் : OFF', nt_ok: 'பிரௌசர் அறிவிப்புகள் இயக்கப்பட்டன - P1 மற்றும் P2-ல் பீப் ஒலிக்கும்',
    nt_denied: 'பிரௌசர் அறிவிப்புகளை தடுத்துள்ளது : சைட் அமைப்புகளில் அனுமதி கொடு', term_denied: 'டெர்மினல் மறுக்கப்பட்டது அல்லது இல்லை : localhost தேவை, அல்லது நிர்வாகியாக திறந்த அறை',
    term_p: 'உண்மையான bash - அம்புகளால் history, Ctrl+C தடுக்கும், Ctrl+D மூடும்', term_restart: 'மீட்டமை',
    navtrm: 'TERM', term_h2: 'டெர்மினல் - வேலை ஷெல், நேரடியாக கன்சோலில்',
    fl_off: 'FLEET : நிறுத்தப்பட்டது', fl_paused: 'FLEET : PAUSE',
    fl_active: 'FLEET : சுறுசுறுப்பு ({n} சுற்று)', fl_last: 'கடைசி சுற்று',
    fl_none: 'இன்னும் சுற்று இல்லை', fl_info: '{i} நிமிட இடைவெளி, {b} req/சுற்று',
    sub_ttl: 'command & control framework', navt: 'செசன்',
    tm_h2: 'குழு செசன்கள் - ஒன்றாக வேட்டை, நெட்வொர்க் இல்லாமலும்', tm_p: 'பகிர்ந்த அறை திற : உன் குழு fleet, findings பார்க்கும் மற்றும் நேரடி ட்ரையாஜ் செய்யும். கீழே தனி செசன் சாட். மூன்று அணுகல் நிலைகள் : LOCAL (தனியாக), நெட்வொர்க்குத் திறவதன் மூலம் LAN, உலகத்துக்குத் திறவதன் மூலம் WORLD - ஒரு பப்ளிக் டனெல் (cloudflared நிறுவப்பட்டிருந்தால்) அழைப்பு இணைப்பை எந்த நெட்வொர்க்கிலிருந்தும் செல்லுபடியாக்கும், உன் கணினி நேரடியாக வெளிப்படுயாமல். எல்லாவற்றின் கதவும் அறை கீ - ஒரே அடியில் அனைவரையும் வெளியேற்ற அதை மீண்டும் உருவாக்கு.',
    tm_handle: 'உன் பெயர் (அதிகபட்சம் 16 எழுத்து)', tm_save_h: 'அமை',
    tm_room_ph: 'அறையின் பெயர் (உதா : c2ff-core)', tm_save: 'பயன்படுத்து',
    tm_on: 'அறை திறந்தது : {r} - {n} ஆன்லைன்', tm_off: 'TEAM MODE முடக்கம் - லோக்கல் தனி செசன்',
    tm_room: 'அறை', tm_key: 'அறை கீ',
    tm_regen: 'கீயை மீண்டும் உருவாக்கு', tm_regen_ok: 'புதிய கீ உருவாக்கப்பட்டது - பழைய இணைப்புகள் இறந்தன',
    tm_invite: 'அழைப்பு இணைப்பு (உன் குழுவுக்கு நகலெடு)', tm_copy: 'நகலெடு',
    tm_copied: 'கிளிப்போர்டுக்கு நகலெடுக்கப்பட்டது', tm_members: 'உறுப்பினர்கள்',
    tm_nobody: 'இன்னும் யாரும் இல்லை - குழுவுக்கு இணைப்பை அனுப்பு', tm_you: '(நீ)',
    tm_here: 'இங்கே', tm_saved: 'பெயர் சேமிக்கப்பட்டது',
    tm_no_handle: 'பெயர் காலி', tm_cfg_ok: 'அறை புதுப்பிக்கப்பட்டது',
    tm_cfg_no: 'தோல்வி', tm_live: 'நெட்வொர்க்குத் திற',
    tm_shore: 'லோக்கலுக்குத் திரும்பு', tm_need_on: 'முதலில் அறையை இயக்கு (ON)',
    tm_bind_lan: 'NETWORK : {a}', tm_bind_lo: 'LOCAL : localhost மட்டும்',
    to_team_live: '[GO-LIVE] நெட்வொர்க் அணுகலுடன் சர்வர் மீண்டும் துவங்கியது - LAN இணைப்பு காட்டப்படுகிறது, 2 நொடியில் மீண்டும் இணைப்பு', to_team_shore: 'சர்வர் லோக்கலில் (127.0.0.1) மீண்டும் துவங்கியது',
    tm_tun_open: 'உலகத்துக்குத் திற (டனெல்)', tm_tun_close: 'டனெலை மூடு',
    tm_tun_wait: 'பப்ளிக் டனெல் திறக்கிறது (சில விநாடிகள்)…', tm_tun_on: 'செசன் உலகத்துக்குத் திறந்தது : {u} - அழைப்பு இணைப்பு எங்கிருந்தும் வேலை செய்யும், ஒரே நெட்வொர்க் தேவையில்லை',
    tm_tun_closed: 'டனெல் மூடப்பட்டது - LAN/லோக்கலுக்குத் திரும்பியது', tm_chat_empty: 'செசன் சானல் திறந்தது - அறை உறுப்பினர்கள் இங்கே ஒருவரையொருவர் படிப்பர்',
    tm_chat_h2: 'செசன் சாட்', tm_msg_ph: 'செசனுக்கு செய்தி…',
    tm_admin: 'நிர்வாகி', tm_guest: 'விருந்தினர்',
    tm_kick: 'KICK', tm_kick_ok: 'உறுப்பினர் அறையிலிருந்து வெளியேற்றப்பட்டார் (மீண்டும் கிளிக் செய்தால் திறக்கும்)',
    tm_role_ok: 'பாத்திரம் புதுப்பிக்கப்பட்டது', tm_mic_on: 'மைக் இயக்கு',
    tm_mic_off: 'மைக் முடக்கு', tm_mic_denied: 'மைக் மறுக்கப்பட்டது அல்லது அணுக முடியவில்லை : HTTPS தேவை (WORLD டனெல் அல்லது localhost) மற்றும் மைக்குக்கு அனுமதி கொடுக்க வேண்டும்',
    navf: 'ஃப்லீட்', navfd: 'Findings',
    navp: 'ப்ரோகிராம்', navai: 'AI',
    navc: 'ஒருங்கிணைப்பு', st_runs: 'ரன்கள்',
    st_beacons: 'சுறுசுறுப்பான பீகன்கள்', st_sig: 'சிக்னல்கள்',
    h2f: 'ஃப்லீட் - அனைத்து ப்ரோகிராம்கள், ஓடும் ஏஜென்ட்கள் முதலில்', h2fd: 'Findings தளம் - நிரந்தர ட்ரையாஜ் டேகிங்',
    h2eng: 'ஃப்லீட் எஞ்சின் - லோக்கல் சுற்றுகள், டோக்கன் இல்லை', h2prog: 'ப்ரோகிராம்கள் - scope, தேவையான ஹெடர், துவக்கம்',
    h2new: 'புதிய ப்ரோகிராம்', h2ai: 'AI ஏஜென்ட் - 100% விருப்பத்தேர்வு இணைப்பு',
    h2c: 'ஒருங்கிணைப்பு - தனியார் சானல்', fl_start: 'துவக்கு',
    fl_pause: 'Pause', fl_cycle: 'இப்போது சுற்று',
    f_add: 'சேர்', f_none: 'இன்னும் சிக்னல் இல்லை',
    f_ph: 'கையேடு finding : endpoint + ஆதாரம் + தற்காக்கக்கூடிய sev…', st_sig_off: 'சிக்னல்',
    st_sig_an: 'பகுப்பாய்வு', st_sig_sub: 'சமர்ப்பிக்கப்பட்டது',
    st_sig_dup: 'dup', st_sig_ref: 'நிராகரிக்கப்பட்டது',
    st_sig_cl: 'மூடப்பட்டது', r_none: 'ரன் கண்டறியப்படவில்லை',
    r_live: '{n} ஓடுகிறது', r_done: 'முடிந்தது',
    r_feed: '▽ ஓடை ({n} ev)', r_close: '△ மடக்கு',
    p_name_ph: 'ப்ரோகிராமின் பெயர் (உதா : PayPal)', p_hdr_ph: 'ரிசர்ச்சர் ஹெடர் தேவை (உதா : X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domain1, domain2, …', p_save: 'சேமி',
    p_local: 'மாட்யூல்(கள்), 100% லோக்கல்', ai_p: 'C2FF முழுவதுமாக AI இல்லாமல் இயங்குகிறது : மோட்கள் டிடர்மினிஸ்டிக் லோக்கல் ப்ரோப்கள். இந்த கேட்வே ஒரு finding-ஐ உடனடி பகுப்பாய்வு செய்ய <b>உன்</b> AI-ஐ (self-hosted அல்லது API) இணைக்க மட்டுமே : FINDINGS-ல் உள்ள <span style="color:var(--green)">AI »</span> பொத்தான், பதில் COORDINATION-ல் காட்டப்படும். இந்த அமைப்பு இல்லாமல் உன் கணினியிலிருந்து எந்த தரவும் வெளியேறாது.',
    ai_off: 'முடக்கப்பட்டது', ai_on: 'இயக்கப்பட்டது',
    ai_st_off: 'AI முடக்கப்பட்டது - ஃப்ரேம்வொர்க் 100% லோக்கலில் அது இல்லாமல் இயங்குகிறது', ai_st_ready: 'AI இணைக்கப்பட்டது : {p} · {m}',
    ai_st_inc: 'AI இயக்கப்பட்டது ஆனால் முழுமையற்றது : baseURL மற்றும் model தேவை', ai_url_ph: 'base URL - உதா : http://localhost:11434 அல்லது https://api.MyAI.tld/v1',
    ai_model_ph: 'model - உதா : llama3.1:8b', ai_key_ph: 'API key (லோக்கல் சர்வர் என்றால் காலியாக விடு)',
    ai_save: 'சேமி', ai_test: 'இணைப்பை சோதி',
    ai_testing: 'சோதனை நடக்கிறது…', ai_ok: 'OK - பதில் : ',
    ai_fail: 'தோல்வி : ', ai_note: 'config லோக்கலில் data/ai.json-ல் சேமிக்கப்படும் - நீ வைக்கும் endpoint-ஐத் தவிர வேறு எங்கும் அனுப்பப்படாது',
    ch_ph: 'root@c2ff:~# பகுப்பாய்வு ஏஜென்டுக்கு செய்தி…', ch_send: 'அனுப்பு',
    ch_empty: 'சானல் திறந்தது. இங்கே தட்டச்சு செய், மானிட்டர் என்னை உடனே எழுப்பும்.', ft: '100% லோக்கல் - டிடர்மினிஸ்டிக் ப்ரோப்கள், டோக்கன் இல்லை, வெளி சார்பு இல்லை - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE சுறுசுறுப்பு : ஒவ்வொரு 30 நிமிடத்திலும் லோக்கல் சுற்றுகள், 0 டோக்கன்.', to_fl_pa: 'FLEET PAUSE - விரும்பினால் எப்போதும் மீண்டும் தொடங்கலாம்.',
    to_fl_cy: 'உடனடி சுற்று துவங்கியது (பட்ஜெட் 60 req).', to_launch: '[GO] {p} மீது mode {m} (CWE {c}) - லோக்கல் சுற்று துவங்கியது',
    to_ai_ok: 'config சேமிக்கப்பட்டது', to_ai_no: 'சேமிப்பு தோல்வி',
    to_ai_no_cfg: 'AI கட்டமைக்கப்படவில்லை - AI டேபில் அமை', to_ai_head: 'AI பகுப்பாய்வு',
    to_ai_bad: 'AI பகுப்பாய்வு தோல்வி', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ துவக்கம்', navar: 'ஆர்சனல்',
    ar_h2: 'ARSENAL - கண்டறிந்த மேற்பரப்பில் CVE, EPSS மற்றும் exploits', ar_sync: 'SYNC தளங்கள்',
    ar_btn: 'அசைவுகள்', ar_exec: 'EXEC',
    ar_none: 'அசைவுகள் இல்லை: முதலில் RECON இயக்கவும், பின் KEV/EPSS ஏற்ற SYNC இயக்கவும்', ar_loading: 'தளங்களின் சுருக்கம் ஏற்றப்படுகிறது...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'டெமோ நிரல் - ஸ்கேன் இல்லை: உங்கள் நிரலை உருவாக்குக', pip_noprog: 'எந்த நிரலும் இல்லை: Programs டேபில் உங்கள் நிரலை உருவாக்குக',
    pip_next: 'அடுத்த கட்டம்:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  te: {
    pl_title: 'పని ప్రణాళిక', pl_empty: 'ఇంకా ప్రణాళిక లేదు : పైన ఉన్న కార్డులో RECON నడుపు, ఊహలు ఇక్కడ పడతాయి (స్టేటస్‌లు నిల్వ ఉంటాయి)',
    pl_run: 'నడుపు', pl_reflect: 'canary ప్రతిధ్వనించింది',
    st_do: 'చేయాల్సినది', st_test: 'పరీక్షించబడింది',
    st_signal: 'సిగ్నల్', st_valid: 'ధృవీకరించబడింది',
    st_void: 'ఏమీ లేదు', atk_btn: 'ATTACK',
    atk_start: 'సర్ఫేస్ దాడి జరుగుతోంది : endpoints, బహిర్గత docs, JWT, secrets...', atk_fail: 'దాడి సాధ్యం కాలేదు : ముందుగా RECON నడుపు',
    atk_none: 'సిగ్నల్ లేదు', atk_findings: 'అభ్యర్థులు',
    atk_done: 'ATTACK : రుజువుతో {n} P1/P2 అభ్యర్థులు findings లోకి చేర్చబడ్డారు', atk_empty: 'ఇంకా attack లేదు : RECON నడిపి తర్వాత ATTACK - req/res రుజువుతో అభ్యర్థులు ఇక్కడ పడతారు',
    navh: 'HUNT', h2hunt: 'HUNT - నిజమైన సర్ఫేస్ మరియు రుజువులు',
    h_ready: 'సిద్ధం', h_empty: 'తెలిసిన సర్ఫేస్ లేదు : పేజీలు, API endpoints, పారామ్స్, JS bundles మరియు సబ్‌డొమైన్‌లను మ్యాప్ చేయడానికి RECON నడుపు',
    h_fnd: 'ప్రోగ్రామ్ findings', h_nofnd: 'ఈ ప్రోగ్రామ్‌లో finding లేదు',
    rc_btn: 'RECON', rc_start: 'సర్ఫేస్ recon జరుగుతోంది : పేజీలు, JS bundles, endpoints, పారామ్స్...',
    rc_done: 'సర్ఫేస్ మ్యాప్ అయింది : endpoints, పారామ్స్ మరియు సబ్‌డొమైన్‌లు ప్రోగ్రామ్ కార్డులో జాబితా చేయబడ్డాయి', rc_fail: 'recon విఫలం : host అందడం లేదు లేదా scope ఖాళీ',
    rc_surface: 'సర్ఫేస్ :', snd_on: 'సౌండ్ : ON',
    snd_off: 'సౌండ్ : OFF', snd_ok: 'ఇంటర్‌ఫేస్ సౌండ్‌లు ఆన్ - లైబ్రరీ : click, tab, copy, అలర్ట్‌లు',
    snd_stop: 'పూర్తి మ్యూట్ ఆన్ : ఇక C2FF సౌండ్ ఏదీ లేదు', amb_on: 'వాతావరణం : ON',
    amb_off: 'వాతావరణం : OFF', amb_ok: 'జీవంతమైన వాతావరణం - రంగు నీడ నెమ్మదిగా కుటుంబాల మధ్య కదులుతుంది (ఆకుపచ్చ, నీలం, పసుపు...)',
    amb_stop: 'వాతావరణం అసలు ఆకుపచ్చపై స్థిరమైంది', nt_on: 'నోటిఫ్ : ON',
    nt_off: 'నోటిఫ్ : OFF', nt_ok: 'బ్రౌజర్ నోటిఫికేషన్లు ఆన్ - P1 మరియు P2 లో బీప్',
    nt_denied: 'బ్రౌజర్ నోటిఫికేషన్లను నిరోధించింది : సైట్ సెట్టింగ్‌లలో అనుమతించు', term_denied: 'టెర్మినల్ తిరస్కరించబడింది లేదా లేదు : localhost కావాలి, లేదా అడ్మిన్‌గా తెరిచిన రూమ్',
    term_p: 'నిజమైన bash - బాణాలతో history, Ctrl+C ఆపుతుంది, Ctrl+D మూసేస్తుంది', term_restart: 'రీసెట్',
    navtrm: 'TERM', term_h2: 'టెర్మినల్ - పని షెల్, నేరుగా కన్సోల్‌లో',
    fl_off: 'FLEET : ఆగింది', fl_paused: 'FLEET : PAUSE',
    fl_active: 'FLEET : క్రియాశీలం ({n} సైకిల్‌లు)', fl_last: 'చివరి సైకిల్',
    fl_none: 'ఇంకా సైకిల్ లేదు', fl_info: '{i} నిమిషాల విరామం, {b} req/సైకిల్',
    sub_ttl: 'command & control framework', navt: 'సెషన్',
    tm_h2: 'గ్రూప్ సెషన్లు - కలిసి వేట, నెట్‌వర్క్ లేకుండా కూడా', tm_p: 'షేర్డ్ రూమ్ తెరువు : నీ గ్రూప్ fleet, findings చూస్తుంది మరియు లైవ్ ట్రయాజ్ చేస్తుంది. కింద ప్రత్యేక సెషన్ చాట్. మూడు యాక్సెస్ స్థాయిలు : LOCAL (ఒంటరి), నెట్‌వర్క్‌కు తెరవడం ద్వారా LAN, ప్రపంచానికి తెరవడం ద్వారా WORLD - ఒక పబ్లిక్ టన్నెల్ (cloudflared ఇన్‌స్టాల్ ఉంటే) ఇన్‌వైట్ లింక్‌ను ఏ నెట్‌వర్క్ నుండైనా చెల్లుబాటు చేస్తుంది, నీ మెషీన్ నేరుగా బహిర్గతం కాకుండా. అంతా రూమ్ కీపై ఆధారపడి ఉంటుంది - ఒక్కసారి అందరినీ తీసేయడానికి దాన్ని మళ్లీ జనరేట్ చెయ్.',
    tm_handle: 'నీ పేరు (గరిష్ఠంగా 16 అక్షరాలు)', tm_save_h: 'సెట్',
    tm_room_ph: 'రూమ్ పేరు (ఉదా : c2ff-core)', tm_save: 'వర్తింపజేయి',
    tm_on: 'రూమ్ తెరిచింది : {r} - {n} ఆన్‌లైన్', tm_off: 'TEAM MODE ఆఫ్ - లోకల్ ఒంటరి సెషన్',
    tm_room: 'రూమ్', tm_key: 'రూమ్ కీ',
    tm_regen: 'కీని మళ్లీ జనరేట్ చెయ్', tm_regen_ok: 'కొత్త కీ జనరేట్ అయింది - పాత లింకులు చనిపోయాయి',
    tm_invite: 'ఇన్‌వైట్ లింక్ (నీ టీమ్‌కి కాపీ చెయ్)', tm_copy: 'కాపీ',
    tm_copied: 'క్లిప్‌బోర్డ్‌కి కాపీ అయింది', tm_members: 'సభ్యులు',
    tm_nobody: 'ఇంకా ఎవరూ లేరు - టీమ్‌కి లింక్ పంపు', tm_you: '(నువ్వు)',
    tm_here: 'ఇక్కడ', tm_saved: 'పేరు సేవ్ అయింది',
    tm_no_handle: 'పేరు ఖాళీ', tm_cfg_ok: 'రూమ్ అప్‌డేట్ అయింది',
    tm_cfg_no: 'విఫలం', tm_live: 'నెట్‌వర్క్‌కు తెరువు',
    tm_shore: 'లోకల్‌కి తిరిగి వెళ్లు', tm_need_on: 'ముందుగా రూమ్ ఆన్ చెయ్ (ON)',
    tm_bind_lan: 'NETWORK : {a}', tm_bind_lo: 'LOCAL : localhost మాత్రమే',
    to_team_live: '[GO-LIVE] నెట్‌వర్క్ యాక్సెస్‌తో సర్వర్ మళ్లీ ప్రారంభమైంది - LAN లింక్ చూపబడుతోంది, 2 సెకన్లలో మళ్లి కనెక్ట్', to_team_shore: 'సర్వర్ లోకల్‌లో (127.0.0.1) మళ్లీ ప్రారంభమైంది',
    tm_tun_open: 'ప్రపంచానికి తెరువు (టన్నెల్)', tm_tun_close: 'టన్నెల్ మూసేయి',
    tm_tun_wait: 'పబ్లిక్ టన్నెల్ తెరుచుకుంటోంది (కొన్ని సెకన్లు)…', tm_tun_on: 'సెషన్ ప్రపంచానికి తెరిచింది : {u} - ఇన్‌వైట్ లింక్ ఎక్కడ నుండైనా పనిచేస్తుంది, ఒకే నెట్‌వర్క్ అవసరం లేదు',
    tm_tun_closed: 'టన్నెల్ మూసివేయబడింది - LAN/లోకల్‌కి తిరిగి', tm_chat_empty: 'సెషన్ ఛానల్ తెరిచింది - రూమ్ సభ్యులు ఇక్కడ ఒకరినొకరు చదువుతారు',
    tm_chat_h2: 'సెషన్ చాట్', tm_msg_ph: 'సెషన్‌కి సందేశం…',
    tm_admin: 'అడ్మిన్', tm_guest: 'అతిథి',
    tm_kick: 'KICK', tm_kick_ok: 'సభ్యుడు రూమ్ నుండి తీసేయబడ్డాడు (మళ్లీ క్లిక్ చేస్తే అన్‌బ్లాక్)',
    tm_role_ok: 'రోల్ అప్‌డేట్ అయింది', tm_mic_on: 'మైక్ ఆన్ చెయ్',
    tm_mic_off: 'మైక్ ఆఫ్ చెయ్', tm_mic_denied: 'మైక్ తిరస్కరించబడింది లేదా అందడం లేదు : HTTPS కావాలి (WORLD టన్నెల్ లేదా localhost) మరియు మైక్‌కి అనుమతి ఇవ్వాలి',
    navf: 'ఫ్లీట్', navfd: 'Findings',
    navp: 'ప్రోగ్రామ్‌లు', navai: 'AI',
    navc: 'సమన్వయం', st_runs: 'రన్‌లు',
    st_beacons: 'క్రియాశీల బీకాన్‌లు', st_sig: 'సిగ్నల్స్',
    h2f: 'ఫ్లీట్ - అన్ని ప్రోగ్రామ్‌లు, నడుస్తున్న ఏజెంట్లు ముందు', h2fd: 'Findings బేస్ - శాశ్వత ట్రయాజ్ ట్యాగింగ్',
    h2eng: 'ఫ్లీట్ ఇంజన్ - లోకల్ సైకిల్‌లు, టోకెన్లు లేవు', h2prog: 'ప్రోగ్రామ్‌లు - scope, అవసరమైన హెడర్, లాంచ్',
    h2new: 'కొత్త ప్రోగ్రామ్', h2ai: 'AI ఏజెంట్ - 100% ఐచ్ఛిక ఇంటిగ్రేషన్',
    h2c: 'సమన్వయం - ప్రైవేట్ ఛానల్', fl_start: 'ప్రారంభించు',
    fl_pause: 'Pause', fl_cycle: 'ఇప్పుడే సైకిల్',
    f_add: 'చేర్చు', f_none: 'ఇంకా సిగ్నల్ లేదు',
    f_ph: 'మాన్యువల్ finding : endpoint + రుజువు + సమర్థించదగిన sev…', st_sig_off: 'సిగ్నల్',
    st_sig_an: 'విశ్లేషణ', st_sig_sub: 'సమర్పించబడింది',
    st_sig_dup: 'dup', st_sig_ref: 'తిరస్కరించబడింది',
    st_sig_cl: 'మూసివేయబడింది', r_none: 'రన్ గుర్తించబడలేదు',
    r_live: '{n} నడుస్తున్నాయి', r_done: 'పూర్తయింది',
    r_feed: '▽ ఫీడ్ ({n} ev)', r_close: '△ మడవు',
    p_name_ph: 'ప్రోగ్రామ్ పేరు (ఉదా : PayPal)', p_hdr_ph: 'రీసెర్చర్ హెడర్ అవసరం (ఉదా : X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domain1, domain2, …', p_save: 'సేవ్',
    p_local: 'మాడ్యూల్(లు), 100% లోకల్', ai_p: 'C2FF మొత్తం AI లేకుండా నడుస్తుంది : మోడ్‌లు డిటర్మినిస్టిక్ లోకల్ ప్రోబ్‌లు. ఈ గేట్‌వే ఒక finding ని యాదృచ్ఛికంగా విశ్లేషించడానికి <b>నీ</b> AI ని (self-hosted లేదా API) కలపడానికి మాత్రమే : FINDINGS లో <span style="color:var(--green)">AI »</span> బటన్, సమాధానం COORDINATION లో కనిపిస్తుంది. ఈ కాన్ఫిగరేషన్ లేకుండా నీ మెషీన్ నుండి ఏ డేటా బయటకు వెళ్ళదు.',
    ai_off: 'ఆఫ్', ai_on: 'ఆన్',
    ai_st_off: 'AI ఆఫ్ - ఫ్రేమ్‌వర్క్ 100% లోకల్‌లో అది లేకుండా నడుస్తుంది', ai_st_ready: 'AI కనెక్ట్ అయింది : {p} · {m}',
    ai_st_inc: 'AI ఆన్ కానీ అసంపూర్తిగా : baseURL మరియు model అవసరం', ai_url_ph: 'base URL - ఉదా : http://localhost:11434 లేదా https://api.MyAI.tld/v1',
    ai_model_ph: 'model - ఉదా : llama3.1:8b', ai_key_ph: 'API key (లోకల్ సర్వర్ అయితే ఖాళీగా ఉంచు)',
    ai_save: 'సేవ్', ai_test: 'కనెక్షన్ పరీక్షించు',
    ai_testing: 'పరీక్ష జరుగుతోంది…', ai_ok: 'OK - స్పందన : ',
    ai_fail: 'విఫలం : ', ai_note: 'config లోకల్‌గా data/ai.json లో నిల్వ ఉంటుంది - నీవు పెట్టిన endpoint తప్ప ఎక్కడికీ పంపబడదు',
    ch_ph: 'root@c2ff:~# విశ్లేషణ ఏజెంట్‌కి సందేశం…', ch_send: 'పంపు',
    ch_empty: 'ఛానల్ తెరిచింది. ఇక్కడ టైప్ చెయ్, మానిటర్ నన్ను తక్షణమే మేల్కొల్పుతుంది.', ft: '100% లోకల్ - డిటర్మినిస్టిక్ ప్రోబ్‌లు, టోకెన్లు లేదు, బాహ్య డిపెండెన్సీలు లేవు - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE క్రియాశీలం : ప్రతి 30 నిమిషాలకు లోకల్ సైకిల్‌లు, 0 టోకెన్‌లు.', to_fl_pa: 'FLEET PAUSE - నువ్వు కోరుకున్నప్పుడు తిరిగి ప్రారంభించు.',
    to_fl_cy: 'తక్షణ సైకిల్ ప్రారంభమైంది (బడ్జెట్ 60 req).', to_launch: '[GO] {p} పై mode {m} (CWE {c}) - లోకల్ సైకిల్ ప్రారంభమైంది',
    to_ai_ok: 'config సేవ్ అయింది', to_ai_no: 'సేవ్ విఫలం',
    to_ai_no_cfg: 'AI కాన్ఫిగర్ చేయలేదు - AI ట్యాబ్‌లో సెట్ చెయ్', to_ai_head: 'AI విశ్లేషణ',
    to_ai_bad: 'AI విశ్లేషణ విఫలం', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ లాంచ్', navar: 'ఆర్సెనల్',
    ar_h2: 'ARSENAL - గుర్తించిన ఉపరితలంపై CVE, EPSS మరియు exploits', ar_sync: 'SYNC బేసులు',
    ar_btn: 'కదలికలు', ar_exec: 'EXEC',
    ar_none: 'కదలికలు లేవు: ముందుగా RECON నడపండి, తర్వాత KEV/EPSS లోడ్ చేయడానికి SYNC నడపండి', ar_loading: 'బేసుల సారాంశం లోడ్ అవుతోంది...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'డెమో ప్రోగ్రామ్ - స్కాన్ లేదు: మీ స్వంత ప్రోగ్రామ్ సృష్టించండి', pip_noprog: 'ప్రోగ్రామ్ లేదు: Programs ట్యాబ్ లో మీ ప్రోగ్రామ్ సృష్టించండి',
    pip_next: 'తదుపరి దశ:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  ml: {
    pl_title: 'ജോലി പദ്ധതി', pl_empty: 'ഇതുവരെ പദ്ധതി ഇല്ല : മുകളിലെ കാർഡിൽ RECON തുടങ്ങുക, അനുമാനങ്ങൾ ഇവിടെ വരും (സ്റ്റാറ്റസുകൾ സൂക്ഷിക്കപ്പെടും)',
    pl_run: 'തുടങ്ങുക', pl_reflect: 'canary പ്രതിഫലിച്ചു',
    st_do: 'ചെയ്യേണ്ടത്', st_test: 'പരിശോധിച്ചു',
    st_signal: 'സിഗ്നൽ', st_valid: 'സ്ഥിരീകരിച്ചു',
    st_void: 'ഒന്നുമില്ല', atk_btn: 'ATTACK',
    atk_start: 'സർഫേസ് ആക്രമണം നടക്കുന്നു : endpoints, തുറന്ന docs, JWT, secrets...', atk_fail: 'ആക്രമണം സാധ്യമല്ല : ആദ്യം RECON തുടങ്ങുക',
    atk_none: 'സിഗ്നൽ ഇല്ല', atk_findings: 'സ്ഥാനാർത്ഥികൾ',
    atk_done: 'ATTACK : തെളിവോടെ {n} P1/P2 സ്ഥാനാർത്ഥികൾ findings-ലേക്ക് ചേർത്തു', atk_empty: 'ഇതുവരെ attack ഇല്ല : RECON തുടങ്ങി പിന്നെ ATTACK - req/res തെളിവോടുള്ള സ്ഥാനാർത്ഥികൾ ഇവിടെ വരും',
    navh: 'HUNT', h2hunt: 'HUNT - യഥാർത്ഥ സർഫേസും തെളിവുകളും',
    h_ready: 'തയ്യാർ', h_empty: 'അറിയപ്പെടുന്ന സർഫേസ് ഇല്ല : പേജുകൾ, API endpoints, പാരാമുകൾ, JS bundles, സബ്ഡൊമെയിനുകൾ മാപ്പ് ചെയ്യാൻ RECON തുടങ്ങുക',
    h_fnd: 'പ്രോഗ്രാമിന്റെ findings', h_nofnd: 'ഈ പ്രോഗ്രാമിൽ finding ഇല്ല',
    rc_btn: 'RECON', rc_start: 'സർഫേസിന്റെ recon നടക്കുന്നു : പേജുകൾ, JS bundles, endpoints, പാരാമുകൾ...',
    rc_done: 'സർഫേസ് മാപ്പ് ചെയ്തു : endpoints, പാരാമുകൾ, സബ്ഡൊമെയിനുകൾ പ്രോഗ്രാം കാർഡിൽ പട്ടികപ്പെടുത്തി', rc_fail: 'recon പരാജയം : host എത്താനാകുന്നില്ല അല്ലെങ്കിൽ scope ശൂന്യം',
    rc_surface: 'സർഫേസ് :', snd_on: 'സൗണ്ട് : ON',
    snd_off: 'സൗണ്ട് : OFF', snd_ok: 'ഇന്റർഫേസ് സൗണ്ടുകൾ ഓണാണ് - ലൈബ്രറി : click, tab, copy, അലേർട്ടുകൾ',
    snd_stop: 'പൂർണ മ്യൂട്ട് സജീവം : ഇനി C2FF ശബ്ദമില്ല', amb_on: 'അന്തരീക്ഷം : ON',
    amb_off: 'അന്തരീക്ഷം : OFF', amb_ok: 'ജീവനുള്ള അന്തരീക്ഷം - നിറത്തിന്റെ തണൽ പതുക്കെ കുടുംബങ്ങൾക്കിടയിലൂടെ നീങ്ങുന്നു (പച്ച, നീല, മഞ്ഞ...)',
    amb_stop: 'അന്തരീക്ഷം ഒറിജിനൽ പച്ചയിൽ ഉറച്ചു', nt_on: 'നോട്ടിഫ് : ON',
    nt_off: 'നോട്ടിഫ് : OFF', nt_ok: 'ബ്രൗസർ നോട്ടിഫിക്കേഷനുകൾ ഓണാണ് - P1-ലും P2-ലും ബീപ്പ്',
    nt_denied: 'ബ്രൗസർ നോട്ടിഫിക്കേഷനുകൾ തടഞ്ഞു : സൈറ്റ് സെറ്റിംഗ്സിൽ അനുവദിക്കുക', term_denied: 'ടെർമിനൽ നിരസിക്കപ്പെട്ടു അല്ലെങ്കിൽ ലഭ്യമല്ല : localhost വേണം, അല്ലെങ്കിൽ അഡ്മിനായി തുറന്ന റൂം',
    term_p: 'യഥാർത്ഥ bash - അമ്പുകളിലൂടെ history, Ctrl+C തടയുന്നു, Ctrl+D അടയ്ക്കുന്നു', term_restart: 'പുനഃസജ്ജമാക്കുക',
    navtrm: 'TERM', term_h2: 'ടെർമിനൽ - ജോലി ഷെൽ, നേരിട്ട് കൺസോളിൽ',
    fl_off: 'FLEET : നിർത്തി', fl_paused: 'FLEET : PAUSE',
    fl_active: 'FLEET : സജീവം ({n} സൈക്കിൾ)', fl_last: 'അവസാന സൈക്കിൾ',
    fl_none: 'ഇതുവരെ സൈക്കിൾ ഇല്ല', fl_info: '{i} മിനിറ്റ് ഇടവേള, {b} req/സൈക്കിൾ',
    sub_ttl: 'command & control framework', navt: 'സെഷൻ',
    tm_h2: 'ഗ്രൂപ്പ് സെഷനുകൾ - ഒരുമിച്ച് വേട്ട, നെറ്റ്വർക്ക് ഇല്ലാതെയും', tm_p: 'പങ്കിട്ട റൂം തുറക്കുക : നിന്റെ ഗ്രൂപ്പിന് fleet, findings കാണാം, ലൈവ് ട്രയാജ് ചെയ്യാം. താഴെ പ്രത്യേക സെഷൻ ചാറ്റ്. മൂന്ന് ആക്സസ് നിലകൾ : LOCAL (ഒറ്റയ്ക്ക്), നെറ്റ്വർക്കിലേക്ക് തുറക്കുന്നതിലൂടെ LAN, ലോകത്തിലേക്ക് തുറക്കുന്നതിലൂടെ WORLD - ഒരു പബ്ലിക് ടണൽ (cloudflared ഇൻസ്റ്റാൾ ഉണ്ടെങ്കിൽ) ക്ഷണ ലിങ്കിനെ ഏത് നെറ്റ്വർക്കിൽ നിന്നും സാധുവാക്കും, നിന്റെ മെഷീൻ നേരിട്ട് തുറന്നുകാട്ടാതെ. എല്ലാം റൂം കീയിലൂടെയാണ് - ഒറ്റനോട്ടത്തിൽ എല്ലാവരെയും പുറത്താക്കാൻ അത് വീണ്ടും സൃഷ്ടിക്കുക.',
    tm_handle: 'നിന്റെ പേര് (പരമാവധി 16 അക്ഷരം)', tm_save_h: 'സെറ്റ്',
    tm_room_ph: 'റൂമിന്റെ പേര് (ഉദാ : c2ff-core)', tm_save: 'ബാധകമാക്കുക',
    tm_on: 'റൂം തുറന്നു : {r} - {n} ഓൺലൈൻ', tm_off: 'TEAM MODE ഓഫ് - ലോക്കൽ ഒറ്റ സെഷൻ',
    tm_room: 'റൂം', tm_key: 'റൂം കീ',
    tm_regen: 'കീ വീണ്ടും സൃഷ്ടിക്കുക', tm_regen_ok: 'പുതിയ കീ സൃഷ്ടിച്ചു - പഴയ ലിങ്കുകൾ മരിച്ചു',
    tm_invite: 'ക്ഷണ ലിങ്ക് (ടീമിന് കോപ്പി ചെയ്യുക)', tm_copy: 'കോപ്പി',
    tm_copied: 'ക്ലിപ്ബോർഡിലേക്ക് കോപ്പി ചെയ്തു', tm_members: 'അംഗങ്ങൾ',
    tm_nobody: 'ഇതുവരെ ആരുമില്ല - ടീമിന് ലിങ്ക് അയക്കുക', tm_you: '(നീ)',
    tm_here: 'ഇവിടെ', tm_saved: 'പേര് സേവ് ചെയ്തു',
    tm_no_handle: 'പേര് ശൂന്യം', tm_cfg_ok: 'റൂം അപ്ഡേറ്റ് ചെയ്തു',
    tm_cfg_no: 'പരാജയം', tm_live: 'നെറ്റ്വർക്കിലേക്ക് തുറക്കുക',
    tm_shore: 'ലോക്കലിലേക്ക് മടങ്ങുക', tm_need_on: 'ആദ്യം റൂം ഓൺ ചെയ്യുക (ON)',
    tm_bind_lan: 'NETWORK : {a}', tm_bind_lo: 'LOCAL : localhost മാത്രം',
    to_team_live: '[GO-LIVE] നെറ്റ്വർക്ക് ആക്സസോടെ സെർവർ വീണ്ടും ആരംഭിച്ചു - LAN ലിങ്ക് കാണിക്കുന്നു, 2 സെക്കൻഡിൽ വീണ്ടും കണക്റ്റ്', to_team_shore: 'സെർവർ ലോക്കലിൽ (127.0.0.1) വീണ്ടും ആരംഭിച്ചു',
    tm_tun_open: 'ലോകത്തിലേക്ക് തുറക്കുക (ടണൽ)', tm_tun_close: 'ടണൽ അടയ്ക്കുക',
    tm_tun_wait: 'പബ്ലിക് ടണൽ തുറക്കുന്നു (കുറച്ച് സെക്കൻഡുകൾ)…', tm_tun_on: 'സെഷൻ ലോകത്തിലേക്ക് തുറന്നു : {u} - ക്ഷണ ലിങ്ക് എവിടെ നിന്നും പ്രവർത്തിക്കും, ഒരേ നെറ്റ്വർക്ക് ആവശ്യമില്ല',
    tm_tun_closed: 'ടണൽ അടച്ചു - LAN/ലോക്കലിലേക്ക് തിരിച്ചു', tm_chat_empty: 'സെഷൻ ചാനൽ തുറന്നു - റൂം അംഗങ്ങൾ ഇവിടെ പരസ്പരം വായിക്കുന്നു',
    tm_chat_h2: 'സെഷൻ ചാറ്റ്', tm_msg_ph: 'സെഷനിലേക്ക് സന്ദേശം…',
    tm_admin: 'അഡ്മിൻ', tm_guest: 'അതിഥി',
    tm_kick: 'KICK', tm_kick_ok: 'അംഗത്തെ റൂമിൽ നിന്ന് പുറത്താക്കി (വീണ്ടും ക്ലിക്ക് ചെയ്താൽ അൺലോക്ക്)',
    tm_role_ok: 'റോൾ അപ്ഡേറ്റ് ചെയ്തു', tm_mic_on: 'മൈക്ക് ഓൺ ചെയ്യുക',
    tm_mic_off: 'മൈക്ക് ഓഫ് ചെയ്യുക', tm_mic_denied: 'മൈക്ക് നിരസിക്കപ്പെട്ടു അല്ലെങ്കിൽ ലഭ്യമല്ല : HTTPS വേണം (WORLD ടണൽ അല്ലെങ്കിൽ localhost), മൈക്കിന് അനുമതി നൽകണം',
    navf: 'ഫ്ലീറ്റ്', navfd: 'Findings',
    navp: 'പ്രോഗ്രാമുകൾ', navai: 'AI',
    navc: 'ഏകോപനം', st_runs: 'റൺസ്',
    st_beacons: 'സജീവ ബീക്കണുകൾ', st_sig: 'സിഗ്നലുകൾ',
    h2f: 'ഫ്ലീറ്റ് - എല്ലാ പ്രോഗ്രാമുകളും, ഓടുന്ന ഏജന്റുകൾ ആദ്യം', h2fd: 'Findings ബേസ് - സ്ഥിര ട്രയാജ് ടാഗിംഗ്',
    h2eng: 'ഫ്ലീറ്റ് എഞ്ചിൻ - ലോക്കൽ സൈക്കിളുകൾ, ടോക്കണില്ല', h2prog: 'പ്രോഗ്രാമുകൾ - scope, ആവശ്യമുള്ള ഹെഡർ, ലോഞ്ച്',
    h2new: 'പുതിയ പ്രോഗ്രാം', h2ai: 'AI ഏജന്റ് - 100% ഓപ്ഷണൽ ഇന്റഗ്രേഷൻ',
    h2c: 'ഏകോപനം - സ്വകാര്യ ചാനൽ', fl_start: 'ആരംഭിക്കുക',
    fl_pause: 'Pause', fl_cycle: 'ഇപ്പോൾ സൈക്കിൾ',
    f_add: 'ചേർക്കുക', f_none: 'ഇതുവരെ സിഗ്നൽ ഇല്ല',
    f_ph: 'മാനുവൽ finding : endpoint + തെളിവ് + ന്യായീകരിക്കാവുന്ന sev…', st_sig_off: 'സിഗ്നൽ',
    st_sig_an: 'വിശകലനം', st_sig_sub: 'സമർപ്പിച്ചു',
    st_sig_dup: 'dup', st_sig_ref: 'നിരസിച്ചു',
    st_sig_cl: 'അടച്ചു', r_none: 'റൺ കണ്ടെത്തിയില്ല',
    r_live: '{n} ഓടുന്നു', r_done: 'പൂർത്തിയായി',
    r_feed: '▽ ഫീഡ് ({n} ev)', r_close: '△ മടക്കുക',
    p_name_ph: 'പ്രോഗ്രാമിന്റെ പേര് (ഉദാ : PayPal)', p_hdr_ph: 'റിസർച്ചർ ഹെഡർ ആവശ്യമാണ് (ഉദാ : X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domain1, domain2, …', p_save: 'സേവ്',
    p_local: 'മൊഡ്യൂൾ(കൾ), 100% ലോക്കൽ', ai_p: 'C2FF മുഴുവനായി AI ഇല്ലാതെ പ്രവർത്തിക്കുന്നു : മോഡുകൾ ഡിറ്റർമിനിസ്റ്റിക് ലോക്കൽ പ്രോബുകളാണ്. ഈ ഗേറ്റ്‌വേ ഒരു finding ആവശ്യാനുസരണം വിശകലനം ചെയ്യാൻ <b>നിന്റെ</b> AI (self-hosted അല്ലെങ്കിൽ API) ഘടിപ്പിക്കാൻ മാത്രം : FINDINGS-ലെ <span style="color:var(--green)">AI »</span> ബട്ടൺ, മറുപടി COORDINATION-ൽ കാണിക്കും. ഈ കോൺഫിഗറേഷൻ ഇല്ലാതെ നിന്റെ മെഷീനിൽ നിന്ന് ഒരു ഡാറ്റയും പുറത്തുപോകില്ല.',
    ai_off: 'ഓഫ്', ai_on: 'ഓൺ',
    ai_st_off: 'AI ഓഫ് - ഫ്രെയിംവർക്ക് 100% ലോക്കലിൽ അതില്ലാതെ പ്രവർത്തിക്കുന്നു', ai_st_ready: 'AI കണക്റ്റഡ് : {p} · {m}',
    ai_st_inc: 'AI ഓൺ പക്ഷേ അപൂർണം : baseURL, model ആവശ്യമാണ്', ai_url_ph: 'base URL - ഉദാ : http://localhost:11434 അല്ലെങ്കിൽ https://api.MyAI.tld/v1',
    ai_model_ph: 'model - ഉദാ : llama3.1:8b', ai_key_ph: 'API key (ലോക്കൽ സെർവർ ആണെങ്കിൽ ശൂന്യമാക്കി വെക്കുക)',
    ai_save: 'സേവ്', ai_test: 'കണക്ഷൻ പരിശോധിക്കുക',
    ai_testing: 'പരിശോധന നടക്കുന്നു…', ai_ok: 'OK - മറുപടി : ',
    ai_fail: 'പരാജയം : ', ai_note: 'config ലോക്കലായി data/ai.json-ൽ സൂക്ഷിക്കുന്നു - നീ വെക്കുന്ന endpoint ഒഴികെ മറ്റൊരിടത്തേക്കും അയക്കില്ല',
    ch_ph: 'root@c2ff:~# വിശകലന ഏജന്റിന് സന്ദേശം…', ch_send: 'അയക്കുക',
    ch_empty: 'ചാനൽ തുറന്നു. ഇവിടെ ടൈപ്പ് ചെയ്യുക, മോണിറ്റർ എന്നെ ഉടനടി ഉണർത്തും.', ft: '100% ലോക്കൽ - ഡിറ്റർമിനിസ്റ്റിക് പ്രോബുകൾ, ടോക്കണില്ല, ബാഹ്യ ഡിപൻഡൻസിയില്ല - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE സജീവം : ഓരോ 30 മിനിറ്റിലും ലോക്കൽ സൈക്കിളുകൾ, 0 ടോക്കൺ.', to_fl_pa: 'FLEET PAUSE - വേണമെങ്കിൽ എപ്പോഴും വീണ്ടും തുടങ്ങാം.',
    to_fl_cy: 'ഉടനടി സൈക്കിൾ ആരംഭിച്ചു (ബജറ്റ് 60 req).', to_launch: '[GO] {p}-ൽ mode {m} (CWE {c}) - ലോക്കൽ സൈക്കിൾ ആരംഭിച്ചു',
    to_ai_ok: 'config സേവ് ചെയ്തു', to_ai_no: 'സേവ് പരാജയം',
    to_ai_no_cfg: 'AI കോൺഫിഗർ ചെയ്തിട്ടില്ല - AI ടാബിൽ സെറ്റ് ചെയ്യുക', to_ai_head: 'AI വിശകലനം',
    to_ai_bad: 'AI വിശകലനം പരാജയം', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ ലോഞ്ച്', navar: 'ആർസനൽ',
    ar_h2: 'ARSENAL - കണ്ടെത്തിയ ഉപരിതലത്തിൽ CVE, EPSS, exploits', ar_sync: 'SYNC ബേസുകൾ',
    ar_btn: 'നീക്കങ്ങൾ', ar_exec: 'EXEC',
    ar_none: 'നീക്കങ്ങളില്ല: ആദ്യം RECON പ്രവർത്തിപ്പിക്കുക, പിന്നെ KEV/EPSS ലോഡ് ചെയ്യാൻ SYNC', ar_loading: 'ബേസുകളുടെ സംഗ്രഹം ലോഡ് ചെയ്യുന്നു...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'ഡെമോ പ്രോഗ്രാം - സ്കാൻ ഇല്ല : സ്വന്തമൊരു പ്രോഗ്രാം ഉണ്ടാക്കുക', pip_noprog: 'പ്രോഗ്രാം ഇല്ല : പ്രോഗ്രാമുകൾ ടാബിൽ സ്വന്തമൊരു പ്രോഗ്രാം ഉണ്ടാക്കുക',
    pip_next: 'അടുത്ത ഘട്ടം :', fnd_n: 'ഫൈൻഡിങ്സ്: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  mr: {
    pl_title: 'कामाचा नकाशा', pl_empty: 'अजून नकाशा नाही : वरील कार्डमध्ये RECON चालवा, गृहितके इथे येतील (स्टेटस जतन होतील)',
    pl_run: 'चालवा', pl_reflect: 'canary परतफेकला',
    st_do: 'करायचे', st_test: 'तपासले',
    st_signal: 'सिग्नल', st_valid: 'पुष्टी',
    st_void: 'काहीही नाही', atk_btn: 'ATTACK',
    atk_start: 'सरफेसवर हल्ला सुरू आहे : endpoints, उघड docs, JWT, secrets...', atk_fail: 'हल्ला अशक्य : आधी RECON चालवा',
    atk_none: 'सिग्नल नाही', atk_findings: 'उमेदवार',
    atk_done: 'ATTACK : पुराव्यासह {n} P1/P2 उमेदवार findings मध्ये टाकले', atk_empty: 'अजून attack नाही : RECON चालवा पुढे ATTACK - req/res पुराव्यासह उमेदवार इथे येतील',
    navh: 'HUNT', h2hunt: 'HUNT - खरा सरफेस आणि पुरावे',
    h_ready: 'तयार', h_empty: 'ज्ञात सरफेस नाही : पाने, API endpoints, पॅराम्स, JS bundles आणि सबडोमेन नकाशी करण्यासाठी RECON चालवा',
    h_fnd: 'प्रोग्रामचे findings', h_nofnd: 'या प्रोग्राममध्ये finding नाही',
    rc_btn: 'RECON', rc_start: 'सरफेसचा recon सुरू आहे : पाने, JS bundles, endpoints, पॅराम्स...',
    rc_done: 'सरफेस नकाशी झाली : endpoints, पॅराम्स आणि सबडोमेन प्रोग्राम कार्डमध्ये दिले', rc_fail: 'recon अयशस्वी : host पोहोचत नाही किंवा scope रिकामा',
    rc_surface: 'सरफेस :', snd_on: 'साऊंड : ON',
    snd_off: 'साऊंड : OFF', snd_ok: 'इंटरफेस साऊंड चालू - लायब्ररी : click, tab, copy, अलर्ट',
    snd_stop: 'पूर्ण म्यूट सुरू : आता C2FF चा एकही आवाज नाही', amb_on: 'वातावरण : ON',
    amb_off: 'वातावरण : OFF', amb_ok: 'जिवंत वातावरण - रंगाचा छटा हळूहळू कुटुंबांमधून फिरतो (हिरवा, निळा, पिवळा...)',
    amb_stop: 'वातावरण मूळ हिरव्यावर खुणावले', nt_on: 'नोटिफ : ON',
    nt_off: 'नोटिफ : OFF', nt_ok: 'ब्राउझर नोटिफिकेशन चालू - P1 आणि P2 वर बीप',
    nt_denied: 'ब्राउझरने नोटिफिकेशन अवरोधले : साइट सेटिंग्समध्ये परवानगी द्या', term_denied: 'टर्मिनल नाकारला किंवा उपलब्ध नाही : localhost आवश्यक, किंवा अ‍ॅडमिन म्हणून उघड असलेली रूम',
    term_p: 'खरी bash - बाणांनी history, Ctrl+C तोडतो, Ctrl+D बंद करतो', term_restart: 'रीसेट',
    navtrm: 'TERM', term_h2: 'टर्मिनल - कामाची शेल, थेट कन्सोलमध्ये',
    fl_off: 'FLEET : थांबले', fl_paused: 'FLEET : PAUSE',
    fl_active: 'FLEET : सक्रिय ({n} सायकल)', fl_last: 'शेवटचे सायकल',
    fl_none: 'अजून सायकल नाही', fl_info: '{i} मिनिटे अंतराळ, {b} req/सायकल',
    sub_ttl: 'command & control framework', navt: 'सेशन',
    tm_h2: 'ग्रुप सेशन - सोबत शिकार, नेटवर्क नसतानाही', tm_p: 'शेअर केलेली रूम उघडा : तुझ्या ग्रुपला fleet, findings दिसतील आणि लाइव्ह ट्रायाज करता येईल. खाली स्वतंत्र सेशन चॅट. तीन प्रवेश स्तर : LOCAL (एकटा), नेटवर्कला उघडणे म्हणजे LAN, आणि जगाला उघडणे म्हणजे WORLD - सार्वजनिक टनेल (cloudflared इन्स्टॉल असल्यास) आमंत्रण लिंक कोणत्याही नेटवर्कवरून वैध ठेवतो, तुझी मशीन थेट उघड न करता. सगळं रूम कीवर आहे - एका क्षणात सगळ्यांना बाहेर काढण्यासाठी ती पुन्हा तयार करा.',
    tm_handle: 'तुझे नाव (जास्तीत जास्त 16 अक्षरे)', tm_save_h: 'सेट',
    tm_room_ph: 'रूमचे नाव (उदा : c2ff-core)', tm_save: 'लागू करा',
    tm_on: 'रूम उघडी आहे : {r} - {n} ऑनलाइन', tm_off: 'TEAM MODE बंद - स्थानिक एकट्याचे सेशन',
    tm_room: 'रूम', tm_key: 'रूम की',
    tm_regen: 'की पुन्हा तयार करा', tm_regen_ok: 'नवीन की तयार - जुने लिंक मृत',
    tm_invite: 'आमंत्रण लिंक (टीमकडे कॉपी करा)', tm_copy: 'कॉपी',
    tm_copied: 'क्लिपबोर्डवर कॉपी झाले', tm_members: 'सदस्य',
    tm_nobody: 'अजून कोणी नाही - टीमला लिंक पाठवा', tm_you: '(तू)',
    tm_here: 'इथे', tm_saved: 'नाव सेव्ह झाले',
    tm_no_handle: 'नाव रिकामे', tm_cfg_ok: 'रूम अपडेट झाली',
    tm_cfg_no: 'अयशस्वी', tm_live: 'नेटवर्कला उघडा',
    tm_shore: 'स्थानिक मोडमध्ये परत', tm_need_on: 'आधी रूम चालू करा (ON)',
    tm_bind_lan: 'NETWORK : {a}', tm_bind_lo: 'LOCAL : फक्त localhost',
    to_team_live: '[GO-LIVE] नेटवर्क प्रवेशासह सर्व्हर पुन्हा सुरू झाला - LAN लिंक दाखवत आहे, 2 सेकंदात पुन्हा कनेक्ट', to_team_shore: 'सर्व्हर स्थानिक (127.0.0.1) पुन्हा सुरू झाला',
    tm_tun_open: 'जगाला उघडा (टनेल)', tm_tun_close: 'टनेल बंद करा',
    tm_tun_wait: 'सार्वजनिक टनेल उघडत आहे (काही सेकंद)…', tm_tun_on: 'सेशन जगाला उघडे : {u} - आमंत्रण लिंक कुठूनही चालेल, एकच नेटवर्क लागणार नाही',
    tm_tun_closed: 'टनेल बंद - नेटवर्क/स्थानिक मोडमध्ये परत', tm_chat_empty: 'सेशन चॅनेल उघडे - रूमचे सदस्य इथे एकमेकांना वाचतात',
    tm_chat_h2: 'सेशन चॅट', tm_msg_ph: 'सेशनकडे संदेश…',
    tm_admin: 'अ‍ॅडमिन', tm_guest: 'पाहुणा',
    tm_kick: 'KICK', tm_kick_ok: 'सदस्य रूममधून बाहेर काढला (पुन्हा क्लिक केल्यास अनलॉक)',
    tm_role_ok: 'भूमिका अपडेट झाली', tm_mic_on: 'मायक चालू करा',
    tm_mic_off: 'मायक बंद करा', tm_mic_denied: 'मायक नाकारला किंवा उपलब्ध नाही : HTTPS आवश्यक (WORLD टनेल किंवा localhost) आणि मायकला परवानगी द्यावी लागेल',
    navf: 'फ्लीट', navfd: 'Findings',
    navp: 'प्रोग्राम', navai: 'AI',
    navc: 'समन्वय', st_runs: 'रन्स',
    st_beacons: 'सक्रिय बीकन', st_sig: 'सिग्नल',
    h2f: 'फ्लीट - सर्व प्रोग्राम, चालू एजंट आधी', h2fd: 'Findings बेस - कायम ट्रायाज टॅगिंग',
    h2eng: 'फ्लीट इंजिन - स्थानिक सायकल, टोकन नाही', h2prog: 'प्रोग्राम - scope, आवश्यक हेडर, लॉन्च',
    h2new: 'नवीन प्रोग्राम', h2ai: 'AI एजंट - 100% ऐच्छिक जोडणी',
    h2c: 'समन्वय - खाजगी चॅनेल', fl_start: 'सुरू करा',
    fl_pause: 'Pause', fl_cycle: 'आत्ताच सायकल',
    f_add: 'जोडा', f_none: 'अजून सिग्नल नाही',
    f_ph: 'मॅन्युअल finding : endpoint + पुरावा + वादग्रस्त असण्यायोग्य sev…', st_sig_off: 'सिग्नल',
    st_sig_an: 'विश्लेषण', st_sig_sub: 'सबमिट झाले',
    st_sig_dup: 'dup', st_sig_ref: 'नाकारले',
    st_sig_cl: 'बंद केले', r_none: 'रन आढळला नाही',
    r_live: '{n} चालू आहेत', r_done: 'संपले',
    r_feed: '▽ फीड ({n} ev)', r_close: '△ घडवा',
    p_name_ph: 'प्रोग्रामचे नाव (उदा : PayPal)', p_hdr_ph: 'रिसर्चर हेडर आवश्यक (उदा : X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domain1, domain2, …', p_save: 'सेव्ह',
    p_local: 'मॉड्यूल, 100% स्थानिक', ai_p: 'C2FF पूर्णपणे AI शिवाय चालते : मोड्स नियतकालिक स्थानिक प्रोब्स आहेत. हे गेटवे फक्त एका finding चे वेळोवेळी विश्लेषण करण्यासाठी <b>तुझा</b> AI (self-hosted किंवा API) जोडण्यासाठी आहे : FINDINGS मधील <span style="color:var(--green)">AI »</span> बटण, उत्तर COORDINATION मध्ये दिसेल. या कॉन्फिगरेशन शिवाय तुझ्या मशीनमधून एकही डेटा बाहेर पडत नाही.',
    ai_off: 'अक्षम', ai_on: 'सक्रिय',
    ai_st_off: 'AI बंद - फ्रेमवर्क 100% स्थानिक त्याशिवाय चालते', ai_st_ready: 'AI जोडले : {p} · {m}',
    ai_st_inc: 'AI चालू पण अपूर्ण : baseURL आणि model आवश्यक', ai_url_ph: 'base URL - उदा : http://localhost:11434 किंवा https://api.MyAI.tld/v1',
    ai_model_ph: 'model - उदा : llama3.1:8b', ai_key_ph: 'API key (लोकल सर्व्हर असल्यास रिकामे ठेवा)',
    ai_save: 'सेव्ह', ai_test: 'कनेक्शन तपासा',
    ai_testing: 'तपासणी सुरू…', ai_ok: 'OK - उत्तर : ',
    ai_fail: 'अयशस्वी : ', ai_note: 'config स्थानिक data/ai.json मध्ये जतन - तू ठेवलेल्या endpoint व्यतिरिक्त इतरत्र कधीही पाठवला जात नाही',
    ch_ph: 'root@c2ff:~# विश्लेषण एजंटकडे संदेश…', ch_send: 'पाठवा',
    ch_empty: 'चॅनेल उघडे आहे. इथे टाइप करा, मॉनिटर मला लगेच जगावतो.', ft: '100% स्थानिक - नियतकालिक प्रोब्स, टोकन नाही, बाह्य अवलंबन नाही - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE सक्रिय : दर 30 मिनिटांनी स्थानिक सायकल, 0 टोकन.', to_fl_pa: 'FLEET PAUSE - हवं तेव्हा पुन्हा सुरू करा.',
    to_fl_cy: 'तात्काळ सायकल सुरू (बजेट 60 req).', to_launch: '[GO] {p} वर mode {m} (CWE {c}) - स्थानिक सायकल सुरू',
    to_ai_ok: 'config सेव्ह झाला', to_ai_no: 'सेव्ह अयशस्वी',
    to_ai_no_cfg: 'AI कॉन्फिगर नाही - AI टॅबमध्ये सेट करा', to_ai_head: 'AI विश्लेषण',
    to_ai_bad: 'AI विश्लेषण अयशस्वी', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ लॉन्च', navar: 'आर्सेनल',
    ar_h2: 'ARSENAL - आढावलेल्या पृष्ठभागावर CVE, EPSS आणि exploits', ar_sync: 'SYNC बेस',
    ar_btn: 'चाली', ar_exec: 'EXEC',
    ar_none: 'चाली नाहीत: आधी RECON चालवा, नंतर KEV/EPSS लोड करण्यासाठी SYNC चालवा', ar_loading: 'बेसचा सारांश लोड होत आहे...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'डेमो प्रोग्राम - स्कॅन नाही : तुझा प्रोग्राम बनव', pip_noprog: 'अजून प्रोग्राम नाही : प्रोग्राम्स टॅबमध्ये तुझा बनव',
    pip_next: 'पुढील टप्पा :', fnd_n: 'फाइंडिंग्ज: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  gu: {
    pl_title: 'કામનો પ્લાન', pl_empty: 'હજી પ્લાન નથી : ઉપરના કાર્ડમાં RECON ચલાવો, અનુમાનો અહીં આવશે (સ્ટેટસ જળવાશે)',
    pl_run: 'ચલાવો', pl_reflect: 'canary પરત ધારિયો',
    st_do: 'કરવાનું', st_test: 'તપાસાયું',
    st_signal: 'સિગ્નલ', st_valid: 'પુષ્ટિ',
    st_void: 'કંઈ નથી', atk_btn: 'ATTACK',
    atk_start: 'સરફેસ પર હુમલો ચાલુ : endpoints, ખુલ્લા docs, JWT, secrets...', atk_fail: 'હુમલો અશક્ય : પહેલા RECON ચલાવો',
    atk_none: 'સિગ્નલ નથી', atk_findings: 'ઉમેદવારો',
    atk_done: 'ATTACK : પુરાવા સાથે {n} P1/P2 ઉમેદવારો findings માં નાખ્યા', atk_empty: 'હજી attack નથી : RECON ચલાવો પછી ATTACK - req/res પુરાવા સાથેના ઉમેદવારો અહીં આવશે',
    navh: 'HUNT', h2hunt: 'HUNT - સાચો સરફેસ અને પુરાવા',
    h_ready: 'તૈયાર', h_empty: 'જાણીતો સરફેસ નથી : પેજ, API endpoints, પેરામ, JS bundles અને સબડોમેઇન નકશી કરવા RECON ચલાવો',
    h_fnd: 'પ્રોગ્રામના findings', h_nofnd: 'આ પ્રોગ્રામમાં finding નથી',
    rc_btn: 'RECON', rc_start: 'સરફેસનું recon ચાલી રહ્યું છે : પેજ, JS bundles, endpoints, પેરામ...',
    rc_done: 'સરફેસ નકશી થઈ : endpoints, પેરામ અને સબડોમેઇન પ્રોગ્રામ કાર્ડમાં યાદીમાં', rc_fail: 'recon નિષ્ફળ : host સુધી પહોંચ નથી કે scope ખાલી',
    rc_surface: 'સરફેસ :', snd_on: 'સાઉન્ડ : ON',
    snd_off: 'સાઉન્ડ : OFF', snd_ok: 'ઇન્ટરફેસ સાઉન્ડ ચાલુ - લાઇબ્રેરી : click, tab, copy, અલર્ટ',
    snd_stop: 'સંપૂર્ણ મ્યુટ ચાલુ : હવે C2FF નો કોઈ અવાજ નહીં', amb_on: 'વાતાવરણ : ON',
    amb_off: 'વાતાવરણ : OFF', amb_ok: 'જીવંત વાતાવરણ - રંગનો છાંયડો ધીમે ધીમે કુટુંબોમાંથી ફરે છે (લીલો, વાદળી, પીળો...)',
    amb_stop: 'વાતાવરણ મૂળ લીલા પર જામ્યું', nt_on: 'નોટિફ : ON',
    nt_off: 'નોટિફ : OFF', nt_ok: 'બ્રાઉઝર નોટિફિકેશન ચાલુ - P1 અને P2 પર બીપ',
    nt_denied: 'બ્રાઉઝરે નોટિફિકેશન અટકાવ્યા : સાઇટ સેટિંગ્સમાં પરવાનગી આપો', term_denied: 'ટર્મિનલ નકારાયો કે અનુપલબ્ધ : localhost જરૂરી, અથવા એડમિન તરીકે ખુલ્લો રૂમ',
    term_p: 'ખરી bash - તીરથી history, Ctrl+C તોડે છે, Ctrl+D બંધ કરે છે', term_restart: 'રીસેટ',
    navtrm: 'TERM', term_h2: 'ટર્મિનલ - કામની શેલ, સીધા કન્સોલમાં',
    fl_off: 'FLEET : અટક્યું', fl_paused: 'FLEET : PAUSE',
    fl_active: 'FLEET : સક્રિય ({n} સાયકલ)', fl_last: 'છેલ્લો સાયકલ',
    fl_none: 'હજી સાયકલ નથી', fl_info: '{i} મિનિટ ગાળો, {b} req/સાયકલ',
    sub_ttl: 'command & control framework', navt: 'સેશન',
    tm_h2: 'ગ્રુપ સેશન - સાથે શિકાર, નેટવર્ક વગર પણ', tm_p: 'શેર કરેલો રૂમ ખોલો : તારા ગ્રુપને fleet, findings દેખાશે અને લાઇવ ટ્રાયાજ કરી શકશે. નીચે અલગ સેશન ચેટ. ત્રણ એક્સેસ સ્તર : LOCAL (એકલા), નેટવર્કમાં ખોલવાથી LAN, અને વિશ્વ સામે ખોલવાથી WORLD - પબ્લિક ટનલ (cloudflared ઇન્સ્ટોલ હોય તો) ઇન્વાઇટ લિંક કોઈપણ નેટવર્કમાંથી માન્ય રાખે છે, તારી મશીન સીધી ખુલ્લી કર્યા વિના. બધું રૂમ કી પર ખુલે છે - એક જ મિજાસમાં બધાને બહાર કાઢવા તે ફરી બનાવો.',
    tm_handle: 'તારું નામ (મહત્તમ 16 અક્ષર)', tm_save_h: 'સેટ',
    tm_room_ph: 'રૂમનું નામ (જેમ : c2ff-core)', tm_save: 'લાગુ કરો',
    tm_on: 'રૂમ ખુલ્લો છે : {r} - {n} ઓનલાઇન', tm_off: 'TEAM MODE બંધ - સ્થાનિક ખાનગી સેશન',
    tm_room: 'રૂમ', tm_key: 'રૂમ કી',
    tm_regen: 'કી ફરી બનાવો', tm_regen_ok: 'નવી કી બની - જૂના લિંક મરી ગયા',
    tm_invite: 'ઇન્વાઇટ લિંક (ટીમ પાસે કોપી કરો)', tm_copy: 'કોપી',
    tm_copied: 'ક્લિપબોર્ડમાં કોપી થયો', tm_members: 'સભ્યો',
    tm_nobody: 'હજી કોઈ નથી - ટીમને લિંક મોકલો', tm_you: '(તું)',
    tm_here: 'અહીં', tm_saved: 'નામ સેવ થયું',
    tm_no_handle: 'નામ ખાલી', tm_cfg_ok: 'રૂમ અપડેટ થયો',
    tm_cfg_no: 'નિષ્ફળ', tm_live: 'નેટવર્ક સામે ખોલો',
    tm_shore: 'સ્થાનિક મોડ પર પાછો', tm_need_on: 'પહેલા રૂમ ચાલુ કરો (ON)',
    tm_bind_lan: 'NETWORK : {a}', tm_bind_lo: 'LOCAL : ફક્ત localhost',
    to_team_live: '[GO-LIVE] નેટવર્ક એક્સેસ સાથે સર્વર ફરી શરૂ થયો - LAN લિંક બતાવાય છે, 2 સુમાં ફરી કનેક્ટ', to_team_shore: 'સર્વર સ્થાનિક (127.0.0.1) ફરી શરૂ થયો',
    tm_tun_open: 'વિશ્વ સામે ખોલો (ટનલ)', tm_tun_close: 'ટનલ બંધ કરો',
    tm_tun_wait: 'પબ્લિક ટનલ ખુલી રહ્યું છે (થોડી સેકંડ)…', tm_tun_on: 'સેશન વિશ્વ સામે ખુલ્લો : {u} - ઇન્વાઇટ લિંક ગમે ત્યાંથી ચાલશે, એક જ નેટવર્કની જરૂર નથી',
    tm_tun_closed: 'ટનલ બંધ - નેટવર્ક/સ્થાનિક મોડ પર પાછો', tm_chat_empty: 'સેશન ચેનલ ખુલ્લી - રૂમના સભ્યો અહીં એકબીજાને વાંચે છે',
    tm_chat_h2: 'સેશન ચેટ', tm_msg_ph: 'સેશન તરફ સંદેશ…',
    tm_admin: 'એડમિન', tm_guest: 'મહેમાન',
    tm_kick: 'KICK', tm_kick_ok: 'સભ્યને રૂમમાંથી બહાર કાઢયો (ફરી ક્લિક કરવાથી અનલોક)',
    tm_role_ok: 'ભૂમિકા અપડેટ થઈ', tm_mic_on: 'માઇક ચાલુ કરો',
    tm_mic_off: 'માઇક બંધ કરો', tm_mic_denied: 'માઇક નકારાયો કે અનુપલબ્ધ : HTTPS જરૂરી (WORLD ટનલ અથવા localhost) અને માઇકને પરવાનગી આપવી પડશે',
    navf: 'ફ્લીટ', navfd: 'Findings',
    navp: 'પ્રોગ્રામ', navai: 'AI',
    navc: 'સંકલન', st_runs: 'રન',
    st_beacons: 'સક્રિય બીકન', st_sig: 'સિગ્નલ',
    h2f: 'ફ્લીટ - બધા પ્રોગ્રામ, ચાલુ એજન્ટ પહેલા', h2fd: 'Findings બેઝ - સ્થિર ટ્રાયાજ ટેગિંગ',
    h2eng: 'ફ્લીટ એન્જિન - સ્થાનિક સાયકલ, ટોકન વગર', h2prog: 'પ્રોગ્રામ - scope, જરૂરી હેડર, લોન્ચ',
    h2new: 'નવો પ્રોગ્રામ', h2ai: 'AI એજન્ટ - 100% વૈકલ્પિક જોડાણ',
    h2c: 'સંકલન - ખાનગી ચેનલ', fl_start: 'શરૂ કરો',
    fl_pause: 'Pause', fl_cycle: 'આત્તા સાયકલ',
    f_add: 'ઉમેરો', f_none: 'હજી સિગ્નલ નથી',
    f_ph: 'મેન્યુઅલ finding : endpoint + પુરાવો + રક્ષણાત્મક sev…', st_sig_off: 'સિગ્નલ',
    st_sig_an: 'વિશ્લેષણ', st_sig_sub: 'સબમિટ થયું',
    st_sig_dup: 'dup', st_sig_ref: 'નકાર્યું',
    st_sig_cl: 'બંધ', r_none: 'કોઈ રન મળ્યો નથી',
    r_live: '{n} ચાલી રહ્યા', r_done: 'સમાપ્ત',
    r_feed: '▽ ફીડ ({n} ev)', r_close: '△ વીંટો',
    p_name_ph: 'પ્રોગ્રામનું નામ (જેમ : PayPal)', p_hdr_ph: 'રિસર્ચર હેડર જરૂરી (જેમ : X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domain1, domain2, …', p_save: 'સેવ',
    p_local: 'મોડ્યુલ, 100% સ્થાનિક', ai_p: 'C2FF સંપૂર્ણ AI વગર ચાલે છે : મોડ નિશ્ચિત સ્થાનિક પ્રોબ છે. આ ગેટવે ફક્ત એક finding નું વેળાપ્રમાણે વિશ્લેષણ કરાવવા <b>તારો</b> AI (self-hosted અથવા API) જોડવા છે : FINDINGS માં <span style="color:var(--green)">AI »</span> બટન, જવાબ COORDINATION માં દેખાશે. આ કોન્ફિગરેશન વગર તારી મશીનમાંથી કોઈ ડેટા બહાર જતો નથી.',
    ai_off: 'બંધ', ai_on: 'ચાલુ',
    ai_st_off: 'AI બંધ - ફ્રેમવર્ક 100% સ્થાનિક તે વગર ચાલે છે', ai_st_ready: 'AI જોડાયો : {p} · {m}',
    ai_st_inc: 'AI ચાલુ પણ અપૂર્ણ : baseURL અને model જરૂરી', ai_url_ph: 'base URL - જેમ : http://localhost:11434 અથવા https://api.MyAI.tld/v1',
    ai_model_ph: 'model - જેમ : llama3.1:8b', ai_key_ph: 'API key (લોકલ સર્વર હોય તો ખાલી છોડો)',
    ai_save: 'સેવ', ai_test: 'કનેક્શન ચકાસો',
    ai_testing: 'ટેસ્ટ ચાલી રહ્યો…', ai_ok: 'OK - જવાબ : ',
    ai_fail: 'નિષ્ફળ : ', ai_note: 'config સ્થાનિક data/ai.json માં સચવાયો - તું મૂકતો endpoint સિવાય બીજે ક્યાંય મોકલાતો નથી',
    ch_ph: 'root@c2ff:~# વિશ્લેષણ એજન્ટ તરફ સંદેશ…', ch_send: 'મોકલો',
    ch_empty: 'ચેનલ ખુલ્લી છે. અહીં ટાઇપ કરો, મોનિટર મને તરત જગાડે છે.', ft: '100% સ્થાનિક - નિશ્ચિત પ્રોબ, ટોકન વગર, બાહ્ય ડિપન્ડન્સી વગર - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE સક્રિય : દર 30 મિનિટે સ્થાનિક સાયકલ, 0 ટોકન.', to_fl_pa: 'FLEET PAUSE - જયારે ઇચ્છો ત્યારે ફરી શરૂ કરો.',
    to_fl_cy: 'તાત્કાલિક સાયકલ શરૂ (બજેટ 60 req).', to_launch: '[GO] {p} પર mode {m} (CWE {c}) - સ્થાનિક સાયકલ શરૂ',
    to_ai_ok: 'config સેવ થયો', to_ai_no: 'સેવ નિષ્ફળ',
    to_ai_no_cfg: 'AI કોન્ફિગર નથી - AI ટેબમાં સેટ કરો', to_ai_head: 'AI વિશ્લેષણ',
    to_ai_bad: 'AI વિશ્લેષણ નિષ્ફળ', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ લોન્ચ', navar: 'આર્સેનલ',
    ar_h2: 'ARSENAL - શોધાયેલ સપાટી પર CVE, EPSS અને exploits', ar_sync: 'SYNC બેઝ',
    ar_btn: 'ચાલો', ar_exec: 'EXEC',
    ar_none: 'કોઈ ચાલ નથી: પહેલા RECON ચલાવો, પછી KEV/EPSS લોડ કરવા SYNC ચલાવો', ar_loading: 'બેઝનો સારાંશ લોડ થાય છે...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'ડેમો પ્રોગ્રામ - સ્કેન નહીં : તારો પ્રોગ્રામ બનાવ', pip_noprog: 'કોઈ પ્રોગ્રામ નથી : પ્રોગ્રામ્સ ટેબમાં તારો બનાવ',
    pip_next: 'આગળનું પગલું :', fnd_n: 'ફાઇન્ડિંગ્સ: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  kn: {
    pl_title: 'ಕೆಲಸದ ಯೋಜನೆ', pl_empty: 'ಇನ್ನೂ ಯೋಜನೆ ಇಲ್ಲ : ಮೇಲಿನ ಕಾರ್ಡ್‌ನಲ್ಲಿ RECON ನಡೆಸು, ಊಹೆಗಳು ಇಲ್ಲಿ ಬರುತ್ತವೆ (ಸ್ಟೇಟಸ್ ಶೇಖರಣಾ ರೂಪದಲ್ಲಿ ಉಳಿಯುತ್ತದೆ)',
    pl_run: 'ನಡೆಸು', pl_reflect: 'canary ಪುನರಾವರ್ತನೆ ಪ್ರತಿಫಲಿತ',
    st_do: 'ಮಾಡಬೇಕಾದವು', st_test: 'ಪರೀಕ್ಷೆ ಆಯಿತು',
    st_signal: 'ಸಿಗ್ನಲ್', st_valid: 'ದೃಢಪಡಿಸಿದ್ದು',
    st_void: 'ಏನೂ ಇಲ್ಲ', atk_btn: 'ATTACK',
    atk_start: 'ಸರ್ಫೇಸ್ ಮೇಲೆ ದಾಳಿ ನಡೆಯುತ್ತಿದೆ : endpoints, ತೆರೆದ docs, JWT, secrets...', atk_fail: 'ದಾಳಿ ಸಾಧ್ಯವಿಲ್ಲ : ಮೊದಲು RECON ನಡೆಸು',
    atk_none: 'ಸಿಗ್ನಲ್ ಇಲ್ಲ', atk_findings: 'ಅಭ್ಯರ್ಥಿಗಳು',
    atk_done: 'ATTACK : ಪುರಾವೆಯೊಂದಿಗೆ {n} P1/P2 ಅಭ್ಯರ್ಥಿಗಳನ್ನು findings ಗೆ ಸೇರಿಸಿದೆ', atk_empty: 'ಇನ್ನೂ attack ಇಲ್ಲ : RECON ನಡೆಸಿ ನಂತರ ATTACK - req/res ಪುರಾವೆಯೊಂದಿಗಿನ ಅಭ್ಯರ್ಥಿಗಳು ಇಲ್ಲಿ ಬರುತ್ತಾರೆ',
    navh: 'HUNT', h2hunt: 'HUNT - ನಿಜವಾದ ಸರ್ಫೇಸ್ ಮತ್ತು ಪುರಾವೆಗಳು',
    h_ready: 'ಸಿದ್ಧ', h_empty: 'ಗೊತ್ತಿರುವ ಸರ್ಫೇಸ್ ಇಲ್ಲ : ಪುಟಗಳು, API endpoints, ಪ್ಯಾರಾಮ್‌ಗಳು, JS bundles ಮತ್ತು ಸಬ್‌ಡೊಮೇನ್‌ಗಳನ್ನು ನಕ್ಷಾ ಮಾಡಲು RECON ನಡೆಸು',
    h_fnd: 'ಪ್ರೋಗ್ರಾಮಿನ findings', h_nofnd: 'ಈ ಪ್ರೋಗ್ರಾಮ್‌ನಲ್ಲಿ finding ಇಲ್ಲ',
    rc_btn: 'RECON', rc_start: 'ಸರ್ಫೇಸ್‌ನ recon ನಡೆಯುತ್ತಿದೆ : ಪುಟಗಳು, JS bundles, endpoints, ಪ್ಯಾರಾಮ್‌ಗಳು...',
    rc_done: 'ಸರ್ಫೇಸ್ ನಕ್ಷಾ ಆಯಿತು : endpoints, ಪ್ಯಾರಾಮ್‌ಗಳು ಮತ್ತು ಸಬ್‌ಡೊಮೇನ್‌ಗಳು ಪ್ರೋಗ್ರಾಮ್ ಕಾರ್ಡಿನಲ್ಲಿ ಪಟ್ಟಿಯಾಗಿವೆ', rc_fail: 'recon ವಿಫಲ : host ಸಿಗುತ್ತಿಲ್ಲ ಅಥವಾ scope ಖಾಲಿ',
    rc_surface: 'ಸರ್ಫೇಸ್ :', snd_on: 'ಸೌಂಡ್ : ON',
    snd_off: 'ಸೌಂಡ್ : OFF', snd_ok: 'ಇಂಟರ್ಫೇಸ್ ಸದ್ದುಗಳು ಆನ್ - ಲೈಬ್ರರಿ : click, tab, copy, ಅಲರ್ಟ್‌ಗಳು',
    snd_stop: 'ಸಂಪೂರ್ಣ ಮ್ಯೂಟ್ ಸಕ್ರಿಯ : ಈಗ C2FF ದಿಂದ ಯಾವ ಸದ್ದೂ ಇಲ್ಲ', amb_on: 'ವಾತಾವರಣ : ON',
    amb_off: 'ವಾತಾವರಣ : OFF', amb_ok: 'ಬೇಹಗಿರಿಯುಳ್ಳ ವಾತಾವರಣ - ಬಣ್ಣದ ಛಾಯೆ ನಿಧಾನವಾಗಿ ಕುಟುಂಬಗಳಲ್ಲಿ ಸಾಗುತ್ತದೆ (ಹಸಿರು, ನೀಲಿ, ಹಳದಿ...)',
    amb_stop: 'ವಾತಾವರಣ ಮೂಲ ಹಸಿರಿನಲ್ಲಿ ಚಿಪ್ಪು ಹಾಕಿದೆ', nt_on: 'ನೋಟಿಫ್ : ON',
    nt_off: 'ನೋಟಿಫ್ : OFF', nt_ok: 'ಬ್ರೌಸರ್ ನೋಟಿಫಿಕೇಶನ್ ಆನ್ - P1 ಮತ್ತು P2 ಗೆ ಬೀಪ್',
    nt_denied: 'ಬ್ರೌಸರ್ ನೋಟಿಫಿಕೇಶನ್ ತಡೆದಿದೆ : ಸೈಟ್ ಸೆಟ್ಟಿಂಗ್ಸ್‌ನಲ್ಲಿ ಅನುಮತಿ ನೀಡಿ', term_denied: 'ಟರ್ಮಿನಲ್ ನಿರಾಕರಿಸಲಾಯಿತು ಅಥವಾ ಲಭ್ಯವಿಲ್ಲ : localhost ಬೇಕು, ಅಥವಾ ಅಡ್ಮಿನ್ ಆಗಿ ತೆರೆದ ರೂಮ್',
    term_p: 'ನಿಜವಾದ bash - ಬಾಣಗಳಿಂದ history, Ctrl+C ತಡೆಯುತ್ತದೆ, Ctrl+D ಮುಚ್ಚುತ್ತದೆ', term_restart: 'ಮರುಹೊಂದಿಸು',
    navtrm: 'TERM', term_h2: 'ಟರ್ಮಿನಲ್ - ಕೆಲಸದ ಶೆಲ್, ನೇರವಾಗಿ ಕನ್ಸೋಲ್‌ನಲ್ಲಿ',
    fl_off: 'FLEET : ನಿಂತಿದೆ', fl_paused: 'FLEET : PAUSE',
    fl_active: 'FLEET : ಸಕ್ರಿಯ ({n} ಸೈಕಲ್)', fl_last: 'ಕೊನೆಯ ಸೈಕಲ್',
    fl_none: 'ಇನ್ನೂ ಸೈಕಲ್ ಇಲ್ಲ', fl_info: '{i} ನಿಮಿಷ ಅಂತರ, {b} req/ಸೈಕಲ್',
    sub_ttl: 'command & control framework', navt: 'ಸೆಷನ್',
    tm_h2: 'ಗುಂಪು ಸೆಷನ್‌ಗಳು - ಒಟ್ಟಿಗೆ ಬೇಟೆ, ನೆಟ್‌ವರ್ಕ್ ಇಲ್ಲದೆಯೂ', tm_p: 'ಹಂಚಿದ ರೂಮ್ ತೆರೆ : ನಿನ್ನ ಗುಂಪಿಗೆ fleet, findings ಕಾಣಿಸುತ್ತವೆ ಮತ್ತು ಲೈವ್ ಟ್ರಯಾಜ್ ಮಾಡಬಹುದು. ಕೆಳಗೆ ಪ್ರತ್ಯೇಕ ಸೆಷನ್ ಚಾಟ್. ಮೂರು ಪ್ರವೇಶ ಮಟ್ಟ : LOCAL (ಒಂಟಿ), ನೆಟ್‌ವರ್ಕ್‌ಗೆ ತೆರೆಯಬೊತ್ತ LAN, ಮತ್ತು ಜಗತ್ತಿಗೆ ತೆರೆಯಬೊತ್ತ WORLD - ಸಾರ್ವಜನಿಕ ಟನೆಲ್ (cloudflared ಇನ್‌ಸ್ಟಾಲ್ ಇದ್ದರೆ) ಆಹ್ವಾನ ಲಿಂಕ್ ಯಾವುದೇ ನೆಟ್‌ವರ್ಕ್‌ನಿಂದ ಮಾನ್ಯವಾಗಿರಿಸುತ್ತದೆ, ನಿನ್ನ ಯಂತ್ರ ನೇರವಾಗಿ ಬಯಲಾಗದಂತೆ. ಎಲ್ಲದರ ಕೀಲಿ ರೂಮ್ ಕೀ - ಒಂದೇ ಬಾರಿ ಎಲ್ಲರನ್ನೂ ಹೊರಹಾಕಲು ಅದನ್ನು ಮರುರಚಿಸು.',
    tm_handle: 'ನಿನ್ನ ಹೆಸರು (ಗರಿಷ್ಠ 16 ಅಕ್ಷರ)', tm_save_h: 'ಹೊಂದಿಸು',
    tm_room_ph: 'ರೂಮ್‌ನ ಹೆಸರು (ಉದಾ : c2ff-core)', tm_save: 'ಅನ್ವಯಿಸು',
    tm_on: 'ರೂಮ್ ತೆರೆದಿದೆ : {r} - {n} ಆನ್‌ಲೈನ್', tm_off: 'TEAM MODE ಆಫ್ - ಸ್ಥಳೀಯ ಏಕ ಸೆಷನ್',
    tm_room: 'ರೂಮ್', tm_key: 'ರೂಮ್ ಕೀ',
    tm_regen: 'ಕೀ ಮರುರಚಿಸು', tm_regen_ok: 'ಹೊಸ ಕೀ ರಚಿತ - ಹಳೆ ಲಿಂಕ್ ಸತ್ತವು',
    tm_invite: 'ಆಹ್ವಾನ ಲಿಂಕ್ (ನಿನ್ನ ಟೀಮ್‌ಗೆ ಕಾಪಿ ಮಾಡು)', tm_copy: 'ಕಾಪಿ',
    tm_copied: 'ಕ್ಲಿಪ್‌ಬೋರ್ಡ್‌ಗೆ ಕಾಪಿ ಆಯಿತು', tm_members: 'ಸದಸ್ಯರು',
    tm_nobody: 'ಇನ್ನೂ ಯಾರೂ ಇಲ್ಲ - ಟೀಮ್‌ಗೆ ಲಿಂಕ್ ಕಳುಹಿಸು', tm_you: '(ನೀ)',
    tm_here: 'ಇಲ್ಲಿ', tm_saved: 'ಹೆಸರು ಉಳಿಸಲಾಯಿತು',
    tm_no_handle: 'ಹೆಸರು ಖಾಲಿ', tm_cfg_ok: 'ರೂಮ್ ಅಪ್‌ಡೇಟ್ ಆಯಿತು',
    tm_cfg_no: 'ವಿಫಲ', tm_live: 'ನೆಟ್‌ವರ್ಕ್‌ಗೆ ತೆರೆ',
    tm_shore: 'ಸ್ಥಳೀಯಕ್ಕೆ ಹಿಂತಿರುಗು', tm_need_on: 'ಮೊದಲು ರೂಮ್ ಆನ್ ಮಾಡು (ON)',
    tm_bind_lan: 'NETWORK : {a}', tm_bind_lo: 'LOCAL : localhost ಮಾತ್ರ',
    to_team_live: '[GO-LIVE] ನೆಟ್‌ವರ್ಕ್ ಪ್ರವೇಶದೊಂದಿಗೆ ಸರ್ವರ್ ಪುನಃ ಆರಂಭ - LAN ಲಿಂಕ್ ತೋರಿಸಲಾಗುತ್ತಿದೆ, 2 ಸೆಕೆಂಡ್‌ನಲ್ಲಿ ಪುನಃ ಕನೆಕ್ಟ್', to_team_shore: 'ಸರ್ವರ್ ಸ್ಥಳೀಯದಲ್ಲಿ (127.0.0.1) ಪುನಃ ಆರಂಭ',
    tm_tun_open: 'ಜಗತ್ತಿಗೆ ತೆರೆ (ಟನೆಲ್)', tm_tun_close: 'ಟನೆಲ್ ಮುಚ್ಚು',
    tm_tun_wait: 'ಸಾರ್ವಜನಿಕ ಟನೆಲ್ ತೆರೆಯುತ್ತಿದೆ (ಕೆಲವು ಸೆಕೆಂಡು)…', tm_tun_on: 'ಸೆಷನ್ ಜಗತ್ತಿಗೆ ತೆರೆದಿದೆ : {u} - ಆಹ್ವಾನ ಲಿಂಕ್ ಎಲ್ಲಿಂದಲಾದರೂ ಕಾರ್ಯನಿರ್ವಹಿಸುತ್ತದೆ, ಒಂದೇ ನೆಟ್‌ವರ್ಕ್ ಬೇಡ',
    tm_tun_closed: 'ಟನೆಲ್ ಮುಚ್ಚಿತು - ನೆಟ್‌ವರ್ಕ್/ಸ್ಥಳೀಯಕ್ಕೆ ಹಿಂತಿರುಗಾಯಿತು', tm_chat_empty: 'ಸೆಷನ್ ಚಾನೆಲ್ ತೆರೆದಿದೆ - ರೂಮ್ ಸದಸ್ಯರು ಇಲ್ಲಿ ಪರಸ್ಪರ ಓದುತ್ತಾರೆ',
    tm_chat_h2: 'ಸೆಷನ್ ಚಾಟ್', tm_msg_ph: 'ಸೆಷನ್‌ಗೆ ಸಂದೇಶ…',
    tm_admin: 'ಅಡ್ಮಿನ್', tm_guest: 'ಅತಿಥಿ',
    tm_kick: 'KICK', tm_kick_ok: 'ಸದಸ್ಯ ರೂಮಿನಿಂದ ಹೊರಹಾಕಲಾಯಿತು (ಪುನಃ ಕ್ಲಿಕ್ ಮಾಡಿದರೆ ಅನ್‌ಲಾಕ್)',
    tm_role_ok: 'ಪಾತ್ರ ಅಪ್‌ಡೇಟ್ ಆಯಿತು', tm_mic_on: 'ಮೈಕ್ ಆನ್',
    tm_mic_off: 'ಮೈಕ್ ಆಫ್', tm_mic_denied: 'ಮೈಕ್ ನಿರಾಕರಿಸಲಾಯಿತು ಅಥವಾ ದೊರೆಯುತ್ತಿಲ್ಲ : HTTPS ಬೇಕು (WORLD ಟನೆಲ್ ಅಥವಾ localhost) ಮತ್ತು ಮೈಕ್‌ಗೆ ಅನುಮತಿ ನೀಡಬೇಕು',
    navf: 'ಫ್ಲೀಟ್', navfd: 'Findings',
    navp: 'ಪ್ರೋಗ್ರಾಮ್‌ಗಳು', navai: 'AI',
    navc: 'ಸಂಘಟನೆ', st_runs: 'ರನ್‌ಗಳು',
    st_beacons: 'ಸಕ್ರಿಯ ಬೀಕನ್‌ಗಳು', st_sig: 'ಸಿಗ್ನಲ್‌ಗಳು',
    h2f: 'ಫ್ಲೀಟ್ - ಎಲ್ಲಾ ಪ್ರೋಗ್ರಾಮ್, ಓಡುತ್ತಿರುವ ಏಜೆಂಟ್ ಮೊದಲು', h2fd: 'Findings ಬೇಸ್ - ಸ್ಥಿರ ಟ್ರಯಾಜ್ ಟ್ಯಾಗಿಂಗ್',
    h2eng: 'ಫ್ಲೀಟ್ ಎಂಜಿನ್ - ಸ್ಥಳೀಯ ಸೈಕಲ್, ಟೋಕನ್ ಇಲ್ಲ', h2prog: 'ಪ್ರೋಗ್ರಾಮ್‌ಗಳು - scope, ಬೇಕಾದ ಹೆಡರ್, ಲಾಂಚ್',
    h2new: 'ಹೊಸ ಪ್ರೋಗ್ರಾಮ್', h2ai: 'AI ಏಜೆಂಟ್ - 100% ಐಚ್ಛಿಕ ಜೋಡಣೆ',
    h2c: 'ಸಂಘಟನೆ - ಖಾಸಗಿ ಚಾನೆಲ್', fl_start: 'ಆರಂಭಿಸು',
    fl_pause: 'Pause', fl_cycle: 'ಇದೀಗ ಸೈಕಲ್',
    f_add: 'ಸೇರಿಸು', f_none: 'ಇನ್ನೂ ಸಿಗ್ನಲ್ ಇಲ್ಲ',
    f_ph: 'ಹಸ್ತಚಾಲಿತ finding : endpoint + ಪುರಾವೆ + ಸಮರ್ಥಿಸಬಹುದಾದ sev…', st_sig_off: 'ಸಿಗ್ನಲ್',
    st_sig_an: 'ವಿಶ್ಲೇಷಣೆ', st_sig_sub: 'ಸಲ್ಲಿಸಲಾಯಿತು',
    st_sig_dup: 'dup', st_sig_ref: 'ತಿರಸ್ಕರಿಸಲಾಯಿತು',
    st_sig_cl: 'ಮುಚ್ಚಲಾಯಿತು', r_none: 'ರನ್ ಕಂಡುಬಂದಿಲ್ಲ',
    r_live: '{n} ಓಡುತ್ತಿವೆ', r_done: 'ಮುಗಿಯಿತು',
    r_feed: '▽ ಫೀಡ್ ({n} ev)', r_close: '△ ಮಡಚು',
    p_name_ph: 'ಪ್ರೋಗ್ರಾಮಿನ ಹೆಸರು (ಉದಾ : PayPal)', p_hdr_ph: 'ರಿಸರ್ಚರ್ ಹೆಡರ್ ಬೇಕು (ಉದಾ : X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domain1, domain2, …', p_save: 'ಉಳಿಸು',
    p_local: 'ಮಾಡ್ಯೂಲ್, 100% ಸ್ಥಳೀಯ', ai_p: 'C2FF ಸಂಪೂರ್ಣ AI ಇಲ್ಲದೆ ಚಾಲನೆಯಲ್ಲಿದೆ : ಮೋಡ್‌ಗಳು ನಿರ್ಧಾರಕ ಸ್ಥಳೀಯ ಪ್ರೋಬ್‌ಗಳು. ಈ ಗೇಟ್‌ವೇ ಒಂದು finding ಅನ್ನು ಅಗತ್ಯವೆಂದಲ್ಲಿ ವಿಶ್ಲೇಷಿಸಲು <b>ನಿನ್ನ</b> AI ಯನ್ನು (self-hosted ಅಥವಾ API) ಜೋಡಿಸಲು ಮಾತ್ರ : FINDINGS ನಲ್ಲಿನ <span style="color:var(--green)">AI »</span> ಬಟನ್, ಉತ್ತರ COORDINATION ನಲ್ಲಿ ಕಾಣುತ್ತದೆ. ಈ ಸಂರಚನೆ ಇಲ್ಲದೆ ನಿನ್ನ ಯಂತ್ರದಿಂದ ಯಾವ ಡೇಟಾವೂ ಹೊರಗೆ ಹೋಗುವುದಿಲ್ಲ.',
    ai_off: 'ಆಫ್', ai_on: 'ಆನ್',
    ai_st_off: 'AI ಆಫ್ - ಫ್ರೇಮ್‌ವರ್ಕ್ 100% ಸ್ಥಳೀಯವಾಗಿ ಅದಿಲ್ಲದೆ ಚಾಲನೆಯಲ್ಲಿದೆ', ai_st_ready: 'AI ಕನೆಕ್ಟ್ ಆಗಿದೆ : {p} · {m}',
    ai_st_inc: 'AI ಆನ್ ಆದರೆ ಅಪೂರ್ಣ : baseURL ಮತ್ತು model ಬೇಕು', ai_url_ph: 'base URL - ಉದಾ : http://localhost:11434 ಅಥವಾ https://api.MyAI.tld/v1',
    ai_model_ph: 'model - ಉದಾ : llama3.1:8b', ai_key_ph: 'API key (ಸ್ಥಳೀಯ ಸರ್ವರ್ ಆದರೆ ಖಾಲಿ ಬಿಡು)',
    ai_save: 'ಉಳಿಸು', ai_test: 'ಸಂಪರ್ಕ ಪರೀಕ್ಷಿಸು',
    ai_testing: 'ಪರೀಕ್ಷೆ ನಡೆಯುತ್ತಿದೆ…', ai_ok: 'OK - ಉತ್ತರ : ',
    ai_fail: 'ವಿಫಲ : ', ai_note: 'config ಸ್ಥಳೀಯವಾಗಿ data/ai.json ನಲ್ಲಿ ಸಂಗ್ರಹ - ನೀವು ಇಟ್ಟ endpoint ಅನ್ನು ಬಿಟ್ಟು ಬೇರೆಲ್ಲಿಗೂ ಕಳುಹಿಸಲಾಗುವುದಿಲ್ಲ',
    ch_ph: 'root@c2ff:~# ವಿಶ್ಲೇಷಣ ಏಜೆಂಟ್‌ಗೆ ಸಂದೇಶ…', ch_send: 'ಕಳುಹಿಸು',
    ch_empty: 'ಚಾನೆಲ್ ತೆರೆದಿದೆ. ಇಲ್ಲಿ ಟೈಪ್ ಮಾಡು, ಮಾನಿಟರ್ ನನ್ನ ತಕ್ಷಣ ಎಬುರುತ್ತದೆ.', ft: '100% ಸ್ಥಳೀಯ - ನಿರ್ಧಾರಾತ್ಮಕ ಪ್ರೋಬ್, ಟೋಕನ್ ಇಲ್ಲ, ಬಾಹ್ಯ ಅವಲಂಬನೆ ಇಲ್ಲ - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ಸಕ್ರಿಯ : ಪ್ರತಿ 30 ನಿಮಿಷಕ್ಕೆ ಸ್ಥಳೀಯ ಸೈಕಲ್, 0 ಟೋಕನ್.', to_fl_pa: 'FLEET PAUSE - ಆಗಮಾಡಿದಾಗ ಪುನಃ ಆರಂಭಿಸು.',
    to_fl_cy: 'ತಕ್ಷಣ ಸೈಕಲ್ ಆರಂಭ (ಬಜೆಟ್ 60 req).', to_launch: '[GO] {p} ಮೇಲೆ mode {m} (CWE {c}) - ಸ್ಥಳೀಯ ಸೈಕಲ್ ಆರಂಭ',
    to_ai_ok: 'config ಉಳಿಸಲಾಯಿತು', to_ai_no: 'ಉಳಿಸಲು ವಿಫಲ',
    to_ai_no_cfg: 'AI ಸಂರಚನೆ ಇಲ್ಲ - AI ಟ್ಯಾಬ್‌ನಲ್ಲಿ ಹೊಂದಿಸು', to_ai_head: 'AI ವಿಶ್ಲೇಷಣೆ',
    to_ai_bad: 'AI ವಿಶ್ಲೇಷಣೆ ವಿಫಲ', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ ಲಾಂಚ್', navar: 'ಆರ್ಸೆನಲ್',
    ar_h2: 'ARSENAL - ಪತ್ತೆಹಚ್ಚಿದ ಮೇಲ್ಮೈಯಲ್ಲಿ CVE, EPSS ಮತ್ತು exploits', ar_sync: 'SYNC ಬೇಸ್‌ಗಳು',
    ar_btn: 'ಚಲನೆಗಳು', ar_exec: 'EXEC',
    ar_none: 'ಚಲನೆಗಳಿಲ್ಲ: ಮೊದಲು RECON ಚಲಾಯಿಸಿ, ನಂತರ KEV/EPSS ಲೋಡ್ ಮಾಡಲು SYNC', ar_loading: 'ಬೇಸ್‌ಗಳ ಸಾರಾಂಶ ಲೋಡ್ ಆಗುತ್ತಿದೆ...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'ಡೆಮೊ ಪ್ರೊಗ್ರಾಂ - ಸ್ಕ್ಯಾನ್ ಇಲ್ಲ : ನಿಮ್ಮದೇ ಪ್ರೊಗ್ರಾಂ ಮಾಡಿ', pip_noprog: 'ಯಾವುದೇ ಪ್ರೊಗ್ರಾಂ ಇಲ್ಲ : ಪ್ರೊಗ್ರಾಂಗಳ ಟ್ಯಾಬಿನಲ್ಲಿ ನಿಮ್ಮದೇ ಮಾಡಿ',
    pip_next: 'ಮುಂದಿನ ಹಂತ :', fnd_n: 'ಫೈಂಡಿಂಗ್ಸ್: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  pa: {
    pl_title: 'ਕੰਮ ਦੀ ਯੋਜਨਾ', pl_empty: 'ਅਜੇ ਕੋਈ ਯੋਜਨਾ ਨਹੀਂ : ਉਪਰਲੇ ਕਾਰਡ ਵਿੱਚ RECON ਚਲਾਓ, ਵਿਆਖਿਆਵਾਂ ਇੱਥੇ ਆਉਣਗੀਆਂ (ਸਟੇਟਸ ਸੰਭਾਲੇ ਰਹਿਣਗੇ)',
    pl_run: 'ਚਲਾਓ', pl_reflect: 'canary ਪਰਤਿਆ',
    st_do: 'ਕਰਨਾ ਹੈ', st_test: 'ਟੈਸਟ ਹੋ ਗਿਆ',
    st_signal: 'ਸਿਗਨਲ', st_valid: 'ਪੁਸ਼ਟੀ',
    st_void: 'ਕੁਝ ਨਹੀਂ', atk_btn: 'ATTACK',
    atk_start: 'ਸਰਫੇਸ ਉੱਤੇ ਹਮਲਾ ਚੱਲ ਰਿਹਾ ਹੈ : endpoints, ਖੁੱਲ੍ਹੇ docs, JWT, secrets...', atk_fail: 'ਹਮਲਾ ਅਸੰਭਵ : ਪਹਿਲਾਂ RECON ਚਲਾਓ',
    atk_none: 'ਕੋਈ ਸਿਗਨਲ ਨਹੀਂ', atk_findings: 'ਉਮੀਦਵਾਰ',
    atk_done: 'ATTACK : ਸਬੂਤ ਨਾਲ {n} P1/P2 ਉਮੀਦਵਾਰ findings ਵਿੱਚ ਪਾਏ', atk_empty: 'ਅਜੇ attack ਨਹੀਂ : RECON ਚਲਾਓ ਫੇਰ ATTACK - req/res ਸਬੂਤ ਨਾਲ ਉਮੀਦਵਾਰ ਇੱਥੇ ਆਉਣਗੇ',
    navh: 'HUNT', h2hunt: 'HUNT - ਸੱਚਾ ਸਰਫੇਸ ਅਤੇ ਸਬੂਤ',
    h_ready: 'ਤਿਆਰ', h_empty: 'ਕੋਈ ਜਾਣਿਆ-ਪਛਾਣਿਆ ਸਰਫੇਸ ਨਹੀਂ : ਪੰਨੇ, API endpoints, ਪੈਰਾਮ, JS bundles ਅਤੇ ਸਬਡੋਮੇਨ ਨਕਸ਼ਾ ਬਣਾਉਣ ਲਈ RECON ਚਲਾਓ',
    h_fnd: 'ਪ੍ਰੋਗਰਾਮ ਦੇ findings', h_nofnd: 'ਇਸ ਪ੍ਰੋਗਰਾਮ ਵਿੱਚ ਕੋਈ finding ਨਹੀਂ',
    rc_btn: 'RECON', rc_start: 'ਸਰਫੇਸ ਦਾ recon ਚੱਲ ਰਿਹਾ ਹੈ : ਪੰਨੇ, JS bundles, endpoints, ਪੈਰਾਮ...',
    rc_done: 'ਸਰਫੇਸ ਨਕਸ਼ਾ ਬਣ ਗਿਆ : endpoints, ਪੈਰਾਮ ਅਤੇ ਸਬਡੋਮੇਨ ਪ੍ਰੋਗਰਾਮ ਕਾਰਡ ਵਿੱਚ ਸੂਚੀਬੱਧ', rc_fail: 'recon ਅਸਫਲ : host ਪਹੁੰਚ ਨਹੀਂ ਕਰਦਾ ਜਾਂ scope ਖਾਲੀ',
    rc_surface: 'ਸਰਫੇਸ :', snd_on: 'ਸਾਊਂਡ : ON',
    snd_off: 'ਸਾਊਂਡ : OFF', snd_ok: 'ਇੰਟਰਫੇਸ ਆਵਾਜ਼ਾਂ ਚਾਲੂ - ਲਾਇਬ੍ਰੇਰੀ : click, tab, copy, ਅਲਰਟ',
    snd_stop: 'ਪੂਰਾ ਮਿਊਟ ਚਾਲੂ : ਹੁਣ C2FF ਦੀ ਕੋਈ ਆਵਾਜ਼ ਨਹੀਂ', amb_on: 'ਮਾਹੌਲ : ON',
    amb_off: 'ਮਾਹੌਲ : OFF', amb_ok: 'ਜੀਵੰਤ ਮਾਹੌਲ - ਰੰਗ ਦੀ ਝਲਕ ਹੌਲੀ-ਹੌਲੀ ਪਰਿਵਾਰਾਂ ਵਿੱਚੋਂ ਭਰਦੀ ਹੈ (ਹਰਾ, ਨੀਲਾ, ਪੀਲਾ...)',
    amb_stop: 'ਮਾਹੌਲ ਅਸਲੀ ਹਰੇ ਤੇ ਜੰਮ ਗਿਆ', nt_on: 'ਨੋਟਿਫ : ON',
    nt_off: 'ਨੋਟਿਫ : OFF', nt_ok: 'ਬ੍ਰਾਊਜ਼ਰ ਸੂਚਨਾਵਾਂ ਚਾਲੂ - P1 ਅਤੇ P2 ਤੇ ਬੀਪ',
    nt_denied: 'ਬ੍ਰਾਊਜ਼ਰ ਨੇ ਸੂਚਨਾਵਾਂ ਰੋਕੀਆਂ : ਸਾਈਟ ਸੈਟਿੰਗਾਂ ਵਿੱਚ ਇਜਾਜ਼ਤ ਦਿਓ', term_denied: 'ਟਰਮੀਨਲ ਨਾਮਨਜ਼ੂਰ ਜਾਂ ਅਣਉਪਲਬਧ : localhost ਚਾਹੀਦਾ ਹੈ, ਜਾਂ ਐਡਮਿਨ ਵਜੋਂ ਖੁੱਲਾ ਰੂਮ',
    term_p: 'ਸੱਚੀ bash - ਤੀਰਾਂ ਨਾਲ history, Ctrl+C ਤੋੜਦਾ ਹੈ, Ctrl+D ਬੰਦ ਕਰਦਾ ਹੈ', term_restart: 'ਰੀਸੈੱਟ',
    navtrm: 'TERM', term_h2: 'ਟਰਮੀਨਲ - ਕੰਮ ਦੀ ਸ਼ੈਲ, ਸਿੱਧਾ ਕਨਸੋਲ ਵਿੱਚ',
    fl_off: 'FLEET : ਰੁਕਿਆ', fl_paused: 'FLEET : PAUSE',
    fl_active: 'FLEET : ਸਰਗਰਮ ({n} ਸਾਈਕਲ)', fl_last: 'ਆਖਰੀ ਸਾਈਕਲ',
    fl_none: 'ਅਜੇ ਕੋਈ ਸਾਈਕਲ ਨਹੀਂ', fl_info: '{i} ਮਿੰਟ ਅੰਤਰਾਲ, {b} req/ਸਾਈਕਲ',
    sub_ttl: 'command & control framework', navt: 'ਸੈਸ਼ਨ',
    tm_h2: 'ਗਰੁੱਪ ਸੈਸ਼ਨ - ਇਕੱਠੇ ਸ਼ਿਕਾਰ, ਨੈੱਟਵਰਕ ਛੱਡ ਕੇ ਵੀ', tm_p: 'ਸਾਂਝਾ ਰੂਮ ਖੋਲ੍ਹੋ : ਤੇਰੀ ਟੀਮ ਨੂੰ fleet, findings ਦਿਸਣਗੇ ਅਤੇ ਲਾਈਵ ਟ੍ਰਾਇਜ ਕਰ ਸਕਣਗੇ। ਹੇਠਾਂ ਵੱਖਰਾ ਸੈਸ਼ਨ ਚੈਟ। ਤਿੰਨ ਪੱਧਰ ਦੀ ਪਹੁੰਚ : LOCAL (ਇੱਕਲੌਤਾ), ਨੈੱਟਵਰਕ ਤੇ ਖੋਲ੍ਹਣ ਨਾਲ LAN, ਅਤੇ ਦੁਨੀਆ ਸਾਮ੍ਹਣੇ ਖੋਲ੍ਹਣ ਨਾਲ WORLD - ਸਾਰਵਜਨਿਕ ਟਨਲ (cloudflared ਇੰਸਟਾਲ ਹੋਵੇ ਤਾਂ) ਸੱਦਾ ਲਿੰਕ ਕਿਸੇ ਵੀ ਨੈੱਟਵਰਕ ਤੋਂ ਵੈਧ ਰੱਖਦਾ ਹੈ, ਤੇਰੀ ਮਸ਼ੀਨ ਸਿੱਧੀ ਖੁੱਲ੍ਹੇ ਬਿਨਾਂ। ਸਭ ਰੂਮ ਕੀ ਦੇ ਪਿੱਛੇ ਹੈ - ਇੱਕੋ ਝਟਕੇ ਵਿੱਚ ਸਭ ਨੂੰ ਬਾਹਰ ਕਾਢਣ ਲਈ ਇਸਨੂੰ ਦੁਬਾਰਾ ਬਣਾਓ।',
    tm_handle: 'ਤੇਰਾ ਨਾਮ (ਵੱਧ ਤੋਂ ਵੱਧ 16 ਅੱਖਰ)', tm_save_h: 'ਸੈੱਟ',
    tm_room_ph: 'ਰੂਮ ਦਾ ਨਾਮ (ਜਿਵੇਂ : c2ff-core)', tm_save: 'ਲਾਗੂ ਕਰੋ',
    tm_on: 'ਰੂਮ ਖੁੱਲ੍ਹਾ ਹੈ : {r} - {n} ਆਨਲਾਈਨ', tm_off: 'TEAM MODE ਬੰਦ - ਲੋਕਲ ਇਕਲੌਤਾ ਸੈਸ਼ਨ',
    tm_room: 'ਰੂਮ', tm_key: 'ਰੂਮ ਕੀ',
    tm_regen: 'ਕੀ ਦੁਬਾਰਾ ਬਣਾਓ', tm_regen_ok: 'ਨਵੀਂ ਕੀ ਬਣ ਗਈ - ਪੁਰਾਣੇ ਲਿੰਕ ਮਰ ਗਏ',
    tm_invite: 'ਸੱਦਾ ਲਿੰਕ (ਟੀਮ ਨੂੰ ਕਾਪੀ ਕਰੋ)', tm_copy: 'ਕਾਪੀ',
    tm_copied: 'ਕਲਿੱਪਬੋਰਡ ਵਿੱਚ ਕਾਪੀ ਹੋ ਗਿਆ', tm_members: 'ਮੈਂਬਰ',
    tm_nobody: 'ਅਜੇ ਕੋਈ ਨਹੀਂ - ਟੀਮ ਨੂੰ ਲਿੰਕ ਭੇਜੋ', tm_you: '(ਤੂੰ)',
    tm_here: 'ਇੱਥੇ', tm_saved: 'ਨਾਮ ਸੇਵ ਹੋਇਆ',
    tm_no_handle: 'ਨਾਮ ਖਾਲੀ', tm_cfg_ok: 'ਰੂਮ ਅੱਪਡੇਟ ਹੋ ਗਿਆ',
    tm_cfg_no: 'ਅਸਫਲ', tm_live: 'ਨੈੱਟਵਰਕ ਤੇ ਖੋਲ੍ਹੋ',
    tm_shore: 'ਲੋਕਲ ਮੋਡ ਪਰ ਵਾਪਸ', tm_need_on: 'ਪਹਿਲਾਂ ਰੂਮ ਚਾਲੂ ਕਰੋ (ON)',
    tm_bind_lan: 'NETWORK : {a}', tm_bind_lo: 'LOCAL : ਸਿਰਫ਼ localhost',
    to_team_live: '[GO-LIVE] ਨੈੱਟਵਰਕ ਪਹੁੰਚ ਨਾਲ ਸਰਵਰ ਦੁਬਾਰਾ ਚਾਲੂ ਹੋਇਆ - LAN ਲਿੰਕ ਦਿਖਾਇਆ ਜਾ ਰਿਹਾ ਹੈ, 2 ਸੈਕਿੰਡ ਵਿੱਚ ਦੁਬਾਰਾ ਕਨੈਕਟ', to_team_shore: 'ਸਰਵਰ ਲੋਕਲ (127.0.0.1) ਦੁਬਾਰਾ ਚਾਲੂ ਹੋਇਆ',
    tm_tun_open: 'ਦੁਨੀਆ ਸਾਮ੍ਹਣੇ ਖੋਲ੍ਹੋ (ਟਨਲ)', tm_tun_close: 'ਟਨਲ ਬੰਦ ਕਰੋ',
    tm_tun_wait: 'ਸਾਰਵਜਨਿਕ ਟਨਲ ਖੁੱਲ੍ਹ ਰਿਹਾ ਹੈ (ਕੁਝ ਸੈਕਿੰਡ)…', tm_tun_on: 'ਸੈਸ਼ਨ ਦੁਨੀਆ ਸਾਮ੍ਹਣੇ ਖੁੱਲ੍ਹਾ : {u} - ਸੱਦਾ ਲਿੰਕ ਕਿਤੇ ਵੀ ਚੱਲੇਗਾ, ਇੱਕੋ ਨੈੱਟਵਰਕ ਦੀ ਲੋੜ ਨਹੀਂ',
    tm_tun_closed: 'ਟਨਲ ਬੰਦ - ਨੈੱਟਵਰਕ/ਲੋਕਲ ਮੋਡ ਪਰ ਵਾਪਸ', tm_chat_empty: 'ਸੈਸ਼ਨ ਚੈਨਲ ਖੁੱਲ੍ਹਾ - ਰੂਮ ਦੇ ਮੈਂਬਰ ਇੱਥੇ ਇੱਕ-ਦੂਜੇ ਨੂੰ ਪੜ੍ਹਦੇ ਹਨ',
    tm_chat_h2: 'ਸੈਸ਼ਨ ਚੈਟ', tm_msg_ph: 'ਸੈਸ਼ਨ ਨੂੰ ਸੁਨੇਹਾ…',
    tm_admin: 'ਐਡਮਿਨ', tm_guest: 'ਮਹਿਮਾਨ',
    tm_kick: 'KICK', tm_kick_ok: 'ਮੈਂਬਰ ਰੂਮ ਵਿੱਚੋਂ ਬਾਹਰ ਕੱਢਿਆ (ਦੁਬਾਰਾ ਕਲਿੱਕ ਕਰਨ ਨਾਲ ਅਨਲਾਕ)',
    tm_role_ok: 'ਭੂਮਿਕਾ ਅੱਪਡੇਟ ਹੋਈ', tm_mic_on: 'ਮਾਈਕ ਚਾਲੂ ਕਰੋ',
    tm_mic_off: 'ਮਾਈਕ ਬੰਦ ਕਰੋ', tm_mic_denied: 'ਮਾਈਕ ਨਾਮਨਜ਼ੂਰ ਜਾਂ ਅਣਉਪਲਬਧ : HTTPS ਚਾਹੀਦਾ ਹੈ (WORLD ਟਨਲ ਜਾਂ localhost) ਅਤੇ ਮਾਈਕ ਨੂੰ ਇਜਾਜ਼ਤ ਦੇਣੀ ਪਵੇਗੀ',
    navf: 'ਫਲੀਟ', navfd: 'Findings',
    navp: 'ਪ੍ਰੋਗਰਾਮ', navai: 'AI',
    navc: 'ਸਮਨਵਯ', st_runs: 'ਰਨ',
    st_beacons: 'ਸਰਗਰਮ ਬੀਕਨ', st_sig: 'ਸਿਗਨਲ',
    h2f: 'ਫਲੀਟ - ਸਾਰੇ ਪ੍ਰੋਗਰਾਮ, ਚੱਲਦੇ ਏਜੰਟ ਪਹਿਲਾਂ', h2fd: 'Findings ਬੇਸ - ਸਥਾਈ ਟ੍ਰਾਇਜ ਟੈਗਿੰਗ',
    h2eng: 'ਫਲੀਟ ਇੰਜਣ - ਲੋਕਲ ਸਾਈਕਲ, ਟੋਕਨ ਨਹੀਂ', h2prog: 'ਪ੍ਰੋਗਰਾਮ - scope, ਲੋੜੀਂਦਾ ਹੈਡਰ, ਲਾਂਚ',
    h2new: 'ਨਵਾਂ ਪ੍ਰੋਗਰਾਮ', h2ai: 'AI ਏਜੰਟ - 100% ਵਿਕਲਪਿਕ ਜੋੜ',
    h2c: 'ਸਮਨਵਯ - ਪ੍ਰਾਈਵੇਟ ਚੈਨਲ', fl_start: 'ਸ਼ੁਰੂ ਕਰੋ',
    fl_pause: 'Pause', fl_cycle: 'ਹੁਣੇ ਸਾਈਕਲ',
    f_add: 'ਜੋੜੋ', f_none: 'ਅਜੇ ਕੋਈ ਸਿਗਨਲ ਨਹੀਂ',
    f_ph: 'ਹੱਥੀਂ finding : endpoint + ਸਬੂਤ + ਬਚਾਊ sev…', st_sig_off: 'ਸਿਗਨਲ',
    st_sig_an: 'ਵਿਸ਼ਲੇਸ਼ਣ', st_sig_sub: 'ਅਰਜ਼ ਭੇਜੀ',
    st_sig_dup: 'dup', st_sig_ref: 'ਰੱਦ',
    st_sig_cl: 'ਬੰਦ', r_none: 'ਕੋਈ ਰਨ ਨਹੀਂ ਲੱਭਾ',
    r_live: '{n} ਚੱਲ ਰਹੇ ਹਨ', r_done: 'ਪੂਰਾ',
    r_feed: '▽ ਫੀਡ ({n} ev)', r_close: '△ ਮੋੜੋ',
    p_name_ph: 'ਪ੍ਰੋਗਰਾਮ ਦਾ ਨਾਮ (ਜਿਵੇਂ : PayPal)', p_hdr_ph: 'ਰਿਸਰਚਰ ਹੈਡਰ ਲੋੜੀਂਦਾ (ਜਿਵੇਂ : X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domain1, domain2, …', p_save: 'ਸੇਵ',
    p_local: 'ਮੋਡੀਊਲ, 100% ਲੋਕਲ', ai_p: 'C2FF ਪੂਰੀ ਤਰ੍ਹਾਂ AI ਤੋਂ ਬਿਨਾਂ ਚੱਲਦਾ ਹੈ : ਮੋਡ ਨਿਰਧਾਰਕ ਲੋਕਲ ਪ੍ਰੋਬ ਹਨ। ਇਹ ਗੇਟਵੇ ਸਿਰਫ਼ ਇੱਕ finding ਦਾ ਵੇਲੇ ਵੇਲੇ ਵਿਸ਼ਲੇਸ਼ਣ ਕਰਾਉਣ ਲਈ <b>ਤੇਰਾ</b> AI (self-hosted ਜਾਂ API) ਜੋੜਨ ਲਈ ਹੈ : FINDINGS ਦਾ <span style="color:var(--green)">AI »</span> ਬਟਨ, ਜਵਾਬ COORDINATION ਵਿੱਚ ਦਿਖੇਗਾ। ਇਸ ਕੌਨਫਿਗਰੇਸ਼ਨ ਤੋਂ ਬਿਨਾਂ ਤੇਰੀ ਮਸ਼ੀਨ ਤੋਂ ਕੋਈ ਡਾਟਾ ਬਾਹਰ ਨਹੀਂ ਜਾਂਦਾ।',
    ai_off: 'ਬੰਦ', ai_on: 'ਚਾਲੂ',
    ai_st_off: 'AI ਬੰਦ - ਫਰੇਮਵਰਕ 100% ਲੋਕਲ ਇਸ ਤੋਂ ਬਿਨਾਂ ਚੱਲਦਾ ਹੈ', ai_st_ready: 'AI ਜੁੜਿਆ : {p} · {m}',
    ai_st_inc: 'AI ਚਾਲੂ ਪਰ ਅਧੂਰਾ : baseURL ਅਤੇ model ਚਾਹੀਦੇ ਹਨ', ai_url_ph: 'base URL - ਜਿਵੇਂ : http://localhost:11434 ਜਾਂ https://api.MyAI.tld/v1',
    ai_model_ph: 'model - ਜਿਵੇਂ : llama3.1:8b', ai_key_ph: 'API key (ਲੋਕਲ ਸਰਵਰ ਹੈ ਤਾਂ ਖਾਲੀ ਛੱਡੋ)',
    ai_save: 'ਸੇਵ', ai_test: 'ਕਨੈਕਸ਼ਨ ਟੈਸਟ ਕਰੋ',
    ai_testing: 'ਟੈਸਟ ਚੱਲ ਰਿਹਾ…', ai_ok: 'OK - ਜਵਾਬ : ',
    ai_fail: 'ਅਸਫਲ : ', ai_note: 'config ਲੋਕਲ data/ai.json ਵਿੱਚ ਸਾਂਭਿਆ - ਤੂੰ ਪੱਥਏ endpoint ਛੱਡ ਹੋਰ ਕਿਤੇ ਨਹੀਂ ਭੇਜਿਆ ਜਾਂਦਾ',
    ch_ph: 'root@c2ff:~# ਵਿਸ਼ਲੇਸ਼ਣ ਏਜੰਟ ਨੂੰ ਸੁਨੇਹਾ…', ch_send: 'ਭੇਜੋ',
    ch_empty: 'ਚੈਨਲ ਖੁੱਲ੍ਹਾ ਹੈ। ਇੱਥੇ ਟਾਈਪ ਕਰੋ, ਮਾਨੀਟਰ ਮੈਨੂੰ ਝੱਟ ਜਗਾਉਂਦਾ ਹੈ।', ft: '100% ਲੋਕਲ - ਨਿਰਧਾਰਿਤ ਪ੍ਰੋਬ, ਟੋਕਨ ਜਾਂ ਬਾਹਰੀ ਨਿਰਭਰਤਾ ਨਹੀਂ - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ਸਰਗਰਮ : ਹਰ 30 ਮਿੰਟ ਲੋਕਲ ਸਾਈਕਲ, 0 ਟੋਕਨ.', to_fl_pa: 'FLEET PAUSE - ਜਦੋਂ ਚਾਹੋ ਦੁਬਾਰਾ ਸ਼ੁਰੂ ਕਰੋ.',
    to_fl_cy: 'ਤੁਰੰਤ ਸਾਈਕਲ ਚਾਲੂ (ਬਜਟ 60 req).', to_launch: '[GO] {p} ਤੇ mode {m} (CWE {c}) - ਲੋਕਲ ਸਾਈਕਲ ਚਾਲੂ',
    to_ai_ok: 'config ਸੇਵ ਹੋਇਆ', to_ai_no: 'ਸੇਵ ਅਸਫਲ',
    to_ai_no_cfg: 'AI ਕੌਨਫਿਗਰ ਨਹੀਂ - AI ਟੈਬ ਵਿੱਚ ਸੈੱਟ ਕਰੋ', to_ai_head: 'AI ਵਿਸ਼ਲੇਸ਼ਣ',
    to_ai_bad: 'AI ਵਿਸ਼ਲੇਸ਼ਣ ਅਸਫਲ', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ ਲਾਂਚ', navar: 'ਅਰਸਨਲ',
    ar_h2: 'ARSENAL - ਖੋਜੀ ਗਈ ਸਤ੍ਹਾ ਤੇ CVE, EPSS ਅਤੇ exploits', ar_sync: 'SYNC ਬੇਸ',
    ar_btn: 'ਚਾਲਾਂ', ar_exec: 'EXEC',
    ar_none: 'ਕੋਈ ਚਾਲ ਨਹੀਂ: ਪਹਿਲਾਂ RECON ਚਲਾਓ, ਫਿਰ KEV/EPSS ਲੋਡ ਕਰਨ ਲਈ SYNC', ar_loading: 'ਬੇਸਾਂ ਦਾ ਸਾਰ ਲੋਡ ਹੋ ਰਿਹਾ ਹੈ...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'ਡੈਮੋ ਪ੍ਰੋਗਰਾਮ - ਸਕੈਨ ਨਹੀਂ : ਆਪਣਾ ਪ੍ਰੋਗਰਾਮ ਬਣਾਓ', pip_noprog: 'ਕੋਈ ਪ੍ਰੋਗਰਾਮ ਨਹੀਂ : ਪ੍ਰੋਗਰਾਮ ਟੈਬ ਵਿੱਚ ਆਪਣਾ ਬਣਾਓ',
    pip_next: 'ਅਗਲਾ ਪੜਾਅ :', fnd_n: 'ਫਾਈਂਡਿੰਗਜ਼: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  sw: {
    pl_title: 'Mpango wa kazi', pl_empty: 'bado hakuna mpango : anza RECON kwenye kadi ya juu, dhana huhifadhiwa hapa (hali zinadumu)',
    pl_run: 'Anzisha', pl_reflect: 'canary imekurudishwa',
    st_do: 'kufanywa', st_test: 'imejaribiwa',
    st_signal: 'ishara', st_valid: 'imethibitishwa',
    st_void: 'hakuna', atk_btn: 'ATTACK',
    atk_start: 'inashambulia uso : endpoints, docs zilizo wazi, JWT, secrets...', atk_fail: 'shambulio halipo : anzisha RECON kwanza',
    atk_none: 'hakuna ishara', atk_findings: 'wagombea',
    atk_done: 'ATTACK : wagombea {n} wa P1/P2 wameingizwa kwenye findings pamoja na ushahidi', atk_empty: 'bado hakuna attack : anzisha RECON kisha ATTACK - wagombea wenye ushahidi wa req/res hufika hapa',
    navh: 'HUNT', h2hunt: 'HUNT - uso halisi na ushahidi',
    h_ready: 'tayari', h_empty: 'hakuna uso unaofahamika : anzisha RECON kupaka ramani ya kurasa, API endpoints, vigezo, JS bundles na subdomains',
    h_fnd: 'Findings za programu', h_nofnd: 'hakuna finding kwenye programu hii',
    rc_btn: 'RECON', rc_start: 'recon ya uno unaendelea : kurasa, JS bundles, endpoints, vigezo...',
    rc_done: 'uno umepakwa ramani : endpoints, vigezo na subdomains vimewekwa kwenye kadi ya programu', rc_fail: 'recon imeshindikana : host haiwezi kufikiwa au scope ni tupu',
    rc_surface: 'uso :', snd_on: 'SAUTI : ON',
    snd_off: 'SAUTI : OFF', snd_ok: 'sauti za interface zimewashwa - library : click, tab, copy, tahadhari',
    snd_stop: 'kimya kikuu kimewashwa : hakuna sauti tena kutoka C2FF', amb_on: 'MAYA : ON',
    amb_off: 'MAYA : OFF', amb_ok: 'maya hai - kivuli cha rangi hutetea taratibu katika makundi (kijani, buluu, njano...)',
    amb_stop: 'maya imelala kwenye kijani cha asili', nt_on: 'ARIFA : ON',
    nt_off: 'ARIFA : OFF', nt_ok: 'arifa za kivinjari zimewashwa - mlio wa bip kwenye P1 na P2',
    nt_denied: 'kivinjari kimezuia arifa : ruhusu katika mipangilio ya tovuti', term_denied: 'terminal imekataliwa au haipo : inahitaji localhost, au chumba kilichofunguliwa kama admin',
    term_p: 'bash halisi - history kwa mishale, Ctrl+C ikata, Ctrl+D funga', term_restart: 'Weka upya',
    navtrm: 'TERM', term_h2: 'Terminal - shell ya kazi, moja kwa moja kwenye console',
    fl_off: 'FLEET : IMESIMAMA', fl_paused: 'FLEET : PAUSE',
    fl_active: 'FLEET : INAFAA ({n} mzunguko)', fl_last: 'mzunguko wa mwisho',
    fl_none: 'bado hakuna mzunguko', fl_info: 'kipindi cha {i} min, bajeti ya {b} req/mzunguko',
    sub_ttl: 'command & control framework', navt: 'KIPINDI',
    tm_h2: 'Vikao vya kikundi - uwindaji pamoja, hata kavu', tm_p: 'Fungua chumba cha pamoja : kikundi chako kinaona fleet na findings, na kinaweza kupanga kwa papo hapo. Chat ya kikao nchini. Ngazi tatu za ufikiaji : LOCAL (mtu mmoja), LAN kwa KUFUNGUA KWA MTANDAO, na DUNIA kwa KUFUNGUA KWA DUNIA - tuneli ya umma (cloudflared ikiwa imesakinishwa) inafanya link ya mwaliko iwe halali kutoka mtandao wowote, bila mashine yako kuonekana moja kwa moja. Kila kitu kimegandwa kwenye ufunguo wa chumba - tengeneza upya ili kumtoa kila mtu kwa mara moja.',
    tm_handle: 'Jina lako (herufi 16 kwa wingi)', tm_save_h: 'Weka',
    tm_room_ph: 'jina la chumba (mf : c2ff-core)', tm_save: 'Tekeleza',
    tm_on: 'CHUMBA KIMEFUNGULIWA : {r} - {n} mtandaoni', tm_off: 'TEAM MODE IMEZIMWA - kipindi cha kipekee',
    tm_room: 'Chumba', tm_key: 'Ufunguo wa chumba',
    tm_regen: 'Tengeneza upya ufunguo', tm_regen_ok: 'ufunguo mpya umetengenezwa - link za kale zimekufa',
    tm_invite: 'Link ya mialiko (nakili kwa timu yako)', tm_copy: 'Nakili',
    tm_copied: 'imenakiliwa kwenye clipboard', tm_members: 'Wanachama',
    tm_nobody: 'hakuna mtu bado - tumia link kwa timu yako', tm_you: '(wewe)',
    tm_here: 'hapa', tm_saved: 'jina limehifadhiwa',
    tm_no_handle: 'jina tupu', tm_cfg_ok: 'chumba limehaririwa',
    tm_cfg_no: 'imeshindikana', tm_live: 'FUNGUA KWA MTANDAO',
    tm_shore: 'RUDI LOCAL', tm_need_on: 'washa chumba kwanza (ON)',
    tm_bind_lan: 'NETWORK : {a}', tm_bind_lo: 'LOCAL : localhost pekee',
    to_team_live: '[GO-LIVE] seva imeanza upya yenye ufikiaji wa mtandao - link la LAN linaonyeshwa, kuunganisha tena kwa 2 s', to_team_shore: 'seva imeanza upya kwenye local (127.0.0.1)',
    tm_tun_open: 'FUNGUA KWA DUNIA (tuneli)', tm_tun_close: 'FUNGA TUNELI',
    tm_tun_wait: 'tuneli ya umma inafunguliwa (sekunde chache)…', tm_tun_on: 'KIKAO KIMEFUNGULIWA KWA DUNIA : {u} - link ya mialiko inafanya kazi popote, mtandao mmoja hauhitajiki',
    tm_tun_closed: 'tuneli imefungwa - nyuma kwa mtandao/local', tm_chat_empty: 'kituo cha kikao kimefunguliwa - wanachama wa chumba wanasoma hapa',
    tm_chat_h2: 'Chat ya kikao', tm_msg_ph: 'ujumbe kwa kikao…',
    tm_admin: 'admin', tm_guest: 'mgeni',
    tm_kick: 'KICK', tm_kick_ok: 'mwanachama ameondolewa kwenye chumba (bofya tena kufungua)',
    tm_role_ok: 'jukumu limesasishwa', tm_mic_on: 'WASHA MAIKROFONI',
    tm_mic_off: 'ZIMA MAIKROFON', tm_mic_denied: 'maikrofon imekataliwa au haipatikani : HTTPS inahitajika (tuneli DUNIA au localhost) na lazima kutoa idhini ya maikrofoni',
    navf: 'Floti', navfd: 'Findings',
    navp: 'Programu', navai: 'AI',
    navc: 'Uratibu', st_runs: 'Runs',
    st_beacons: 'Beacon hai', st_sig: 'Ishara',
    h2f: 'Floti - programu zote, wawakala wanaokimbiza kwanza', h2fd: 'Msingi wa findings - alama za triage daima',
    h2eng: 'Mfumo wa fleet - mizunguko ya kienyeji, bila tokens', h2prog: 'Programu - scope, header muhimu, uzinduzi',
    h2new: 'Programu mpya', h2ai: 'Kichuku cha AI - 100% hiari',
    h2c: 'Uratibu - kituo cha faragha', fl_start: 'Anza',
    fl_pause: 'Pause', fl_cycle: 'Mzunguko sasa',
    f_add: 'Ongeza', f_none: 'bado hakuna ishara',
    f_ph: 'finding ya mkono : endpoint + ushahidi + sev inayoweza kuzuiwa…', st_sig_off: 'ishara',
    st_sig_an: 'uchambuzi', st_sig_sub: 'iliwasilishwa',
    st_sig_dup: 'dup', st_sig_ref: 'iliyokataliwa',
    st_sig_cl: 'imefungwa', r_none: 'hakuna run iliyotambuliwa',
    r_live: '{n} INAENDELEA', r_done: 'IMEKAMILIKA',
    r_feed: '▽ mtiririko ({n} ev)', r_close: '△ kushinikiza',
    p_name_ph: 'Jina la programu (mf : PayPal)', p_hdr_ph: 'header ya mtafiti inahitajika (mf : X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domain1, domain2, …', p_save: 'Hifadhi',
    p_local: 'module, 100% kienyeji', ai_p: 'C2FF inafanya kazi kikamilifu bila AI : modaliti ni probes deterministic za kienyeji. Geri hii inatumika tu kuunganisha <b>AI yako</b> (self-hosted au API) kwa uchambuzi wa finding mmoja inapohitajika : kitufe <span style="color:var(--green)">AI »</span> kwenye FINDINGS, jibu linageuka COORDINATION. Hakuna data inayotoka kwenye mashine yako bila usanidi huu.',
    ai_off: 'imezimwa', ai_on: 'imewashwa',
    ai_st_off: 'AI IMEZIMWA - framework inaendelea 100% kienyeji bila yake', ai_st_ready: 'AI IMEUNGANISHWA : {p} · {m}',
    ai_st_inc: 'AI IMEWASHWA ILA HAIKAMILI : baseURL na model zinahitajika', ai_url_ph: 'base URL - mf : http://localhost:11434 au https://api.MyAI.tld/v1',
    ai_model_ph: 'model - mf : llama3.1:8b', ai_key_ph: 'API key (iache wazi kwa seva ya kienyeji)',
    ai_save: 'Hifadhi', ai_test: 'Jaribu muunganisho',
    ai_testing: 'inajaribu…', ai_ok: 'OK - jibu : ',
    ai_fail: 'IMEFELI : ', ai_note: 'config imetunziwa kienyeji data/ai.json - haitumwi mahali pengine isipokuwa endpoint uliyoiweka',
    ch_ph: 'root@c2ff:~# ujumbe kwa wakala wa uchambuzi…', ch_send: 'Tuma',
    ch_empty: 'Kituo kimefunguliwa. Andika hapa, monitor inaniamsha papo hapo.', ft: '100% kienyeji - probes za kienyeji, bila tokens au dependencies za nje - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE INAFAA : mizunguko ya kienyeji kila dakika 30, token 0.', to_fl_pa: 'FLEET KWA PAUSE - endelea unavyotaka.',
    to_fl_cy: 'Mzunguko wa papo hapo umeanza (bajeti 60 req).', to_launch: '[GO] mode {m} (CWE {c}) kwenye {p} - mzunguko wa kienyeji umeanza',
    to_ai_ok: 'config imehifadhiwa', to_ai_no: 'kuhifadhi kimefeli',
    to_ai_no_cfg: 'AI haijapangwa - iweke kwenye tab ya AI', to_ai_head: 'UCHAMBUZI WA AI',
    to_ai_bad: 'Uchambuzi wa AI umefeli', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ UZINDUZI', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS na exploits kwenye uso uliogunduliwa', ar_sync: 'SYNC HIFADHI',
    ar_btn: 'HATUA', ar_exec: 'EXEC',
    ar_none: 'hakuna hatua: endesha RECON kwanza, kisha SYNC kupakia KEV/EPSS', ar_loading: 'muhtasari wa hifadhi inapakiwa...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'programu ya mfano - hakuna uchanganuzi : tengeneza programu yako', pip_noprog: 'hakuna programu : tengeneza yako kwenye Programu',
    pip_next: 'hatua inayofuata :', fnd_n: 'matokeo: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  am: {
    pl_title: 'የሥራ እቅድ', pl_empty: 'እስካሁን እቅድ የለም : ከላይ ባለው ካርድ ላይ RECON አስጀምር፣ ግምቶች እዚህ ይወድቃሉ (ሁኔታዎች ይቀመጣሉ)',
    pl_run: 'አስንበቅ', pl_reflect: 'canary ተመለስቷል',
    st_do: 'መሥራት ያለበት', st_test: 'የተፈተነ',
    st_signal: 'ምልክት', st_valid: 'የተረጋገጠ',
    st_void: 'ምንም የለም', atk_btn: 'ATTACK',
    atk_start: 'ላይኛውን ገጽ በመደበር ላይ : endpoints, የተከፈቱ docs, JWT, secrets...', atk_fail: 'መደበር አልተቻለም : በመጀመሪያ RECON አስጀምር',
    atk_none: 'ምንም ምልክት የለም', atk_findings: 'ተወዳደሮች',
    atk_done: 'ATTACK : ማስረጃ ጋር የ{n} P1/P2 ተወዳደሮች ወደ findings ገቡ', atk_empty: 'እስካሁን attack የለም : RECON አስጀምር ከዚያ ATTACK - ማስረጃ req/res ጋር ተወዳደሮች እዚህ ይወድቃሉ',
    navh: 'HUNT', h2hunt: 'HUNT - እውነተኛ ገጽ እና ማስረጃዎች',
    h_ready: 'ተዘጋጅቷል', h_empty: 'የሚታወቅ ገጽ የለም : ገጾችን፣ API endpoints፣ ተለዋዋጮችን፣ JS bundles እና subdomains ለመከለስ RECON አስጀምር',
    h_fnd: 'የቡድኑ findings', h_nofnd: 'በዚህ ቡድን ላይ finding የለም',
    rc_btn: 'RECON', rc_start: 'ገጹ ገጽ በመከለስ ላይ : ገጾች፣ JS bundles፣ endpoints፣ ተለዋዋጮች...',
    rc_done: 'ገጽ ተከለሰ : endpoints፣ ተለዋዋጮች እና subdomains በቡድን ካርድ ላይ ተዘረዘሩ', rc_fail: 'recon አልተሳካም : host መዳረስ አልተቻለም ወይም scope ባዶ ነው',
    rc_surface: 'ገጽ :', snd_on: 'ድምፅ : ON',
    snd_off: 'ድምፅ : OFF', snd_ok: 'የገጽታ ድምፆች እነቃቁ - ቤተ-መጻሕፍት : click, tab, copy, ማንቂያዎች',
    snd_stop: 'ሙሉ ፀረ-ድምፅ ተነቃቋል : ከዚህ በኋላ የC2FF ድምፅ የለም', amb_on: 'ስሜት : ON',
    amb_off: 'ስሜት : OFF', amb_ok: 'በሕይወት ስሜት - የቀለም ብርሃን በቀስታ በቤተሰቦች ውስጥ ያረፈሳል (አረንጓዴ፣ ሰማያዊ፣ ቢጫ...)',
    amb_stop: 'ስሜት በመጀመሪያው አረንጓዴ ላይ ምስቃል ሆነ', nt_on: 'ማንቂያ : ON',
    nt_off: 'ማንቂያ : OFF', nt_ok: 'የአሰሳ ማንቂያዎች ተነቃቁ - በP1 እና P2 ላይ ቢፕ',
    nt_denied: 'አሳሹ ማንቂያዎችን ከልክሏል : በድረ-ገጹ ማዘጋጀት ውስጥ ፈቅድ', term_denied: 'ተርሚናል ተቀባይነት አጣ ወይም የለም : localhost ያስፈልጋል፣ ወይም እንደ አስተዳዳሪ ክፍል ክፍት ነው',
    term_p: 'ትክክለኛ bash - በቀኝ በግራ በመንቀሳቀስ history፣ Ctrl+C ይከላከላል፣ Ctrl+D ይዝጋል', term_restart: 'ዳግም ማስጀመር',
    navtrm: 'TERM', term_h2: 'ተርሚናል - የሥራ ሽፌይል፣ በቀጥታ በኮንሶል ውስጥ',
    fl_off: 'FLEET : ቆሟል', fl_paused: 'FLEET : PAUSE',
    fl_active: 'FLEET : ንቁ ({n} ዙር)', fl_last: 'የመጨረሻ ዙር',
    fl_none: 'እስካሁን ዙር የለም', fl_info: '{i} min ክፈል፣ {b} req/ዙር',
    sub_ttl: 'command & control framework', navt: 'ክፍለ-ጊዜ',
    tm_h2: 'ቡድነ ጊዜያት - አብረው ማደን፣ ያለ ሰሌዳም', tm_p: 'የተጋራ ክፍል ክፈት : ቡድንህ fleet እና findings ያያል እና በቀጥታ ማጣበቅ ይችላል። ከታች ልዩ የስብሰባ ቻት። ሦስት ደረጃ ያለው መዳረስ : LOCAL (ብቻውን)፣ LAN በወደ በር መክፈት፣ እና ዓለም በወደ ዓለም በር - ሕዝባዊ ቱነል (cloudflared ተጭኗል ካለ) የጋብዣ ሊንክ ከማንኛውም ሰሌዳ በወደፊት ውጤታማ ይሆናል፣ የአንተ ቆጣሪ ያለማሳየት። ሁሉም በክፍል ቁልፍ የተከለለ ነው - አንዴ ብቻ በአንድ ልክ ሁሉንም በር ለማጥፋት ዳግም ሥራው።',
    tm_handle: 'ስምህ (ከ16 ፊደል ጎልቶ)', tm_save_h: 'ተክ',
    tm_room_ph: 'የክፍል ስም (ለም : c2ff-core)', tm_save: 'ውጤት',
    tm_on: 'ክፍል ተከፈተ : {r} - {n} ክፈት', tm_off: 'TEAM MODE የተዘጋ - አካባቢያ ልዩ ስብሰባ',
    tm_room: 'ክፍል', tm_key: 'የክፍል ቁልፍ',
    tm_regen: 'ቁልፍ እንደገና ሥራ', tm_regen_ok: 'አዲስ ቁልፍ ተፈጠረ - የድሮ ሊንኮች ሞቱ',
    tm_invite: 'የጋብዣ ሊንክ (ወደ ቡድንህ ቅጂ)', tm_copy: 'ቅጂ',
    tm_copied: 'ወደ ቅጂ ሰሌዳ ተቫላ', tm_members: 'አባዛዎች',
    tm_nobody: 'እስካሁን ሰው የለም - ሊንኩን ለቡድንህ ላክ', tm_you: '(አንተ)',
    tm_here: 'እዚህ', tm_saved: 'ስም ተቀመጠ',
    tm_no_handle: 'ስም ባዶ', tm_cfg_ok: 'ክፍል ተሻሽሏል',
    tm_cfg_no: 'አልተሳካም', tm_live: 'ወደ ሰሌዳ ክፈት',
    tm_shore: 'ወደ አካባቢ ተመለስ', tm_need_on: 'ክፍሉን በመጀመሪያ አንቃ (ON)',
    tm_bind_lan: 'NETWORK : {a}', tm_bind_lo: 'LOCAL : localhost ብቻ',
    to_team_live: '[GO-LIVE] ሰርቨሩ በአካባቢ መዳረሻ ዳግም ጀምሯል - LAN ሊንክ ይታያል፣ በ2 ሰከንድ ውስጥ ዳግም ተጠጘ', to_team_shore: 'ሰርቨሩ አካባቢው (127.0.0.1) ዳግም ጀምሯል',
    tm_tun_open: 'ወደ አለም ክፈት (ቱነል)', tm_tun_close: 'ቱነልን ዝጋ',
    tm_tun_wait: 'ሕዝባዊ ቱነል ይከፈታል (ጥቂት ሰከንድ)…', tm_tun_on: 'ስብሰባው ወደ አለም ተከፈተ : {u} - የጋብዣ ሊንክ ከየትም ይሠራል፣ አንድ ሰሌዳ አያስፈልግም',
    tm_tun_closed: 'ቱነሉ ተዘጋ - ወደ ሰሌዳ/አካባቢ ተመለስ', tm_chat_empty: 'የስብሰባ ገጽታ ተከፈተ - የክፍል አባዛዎች እዚህ እርስ በርስ ያነባሉ',
    tm_chat_h2: 'የስብሰባ ቻት', tm_msg_ph: 'ወደ ስብሰባ መልእክት…',
    tm_admin: 'አስተዳዳሪ', tm_guest: 'እንግዳ',
    tm_kick: 'KICK', tm_kick_ok: 'አባዛው ከክፍሉ ተወግዷል (ዳግም ጠቅ ማድረግ ይከፍታል)',
    tm_role_ok: 'ሚና ተሻሽሏል', tm_mic_on: 'ማይክሮፎን አንቃ',
    tm_mic_off: 'ማይክሮፎን አጥፋ', tm_mic_denied: 'ማይክሮፎን ተቀባይነት አጣ ወይም አይደረስም : HTTPS ያስፈልጋል (የዓለም ቱነል ወይም localhost) እና ለማይክሮፎን ፈቃድ መስጠት ያስፈልጋል',
    navf: 'ቦታ', navfd: 'Findings',
    navp: 'ቡድን', navai: 'AI',
    navc: 'አያካሊም', st_runs: 'ጊዜያት',
    st_beacons: 'ንቁ ማዕረጎች', st_sig: 'ምልክቶች',
    h2f: 'ቦታ - ሌሎች ቡድኖች፣ ኗሪ ወኪሎች መጀመሪያ', h2fd: 'Findings መሰረት - የተረጋገጠ የትሪያጅ አስመራጭ',
    h2eng: 'የቦታ ሞተር - አካባቢዊ ዙሮች፣ ታኮን የለም', h2prog: 'ቡድኖች - scope፣ ፊርማ፣ ማስነሳት',
    h2new: 'አዲስ ቡድን', h2ai: 'AI ወኪል - 100% በዑሰ',
    h2c: 'አያካሊም - የግል ገጽ', fl_start: 'ጀምር',
    fl_pause: 'Pause', fl_cycle: 'ዙር አሁን',
    f_add: 'ጨምር', f_none: 'እስካሁን ምልክት የለም',
    f_ph: 'በእጅ finding : endpoint + ማስረጃ + አትትከሻሻ sev…', st_sig_off: 'ምልክት',
    st_sig_an: 'ትንታኔ', st_sig_sub: 'በያዘ',
    st_sig_dup: 'dup', st_sig_ref: 'ተቀባይነት አላገኘም',
    st_sig_cl: 'ተዘጋ', r_none: 'ዙር አልተገኘም',
    r_live: '{n} እየተካሉ', r_done: 'ተመሳረሰ',
    r_feed: '▽ ፍንጭ ({n} ev)', r_close: '△ መሷለክ',
    p_name_ph: 'የቡድን ስም (ለም : PayPal)', p_hdr_ph: 'የተመራማሪ ፊርማ ያስፈልጋል (ለም : X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domain1, domain2, …', p_save: 'አስቀምጥ',
    p_local: 'ሞድዮል፣ 100% አካባቢዊ', ai_p: 'C2FF ሙሉ በሙሉ AI ያለ ይሰራል : ሞዶች በአካባቢ የተወሰኑ ፕሮቦች ናቸው። ይህ በር አንድ finding በተወሰነ ጊዜ ለመተንተን <b>የአንተ</b> AI (self-hosted ወይም API) ለማገናዘብ ብቻ ነው : በFINDINGS ውስጥ <span style="color:var(--green)">AI »</span> አዝራር፣ መልሱ በCOORDINATION ይታያል። ይህ ማዋቀር ካልሆነ ከአክሊህ ቆጣሪ ማንም መረጃ አይወጣም።',
    ai_off: 'ጠፋ', ai_on: 'ነቃ',
    ai_st_off: 'AI ጠፋ - ትእዛዙ 100% አካባቢዊ ያለእሱ ይሰራል', ai_st_ready: 'AI ተገናኝቷል : {p} · {m}',
    ai_st_inc: 'AI ነቃ ነገር ግን አልተሟላም : baseURL እና model ያስፈልጋሉ', ai_url_ph: 'base URL - ለም : http://localhost:11434 ወይም https://api.MyAI.tld/v1',
    ai_model_ph: 'model - ለም : llama3.1:8b', ai_key_ph: 'API key (ለአካባቢዊ ሰርቨር ባዶ አብተው)',
    ai_save: 'አስቀምጥ', ai_test: 'ግንኙነት ፈትሽ',
    ai_testing: 'ፈተና እየሰራ…', ai_ok: 'OK - መልስ : ',
    ai_fail: 'አልተሳካም : ', ai_note: 'ማዋቀሩ በአካባቢ data/ai.json ውስጥ ይቀመጣል - አንተ የመረጥከውን endpoint ሳይሆን በሌላ ማንኛውም ላይ አይላክም',
    ch_ph: 'root@c2ff:~# መልእክት ወደ ተንታኝ ወኪል…', ch_send: 'ላክ',
    ch_empty: 'ገጽታው ተከፈተ። እዚህ ተንጠፍ፣ ማየት ያለምንም ያነቃኛል።', ft: '100% አካባቢዊ - ሚዛናዊ መለኪያዎች፣ ተከላካዪ የለም፣ የውጭ ጥገኛ የለም - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ንቁ : በየ30 ደቂቃው አካባቢዊ ዙሮች፣ 0 ምልክት.', to_fl_pa: 'FLEET PAUSE - እንደገና እንደፈለግክ ነንቃ.',
    to_fl_cy: 'ቋሚ ዙር ጀምሯል (በጀት 60 req).', to_launch: '[GO] mode {m} (CWE {c}) በ{p} - አካባቢዊ ዙር ጀምሯል',
    to_ai_ok: 'ማዟዟ ተቀመጠ', to_ai_no: 'ማስቀመጥ አልተሳካም',
    to_ai_no_cfg: 'AI አልተዋቀረም - በAI ታብ ውስጥ አስተካክለው', to_ai_head: 'የAI ትንታኔ',
    to_ai_bad: 'የAI ትንታኔ አልተሳካም', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ ክፈት', navar: 'አርሴናል',
    ar_h2: 'ARSENAL - በተገኘው ገጽ ላይ CVE፣ EPSS እና exploits', ar_sync: 'SYNC ቤዞች',
    ar_btn: 'እንቅስቃሴዎች', ar_exec: 'EXEC',
    ar_none: 'እንቅስቃሴ የለም: መጀመሪያ RECON ያሂዱ፣ ከዚያ KEV/EPSS ለመጫን SYNC ያሂዱ', ar_loading: 'የቤዞች ማጠቃለያ በመጫን ላይ...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'የማሳያ ፕሮግራም - ስካን የለም : የራስህን ፕሮግራም ፍጠር', pip_noprog: 'ፕሮግራም የለም : በፕሮግራሞች ትር ውስጥ የራስህን ፍጠር',
    pip_next: 'ቀጣዩ ደረጃ :', fnd_n: 'ውጤቶች: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  ha: {
    pl_title: 'Shirin aiki', pl_empty: 'babu shirin har yanzu : gudanar da RECON a cikin katin da ke sama, hasashe za fadi a nan (matsayi za zauna)',
    pl_run: 'Gudanar', pl_reflect: 'canary an maido',
    st_do: 'abinda zaiyi', st_test: 'an gwada',
    st_signal: 'sigina', st_valid: 'an tabbatar',
    st_void: 'babu', atk_btn: 'ATTACK',
    atk_start: 'ana kai hari kan farfajiya : endpoints, docs na buɗe, JWT, secrets...', atk_fail: 'ba a iya kai hari : farko gudanar da RECON',
    atk_none: 'babu sigina', atk_findings: 'mazata',
    atk_done: 'ATTACK : shaidar req/res, {n} mazata na P1/P2 an shiga ciki findings', atk_empty: 'babu attack a yanzu : gudanar da RECON sannan ATTACK - mazata tare da shaidar req/res za fadi nan',
    navh: 'HUNT', h2hunt: 'HUNT - farfajiya na gaske da shaidu',
    h_ready: 'a shirye', h_empty: 'babu farfajiya da aka sani : gudanar da RECON don nadi shafi, API endpoints, sigogi, JS bundles da subdomains',
    h_fnd: 'Findings na shiri', h_nofnd: 'babu finding a wannan shiri',
    rc_btn: 'RECON', rc_start: 'recon na farfajiya na gudana : shafuka, JS bundles, endpoints, sigogi...',
    rc_done: 'an nadi farfajiya : endpoints, sigogi da subdomains an jera su a katin shiri', rc_fail: 'recon ya kasa : ba za a samu host ko fanko ne scope',
    rc_surface: 'farfajiya :', snd_on: 'SAUTI : ON',
    snd_off: 'SAUTI : OFF', snd_ok: 'sautin interface sun rika - library : click, tab, copy, gargadi',
    snd_stop: 'kadauri na cikakken sauti ya aiki : babu wani sautin C2FF daga yanzu', amb_on: 'MUHALLI : ON',
    amb_off: 'MUHALLI : OFF', amb_ok: 'muhalli mai rai - hasken launi yana jinkirta a kusan kungiyoyi (kore, shuɗi, ja rawaya...)',
    amb_stop: 'muhalli ya rataye a kan kore na asali', nt_on: 'SANARWA : ON',
    nt_off: 'SANARWA : OFF', nt_ok: 'sanarwa na yanar gizo su rika - bip a kan P1 da P2',
    nt_denied: 'yanar gizo ya toshe sanarwa : ba da izini cikin saitunan shafi', term_denied: 'an ki terminal ko ba a gani : localhost ya bukace, ko a kasa tabbata kamar admin',
    term_p: 'bash na gaske - tarihi da makafi na hagu, Ctrl+C ta dakatar, Ctrl+D ta rufe', term_restart: 'Sake saita',
    navtrm: 'TERM', term_h2: 'Terminal - shel na aiki, kuma ga nan a konsol',
    fl_off: 'FLEET : AN TSAYA', fl_paused: 'FLEET : PAUSE',
    fl_active: 'FLEET : MUNKARE ({n} zagaye)', fl_last: 'zagaye na karshe',
    fl_none: 'babu zagaye har yanzu', fl_info: 'araha tsakanin {i} min, {b} req/zagaye',
    sub_ttl: 'command & control framework', navt: 'ZAMAN',
    tm_h2: 'Zaman kungiya - neman tare, ba tare da yanar gizo ma', tm_p: 'Buɗe dakin raba : kungiyarka na ga fleet, findings, kuma za ta iya tarayya ta kai kan gari. Kasa chat na kafa zaman ta daban. Hanyar isa uku : LOCAL (kai daya), LAN ta BUDU HAR YANAR GIZO, da DUNIYA ta BUDU HAR DUNIYA - hanyar tunel jama\'a (cloudflared idan aka shigar) na sanya hanyar gayyata na aiki daga kowane yanar gizo, ba kai kan gari kan naka maɓalli ka ba. Duk abin da ke gare ta maballin daki - sake samar dashi don kore kowa lokaci daya.',
    tm_handle: 'Sunanka (har 16 harufovi)', tm_save_h: 'Saita',
    tm_room_ph: 'sunan daki (mis : c2ff-core)', tm_save: 'Aiki da',
    tm_on: 'DAKI BUDU : {r} - {n} online', tm_off: 'TEAM MODE KASHE - kasa na daki daya',
    tm_room: 'Daki', tm_key: 'Maballi na daki',
    tm_regen: 'Sake maballi', tm_regen_ok: 'maballin sabon an saita - tsofaffin hanyar sun fafin',
    tm_invite: 'Hanyar gayyata (naka copy zuwa kungiyarka)', tm_copy: 'Copy',
    tm_copied: 'an copy zuwa kan clipboard', tm_members: 'Membobi',
    tm_nobody: 'babu kowa har yanzu - aika link zuwa kungiyarka', tm_you: '(kai)',
    tm_here: 'a nan', tm_saved: 'an ajiye suna',
    tm_no_handle: 'fanko ne sunan', tm_cfg_ok: 'daki ya sabunta',
    tm_cfg_no: 'ya kasa', tm_live: 'BUDU CI',
    tm_shore: 'KOMOWA LOCAL', tm_need_on: 'fara buɗe daki (ON)',
    tm_bind_lan: 'NETWORK : {a}', tm_bind_lo: 'LOCAL : localhost kadai',
    to_team_live: '[GO-LIVE] sarwara ta sake budewa tare da isa daga hanyar sadarwa - nuna ƙonar LAN, haɗa daga 2 s', to_team_shore: 'sarwara ta sake budewa a local (127.0.0.1)',
    tm_tun_open: 'BUDU DUNIYA (tunel)', tm_tun_close: 'RUFETURE TUNEL',
    tm_tun_wait: 'tunel kama ya nadi (saniyan)…', tm_tun_on: 'KUNUNWA TARE DUNIYA : {u} - hanyar gayyata tazama kowane wuri, bukan hanyar daya',
    tm_tun_closed: 'tunel ya rufe - dawo local', tm_chat_empty: 'kafar zaman budu - jama\'a na daki na kai su ga a nan',
    tm_chat_h2: 'Chat na zaman', tm_msg_ph: 'sako zuwa zaman…',
    tm_admin: 'admin', tm_guest: 'bakon',
    tm_kick: 'KICK', tm_kick_ok: 'membran a fitar da daki (danna sake don buɗewa)',
    tm_role_ok: 'matsayi ya sabunta', tm_mic_on: 'KUNNA MIKIRO',
    tm_mic_off: 'KASHE MIKIRO', tm_mic_denied: 'mikiro an ki ko ba a samu : HTTPS a bukace (tunel na DUNIYA ko localhost) kasa da amincin mikrofoni',
    navf: 'Mulki', navfd: 'Tafin',
    navp: 'Shiri', navai: 'AI',
    navc: 'Sanari', st_runs: 'Runs',
    st_beacons: 'Hasumiyoyin Munkare', st_sig: 'Sigina',
    h2f: 'Mulki - duk shirin, abubuwa a farko', h2fd: 'Tushen findings - tamga na dindindin',
    h2eng: 'Gudana na mulki - zagaye na gida, babu token', h2prog: 'Shirya - scope, mai sa kasa, zama',
    h2new: 'Shiri saban', h2ai: 'Wakilin AI - 100% dole ne a ba',
    h2c: 'Sanari - hanya na kware', fl_start: 'Fara',
    fl_pause: 'Pause', fl_cycle: 'Zagaye yanzu',
    f_add: 'Kara', f_none: 'babu sigina har yanzu',
    f_ph: 'finding ta hannu : endpoint + shaida + sev da a zabi...', st_sig_off: 'sigina',
    st_sig_an: 'nazari', st_sig_sub: 'an tura',
    st_sig_dup: 'dup', st_sig_ref: 'an ki da',
    st_sig_cl: 'rufe', r_none: 'babu run da aka ganin',
    r_live: '{n} AKAN GUDANA', r_done: 'AN GAMMA',
    r_feed: '▽ rafi ({n} ev)', r_close: '△ kasance',
    p_name_ph: 'Sunan shiri (mis : PayPal)', p_hdr_ph: 'bayar da mai bincike a bukace (mis : X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domain1, domain2, …', p_save: 'Ajiye',
    p_local: 'modul, 100% na gida', ai_p: 'C2FF yana gudana gabadaya ba tare da AI ba : matakai sun gaskiyawa gida. Wannan gefe kawai ta sa ya hada <b>AI naka</b> (self-hosted ko API) domin nazarin finding : ma\'aunin <span style="color:var(--green)">AI »</span> a FINDINGS, amsa a COORDINATION. Ba a fitar da bayani daga matan ba tare da saitin nan.',
    ai_off: 'kashe', ai_on: 'kunna',
    ai_st_off: 'AI KASHE - framework na gudana gida 100%', ai_st_ready: 'AI HADA : {p} · {m}',
    ai_st_inc: 'AI KONNA AMMA INCOMPLETE : baseURL da model a bukace', ai_url_ph: 'base URL - mis : http://localhost:11434 ko https://api.MyAI.tld/v1',
    ai_model_ph: 'model - mis : llama3.1:8b', ai_key_ph: 'API key (bari babu komai idan sabar ta gida)',
    ai_save: 'Ajiye', ai_test: 'Gwada haɗuwa',
    ai_testing: 'ana gwadawa…', ai_ok: 'OK - amsa : ',
    ai_fail: 'GALLALA : ', ai_note: 'saitun nan a data/ai.json a gida - kada tuhuma zuwa wani inda ka kasance',
    ch_ph: 'root@c2ff:~# sako zuwa wakilin nazari…', ch_send: 'Tura',
    ch_empty: 'Kafar na budu. Rubuta nan, monitor zai maka nan take.', ft: '100% na gida - gwajin gaske, ba token ko dogaro - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE MUNKARE : zagaye na gida kowane 30 min, 0 token.', to_fl_pa: 'FLEET KASA - juya lokacin da kake.',
    to_fl_cy: 'Zagaye na gaskiya ya fara (bajet 60 req).', to_launch: '[GO] mode {m} (CWE {c}) a {p} - zagaye na gida ya fara',
    to_ai_ok: 'saitun nan ya save', to_ai_no: 'ya kasa save',
    to_ai_no_cfg: 'AI ba a sasanta - taba AI a tab', to_ai_head: 'NAZARIN AI',
    to_ai_bad: 'Nazarin AI ya fadi', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ FARAWA', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS da exploits a kan farfajiyar da aka gano', ar_sync: 'SYNC TUSHE',
    ar_btn: 'MOTSUKA', ar_exec: 'EXEC',
    ar_none: 'babu motsuka: fara RECON da farko, sannan SYNC don loda KEV/EPSS', ar_loading: 'taƙaitaccen bayanan tushe ana loda su...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'shirin misali - babu dubawa : ka kirkiri naka', pip_noprog: 'babu shiri : ka kirkiri naka a shafin Programmes',
    pip_next: 'mataki na gaba :', fnd_n: 'sakamako: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  yo: {
    pl_title: 'Eto isise', pl_empty: 'ko si eto sibẹsibẹ : mu RECON sise ninu kaadi ti o wa lọkẹ, awọn iṣaaro yoo wọle nibi (awọn ipo yo duro titi)',
    pl_run: 'Mu sise', pl_reflect: 'canary ti pada',
    st_do: 'ṣe nigbati', st_test: 'ti danwo',
    st_signal: 'ami', st_valid: 'o tọ',
    st_void: 'kankan', atk_btn: 'ATTACK',
    atk_start: 'ipaaju ni n sise lori oju : endpoints, awọn doc ti o ṣí, JWT, secrets...', atk_fail: 'ipaaju ko ṣeṣe : mu RECON sise kọkọ',
    atk_none: 'ko si ami', atk_findings: 'awọn oludije',
    atk_done: 'ATTACK : awọn oludije {n} ti P1/P2 ti wọle sinu findings pẹlu ẹri', atk_empty: 'ko si attack sibẹsibẹ : mu RECON sise lẹhinna ATTACK - awọn oludije pẹlu ẹri req/res yoo wọle nibi',
    navh: 'HUNT', h2hunt: 'HUNT - oju ti o gidi ati awọn ẹri',
    h_ready: 'ti ṣetan', h_empty: 'ko si oju ti a mọ : mu RECON sise lati ṣe aworan oju-iwe, API endpoints, awọn param, JS bundles ati subdomains',
    h_fnd: 'Awọn findings eto', h_nofnd: 'ko si finding lori eto yii',
    rc_btn: 'RECON', rc_start: 'recon oju ti n sise : awọn oju-iwe, JS bundles, endpoints, awọn param...',
    rc_done: 'oju ti ya aworan : endpoints, param ati subdomains ti wo sinu kaadi eto', rc_fail: 'recon kuna : host ko si ni ibikibi tabi scope jẹ efu',
    rc_surface: 'oju :', snd_on: 'OHUN : ON',
    snd_off: 'OHUN : OFF', snd_ok: 'awọn ohun interface ti n tàn - library : click, tab, copy, ikilo',
    snd_stop: 'didẹti ti n ṣiṣẹ : ohun C2FF kan ko fẹrẹ ṣugbọn', amb_on: 'AYEPO : ON',
    amb_off: 'AYEPO : OFF', amb_ok: 'ayepo ti o maa n fi ẹmi - awọ-iyi n yi lọ perepe lori awọn idile (ewé, bulu, pupa...)',
    amb_stop: 'ayepo ti du lori ewẹ ti o tẹlerẹ', nt_on: 'IKILO : ON',
    nt_off: 'IKILO : OFF', nt_ok: 'ikilo aṣawakiri ti n tàn - bip lori P1 ati P2',
    nt_denied: 'aṣawakiri ti di ikilo : fọwọ si ni eto aaye ayẹwo', term_denied: 'terminal ti kọ tabi ko wa : localhost nilo, tabi yara ṣíbi bi oludari',
    term_p: 'bash odi - itan kiko pẹlu aami, Ctrl+C da duro, Ctrl+D pa ile', term_restart: 'Tun ṣeto',
    navtrm: 'TERM', term_h2: 'Terminal - shel ise, ni taara ninu console',
    fl_off: 'FLEET : DA DURUKU', fl_paused: 'FLEET : PAUSE',
    fl_active: 'FLEET : TI NSISE ({n} ayika)', fl_last: 'ayika kẹhin',
    fl_none: 'ko si ayika sibẹsibẹ', fl_info: 'aarin {i} min, {b} req/ayika',
    sub_ttl: 'command & control framework', navt: 'IPESE',
    tm_h2: 'Ijirapa ẹgbẹ - ọdẹ papọ, lai lori aye kan', tm_p: 'Ṣi yara pinpin : ẹgbẹ rẹ yoo ri fleet ati findings, won si le se isiro laipe. Chat akọkọ lè isalẹ. Ipele mẹta ti wọle : LOCAL (kan sooso), LAN nipasẹ SI AJA-AIYE, ati AGBAYE nipasẹ SI AGBAYE - ina ijafafa gbangba (cloudflared ti a fi sori) yoo fa ọna gbigba lati kẹhin eyikeyi, lai fi ibile rẹ han. Ohun gbogbo ni ikilo ati ikojade, mura si ọna rẹ.',
    tm_handle: 'Orukọ rẹ (ọrọ 16 pọ', tm_save_h: 'Ṣeto',
    tm_room_ph: 'orukọ yara (af : c2ff-core)', tm_save: 'Fi sori',
    tm_on: 'YARA ṢI : {r} - {n} lori ẹrọ', tm_off: 'TEAM MODE PA - ise akoko ojulowo',
    tm_room: 'Yara', tm_key: 'Kọkọ yara',
    tm_regen: 'Tun ṣe kọkọ', tm_regen_ok: 'kọkọ tun ti ṣẹda - awọn ọna atijọ ti ku',
    tm_invite: 'Ipe rẹ (kọwọ fun ẹgbẹ rẹ)', tm_copy: 'Daakọ',
    tm_copied: 'ti daakọ si akosile', tm_members: 'Awọn ọmọ',
    tm_nobody: 'ko si enia sibẹsibẹ - fi ọna si ẹgbẹ rẹ', tm_you: '(iwọ)',
    tm_here: 'nibi', tm_saved: 'orukọ ti fi pamọ',
    tm_no_handle: 'kọkọ danna', tm_cfg_ok: 'yara ti yi pada',
    tm_cfg_no: 'kuna', tm_live: 'SI AJA-AIYE',
    tm_shore: 'YIPADA SI ABULE', tm_need_on: 'tun awọn yara sise ni kọkọ (ON)',
    tm_bind_lan: 'AIYE : {a}', tm_bind_lo: 'ABULE : localhost soso',
    to_team_live: '[GO-LIVE] server ti pada bẹrẹ pẹlu oju aja-aaye - ifihan ipe aiye LAN, wọle pada laarin iṣẹju 2', to_team_shore: 'server ti pada bẹrẹ lori abule (127.0.0.1)',
    tm_tun_open: 'NI AGBAYE', tm_tun_close: 'PA AJA-AIYE',
    tm_tun_wait: 'inà tun ti ṣí (iṣẹju die)…', tm_tun_on: 'IPE NI AGbaye : {u} - imọlẹ ti ọdọ rẹ yoo ṣiṣẹ nigbikibiti, kọ si nikan aiye kan',
    tm_tun_closed: 'inà ti pa - pada lati si LAN/abule', tm_chat_empty: 'ẹrọ ayẹwo ni gbaye - awọn ọmọ yara ti kika laarin ara wọn',
    tm_chat_h2: 'Chat akoko', tm_msg_ph: 'ọrọ si akoko…',
    tm_admin: 'oludari', tm_guest: 'alejo',
    tm_kick: 'KICK', tm_kick_ok: 'ẹniti o ṣẹda yara ti ya kuro (tẹ lẹẹkansi lati ṣii)',
    tm_role_ok: 'ipò ti yipada', tm_mic_on: 'ṢI MIKÍKÍ',
    tm_mic_off: 'PA MIKÍKÍ', tm_mic_denied: 'mikiki ti kọ tabi ko gba : HTTPS nilo (ina AGBAYE tabi localhost) ati pe fún mikiki laaye',
    navf: 'Odun', navfd: 'Findings',
    navp: 'Eto', navai: 'AI',
    navc: 'Ijirapa', st_runs: 'Ọkọ',
    st_beacons: 'Awọn amii ṣiṣẹ', st_sig: 'Ami',
    h2f: 'Odun - gbogbo eto, awọn ami ṣiṣẹ kọkọ', h2fd: 'Ile findings - akọkọ ti yipada',
    h2eng: 'Iṣẹ ọkọ - aṣayan ojulowo, ko si token', h2prog: 'Eto - oju ati ọna ikọ',
    h2new: 'Eto tun', h2ai: 'Aṣojú AI - 100% aṣàyàn',
    h2c: 'Ijirapa - ọna tìtì kán', fl_start: 'Bẹrẹ',
    fl_pause: 'Pause', fl_cycle: 'Ayika ni bayo',
    f_add: 'Fi kun', f_none: 'ko si ami sibẹsibẹ',
    f_ph: 'finding ọwọ : endpoint + ẹri + sev ti o le so…', st_sig_off: 'ami',
    st_sig_an: 'ṣewadii', st_sig_sub: 'ti fi ṣeto',
    st_sig_dup: 'dup', st_sig_ref: 'ti kọ',
    st_sig_cl: 'ti pa', r_none: 'ko si ọkọ ti a rii',
    r_live: '{n} TINSISE', r_done: 'TI SAN',
    r_feed: '▽ ojuami ({n} ev)', r_close: '△ da pada',
    p_name_ph: 'Orukọ eto (aapẹẹrẹ : PayPal)', p_hdr_ph: 'ọrọ ọwọ nilo (aapẹẹrẹ : X-Bug-Bounty: xxx)',
    p_scope_ph: 'oju : domain1, domain2, …', p_save: 'Fi pamọ',
    p_local: 'modu, 100% ibile', ai_p: 'C2FF nṣiṣẹ 100% lai AI : ipo jẹ awọn ẹrọ ibile ti o ṣọra. Ẹrọ yiyan ṣe fun fifi <b>AI rẹ</b> (self-hosted tabi API) sinu iṣẹ idaniloju finding kan : bọtini <span style="color:var(--green)">AI »</span> ninu FINDINGS, idahun n han ninu COORDINATION. Ko si data ti o jade kuro ninu ẹrọ rẹ lai ti o si eto yi.',
    ai_off: 'ti pa', ai_on: 'ti ṣi',
    ai_st_off: 'AI PA - ẹrọ nṣiṣẹ 100% lori ibile', ai_st_ready: 'AI TI WA : {p} · {m}',
    ai_st_inc: 'AI ṢUGBON KO KUN : baseURL ati model nilo', ai_url_ph: 'base URL - aapẹẹrẹ : http://localhost:11434 tabi https://api.MyAI.tld/v1',
    ai_model_ph: 'model - aapẹẹrẹ : llama3.1:8b', ai_key_ph: 'API kọkọ (fi efu ni serwisi ibile)',
    ai_save: 'Fi pamọ', ai_test: 'Danwo àmì isọpọ',
    ai_testing: 'n danwo…', ai_ok: 'OK - idahun : ',
    ai_fail: 'KUNA : ', ai_note: 'eto ti fi pamọ ni data/ai.json - ko si ibikibi ti a le fi ranṣe lai ti endpoint',
    ch_ph: 'root@c2ff:~# Ọrọ si aṣojú ìwádì…', ch_send: 'Fi rán',
    ch_empty: 'Ile-ọrọ ti ṣí. Kọ nibi, olumo yoo ji mi lakutukun.', ft: '100% ibile - awọn ẹrọ ṣiṣẹ ti o gboju, ko si tabi tokeni ibẹrẹ - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE TI NSISE : awọn ayika ibile ni 30 min, 0 token.', to_fl_pa: 'FLEET PAUSE - tun bẹrẹ nigbati o ba fẹ.',
    to_fl_cy: 'Ayika kíìkí ti bẹrẹ (budget 60 req).', to_launch: '[GO] mode {m} (CWE {c}) lori {p} - ayika ibile ti bẹrẹ',
    to_ai_ok: 'eto fi pamọ', to_ai_no: 'kuna fi pamọ',
    to_ai_no_cfg: 'AI ko ṣeto - fi sori tab AI', to_ai_head: 'EWADI AI',
    to_ai_bad: 'EWADI AI KUNA', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ BỌSỌ', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS ati exploits lori aye ti a ri', ar_sync: 'SYNC IPILE',
    ar_btn: 'IGBESE', ar_exec: 'EXEC',
    ar_none: 'ko si igbese: se RECON ni akoko, lehin naa SYNC lati gbe KEV/EPSS wa', ar_loading: 'akotan awon ipile n gbe wa...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'eto apere - ko si ayewo : da eto tire sile', pip_noprog: 'ko si eto : da eto tire ninu Eto',
    pip_next: 'igbese ikehin :', fnd_n: 'awari: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  zu: {
    pl_title: 'Uhlelo lomsebenzi', pl_empty: 'akukho uhlelo okwangoku : qalisa i-RECON enkathini yangaphezulu, ukucabanga kuyowehla lapha (izimo kuyahlala)',
    pl_run: 'Qalisa', pl_reflect: 'i-canary ibuyisiwe',
    st_do: 'okumele kwenziwe', st_test: 'kuhlolwe',
    st_signal: 'uphawu', st_valid: 'kuqinisekisiwe',
    st_void: 'lutho', atk_btn: 'ATTACK',
    atk_start: 'uhlaselo lwendawo luqhubekile : ama-endpoint, imibhalo evulekile, i-JWT, izimfihlo...', atk_fail: 'uhlaselo akunakwenzeka : qala ngokusebenzisa i-RECON',
    atk_none: 'akukho uphawu', atk_findings: 'abakhweleni',
    atk_done: 'ATTACK : abakhweleni abangu-{n} be-P1/P2 bafakwe kuma-findings kanye nobufakazi', atk_empty: 'akukho attack okwangoku : qalisa i-RECON bese i-ATTACK - abakhweleni nobufakazi be-req/res beyowehla lapha',
    navh: 'HUNT', h2hunt: 'HUNT - indawo yeqiniso nobufakazi',
    h_ready: 'kulungile', h_empty: 'akukho indawo eyaziwayo : qalisa i-RECON ukuze umephele amakhasi, ama-API endpoints, amapharamitha, ama-JS bundles nama-subdomains',
    h_fnd: 'Ama-findings ohlelo', h_nofnd: 'akukho finding kulolu hlelo',
    rc_btn: 'RECON', rc_start: 'recon yendawo kuqubekile : amakhasi, ama-JS bundles, ama-endpoints, amapharamitha...',
    rc_done: 'indawo imepeke : ama-endpoints, amapharamitha nama-subdomains kufakwe enkathini yohlelo', rc_fail: 'recon yehlulekile : host ayitholakali noma scope ingenalutho',
    rc_surface: 'indawo :', snd_on: 'UMSINDO : ON',
    snd_off: 'UMSINDO : OFF', snd_ok: 'imisindo ye-interface iyasebenza - umtapo : click, tab, copy, izexwayiso',
    snd_stop: 'ukuthulisa kwaphumelela : akukho msindo we-C2FF osala', amb_on: 'AIMO : ON',
    amb_off: 'AIMO : OFF', amb_ok: 'imvelo ephilayo - umbala wehlisa kancane phakathi kweziqu (okuluhlaza, okuluhlaza okwesibhakabhaka, okuphuzi...)',
    amb_stop: 'imvelo iqinile kokuluhlaza kokuqala', nt_on: 'IZAZISO : ON',
    nt_off: 'IZAZISO : OFF', nt_ok: 'izaziso zephephandaba zinikwe amandla - i-beep ku-P1 ne-P2',
    nt_denied: 'iphephandaba lilethe izaziso : yivumele kusipho sezihlelo', term_denied: 'i-terminal inqatikelwe noma ayitholakali : i-localhost iyadingeka, noma igumbi elivulekile njengomlawuli',
    term_p: 'i-bash yangempela - umlando ngemisele, i-Ctrl+C isika, i-Ctrl+D ivala', term_restart: 'Qalisa kabusha',
    navtrm: 'TERM', term_h2: 'Iterminali - shell yokusebenza, ngqo kuconsole',
    fl_off: 'FLEET : MIYIWE', fl_paused: 'FLEET : PAUSE',
    fl_active: 'FLEET : SEBENZA ({n} ukuqubeka)', fl_last: 'ukuqubuka kokugcina',
    fl_none: 'akukho ukuqubeka okwangoku', fl_info: 'isikhathi esiphakathi {i} min, {b} req/nje',
    sub_ttl: 'command & control framework', navt: 'ISESHINI',
    tm_h2: 'Izinhlela zeqembu - ukubulawa ndawonye, nakaphandle kwenethiwekhi', tm_p: 'Vula igumbi elabiwe : iqembu lakho libona i-fleet, ama-findings, futhi lingahlela ngendlela eqondile. Chat yesikhathi esizodwa ngezansi. Izinhlaka zokufinyelela ezintathu : LOCAL (umuntu wedwa), LAN nge-VULA KWENETHIWEKHI, kanye nomhlaba nge-OPEN KWEMHLABA - ithonela yomphakathi (cloudflared uma ifakiwe) yenza ikheli lokuqagela lisebenze kusuka kunoma yimuphi unethiwekhi, ngaphandle kokudalula umshini wakho. Konke kuyilolusu lwegumbi - qaphela, vula kabusha ukuhambisa wonke umuntu kanye.',
    tm_handle: 'Ibhange lakho (uphawu olungafika ku-16)', tm_save_h: 'Setha',
    tm_room_ph: 'igama legumbi (isb : c2ff-core)', tm_save: 'Yilondoloza',
    tm_on: 'IGUMBI LIVULEKILE : {r} - {n} oku-online', tm_off: 'TEAM MODE VALIWE - iviki elilona nje',
    tm_room: 'Igumbi', tm_key: 'Ukhiye wegumbi',
    tm_regen: 'Yenisa kabusha ukhiye', tm_regen_ok: 'ukhiye omusha wenziwa - izixhumanisi ezindala zishone',
    tm_invite: 'Isixhumanisi sokumema (kopishalela iqembu lakho)', tm_copy: 'Kopisha',
    tm_copied: 'kukopishiwe ku-clipboard', tm_members: 'Amalungu',
    tm_nobody: 'akukho munye okwangoku - thumela isixhumanisi eqenjini lakho', tm_you: '(wena)',
    tm_here: 'lapha', tm_saved: 'igama lilondoloziwe',
    tm_no_handle: 'igama lingenalutho', tm_cfg_ok: 'igumbi liyibuyekeziwe',
    tm_cfg_no: 'yehlulekile', tm_live: 'VULA KWENETHIWEKHI',
    tm_shore: 'BUYELA KU-LOCAL', tm_need_on: 'vula igumbi kuqala (ON)',
    tm_bind_lan: 'INETHIWEKHI : {a}', tm_bind_lo: 'I-LOCAL : localhost kuphela',
    to_team_live: '[GO-LIVE] i-seva iqalwe kabusha ngezinpawu zokuxhumana - ikheli le-LAN lichazwa, ukuxhumana kabusha kungeminye yamasekhondi 2', to_team_shore: 'i-seva iqalwe kabusha endaweni (127.0.0.1)',
    tm_tun_open: 'VULA KWEMHLABA (ithonela)', tm_tun_close: 'VALA ITHONELA',
    tm_tun_wait: 'ithonela yomphakathi ivulekile (imizuzwana embalwa)…', tm_tun_on: 'I-SESHINI IVULEKILE KWEMHLABA : {u} - ikheli lokuqagela liyasebenza noma ngaphi, ukuhlangana kwenethiwekhi kudingeki',
    tm_tun_closed: 'ithonela ivaliwe - buyela LAN/indawo', tm_chat_empty: 'isiteshi seseshini sivulekile - amalungu egumbi awahlangana lapha',
    tm_chat_h2: 'Ingxoxo yeseshini', tm_msg_ph: 'umyalezo ku-selebhu…',
    tm_admin: 'umlawuli', tm_guest: 'isivakashi',
    tm_kick: 'KICK', tm_kick_ok: 'ilungu likhishwe egumbini (chofoza futhi ukuvula)',
    tm_role_ok: 'indima ibuyekeziwe', tm_mic_on: 'VULA I-MIKROFONI',
    tm_mic_off: 'CIMA I-MIKROFONI', tm_mic_denied: 'i-microphone ayivumelekile noma ayitholakali : i-HTTPS iyadingeka (ithonela ye-MHLABA noma i-localhost) futhi kufanele uvumele i-microphone',
    navf: 'Amaqembu', navfd: 'Findings',
    navp: 'Izinhlelo', navai: 'AI',
    navc: 'Ukuxhuba', st_runs: 'Ukusebenza',
    st_beacons: 'Amabeacon asebenza', st_sig: 'Izimpawu',
    h2f: 'Amaqembu - zonke izinhlelo, ama-agent aqhubeka kuqala', h2fd: 'Insika yama-findings - ukubeka izimpawu zokuhlehla kuphinda nini',
    h2eng: 'Injini yeqembu - imizuliswano yendawo, ngaphandle kwamathokheni', h2prog: 'Izinhlelo - i-scope, i-header edingekayo, ukuqalisa',
    h2new: 'Uhlelo olusha', h2ai: 'Umsebenzisi we-AI - 100% yinketho',
    h2c: 'Ukuxoxa - isiteshi sezimfihlo', fl_start: 'Qalisa',
    fl_pause: 'Pause', fl_cycle: 'Qhubeka manje',
    f_add: 'Engeza', f_none: 'akukho uphawu okwangoku',
    f_ph: 'finding yesandla : endpoint + bufakazi + sev egcokelekile…', st_sig_off: 'uphawu',
    st_sig_an: 'uhlaziyo', st_sig_sub: 'kunikezwe',
    st_sig_dup: 'dup', st_sig_ref: 'yeqatshelwe',
    st_sig_cl: 'kuvalwe', r_none: 'akukho run etholakalayo',
    r_live: '{n} KUQHUBEKA', r_done: 'KUPHELELE',
    r_feed: '▽ umoya ({n} ev)', r_close: '△ phinda',
    p_name_ph: 'Igama lohlelo (isb : PayPal)', p_hdr_ph: 'iheda lomcwaningi idingeka (isb : X-Bug-Bounty: xxx)',
    p_scope_ph: 'i-scope : domain1, domain2, …', p_save: 'Londoloza',
    p_local: 'imodyuli, i-100% indawo', ai_p: 'I-C2FF isebenza ngokuphelele ngaphandle kwe-AI : imodi ziyizihlolobuzwe zangaphakathi. Ukwamukelwa lokhu kuzosetshenziselwa ukuxhumanisa <b>AI yakho</b> (self-hosted noma i-API) ukuze ulondolola okukodwa kwe-finding : isithombe <span style="color:var(--green)">AI »</span> ku-FINDINGS, impendulo ikhonjiswa ku-COORDINATION. Akukho imininingwane ephumayo emshinin wakho ngaphandle kokucushwa oku.',
    ai_off: 'kuvaliwe', ai_on: 'kuvuliwe',
    ai_st_off: 'AI IVALIWE - umqondo usebenza 100% yendawo ngaphandle kwalona', ai_st_ready: 'I-AI IXHUMANISIWE : {p} · {m}',
    ai_st_inc: 'I-AI IVULIWE KODWA INGEHLUKILE : i-baseURL kanye ne-model kudingeka', ai_url_ph: 'base URL - isb : http://localhost:11434 noma https://api.MyAI.tld/v1',
    ai_model_ph: 'model - isb : llama3.1:8b', ai_key_ph: 'i-API key (yishiywe ingenalutho uma usebenza iseva yendawo)',
    ai_save: 'Londoloza', ai_test: 'Hlola ukuxhumana',
    ai_testing: 'kuhlolwa…', ai_ok: 'OK - impendulo : ',
    ai_fail: 'YEHULEKILE : ', ai_note: 'ukucushwa kulondoloziwe endaweni ku-data/ai.json - akunikezwa kwenye indawo ngaphandle kwe-endpoint oyibekile',
    ch_ph: 'root@c2ff:~# umyalezo kumlawuli wehlaziyo…', ch_send: 'Thumela',
    ch_empty: 'Isiteshi sivulekile. Bhala lapha, umhleli uzongiqabula masinyane.', ft: 'I-100% indawo - izilolelo ezimeleyo, angabi nangamathokheni noma ukuncika - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE SEBENZA : imizuliswano yendawo njalo ngemizuzu engu-30, 0 amathokheni.', to_fl_pa: 'FLEET PAUSE - qalisa kabusha nini nani.',
    to_fl_cy: 'Ukuqubeka ngqo kwaqalwa (i-60 req ishejuli).', to_launch: '[GO] imodi {m} (CWE {c}) ku-{p} - umjikelezo we-ndawo usebenza',
    to_ai_ok: 'ukucushwa kulondoloziwe', to_ai_no: 'ukulondoloza kuhlulekile',
    to_ai_no_cfg: 'AI ayilungisiwe - yi-set ku-tab ye-AI', to_ai_head: 'UHLALO LWE-AI',
    to_ai_bad: 'UHLALO LWE-AI LWEHULEKILE', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ QALISA', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS nezokuhlasela endaweni etholakele', ar_sync: 'SYNC IZINQOLOBANE',
    ar_btn: 'IZINYATHELO', ar_exec: 'EXEC',
    ar_none: 'azikho izinyathelo: sebenzisa RECON kuqala, bese usebenzisa SYNC ukulayisha KEV/EPSS', ar_loading: 'isishwanshelelo sezinqolobane siyalayisha...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'uhlelo lokubonisa - ayikho ukuskena : yakha uhlelo lwakho', pip_noprog: 'ayikho uhlelo : yakha owakho kuzinhlelo',
    pip_next: 'inyathelo elilandelayo :', fnd_n: 'okutholiwe: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  af: {
    pl_title: 'Werkplan', pl_empty: 'nog geen plan nie : laat RECON in die kaart hierbo loop, hipoteses val hier (statusse bly staan)',
    pl_run: 'Laat loop', pl_reflect: 'canary gereflekteer',
    st_do: 'om te doen', st_test: 'getoets',
    st_signal: 'sein', st_valid: 'bevestig',
    st_void: 'niks', atk_btn: 'ATTACK',
    atk_start: 'val die oppervlak aan : endpoints, blootgestelde docs, JWT, secrets...', atk_fail: 'aanval onmoontlik : laat eers RECON loop',
    atk_none: 'geen sein', atk_findings: 'kandidate',
    atk_done: 'ATTACK : {n} P1/P2 kandidate met bewys in die findings ingespuit', atk_empty: 'nog geen attack nie : laat RECON loop dan ATTACK - kandidate met req/res-bewys val hier',
    navh: 'HUNT', h2hunt: 'HUNT - werklike oppervlak en bewyse',
    h_ready: 'gereed', h_empty: 'geen bekende oppervlak nie : laat RECON loop om bladsye, API endpoints, params, JS-bundles en subdomeine te karteer',
    h_fnd: 'Findings van die program', h_nofnd: 'geen finding vir hierdie program',
    rc_btn: 'RECON', rc_start: 'recon van die oppervlak aan die gang : bladsye, JS-bundles, endpoints, params...',
    rc_done: 'oppervlak gemeet : endpoints, params en subdomeine gelys in die programkaart', rc_fail: 'recon misluk : host onbereikbaar of scope leeg',
    rc_surface: 'oppervlak :', snd_on: 'KLANK : AAN',
    snd_off: 'KLANKE : UIT', snd_ok: 'koppelvlakklanke aan - biblioteek : klik, oortjie, kopie, waarskuwings',
    snd_stop: 'totale demping geaktiveer : geen C2FF-klanke meer', amb_on: 'STEMMING : AAN',
    amb_off: 'STEMMING : UIT', amb_ok: 'lewende stemming - die skakering gly sag deur die families (groen, blou, geel...)',
    amb_stop: 'stemming bevrore op die oorspronklike groen', nt_on: 'KENNISGEWINGS : AAN',
    nt_off: 'KENNISGEWINGS : UIT', nt_ok: 'blaaierkennisgewings geaktiveer - piep op P1 en P2',
    nt_denied: 'kennisgewings deur die blaaier geblokkeer : stel hulle in die webwerf se instellings vry', term_denied: 'terminaal geweier of onbeskikbaar : localhost nodig, of \'n OOP kamer as admin',
    term_p: 'egte bash - geskiedenis met pyltjies, Ctrl+C onderbreek, Ctrl+D sluit', term_restart: 'Herstel',
    navtrm: 'TERM', term_h2: 'Terminal - werksdop, regstreeks in die konsole',
    fl_off: 'FLEET : GESTAAK', fl_paused: 'FLEET : POUSE',
    fl_active: 'FLEET : AKTIEF ({n} siklusse)', fl_last: 'laaste siklus',
    fl_none: 'nog geen siklus nie', fl_info: 'interval {i} min, begroting {b} req/siklus',
    sub_ttl: 'command & control framework', navt: 'SITSIE',
    tm_h2: 'Groepsitsies - saam jag, selfs sonder netwerk', tm_p: 'Maak \'n gedeelde kamer : jou groep sien die vloot, die findings, en kan regstreeks sortering doen. Toegewyde sitklets hieronder. Drie toegangsvlakke : LOKAAL (alleen), LAN via OPEN VIR NETWERK, en WÊRELD via OPEN VIR WÊRELD - \'n publieke tonnel (cloudflared indien geïnstalleer) maak die uitnodigingskakel geldig uit enige netwerk, jou masjien nie direk blootgestel nie. Alles loop deur die kamersleutel - herskep dit om almal gelyktydig te skop.',
    tm_handle: 'Jou hanteer (maks 16 karakters)', tm_save_h: 'Stel',
    tm_room_ph: 'naam van die kamer (bv : c2ff-core)', tm_save: 'Toepas',
    tm_on: 'KAMER OOP : {r} - {n} aanlyn', tm_off: 'TEAM MODUS UIT - plaaslike solo-sitsie',
    tm_room: 'Kamer', tm_key: 'Kamersleutel',
    tm_regen: 'Sleutel herskep', tm_regen_ok: 'nuwe sleutel geskep - ou skakels is dood',
    tm_invite: 'Uitnodigingskakel (kopieer na jou span)', tm_copy: 'Kopieer',
    tm_copied: 'gekopiëer na die klembord', tm_members: 'Lede',
    tm_nobody: 'nog niemand - stuur die skakel aan jou span', tm_you: '(jy)',
    tm_here: 'hier', tm_saved: 'hanteerder gestoor',
    tm_no_handle: 'hanteerder leeg', tm_cfg_ok: 'kamer opgedateer',
    tm_cfg_no: 'misluk', tm_live: 'OPEN VIR NETWERK',
    tm_shore: 'TERUG NA LOKAAL', tm_need_on: 'skakel eers die kamer aan (AAN)',
    tm_bind_lan: 'NETWERK : {a}', tm_bind_lo: 'LOKAAL : slegs localhost',
    to_team_live: '[GO-LIVE] bediener herlaai met netwerktoegang - LAN-skakel gewys, herverbind oor 2 s', to_team_shore: 'bediener weer plaaslik begin (127.0.0.1)',
    tm_tun_open: 'OPEN VIR WÊRELD (tonnel)', tm_tun_close: 'SLUIT TONNEL',
    tm_tun_wait: 'publieke tonnel kom op (n paar sekondes)…', tm_tun_on: 'SITSIE OPEN VIR WÊRELD : {u} - die uitnodigingskakel werk orals, geen gedeelde netwerk nodig',
    tm_tun_closed: 'tonnel gesluit - terug netwerk/plaaslik', tm_chat_empty: 'sitsiekanaal oop - kamerlede lees mekaar hier',
    tm_chat_h2: 'Sitsieklets', tm_msg_ph: 'boodskap na die sitsie…',
    tm_admin: 'admin', tm_guest: 'gas',
    tm_kick: 'KICK', tm_kick_ok: 'lid uit die kamer geskop (klik weer om te deblokkeer)',
    tm_role_ok: 'rol opgedateer', tm_mic_on: 'AKTIVEER MIKROFOON',
    tm_mic_off: 'DEMP MIKROFOON', tm_mic_denied: 'mikrofoon geweier of onbeskikbaar : HTTPS is nodig (WÊRELD-tonnel of localhost) en toestemming moet verleen word',
    navf: 'Vloot', navfd: 'Findings',
    navp: 'Programme', navai: 'KI',
    navc: 'Koördinasie', st_runs: 'Lopies',
    st_beacons: 'Aktiewe bakens', st_sig: 'Seine',
    h2f: 'Vloot - alle programme, lopende agents eerste', h2fd: 'Findings-basis - blywende triage-merking',
    h2eng: 'Vlootenjin - plaaslike siklusse, geen tokens', h2prog: 'Programme - scope, vereiste kop, lansering',
    h2new: 'Nuwe program', h2ai: 'KI-agent - 100% opsioneel',
    h2c: 'Koördinasie - privaat kanaal', fl_start: 'Begin',
    fl_pause: 'Pouse', fl_cycle: 'Siklus nou',
    f_add: 'Voeg by', f_none: 'nog geen sein nie',
    f_ph: 'handmatige finding : endpoint + bewys + verdedigbare erns…', st_sig_off: 'sein',
    st_sig_an: 'ontleding', st_sig_sub: 'ingedien',
    st_sig_dup: 'dup', st_sig_ref: 'verwerp',
    st_sig_cl: 'gesluit', r_none: 'geen lopies opgemerk nie',
    r_live: '{n} IN DIE LOOP', r_done: 'KLAAR',
    r_feed: '▽ vloei ({n} ev)', r_close: '△ vou in',
    p_name_ph: 'Naam van die program (bv : PayPal)', p_hdr_ph: 'vereiste navorserhoof (bv : X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domein1, domein2, …', p_save: 'Stoor',
    p_local: 'module(s), 100% plaaslik', ai_p: 'C2FF werk ten volle sonder KI : die modusse is deterministiese plaaslike probe. Hierdie deurgang is net om <b>jou</b> KI (self-gegas of API) te koppel vir geleentheidsontleding van \'n finding : die <span style="color:var(--green)">KI »</span> knoppie in FINDINGS, antwoord vertoon in COORDINATION. Geen data verlaat jou masjien sonder hierdie opstelling nie.',
    ai_off: 'gedeaktiveer', ai_on: 'geaktiveer',
    ai_st_off: 'KI GEDEAKTIVEER - die raamwerk loop 100% lokaal sonder dit', ai_st_ready: 'KI VERBIND : {p} · {m}',
    ai_st_inc: 'KI GEAKTIVEER MAAR ONVOLLEDIG : baseURL en model vereis', ai_url_ph: 'base URL - bv : http://localhost:11434 of https://api.MyAI.tld/v1',
    ai_model_ph: 'model - bv : llama3.1:8b', ai_key_ph: 'API-sleutel (laat leeg vir plaaslike bedienaar)',
    ai_save: 'Stoor', ai_test: 'Toets die verbinding',
    ai_testing: 'toets loop…', ai_ok: 'OK - antwoord : ',
    ai_fail: 'GEFAAL : ', ai_note: 'konfigurasie plaaslik gehou in data/ai.json - word nooit elders gestuur as na die endpoint wat jy daar sit nie',
    ch_ph: 'root@c2ff:~# boodskap na die ontledingsagent…', ch_send: 'Stuur',
    ch_empty: 'Die kanaal is oop. Tik hier, die monitor wek my teenwoordig op.', ft: '100% plaaslik - deterministiese probe, geen tekeninge of eksterne afhanklikhede nie - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODUS AKTIEF : plaaslike siklusse elke 30 min, 0 tekeninge.', to_fl_pa: 'FLEET IN POUSE - herlaai wanneer jy wil.',
    to_fl_cy: 'Onmiddellike siklus begin (begroting 60 req).', to_launch: '[GO] modus {m} (CWE {c}) op {p} - plaaslike siklus begin',
    to_ai_ok: 'konfigurasie gestoor', to_ai_no: 'stoor misluk',
    to_ai_no_cfg: 'KI nie opgestel nie - stel dit in die KI-oortjie', to_ai_head: 'KI-ONTLEDING',
    to_ai_bad: 'KI-ONTLEDING misluk', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'KI',
    w_launch: '⚡ LANSEER', navar: 'Arsenaal',
    ar_h2: 'ARSENAL - CVE, EPSS en exploits op die opgespoorde oppervlak', ar_sync: 'SYNC BASISSE',
    ar_btn: 'SKUIWE', ar_exec: 'EXEC',
    ar_none: 'geen skuiwe: laat RECON eers loop, dan SYNC om KEV/EPSS te laai', ar_loading: 'opsomming van die basisse laai tans...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demo program - geen skandering : skep jou eie program', pip_noprog: 'geen program nie : skep joune by Programme',
    pip_next: 'volgende stap :', fnd_n: 'bevindings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  so: {
    pl_title: 'Qorshaha shaqada', pl_empty: 'weli qorshe ma jiro: RECON ku bilow khaanada kor ka ah, mala-awaalku halkan ayay kuugu dhacayaan (xaaladaha lagu kaydiyay)',
    pl_run: 'Bilow', pl_reflect: 'canary la muujiyay',
    st_do: 'la sameeyo', st_test: 'la tijaabiyay',
    st_signal: 'calaamad', st_valid: 'xaqiij',
    st_void: 'waxba', atk_btn: 'ATTACK',
    atk_start: 'attack-ka dusha: endpoints, docs muuqda, JWT, siraha...', atk_fail: 'attack lama fulin: marka hore RECON bilow',
    atk_none: 'calaamad lama helin', atk_findings: 'musharaxiin',
    atk_done: 'ATTACK: {n} musharax P1/P2 oo daliil req/res la leh ayaa findings lagu galay', atk_empty: 'weli attack lama qaadin: RECON bilow markaas ATTACK - musharaxyada daliil req/res leh halkan ayay kuugu yimaadaan',
    navh: 'HUNT', h2hunt: 'HUNT - dhabta dusha iyo daliilada',
    h_ready: 'diyaar', h_empty: 'dusha lama ogeyn: RECON bilow si aad u sawirto bogagga, endpoints API, params, bundles JS iyo subdomains',
    h_fnd: 'Findings-ka barnaamijka', h_nofnd: 'weli finding lama helin barnaamijkan',
    rc_btn: 'RECON', rc_start: 'recon-ka dusha socda: bogagga, bundles JS, endpoints, params...',
    rc_done: 'dusha la sawiray: endpoints, params iyo subdomains lagu tusay khaanada barnaamijka', rc_fail: 'recon gu\'daray: host lama gaarayo ama scope madhan',
    rc_surface: 'dusha:', snd_on: 'CODKA: ON',
    snd_off: 'CODKA: OFF', snd_ok: 'codadka interface shaqaynaya - maktabad: guji, tab, copy, ogeysiis',
    snd_stop: 'mute buuxa la furnay: C2FF cod uma soo bixinayo', amb_on: 'AMBIANCE: ON',
    amb_off: 'AMBIANCE: OFF', amb_ok: 'ambiance nool - midabku si tarraagsan ayuu u dhaqaaqaa qoysaska (cagaar, buluug, jaalle...)',
    amb_stop: 'ambiance la xiray cagaarkii asalka ahaa', nt_on: 'NOTIFS: ON',
    nt_off: 'NOTIFS: OFF', nt_ok: 'ogeysiisyada browser la furnay - P1 iyo P2 waxay dhawaqaan',
    nt_denied: 'ogeysiisyada browserku waa xiran: u oggolow settings-ka site-ka', term_denied: 'terminal la diiday ama lama heli karo: localhost waa loo baahan yahay, ama qol LA FURO oo admin aad tahay',
    term_p: 'bash dhabta ah - falsada kor history-ga, Ctrl+C waa joojin, Ctrl+D waa xir', term_restart: 'Dib u bilow',
    navtrm: 'TERM', term_h2: 'Terminal - shell shaqo, toos console-ka',
    fl_off: 'FLEET: JOOJIYAY', fl_paused: 'FLEET: NASASHO',
    fl_active: 'FLEET: FIRFIRCOON ({n} cycles)', fl_last: 'cycle-kii u dambeeyay',
    fl_none: 'weli cycle lama hayo', fl_info: 'dhererka {i} daq, budget {b} req/cycle',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Session koox ah - uga dhex-yaal isku xig kasta, shabakad la mid ama aan la', tm_p: 'Qol la wadaago fur: kooxdaadu waxay arkaan fleet-ka, findings-ka oo ay live u qaybi karaan. Chat session gaar ah hoos waxaa ku yaal. Saddex heer oo gelitaan ah: LOCAL (solo), LAN iyada oo la isticmaalayo FUR SHABAKADA, iyo ADUUNKA iyada oo la isticmaalayo FUR ADUUNKA - tunnel bulsho (cloudflared hadduu la rakibo) wuxuu ka dhigaa linkada casumaad meel kasta ka shaqeeya, adigoo aan mashiinkaaga toos ugu soo bandhigin. Wax walba furaha qolka ayay ku xidhan yihiin - dib u cusboonaysii si aad uga saarto dhammaan dadka marka hore.',
    tm_handle: 'Magacaaga (16 xaraf ugu badan)', tm_save_h: 'Dhig',
    tm_room_ph: 'magaca qolka (tus: c2ff-core)', tm_save: 'Dhaqan geli',
    tm_on: 'QOL LA FURAY: {r} - {n} online', tm_off: 'TEAM MODE LA DAMIYAY - session local solo ah',
    tm_room: 'Qol', tm_key: 'Furaha qolka',
    tm_regen: 'Furaha cusub samee', tm_regen_ok: 'fure cusub la sameeyay - linkadkii hore way dhinteen',
    tm_invite: 'Linkada casumaadda (nuqul samee kooxda)', tm_copy: 'Nuqul',
    tm_copied: 'clipboard-ka lagu gelbay', tm_members: 'Xubnaha',
    tm_nobody: 'weli qof ma jiro - linkada u dir kooxda', tm_you: '(adiga)',
    tm_here: 'halkan', tm_saved: 'magaca la kaydiyay',
    tm_no_handle: 'magac madhan', tm_cfg_ok: 'qolka la cusboonaysiiyay',
    tm_cfg_no: 'gu\'darran', tm_live: 'SHABAKADA FUR',
    tm_shore: 'GOONI U LAAB', tm_need_on: 'marka hore qolka furnaw (ON)',
    tm_bind_lan: 'SHABAKAD: {a}', tm_bind_lo: 'GOONI: localhost oo keliya',
    to_team_live: '[GO-LIVE] server dib loo bilaabay si network ah - link LAN muuqday, 2 s gudahood isku xir', to_team_shore: 'server dib loo bilaabay gooni (127.0.0.1)',
    tm_tun_open: 'ADUUNKA FUR (tunnel)', tm_tun_close: 'TUNNEL XIR',
    tm_tun_wait: 'tunnel bulsho la furayaa (daqiiqado yar)…', tm_tun_on: 'SESSION ADUUNKA LA FURAY: {u} - linkada casumaad meel kasta shaqeeyaa, shabakad isla ma u baahnid',
    tm_tun_closed: 'tunnel la xiray - LAN/local u laabasho', tm_chat_empty: 'kanalka session waa furan - xubnaha qolka halkan ayay isku arkaan',
    tm_chat_h2: 'Chat-ka session', tm_msg_ph: 'fariin u dir session-ka…',
    tm_admin: 'admin', tm_guest: 'casumaad',
    tm_kick: 'KICK', tm_kick_ok: 'xubin laga saaray qolka (mar kale guji si aad furto)',
    tm_role_ok: 'xaalad la cusboonaysiiyay', tm_mic_on: 'MICROPHONE FUR',
    tm_mic_off: 'MICROPHONE DAMI', tm_mic_denied: 'microphone la diiday ama lama heli karo: HTTPS ayaa loo baahan yahay (tunnel ADUUNKA ama localhost) iyo waqti la siin u oggolow',
    navf: 'FLEET', navfd: 'FINDINGS',
    navp: 'Barnaamijyada', navai: 'AI',
    navc: 'Xiriirka', st_runs: 'Runs',
    st_beacons: 'Beacons firfircoon', st_sig: 'Calaamadaha',
    h2f: 'FLEET - dhammaan barnaamijyada, agents shaqaynaya hore loo dhig', h2fd: 'Keydka FINDINGS - calaamaynta triage waqti ah',
    h2eng: 'Mashiinka FLEET - cycles local ah, token la\'aan', h2prog: 'Barnaamijyada - scope, header loo baahan yahay, bilaabid',
    h2new: 'Barnaamij cusub', h2ai: 'Agent AI - xiriir 100% optional ah',
    h2c: 'Xiriirka - kanal gaar ah', fl_start: 'Bilow',
    fl_pause: 'Nasasho', fl_cycle: 'Cycle hadda',
    f_add: 'Ku dar', f_none: 'weli calaamad lama helin',
    f_ph: 'finding gacanta laga sameeyay: endpoint + daliil + la difaaci karo…', st_sig_off: 'calaamad',
    st_sig_an: 'faalayn', st_sig_sub: 'la gudbiyay',
    st_sig_dup: 'dup', st_sig_ref: 'la diiday',
    st_sig_cl: 'la xiray', r_none: 'run lama arag',
    r_live: '{n} SHAQAYNAYA', r_done: 'DHAMEEYAY',
    r_feed: '▽ flow ({n} ev)', r_close: '△ yaree',
    p_name_ph: 'Magaca barnaamijka (tus: PayPal)', p_hdr_ph: 'header loo baahan yahay (tus: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domain1, domain2, …', p_save: 'Kaydi',
    p_local: 'module(s), 100% local', ai_p: 'C2FF si buuxda waxay u shaqeysaa AI la\'aan: hababku waa probes local oo go\'aan ah. Gateway-gani wuxuu keliya u adeegaa inaad ku xirto <b>AI-gaaga</b> (self-hosted ama API) si falanqayn gaar ah oo finding ah la sameeyo: badhan <span style="color:var(--green)">AI »</span> gudaha FINDINGS, jawaabtaana COORDINATION lagu bedelayaa. Wax xog ah mashiinkaaga kuma baxo hadduu config-aankan jirin.',
    ai_off: 'la damiyay', ai_on: 'la furnay',
    ai_st_off: 'AI LA DAMIYAY - framework-ku 100% local shaqeeyaa iyada oo aan lahayn', ai_st_ready: 'AI KU XIRAN: {p} · {m}',
    ai_st_inc: 'AI LA FURAY LAAKIN BUUXIN: baseURL iyo model ayaa loo baahan yahay', ai_url_ph: 'base URL - tus: http://localhost:11434 ama https://api.MyAI.tld/v1',
    ai_model_ph: 'model - tus: llama3.1:8b', ai_key_ph: 'fure API (madhan u dhaaf server local ah)',
    ai_save: 'Kaydi', ai_test: 'Tijaabi xiriirka',
    ai_testing: 'tijaabitaan socda…', ai_ok: 'OK - jawaab: ',
    ai_fail: 'GU\'DARRAN: ', ai_note: 'config-aan local lagu kaydiyay data/ai.json - meel kale lama dirayyo maaahee endpoint-ka aad ku dhigay',
    ch_ph: 'root@c2ff:~# fariin u dir agent-ka falanqaynta…', ch_send: 'Dir',
    ch_empty: 'Kanal-ka waa furan. Halkan ku qor, monitor-ka iigu dhaawac dhab ahaan.', ft: '100% local - probes go\'aamiyey, token iyo deps dibedda lama hayo - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE FIRFIRCOON: cycles local 30 daq walba, 0 token.', to_fl_pa: 'FLEET NASASHO - markaad rabto dib u bilaab.',
    to_fl_cy: 'Cycle degdeg ah la bilaabay (budget 60 req).', to_launch: '[GO] mode {m} (CWE {c}) {p} - cycle local la bilaabay',
    to_ai_ok: 'config la kaydiyay', to_ai_no: 'kaydinta gu\'daray',
    to_ai_no_cfg: 'AI lama habeyn - AI tab-ka ku dhig', to_ai_head: 'FALANQAYN AI',
    to_ai_bad: 'FALANQAYN AI gu\'daray', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ BILAAB', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS iyo exploits dusha la helay', ar_sync: 'SYNC SALDHIGYO',
    ar_btn: 'DHAQAAQYO', ar_exec: 'EXEC',
    ar_none: 'dhaqaaqyo ma jiraan: horay u orod RECON, kadib SYNC si loo shubo KEV/EPSS', ar_loading: 'dulmar saldhigyada ayaa soo shubmaya...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'barnaamij tusaale - ma jiro soo saarid : samee barnaamijkaaga', pip_noprog: 'ma jiro barnaamij : samee kii gaarka ah ee Barnaamijyada',
    pip_next: 'tallaabada xigta :', fnd_n: 'natiijooyin: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  ti: {
    pl_title: 'መደብ ስራሕ', pl_empty: 'ገና መደብ የብሉን፡ RECON ኣብቲ ላዕላይ ካርዳ ግበር፣ ሓሳባት ኣብዚ ይወድቁ (ኹነታት ይቐመጡ)',
    pl_run: 'ግበር', pl_reflect: 'canary ተረኣኡ',
    st_do: 'ክግበር', st_test: 'ተፈቲሹ',
    st_signal: 'ምልክት', st_valid: 'ስሉጥ',
    st_void: 'ምንም', atk_btn: 'ATTACK',
    atk_start: 'attack ናይቲ ላዕል፡ endpoints፣ ዝተሪኡ docs፣ JWT፣ ሚስጥራት...', atk_fail: 'attack ኣይተኻእለን፡ ቅድሚ RECON ግበር',
    atk_none: 'ምንም ምልክት የብሉን', atk_findings: 'እጩታት',
    atk_done: 'ATTACK፡ {n} እጩታት P1/P2 ምስ ኣስማት req/res ኣብ findings ተኣታቲኡ', atk_empty: 'ገና attack የብሉን፡ RECON ግበር ድሕሪኡ ATTACK - እጩታት ምስ ኣስማት req/res ኣብዚ ይወድቁ',
    navh: 'HUNT', h2hunt: 'HUNT - ሓቁ ላዕልን ኣስማትን',
    h_ready: 'ተዳሊኡ', h_empty: 'ላዕል የብሉን፡ RECON ግበር ንምግላጽ pages፣ endpoints API፣ params፣ bundles JSን subdomainsን',
    h_fnd: 'Findings ናይቲ ፕሮግራም', h_nofnd: 'ኣብዚ ፕሮግራም ምንም findings የብሉን',
    rc_btn: 'RECON', rc_start: 'recon ናይቲ ላዕል ይቕጽል፡ pages፣ bundles JS፣ endpoints፣ params...',
    rc_done: 'ላዕል ተገሊጹ፡ endpoints፣ paramsን subdomainsን ኣብ ካርዳ ፕሮግራም ተዘርዚሮም', rc_fail: 'recon ወዲኡ፡ host የብኡ ወይ scope ባዶ',
    rc_surface: 'ላዕል፦', snd_on: 'ድምጺ፡ ON',
    snd_off: 'ድምጺ፡ OFF', snd_ok: 'ድምጽታት interface ተኪኦም - መጽሓፍቲ፡ click፣ tab፣ copy፣ ምንጋሎታት',
    snd_stop: 'ምሉእ ስቱር ተኪኡ፡ ድምጺ C2FF ከየወጻእ', amb_on: 'AMBIANCE: ON',
    amb_off: 'AMBIANCE: OFF', amb_ok: 'ህያው ኣትሚስሪ፡ ሕብሪ ቀሲ ቀሊሉ ብማዕዶታት ይንቀሳቐስ (ጎምዓይ፣ ሰማያዊ፣ ቢጫ...)',
    amb_stop: 'ኣትሚስሪ ተዘግቢሩ ኣብቲ ቀደምቲ ጎምዓይ ሕብሪ', nt_on: 'NOTIFS: ON',
    nt_off: 'NOTIFS: OFF', nt_ok: 'መእተዊታት browser ተኪኦም - P1ን P2ን ይደምጹ',
    nt_denied: 'መእተዊታት ኣብ browser ተዓጺቶም፡ ኣብ ቅጥዕታት site ኣክብሎም', term_denied: 'terminal ዝተነፈረ ወይ የብሉን፡ localhost ይጠዘቐ፣ ወይ ክፍሊ ተከፊቱ ከም admin',
    term_p: 'ሓቁ bash - ታሪኽ ቐንዲ ላዕሊ፣ Ctrl+C ይዕጾ፣ Ctrl+D ይዕጾ', term_restart: 'ዳግም ግበር',
    navtrm: 'TERM', term_h2: 'Terminal - shell ስራሕ፣ ቐጥታ ኣብቲ console',
    fl_off: 'FLEET፡ ተዓጊቱ', fl_paused: 'FLEET፡ ዝተዓገበ',
    fl_active: 'FLEET፡ ኣብ ስራሕ ({n} cycles)', fl_last: 'cycle-kii ዝሓለወ',
    fl_none: 'ገና cycle የብሉን', fl_info: 'ፍልልይ {i} ደቒቕ፡ budget {b} req/cycle',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Session ብቡድን - ጽቡቕ ስድራ ኣብ ሓደ ቡድን፣ ምስ መስመር ወይ ዘይ ምስ መስመር', tm_p: 'ክፍሊ ርክብ ክፍቶ፡ ቡድንካ fleet፣ findings ይርኣዩን live ይደሉዩን ይኽእሉ። ቻንል chat session ዝተመስረተ ታሕቲ። ሰለስተ ደረጃ ምፍታሕ፡ LOCAL (solo)፣ LAN ብመሰረት ክፈቶ መስመር፣ ከምኡ ውን ዓለም ብመሰረት ክፈቶ ዓለም - ህዝባዊ tunnel (cloudflared እንተተተከወ) መስመር ስዕብ ካብ ክንደይ መስመር ከም ይሰርሕ ወዲኡ፡ ሓዳራ፡ ምሉእ ብቁልፊ ክፍሊ ይፈልስ፡ ቁልፊ ዳግም ፍጠር ንኽትወጽእ ምሉእ',
    tm_handle: 'ስምኻ (16 ቁጠባታ ኣብ ላዕሊ)', tm_save_h: 'ቐይር',
    tm_room_ph: 'ስም ክፍሊ (ኣብነት፡ c2ff-core)', tm_save: 'ተግብር',
    tm_on: 'ክፍሊ ተከፊቱ፡ {r} - {n} ኣብ መስመር', tm_off: 'MODE TEAM ተዓጊቱ - session ባዶ solo',
    tm_room: 'ክፍሊ', tm_key: 'ቁልፊ ክፍሊ',
    tm_regen: 'ቁልፊ ዳግም ፍጠር', tm_regen_ok: 'ሓድሽ ቁልፊ ተፈጢሩ - መስመር ቀደምቲ ተዓጺቶም',
    tm_invite: 'መስመር ስዕብ (ኣብ ቡድንካ ስዕብ)', tm_copy: 'ስዕብ',
    tm_copied: 'ኣብ clipboard ተቐቢሉ', tm_members: 'ኣባላት',
    tm_nobody: 'ገና ሰብ የብሉን - መስመር ስዕብ ኣብ ቡድንካ', tm_you: '(ንስኻ)',
    tm_here: 'ኣብዚ', tm_saved: 'ስም ተከማቸ',
    tm_no_handle: 'ስም ባዶ', tm_cfg_ok: 'ክፍሊ ተዓዚቡ',
    tm_cfg_no: 'ወዲኡ', tm_live: 'መስመር ክፈቶ',
    tm_shore: 'ናብ ባዶ ተመለስ', tm_need_on: 'ቅድሚኡ ክፍሊ ኣክብሎ (ON)',
    tm_bind_lan: 'መስመር፡ {a}', tm_bind_lo: 'ባዶ፡ localhost ብጸንቲኡ',
    to_team_live: '[GO-LIVE] ሰርቨር ብመስመር ዳግም ተኪኡ - መስመር LAN ተሪኢቱ፡ 2 s ውሽጢ ዳግም ተገንጻለ', to_team_shore: 'ሰርቨር ባዶ ዳግም ተኪኡ (127.0.0.1)',
    tm_tun_open: 'ናብ ዓለም ክፈቶ (tunnel)', tm_tun_close: 'TUNNEL ዕግዖ',
    tm_tun_wait: 'ህዝባዊ tunnel ይከፍት ኣሎ (ሳዕቢታት ቅጭ)…', tm_tun_on: 'SESSION ናብ ዓለም ተከፊቱ፡ {u} - መስመር ስዕብ ከም ቦታ ይሰርሕ፡ መስመር ሓደ ኣይጠዘቕ',
    tm_tun_closed: 'tunnel ተዕግዩ - ናብ LAN/ባዶ ተመሊሱ', tm_chat_empty: 'ሻነይ session ተከፊቱ - ኣባላት ክፍሊ ኣብዚ እንታይ ይረኣኡ',
    tm_chat_h2: 'Chat ስሩዕ', tm_msg_ph: 'መልእክቲ ናብ ስሩዕ…',
    tm_admin: 'admin', tm_guest: 'ዓዋዲ',
    tm_kick: 'KICK', tm_kick_ok: 'ኣባል ካብቲ ክፍሊ ወጺኡ (ዳግም ጥውዒት ክፍታሕ)',
    tm_role_ok: 'ደረጃ ተዓዚባ', tm_mic_on: 'MICROPHONE ክፈቶ',
    tm_mic_off: 'MICROPHONE ዕግዖ', tm_mic_denied: 'microphone ዝተነፈረ ወይ የይትረኣይ፡ HTTPS ይዕዘቡ (tunnel ዓለም ወይ localhost) ከምኡ ውን ፍቓድ ኣክብሎ',
    navf: 'FLEET', navfd: 'FINDINGS',
    navp: 'ፕሮግራማት', navai: 'AI',
    navc: 'ምትሕብባብ', st_runs: 'Runs',
    st_beacons: 'Beacons ኣብ ስራሕ', st_sig: 'ምልክታት',
    h2f: 'FLEET - ኩሉ ፕሮግራምፐታት፡ agents ኣብ ስራሕ ቅድሚ', h2fd: 'መሰረት FINDINGS - ምልክት triage ዝተዓገበ',
    h2eng: 'ማሽን FLEET - cycles ባዶ፣ token ዘይፈትሕ', h2prog: 'ፕሮግራማት - scope፡ header ይጠዘቐ፡ ምጅማር',
    h2new: 'ሓድሽ ፕሮግራም', h2ai: 'ወኪል AI - ዝተመርሓ 100% optional',
    h2c: 'ምትሕብባብ - ሻንይ ብሕቲ', fl_start: 'ጀምር',
    fl_pause: 'ዕረፍቲ', fl_cycle: 'Cycle ሕጂ',
    f_add: 'ወስእ', f_none: 'ገና ምልክት የብሉን',
    f_ph: 'finding ባዶ፡ endpoint + ኣስማት + sev ዝረጋገጽ…', st_sig_off: 'ምልክት',
    st_sig_an: 'ትንታነ', st_sig_sub: 'ተስጒሙ',
    st_sig_dup: 'dup', st_sig_ref: 'ዝተነፈረ',
    st_sig_cl: 'ዝተዓጸበ', r_none: 'run ዘይተሪኢቱ',
    r_live: '{n} ኣብ ስራሕ', r_done: 'ተዛዚሙ',
    r_feed: '▽ ዕላል ({n} ev)', r_close: '△ ምስጋር',
    p_name_ph: 'ስም ፕሮግራም (ኣብነት፡ PayPal)', p_hdr_ph: 'header ዝጠለበ (ኣብነት፡ X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope፡ domain1፣ domain2፣ …', p_save: 'ቆጸር',
    p_local: 'module(s)፡ 100% ባዶ', ai_p: 'C2FF AI ዘይጠዘቐ ይሰርሕ፡ ሞዳት ባዶ probes ዝተዋህባቲኡ። እዚ gateway እዚ ብጾቱ ንምረኻት <b>AI ናትኻ</b> (self-hosted ወይ API) ንትንተና ሓደ finding ይሕግዝ፡ badሕን <span style="color:var(--green)">AI »</span> ኣብ FINDINGS፣ መልሲ ኣብ COORDINATION ይሪኢ። እንተዘይተኣዘዘ መረዳዕታ ካብ ማሽንካ ኣይወጻእን።',
    ai_off: 'ዝተዓገበ', ai_on: 'ዝተከፈተ',
    ai_st_off: 'AI ተዓጊቱ - framework 100% ባዶ ዘይ ንሕና', ai_st_ready: 'AI ተገንጺሩ፡ {p} · {m}',
    ai_st_inc: 'AI ተከፊቱ ግን ምሉእ ኣይኮነን፡ baseURL ከምኡ ውን model ይዕዘባ', ai_url_ph: 'base URL - ኣብነት፡ http://localhost:11434 ወይ https://api.MyAI.tld/v1',
    ai_model_ph: 'model - ኣብነት፡ llama3.1:8b', ai_key_ph: 'ቁልፊ API (ባዶ ቆጸር ሰርቨር ባዶ)',
    ai_save: 'ቆጸር', ai_test: 'ግንኙነት ፈትሽ',
    ai_testing: 'ፍተሻ ይቕጽል…', ai_ok: 'OK - መልሲ፦ ',
    ai_fail: 'ወዲኡ፦ ', ai_note: 'ቅጥዕት ባዶ ተከማቸ data/ai.json - ምስ ሸይጭ ኣይተላከኸን እንተዘይተሰደደ endpoint',
    ch_ph: 'root@c2ff:~# መልእክቲ ናብ ወኪል ትንተና…', ch_send: 'ሰደይ',
    ch_empty: 'ቻኽ ተከፊቱ። ኣብዚ ተሓዘብ፡ ሞኒተር ብቕጽበት የቕዝበኒ።', ft: '100% ባዶ - probes ምሉእ፣ token ከምኡ ውን deps ወጻኢ ለበሳ - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ኣብ ስራሕ፡ cycles ባዶ 30 ደቒቕ ኵሉ፡ 0 token.', to_fl_pa: 'FLEET ዝተዓገበ - ከም ዝደሊ ዳግም ጀምር።',
    to_fl_cy: 'Cycle ቅጽበታዊ ጀምር ተገይሩ (budget 60 req).', to_launch: '[GO] mode {m} (CWE {c}) ኣብ {p} - cycle ባዶ ጀምር ተገይሩ',
    to_ai_ok: 'config ተከማቸ', to_ai_no: 'ምቕማጥ ወዲኡ',
    to_ai_no_cfg: 'AI ኣይተዓወተን - ኣብ tab AI ኣዉሮታ', to_ai_head: 'ትንተና AI',
    to_ai_bad: 'ትንተና AI ወዲኡ', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ ጀምር', navar: 'ኣርሰናል',
    ar_h2: 'ARSENAL - ኣብታ ተረኺቡ ገጽ ዘሎ CVE, EPSS እና exploits', ar_sync: 'SYNC መሰረታት',
    ar_btn: 'ምንቅስቓሳት', ar_exec: 'EXEC',
    ar_none: 'ምንቅስቓስ የለን: ቅድሚ RECON ኣሂቡ፣ ቀጺሉ SYNC ን KEV/EPSS ምጽንባት', ar_loading: 'መግለጺ መሰረታት ይጽናዕ ኣሎ...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'ናሙና ፕሮግራም - ስካን የለን : ናይ ገዛኻ ፕሮግራም ስርሓሎ', pip_noprog: 'ፕሮግራም የለን : ኣብ ፕሮግራማት ታብ ናይ ገዛኻ ስርሓሎ',
    pip_next: 'ዝመጽእ ደረጃ :', fnd_n: 'ውጽኢታት: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  ca: {
    pl_title: 'Pla de treball', pl_empty: 'encara no hi ha pla: llança RECON a la targeta de dalt, les hipòtesis cauen aquí (els estats es guarden)',
    pl_run: 'Executa', pl_reflect: 'canary reflectit',
    st_do: 'a fer', st_test: 'provat',
    st_signal: 'senyal', st_valid: 'vàlid',
    st_void: 'res', atk_btn: 'ATTACK',
    atk_start: 'attack de la superfície: endpoints, documents exposats, JWT, secrets...', atk_fail: 'attack impossible: llança abans RECON',
    atk_none: 'cap senyal', atk_findings: 'candidats',
    atk_done: 'ATTACK: {n} candidats P1/P2 injectats als findings amb prova', atk_empty: 'encara no hi ha attack: llança RECON i després ATTACK - els candidats amb prova req/res cauen aquí',
    navh: 'HUNT', h2hunt: 'HUNT - superfície real i proves',
    h_ready: 'llest', h_empty: 'cap superfície coneguda: llança RECON per cartografiar pàgines, endpoints d\'API, params, bundles JS i subdominis',
    h_fnd: 'Findings del programa', h_nofnd: 'cap finding en aquest programa',
    rc_btn: 'RECON', rc_start: 'recon de la superfície en curs: pàgines, bundles JS, endpoints, params...',
    rc_done: 'superfície cartografiada: endpoints, params i subdominis llistats a la targeta del programa', rc_fail: 'recon ha fallat: host inabastable o scope buit',
    rc_surface: 'superfície:', snd_on: 'SO: ON',
    snd_off: 'SO: OFF', snd_ok: 'sons d\'interfície actius - llibreria: clic, pestanya, copia, alertes',
    snd_stop: 'silenci total activat: cap més so de C2FF', amb_on: 'AMBIENT: ON',
    amb_off: 'AMBIENT: OFF', amb_ok: 'ambient viu - el to llisca suaument per les famílies (verd, blau, groc...)',
    amb_stop: 'ambient congelat al verd original', nt_on: 'NOTIFS: ON',
    nt_off: 'NOTIFS: OFF', nt_ok: 'notificacions del navegador activades - piulada a P1 i P2',
    nt_denied: 'notificacions bloquejades pel navegador: permet-les als ajustos del lloc', term_denied: 'terminal denegat o no disponible: es requereix localhost, o una sala OBERTA com a admin',
    term_p: 'bash real - historial amb fletxes, Ctrl+C interromp, Ctrl+D tanca', term_restart: 'Reinicia',
    navtrm: 'TERM', term_h2: 'Terminal - shell de treball, directe a la consola',
    fl_off: 'FLEET: ATURAT', fl_paused: 'FLEET: EN PAUSA',
    fl_active: 'FLEET: ACTIU ({n} cicles)', fl_last: 'últim cicle',
    fl_none: 'encara cap cicle', fl_info: 'interval {i} min, pressupost {b} req/cicle',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Sessions en grup - caça a la vegada, fins i tot fora de xarxa', tm_p: 'Obre una sala compartida: el teu grup veu la flota, els findings i pot triar en directe. Xat de sessió dedicat a sota. Tres nivells d\'accés: LOCAL (sol), LAN via OBRIR A LA XARXA, i MÓN via OBRIR AL MÓN - un túnel públic (cloudflared si està instal·lat) fa que l\'enllaç d\'invitació sigui vàlid des de qualsevol xarxa, sense exposar directament la teva màquina. Tot passa per la clau de sala - regenera-la per fer fora tothom d\'una vegada.',
    tm_handle: 'El teu àlies (16 caràcters màx)', tm_save_h: 'Escull',
    tm_room_ph: 'nom de la sala (ex: c2ff-core)', tm_save: 'Aplica',
    tm_on: 'SALA OBERTA: {r} - {n} en línia', tm_off: 'MODE TEAM DESACTIVAT - sessió local en solitari',
    tm_room: 'Sala', tm_key: 'Clau de sala',
    tm_regen: 'Regenera la clau', tm_regen_ok: 'clau nova generada - els enllaços antics són morts',
    tm_invite: 'Enllaç d\'invitació (copia\'l al teu equip)', tm_copy: 'Copia',
    tm_copied: 'copiat al porta-retalls', tm_members: 'Membres',
    tm_nobody: 'encara ningú - envia l\'enllaç al teu equip', tm_you: '(tu)',
    tm_here: 'present', tm_saved: 'àlies desat',
    tm_no_handle: 'àlies buit', tm_cfg_ok: 'sala actualitzada',
    tm_cfg_no: 'error', tm_live: 'OBRIR A LA XARXA',
    tm_shore: 'TORNA A LOCAL', tm_need_on: 'activa primer la sala (ON)',
    tm_bind_lan: 'XARXA: {a}', tm_bind_lo: 'LOCAL: només localhost',
    to_team_live: '[GO-LIVE] servidor relançat amb accés de xarxa - enllaç LAN a la vista, reconexió en 2 s', to_team_shore: 'servidor relançat en local (127.0.0.1)',
    tm_tun_open: 'OBRIR AL MÓN (túnel)', tm_tun_close: 'TANCA EL TÚNEL',
    tm_tun_wait: 'túnel públic obrint-se (uns segons)…', tm_tun_on: 'SESSIÓ OBERTA AL MÓN: {u} - l\'enllaç d\'invitació funciona des de qualsevol lloc, no cal la mateixa xarxa',
    tm_tun_closed: 'túnel tancat - tornada a LAN/local', tm_chat_empty: 'canal de sessió obert - els membres de la sala es llegeixen aquí',
    tm_chat_h2: 'Xat de sessió', tm_msg_ph: 'missatge cap a la sessió…',
    tm_admin: 'admin', tm_guest: 'convidat',
    tm_kick: 'KICK', tm_kick_ok: 'membre expulsat de la sala (clica de nou per desbloquejar)',
    tm_role_ok: 'rol actualitzat', tm_mic_on: 'ACTIVA EL MICRO',
    tm_mic_off: 'SILENCIA EL MICRO', tm_mic_denied: 'micro denegat o inaccessible: es requereix HTTPS (túnel MÓN o localhost) i cal donar permís al micro',
    navf: 'FLEET', navfd: 'FINDINGS',
    navp: 'Programes', navai: 'IA',
    navc: 'Coordinació', st_runs: 'Runs',
    st_beacons: 'Beacons actius', st_sig: 'Senyals',
    h2f: 'FLEET - tots els programes, agents en curs primer', h2fd: 'Base de findings - etiquetatge de triatge persistent',
    h2eng: 'Motor FLEET - cicles locals sense tokens', h2prog: 'Programes - scope, header requerit, llançament',
    h2new: 'Nou programa', h2ai: 'Agent IA - integració 100% opcional',
    h2c: 'Coordinació - canal privat', fl_start: 'Engega',
    fl_pause: 'Pausa', fl_cycle: 'Cicle ara',
    f_add: 'Afegeix', f_none: 'encara cap senyal',
    f_ph: 'finding manual: endpoint + prova + severitat defensable…', st_sig_off: 'senyal',
    st_sig_an: 'anàlisi', st_sig_sub: 'presentat',
    st_sig_dup: 'dup', st_sig_ref: 'refusat',
    st_sig_cl: 'tancat', r_none: 'cap run detectat',
    r_live: '{n} EN CURS', r_done: 'FET',
    r_feed: '▽ flux ({n} ev)', r_close: '△ plega',
    p_name_ph: 'Nom del programa (ex: PayPal)', p_hdr_ph: 'header requerit del researcher (ex: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domini1, domini2, …', p_save: 'Desa',
    p_local: 'mòdul(s), 100% local', ai_p: 'C2FF funciona íntegrament sense IA: els modes són sondes deterministes locals. Aquesta passarel·la només serveix per connectar <b>la teva</b> IA (autoallotjada o API) per a l\'anàlisi puntual d\'un finding: botó <span style="color:var(--green)">IA »</span> a FINDINGS, resposta mostrada a COORDINATION. Cap dada surt de la teva màquina sense aquesta configuració.',
    ai_off: 'desactivada', ai_on: 'activada',
    ai_st_off: 'IA DESACTIVADA - el framework funciona 100% local sense ella', ai_st_ready: 'IA CONNECTADA: {p} · {m}',
    ai_st_inc: 'IA ACTIVADA PERÒ INCOMPLETA: calen baseURL i model', ai_url_ph: 'base URL - ex: http://localhost:11434 o https://api.LaTeuaIA.tld/v1',
    ai_model_ph: 'model - ex: llama3.1:8b', ai_key_ph: 'clau API (deixa-ho buit per a servidors locals)',
    ai_save: 'Desa', ai_test: 'Prova la connexió',
    ai_testing: 'prova en curs…', ai_ok: 'OK - resposta: ',
    ai_fail: 'ERROR: ', ai_note: 'config desada localment a data/ai.json - no s\'envia enlloc més que a l\'endpoint que hi posis',
    ch_ph: 'root@c2ff:~# missatge cap a l\'agent d\'anàlisi…', ch_send: 'Envia',
    ch_empty: 'El canal és obert. Escriu aquí, el monitor em desperta a l\'instant.', ft: '100% local - sondes deterministes, sense tokens ni dependències externes - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ACTIU: cicles locals cada 30 min, 0 tokens.', to_fl_pa: 'FLEET EN PAUSA - reprèn quan vulguis.',
    to_fl_cy: 'Cicle immediat llançat (pressupost 60 req).', to_launch: '[GO] mode {m} (CWE {c}) sobre {p} - cicle local llançat',
    to_ai_ok: 'config desada', to_ai_no: 'error en desar',
    to_ai_no_cfg: 'IA no configurada - posa-la a la pestanya IA', to_ai_head: 'ANÀLISI IA',
    to_ai_bad: 'ANÀLISI IA fallida', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'IA',
    w_launch: '⚡ LANÇAMENT', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS i exploits a la superficie detectada', ar_sync: 'SYNC BASES',
    ar_btn: 'MOVIMENTS', ar_exec: 'EXEC',
    ar_none: 'cap moviment: executa primer RECON, despres SYNC per carregar KEV/EPSS', ar_loading: 'carregant el resum de les bases...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'programa de demostracio - no escaneja : crea el teu programa', pip_noprog: 'cap programa : crea el teu a Programes',
    pip_next: 'pas seguent :', fnd_n: 'resultats: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  eu: {
    pl_title: 'Lan-plana', pl_empty: 'oraindik planik ez: RECON jarri goiko txartelan, hipotesiak hemen erortzen dira (egoerak gordeta geratzen dira)',
    pl_run: 'Exekutatu', pl_reflect: 'canary islatuta',
    st_do: 'egiteke', st_test: 'probatuta',
    st_signal: 'seinale', st_valid: 'baliozkoa',
    st_void: 'ezer', atk_btn: 'ATTACK',
    atk_start: 'gainazalaren ataquea: endpointak, espositutako doc-ak, JWT, sekretuak...', atk_fail: 'attack ezinezkoa: lehenik RECON jarri',
    atk_none: 'seinalerik ez', atk_findings: 'hautagaiak',
    atk_done: 'ATTACK: {n} hautagai P1/P2 frogarekin findings-etan sartuta', atk_empty: 'oraindik attack ez: RECON jarri, gero ATTACK - req/res frogadun hautagaiak hemen erortzen dira',
    navh: 'HUNT', h2hunt: 'HUNT - benetako gainazala eta frogak',
    h_ready: 'prest', h_empty: 'gainazalik ez ezagutzen: RECON jarri orriak, API endpointak, param-ak, JS paketeak eta azpidomeinuak mapatzeko',
    h_fnd: 'Programaren findings-ak', h_nofnd: 'findingik ez programa honetan',
    rc_btn: 'RECON', rc_start: 'gainazaleko recon lantzen: orriak, JS paketeak, endpointak, param-ak...',
    rc_done: 'gainazala mapatuta: endpointak, param-ak eta azpidomeinuak programaren txarteleran zerrendatuta', rc_fail: 'recon-ek huts egin du: host eskuraezin edo scope hutsik',
    rc_surface: 'gainazala:', snd_on: 'SOINUA: ON',
    snd_off: 'SOINUA: OFF', snd_ok: 'interfaze-soinuak aktibo - liburutegia: klik, fitxa, kopiatu, alertak',
    snd_stop: 'isilarazte osoa aktibatuta: C2FF soinurik gehiagorik ez', amb_on: 'INGURUGIROA: ON',
    amb_off: 'INGURUGIROA: OFF', amb_ok: 'ingurugiro biziak - tonua pixkanaka irristatzen da familiaetan (berdea, urdina, horia...)',
    amb_stop: 'ingurugiroa jatorrizko berdean izoztuta', nt_on: 'NOTIFS: ON',
    nt_off: 'NOTIFS: OFF', nt_ok: 'nabigatzailearen jakinarazpenak aktibatuta - P1 eta P2-tan tonua',
    nt_denied: 'jakinarazpenak nabigatzaileak blokeatu ditu: baimendu itzazu gunearen ezarpenetan', term_denied: 'terminal ukatuta edo eskuraezin: localhost behar da, edo IREKITA dagoen gela admin gisa',
    term_p: 'benetako bash - geziekin historia, Ctrl+C-k eteten du, Ctrl+D-k ixten du', term_restart: 'Berrabiarazi',
    navtrm: 'TERM', term_h2: 'Terminal - lanerako shell, kontsolan zuzenean',
    fl_off: 'FLEET: GELDITUTA', fl_paused: 'FLEET: ETENITA',
    fl_active: 'FLEET: AKTIBO ({n} ziklo)', fl_last: 'azken zikloa',
    fl_none: 'oraindik ziklorik ez', fl_info: '{i} min tarte, {b} req/ziklo aurrekontua',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Taldekako saioak - elkarrekin ehizatu, sarerik gabe ere bai', tm_p: 'Gela partekatu bat ireki: zure taldeak flota eta findings ikus ditzake eta zuzenean sailkatu. Behean saiorako txat esklusiboa. Hiru sarbide-maila: LOCAL (bakarka), LAN bidez SAREAN IREKI, eta MUNDUA bidez MUNDURAKO IREKI - tunel publiko batek (cloudflared instalatuta badago) gonbidapen-esteka edozein saretatik baliozko bihurtzen du, zure makina zuzenean esposatu gabe. Dena gelako gakoaren menpe dago - birsortu dezakezu denak aldi bakarrean kanporatzeko.',
    tm_handle: 'Zure ezizena (16 karaktere gehienez)', tm_save_h: 'Aukeratu',
    tm_room_ph: 'gelaren izena (adib: c2ff-core)', tm_save: 'Aplikatu',
    tm_on: 'GELA IREKIA: {r} - {n} linean', tm_off: 'TEAM MODUA DESAKTIBATUTA - saio lokal bakarkakoa',
    tm_room: 'Gela', tm_key: 'Gelako gakoa',
    tm_regen: 'Gakoa birsortu', tm_regen_ok: 'gako berria sortuta - esteka zaharrak hil dira',
    tm_invite: 'Gonbidapen-esteka (kopiatu zure taldera)', tm_copy: 'Kopiatu',
    tm_copied: 'arbelaera kopiatuta', tm_members: 'Partaideak',
    tm_nobody: 'oraindik inor ez - bidali esteka zure taldeari', tm_you: '(zu)',
    tm_here: 'presente', tm_saved: 'ezizena gordeta',
    tm_no_handle: 'ezizen hutsa', tm_cfg_ok: 'gela eguneratuta',
    tm_cfg_no: 'errorea', tm_live: 'SAREAN IREKI',
    tm_shore: 'ITZULI LOKALERA', tm_need_on: 'lehenik gela aktibatu (ON)',
    tm_bind_lan: 'SAREA: {a}', tm_bind_lo: 'LOKALA: localhost bakarrik',
    to_team_live: '[GO-LIVE] zerbitzaria sareko sarbidearekin berrabiarazita - LAN esteka ikusgai, 2 s-tan bir konektatzen', to_team_shore: 'zerbitzaria lokalean berrabiarazita (127.0.0.1)',
    tm_tun_open: 'MUNDURAKO IREKI (tunela)', tm_tun_close: 'ITXI TUNELA',
    tm_tun_wait: 'tunel publikoa zabaltzen (segundo batzuk)…', tm_tun_on: 'SAIOA MUNDURAKO IREKITA: {u} - gonbidapen-esteka edononetan funtzionatzen du, sare bera beharrik gabe',
    tm_tun_closed: 'tunela itxita - LAN/lokaleko itzulera', tm_chat_empty: 'saio-kanala irekita - gelako partaideak hemen irakurtzen dira',
    tm_chat_h2: 'Saio-txata', tm_msg_ph: 'mezua saiora…',
    tm_admin: 'admin', tm_guest: 'gonbidatura',
    tm_kick: 'KICK', tm_kick_ok: 'partaideak gelatik kanporatuta (berriro klik egin desblokeatzeko)',
    tm_role_ok: 'eginkizuna eguneratuta', tm_mic_on: 'MIKROFONOA AKTIBATU',
    tm_mic_off: 'MIKROFONOA MUTUTU', tm_mic_denied: 'mikrofonoa ukatuta edo eskuraezin: HTTPS behar da (MUNDU tunela edo localhost) eta mikrofonoari baimena eman behar',
    navf: 'FLEET', navfd: 'FINDINGS',
    navp: 'Programak', navai: 'AA',
    navc: 'Koordinazioa', st_runs: 'Runs',
    st_beacons: 'Beacon aktiboak', st_sig: 'Seinaleak',
    h2f: 'FLEET - programa guztiak, martxan dauden agenteak lehenik', h2fd: 'Findings oinarria - triaje etiketak iraunkorrak',
    h2eng: 'FLEET motorea - ziklo lokalak, token-ik gabe', h2prog: 'Programak - scope, beharrezko header-a, jaurtitzea',
    h2new: 'Programa berria', h2ai: 'AA agentea - 100% aukerako integrazioa',
    h2c: 'Koordinazioa - kanal pribatua', fl_start: 'Hasi',
    fl_pause: 'Gelditu', fl_cycle: 'Zikloa orain',
    f_add: 'Gehitu', f_none: 'oraindik seinalerik ez',
    f_ph: 'eskuzko findinga: endpoint + froga + defendagarria den severity…', st_sig_off: 'seinale',
    st_sig_an: 'azterketa', st_sig_sub: 'aurkeztuta',
    st_sig_dup: 'dup', st_sig_ref: 'baztertuta',
    st_sig_cl: 'itxita', r_none: 'run-ik detektatu ez',
    r_live: '{n} MARTXAN', r_done: 'EGINDA',
    r_feed: '▽ iturria ({n} ev)', r_close: '△ tolestu',
    p_name_ph: 'Programaren izena (adib: PayPal)', p_hdr_ph: 'beharrezko ikertzaile-headera (adib: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domeinu1, domeinu2, …', p_save: 'Gorde',
    p_local: 'moduloak, 100% lokala', ai_p: 'C2FF erabat funtzionatzen du AArik gabe: moduak probe determinista lokalak dira. Ate hau <b>zure</b> AAra (auto-hosted edo API) lotzeko bakarrik balio du, finding baten analisi puntualerako: FINDINGS barruko <span style="color:var(--green)">AA »</span> botoia, erantzuna COORDINATION-n ikusgai. Konfigurazio hau gabe, daturik ez da zure makinetik irteten.',
    ai_off: 'desaktibatuta', ai_on: 'aktibatuta',
    ai_st_off: 'AA DESAKTIBATUTA - framework-a 100% lokalan dabil bera gabe', ai_st_ready: 'AA KONEKTATUTA: {p} · {m}',
    ai_st_inc: 'AA AKTIBATUTA BAINA OSATU GABE: baseURL eta model behar dira', ai_url_ph: 'base URL - adib: http://localhost:11434 edo https://api.NireAA.tld/v1',
    ai_model_ph: 'model - adib: llama3.1:8b', ai_key_ph: 'API gakoa (utsik utzi zerbitzari lokaletarako)',
    ai_save: 'Gorde', ai_test: 'Probatu konexioa',
    ai_testing: 'probatzen…', ai_ok: 'OK - erantzuna: ',
    ai_fail: 'HUTSA: ', ai_note: 'config lokalki gordeta data/ai.json - ez da inoiz bidaltzen zuk ezarritako endpointera izan ezik',
    ch_ph: 'root@c2ff:~# mezua analisi-agentera…', ch_send: 'Bidali',
    ch_empty: 'Kanala irekita dago. Idatz hemen, monitor-ak berehala esnatarazten nau.', ft: '100% lokala - probe deterministak, token edo kanpoko menpekotasunik gabe - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE AKTIBO: ziklo lokalak 30 minetik behin, 0 token.', to_fl_pa: 'FLEET ETENITA - nahi duzunean berrekin.',
    to_fl_cy: 'Berehala bideratutako zikloa (60 req aurrekontua).', to_launch: '[GO] {m} modua (CWE {c}) {p}-n - ziklo lokala bideratuta',
    to_ai_ok: 'config gordeta', to_ai_no: 'gordetzeak huts egin du',
    to_ai_no_cfg: 'AA konfiguratu gabe - ezarri AA fitxan', to_ai_head: 'AA AZTERKETA',
    to_ai_bad: 'AA AZTERKETAK HUTS EGIN DU', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AA',
    w_launch: '⚡ HASIERA', navar: 'Arsenala',
    ar_h2: 'ARSENAL - CVE, EPSS eta exploitak antzemitako azalean', ar_sync: 'SYNC OINARRIAK',
    ar_btn: 'MUGIMENDUAK', ar_exec: 'EXEC',
    ar_none: 'mugimendurik ez: exekutatu RECON lehenik, gero SYNC KEV/EPSS kargatzeko', ar_loading: 'oinarrien laburpena kargatzen...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demo programa - ez dago eskaneatzerik : sortu zure programa', pip_noprog: 'programarik ez : sortu zurea Programak atalean',
    pip_next: 'hurrengo urratsa :', fnd_n: 'aurkitutakoak: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  gl: {
    pl_title: 'Plan de traballo', pl_empty: 'ain non hai plan: lanza RECON na tarxeta de enriba, as hipóteses caen aquí (os estados gárdanse)',
    pl_run: 'Executar', pl_reflect: 'canary reflectido',
    st_do: 'por facer', st_test: 'probado',
    st_signal: 'sinal', st_valid: 'válido',
    st_void: 'nada', atk_btn: 'ATTACK',
    atk_start: 'attack da superficie: endpoints, documentos expostos, JWT, segredos...', atk_fail: 'attack imposible: lanza antes RECON',
    atk_none: 'ningún sinal', atk_findings: 'candidatos',
    atk_done: 'ATTACK: {n} candidatos P1/P2 inxectados nos findings con proba', atk_empty: 'ain non hai attack: lanza RECON e despois ATTACK - os candidatos con proba req/res caen aquí',
    navh: 'HUNT', h2hunt: 'HUNT - superficie real e probas',
    h_ready: 'listo', h_empty: 'ningúnha superficie coñecida: lanza RECON para cartografar páxinas, endpoints de API, params, bundles JS e subdominios',
    h_fnd: 'Findings do programa', h_nofnd: 'ningún finding neste programa',
    rc_btn: 'RECON', rc_start: 'recon da superficie en curso: páxinas, bundles JS, endpoints, params...',
    rc_done: 'superficie cartografada: endpoints, params e subdominios listados na tarxeta do programa', rc_fail: 'recon fallou: host inalcanzable ou scope baleiro',
    rc_surface: 'superficie:', snd_on: 'SON: ON',
    snd_off: 'SON: OFF', snd_ok: 'sons de interface activos - biblioteca: clic, pestana, copia, alertas',
    snd_stop: 'silencio total activado: ningún son máis de C2FF', amb_on: 'AMBIENTE: ON',
    amb_off: 'AMBIENTE: OFF', amb_ok: 'ambiente vivo - o matiz desliza suavemente polas familias (verde, azul, amarelo...)',
    amb_stop: 'ambiente conxelado no verde orixinal', nt_on: 'NOTIFS: ON',
    nt_off: 'NOTIFS: OFF', nt_ok: 'notificacións do navegador activadas - piado en P1 e P2',
    nt_denied: 'notificacións bloqueadas polo navegador: permíteas nos axustes do sitio', term_denied: 'terminal denegado ou non dispoñible: requírese localhost, ou unha sala ABERTA como admin',
    term_p: 'bash real - historial con frechas, Ctrl+C interrompe, Ctrl+D pecha', term_restart: 'Reiniciar',
    navtrm: 'TERM', term_h2: 'Terminal - shell de traballo, directo na consola',
    fl_off: 'FLEET: DETIDO', fl_paused: 'FLEET: EN PAUSA',
    fl_active: 'FLEET: ACTIVO ({n} ciclos)', fl_last: 'último ciclo',
    fl_none: 'aínda ningún ciclo', fl_info: 'intervalo {i} min, orzamento {b} req/ciclo',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Sesións en grupo - caza xuntos, mesmo fóra de rede', tm_p: 'Abre unha sala compartida: o teu grupo ve a frota, os findings e pode triar en directo. Chat de sesión dedicado abaixo. Tres niveis de acceso: LOCAL (só), LAN vía ABRIR Á REDE, e MUNDO vía ABRIR AO MUNDO - un túnel público (cloudflared se está instalado) fai que a ligazón de invitación sexa válida desde calquera rede, sen expor directamente a túa máquina. Todo pasa pola clave de sala -rexeréraa para expulsar a todos de golpe.',
    tm_handle: 'O teu alcume (16 caracteres máx)', tm_save_h: 'Escoller',
    tm_room_ph: 'nome da sala (ex: c2ff-core)', tm_save: 'Aplicar',
    tm_on: 'SALA ABERTA: {r} - {n} en liña', tm_off: 'MODO TEAM DESACTIVADO - sesión local en solitario',
    tm_room: 'Sala', tm_key: 'Clave de sala',
    tm_regen: 'Rexerar a clave', tm_regen_ok: 'clave nova xerada - as ligazóns antigas están mortas',
    tm_invite: 'Ligazón de invitación (copía ao teu equipo)', tm_copy: 'Copiar',
    tm_copied: 'copiado no portapapeis', tm_members: 'Membros',
    tm_nobody: 'aínda ninguén - envía a ligazón ao teu equipo', tm_you: '(ti)',
    tm_here: 'presente', tm_saved: 'alcume gardado',
    tm_no_handle: 'alcume baleiro', tm_cfg_ok: 'sala actualizada',
    tm_cfg_no: 'erro', tm_live: 'ABRIR Á REDE',
    tm_shore: 'VOLVER A LOCAL', tm_need_on: 'activa primeiro a sala (ON)',
    tm_bind_lan: 'REDE: {a}', tm_bind_lo: 'LOCAL: só localhost',
    to_team_live: '[GO-LIVE] servidor relanzado con acceso de rede - ligazón LAN á vista, reconexión en 2 s', to_team_shore: 'servidor relanzado en local (127.0.0.1)',
    tm_tun_open: 'ABRIR AO MUNDO (túnel)', tm_tun_close: 'PECHAR O TÚNEL',
    tm_tun_wait: 'túnel público abríndose (uns segundos)…', tm_tun_on: 'SESIÓN ABERTA AO MUNDO: {u} - a ligazón de invitación funciona desde calquera sitio, non hai que estar na mesma rede',
    tm_tun_closed: 'túnel pechado - volta a LAN/local', tm_chat_empty: 'canle de sesión aberto - os membros da sala lense aquí',
    tm_chat_h2: 'Chat de sesión', tm_msg_ph: 'mensaxe cara á sesión…',
    tm_admin: 'admin', tm_guest: 'convidado',
    tm_kick: 'KICK', tm_kick_ok: 'membro expulsado da sala (clica de novo para desbloquear)',
    tm_role_ok: 'rol actualizado', tm_mic_on: 'ACTIVAR O MICRO',
    tm_mic_off: 'SALIR O MICRO', tm_mic_denied: 'micro denegado ou inaccesible: requírese HTTPS (túnel MUNDO ou localhost) e hai que dar permiso ao micro',
    navf: 'FLEET', navfd: 'FINDINGS',
    navp: 'Programas', navai: 'IA',
    navc: 'Coordinación', st_runs: 'Runs',
    st_beacons: 'Beacons activos', st_sig: 'Sinais',
    h2f: 'FLEET - todos os programas, axentes en curso primeiro', h2fd: 'Base de findings - etiquetaxe de triaxe persistente',
    h2eng: 'Motor FLEET - ciclos locais sen tokens', h2prog: 'Programas - scope, header requerido, lanzamento',
    h2new: 'Novo programa', h2ai: 'Axente IA - integración 100% opcional',
    h2c: 'Coordinación - canle privada', fl_start: 'Arrincar',
    fl_pause: 'Pausa', fl_cycle: 'Ciclo agora',
    f_add: 'Engadir', f_none: 'aínda ningún sinal',
    f_ph: 'finding manual: endpoint + proba + severidade defendible…', st_sig_off: 'sinal',
    st_sig_an: 'análise', st_sig_sub: 'enviado',
    st_sig_dup: 'dup', st_sig_ref: 'rexeitado',
    st_sig_cl: 'pechado', r_none: 'ningún run detectado',
    r_live: '{n} EN CURSO', r_done: 'FEITO',
    r_feed: '▽ fluxo ({n} ev)', r_close: '△ preguear',
    p_name_ph: 'Nome do programa (ex: PayPal)', p_hdr_ph: 'header requirido de researcher (ex: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: dominio1, dominio2, …', p_save: 'Gardar',
    p_local: 'módulo(s), 100% local', ai_p: 'C2FF funciona integramente sen IA: os modos son sondas deterministas locais. Esta pasarela só serve para conectar <b>a túa</b> IA (autoaloxada ou API) para a análise puntual dun finding: botón <span style="color:var(--green)">IA »</span> en FINDINGS, resposta amosada en COORDINATION. Ningún dato sae da túa máquina sen esta configuración.',
    ai_off: 'desactivada', ai_on: 'activada',
    ai_st_off: 'IA DESACTIVADA - o framework funciona 100% local sen ela', ai_st_ready: 'IA CONECTADA: {p} · {m}',
    ai_st_inc: 'IA ACTIVADA MAIS INCOMPLETA: precisanse baseURL e model', ai_url_ph: 'base URL - ex: http://localhost:11434 ou https://api.AMinhaIA.tld/v1',
    ai_model_ph: 'model - ex: llama3.1:8b', ai_key_ph: 'clave API (deixar baleiro para servidores locais)',
    ai_save: 'Gardar', ai_test: 'Probar a conexión',
    ai_testing: 'proba en curso…', ai_ok: 'OK - resposta: ',
    ai_fail: 'FALLOU: ', ai_note: 'config gardada localmente en data/ai.json - nunca se envía a outro lugar que non sexa o endpoint que alí poñas',
    ch_ph: 'root@c2ff:~# mensaxe cara ao axente de análise…', ch_send: 'Enviar',
    ch_empty: 'A canle está aberta. Escribe aquí, o monitor despértame ao instante.', ft: '100% local - sondas deterministas, sen tokens nin dependencias externas - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ACTIVO: ciclos locais cada 30 min, 0 tokens.', to_fl_pa: 'FLEET EN PAUSA - retoma cando queiras.',
    to_fl_cy: 'Ciclo inmediato lanzado (orzamento 60 req).', to_launch: '[GO] modo {m} (CWE {c}) sobre {p} - ciclo local lanzado',
    to_ai_ok: 'config gardada', to_ai_no: 'erro ao gardar',
    to_ai_no_cfg: 'IA non configurada - axústaa na pestana IA', to_ai_head: 'ANÁLISE IA',
    to_ai_bad: 'ANÁLISE IA fallida', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'IA',
    w_launch: '⚡ LANZAMENTO', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS e exploits na superficie detectada', ar_sync: 'SYNC BASES',
    ar_btn: 'MOVEMENTOS', ar_exec: 'EXEC',
    ar_none: 'sen movementos: executa primeiro RECON, despois SYNC para cargar KEV/EPSS', ar_loading: 'cargando o resumo das bases...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'programa de demostracion - non escanea : crea o teu programa', pip_noprog: 'ningun programa : crea o teu en Programas',
    pip_next: 'seguinte paso :', fnd_n: 'resultados: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  cy: {
    pl_title: 'Cynllun gwaith', pl_empty: 'dim cynllun eto: defnyddia RECON yn y cerdyn uchod, mae rhagdybiaethau\'n disgyn yma (caiff y statwsau eu cadw)',
    pl_run: 'Rhed', pl_reflect: 'canary wedi ei adlewyrchu',
    st_do: 'i\'w wneud', st_test: 'wedi profi',
    st_signal: 'arwydd', st_valid: 'dilys',
    st_void: 'dim', atk_btn: 'ATTACK',
    atk_start: 'ymosod ar yr wyneb: endpoints, docs agored, JWT, cyfrinachau...', atk_fail: 'methu ymosod: defnyddia RECON yn gyntaf',
    atk_none: 'dim arwydd', atk_findings: 'geisiadau',
    atk_done: 'ATTACK: {n} geisiadau P1/P2 wedi eu chwistrellu i\'r findings â phrawf', atk_empty: 'dim ymosodiad eto: defnyddia RECON yna ATTACK - mae geisiadau â phrawf req/res yn disgyn yma',
    navh: 'HUNT', h2hunt: 'HUNT - wyneb go iawn a phrawf',
    h_ready: 'parod', h_empty: 'dim wyneb adnabyddus: defnyddia RECON i falnoryddu tudalennau, endpoints API, params, bundles JS ac is-barthau',
    h_fnd: 'Findings y rhaglen', h_nofnd: 'dim findings ar y rhaglen hon',
    rc_btn: 'RECON', rc_start: 'recon ar yr wyneb ar y gweill: tudalennau, bundles JS, endpoints, params...',
    rc_done: 'wyneb wedi falnoryddu: endpoints, params ac is-barthau yn rhestr ar gerdyn y rhaglen', rc_fail: 'recon wedi methu: host allan o gyrraedd neu scope gwag',
    rc_surface: 'wyneb:', snd_on: 'SAIN: ON',
    snd_off: 'SAIN: OFF', snd_ok: 'sain rhyngwyneb yn weithredol - llyfrgell: clic, tab, copïo, rhybuddion',
    snd_stop: 'mudo cyflawn wedi\'i alluogi: dim mwy o sain o C2FF', amb_on: 'AWYRGYLCH: ON',
    amb_off: 'AWYRGYLCH: OFF', amb_ok: 'awyrgylch byw - mae\'r liw yn llithro\'n feddal drwy\'r teuluoedd (gwyrdd, glas, melyn...)',
    amb_stop: 'awyrgylch wedi rhewi ar y gwyrdd gwreiddiol', nt_on: 'NOTIFS: ON',
    nt_off: 'NOTIFS: OFF', nt_ok: 'notifïau porwr wedi\'u galluogi - tinc ar P1 a P2',
    nt_denied: 'notifïau wedi\'u rhwystro gan y porwr: gadael iddyn nhw yng ngosodiadau\'r safle', term_denied: 'terfynell wedi\'i wrthod neu ddim ar gael: mae localhost angen, neu ystafell AGORED fel admin',
    term_p: 'bash go iawn - hanes gyda saethau, Ctrl+C yn torri, Ctrl+D yn cau', term_restart: 'Ailosod',
    navtrm: 'TERM', term_h2: 'Terfynell - cregyn gwaith, yn union yn y consol',
    fl_off: 'FLEET: WEDI STOP', fl_paused: 'FLEET: YN SEIBI',
    fl_active: 'FLEET: YN WEITHREDOL ({n} cylch)', fl_last: 'cylch diwethaf',
    fl_none: 'dim cylch eto', fl_info: 'cyfnod {i} mun, cyllideb {b} req/cylch',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Sesiynau grŵp - hela gyda\'i gilydd, hyd yn oed allan o\'r rhwydwaith', tm_p: 'Agor ystafell rannu: dy grŵp yn gweld y fflyd, y findings, a gall dethol yn fyw. Sgwrs sesiwn benodol islaw. Tri lefel fynediad: LOCAL (unigol), LAN trwy AGOR I\'R RHWYDWAITH, a BYD trwy AGOR I\'R BYD - mae twnnel cyhoeddus (cloudflared os fe\'i gosodwyd) yn gwneud y ddolen wahodd yn ddilys o unrhyw rwydwaith, heb ddatgelu dy beiriant yn uniongyrchol. Mae popeth yn mynd drwy allwedd yr ystafell - ail-gre hi i gael gwared ar bawb ar unwaith.',
    tm_handle: 'Dy llysenw (16 cymeriad ar yr ychwaneg)', tm_save_h: 'Dewis',
    tm_room_ph: 'enw\'r ystafell (ex: c2ff-core)', tm_save: 'Cymhwyso',
    tm_on: 'YSTAFELL AR AGOR: {r} - {n} ar-lein', tm_off: 'MODD TEAM WEDI\'I DDAWRECHU - sesiwn leol unigol',
    tm_room: 'Ystafell', tm_key: 'Allwedd yr ystafell',
    tm_regen: 'Ail-gre\'r allwedd', tm_regen_ok: 'allwedd newydd wedi creu - mae\'r dolenni hyn cyn mwy',
    tm_invite: 'Dolen wahodd (copïo i dy dîm)', tm_copy: 'Copïo',
    tm_copied: 'wedi\'i gopïo i\'r clipfwrdd', tm_members: 'Aelodau',
    tm_nobody: 'dim un eto - anfon dolen i dy dîm', tm_you: '(ti)',
    tm_here: 'presennol', tm_saved: 'llysenw wedi cadw\'n glir',
    tm_no_handle: 'llysenw gwag', tm_cfg_ok: 'ystafell wedi diweddaru',
    tm_cfg_no: 'methoddiad', tm_live: 'AGOR I\'R RHWYDWAITH',
    tm_shore: 'NÔL LEOL', tm_need_on: 'alluogi\'r ystafell yn gyntaf (ON)',
    tm_bind_lan: 'RHwYDWAITH: {a}', tm_bind_lo: 'LEOL: localhost yn unig',
    to_team_live: '[GO-LIVE] gweinydd wedi ailo â mynediad rhwydwaith - dolen LAN yn dangos, ail-gysylltu mewn 2 s', to_team_shore: 'gweinydd wedi ailo\'n lleol (127.0.0.1)',
    tm_tun_open: 'AGOR I\'R BYD (twnnel)', tm_tun_close: 'CAU\'R TWNNEL',
    tm_tun_wait: 'twnnel cyhoeddus yn agor (ychydig eiliadau)…', tm_tun_on: 'SESIWN AR AGOR I\'R BYD: {u} - mae\'r ddolen wahodd yn gweithio o unrhyw le, rhaid dim rhwydwaith cyffredin',
    tm_tun_closed: 'twnnel wedi cau - yn ôl at LAN/leol', tm_chat_empty: 'sianel sesiwn ar agor - mae aelodau\'r ystafell yn darllen ei gilydd yma',
    tm_chat_h2: 'Sgwrs sesiwn', tm_msg_ph: 'neges at y sesiwn…',
    tm_admin: 'gweinyddwr', tm_guest: 'gwestai',
    tm_kick: 'KICK', tm_kick_ok: 'aelod wedi\'i allgáu o\'r ystafell (cliciwch eto i ddatgloi)',
    tm_role_ok: 'rôl wedi diweddaru', tm_mic_on: 'GALLUOGI MICROFFON',
    tm_mic_off: 'MUDDO MICROFFON', tm_mic_denied: 'microffon wedi\'i wrthod neu ddim ar gael: mae HTTPS angenrheidiol (twnnel BYD neu localhost) a rhaid caniatáu\'r microffon',
    navf: 'FLEET', navfd: 'FINDINGS',
    navp: 'Rhaglenni', navai: 'DA',
    navc: 'Cydlyniad', st_runs: 'Rhediadau',
    st_beacons: 'Beacons gweithredol', st_sig: 'Arwyddion',
    h2f: 'FLEET - yr holl raglenni, asiantau ar rediad yn gyntaf', h2fd: 'Cronfa FINDINGS - taggio triage parhaus',
    h2eng: 'Peiriant FLEET - cylchrau lleol heb tokenau', h2prog: 'Rhaglenni - scope, pennyn gofynnol, lansio',
    h2new: 'Rhaglen newydd', h2ai: 'Asiant DA - integreiddio 100% dewisol',
    h2c: 'Cydlyniad - sianel breifat', fl_start: 'Dechrau',
    fl_pause: 'Seibi', fl_cycle: 'Cylch nawr',
    f_add: 'Ychwanegu', f_none: 'dim arwydd eto',
    f_ph: 'finding â llaw: endpoint + prawf + difrifoldeb amddiffynnadwy…', st_sig_off: 'arwydd',
    st_sig_an: 'dadansoddi', st_sig_sub: 'cyflwynwyd',
    st_sig_dup: 'dup', st_sig_ref: 'gwrthodwyd',
    st_sig_cl: 'caeedig', r_none: 'dim rhediad wedi ei ganfod',
    r_live: '{n} AR REDIAD', r_done: 'CWBLHEIAD',
    r_feed: '▽ llif ({n} ev)', r_close: '△ plegu',
    p_name_ph: 'Enw\'r rhaglen (ex: PayPal)', p_hdr_ph: 'pennawd ymchwilydd gofynnol (ex: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: parth1, parth2, …', p_save: 'Cadw',
    p_local: 'modwl(au), 100% lleol', ai_p: 'Mae C2FF yn gweithio\'n gwbl heb DA: moddau yw\'r moddau\'n brobec penderfynol lleol. Mae\'r borth hwn dim ond ar gyfer cysylltu <b>dy DA di</b> (self-hosted neu API) i dadansoddi un finding: botwm <span style="color:var(--green)">DA »</span> yn FINDINGS, ymateb yn cael ei ddangos yn COORDINATION. Dim data yn dod o dy beiriant di heb y cyflun hwn.',
    ai_off: 'wedi\'i analluogi', ai_on: 'wedi\'i alluogi',
    ai_st_off: 'DA WEDI\'I ANALLUOGI - y fframwaith yn rhedeg 100% lleol hebdda', ai_st_ready: 'DA WEDI\'I GYSYLTU: {p} · {m}',
    ai_st_inc: 'DA WEDI\'I ALLUOGI OND ANGHYFLAWN: mae angen baseURL a model', ai_url_ph: 'base URL - ex: http://localhost:11434 neu https://api.FynyDA.tld/v1',
    ai_model_ph: 'model - ex: llama3.1:8b', ai_key_ph: 'allwedd API (gadael wag ar gyfer gweinydd lleol)',
    ai_save: 'Cadw', ai_test: 'Prawf cysylltiad',
    ai_testing: 'prawf ar y gweill…', ai_ok: 'OK - ymateb: ',
    ai_fail: 'METHODDIAD: ', ai_note: 'config wedi\'i storio\'n lleol yn data/ai.json - ni fydd byth yn cael ei anfon dim byd ond yr endpoint yr ych chi\'n ei osod',
    ch_ph: 'root@c2ff:~# neges at yr asiant dadansoddi…', ch_send: 'Anfon',
    ch_empty: 'Mae\'r sianel ar agor. Teipia yma, mae\'r monitor yn fy nghodi ar unwaith.', ft: '100% lleol - brobec penderfynol, dim token na dibyniaeth allanol - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE YN WEITHREDOL: cylchrau lleol bob 30 mun, 0 token.', to_fl_pa: 'FLEET SEIBI - ail-ddechrau pryd bynnag sydd angen.',
    to_fl_cy: 'Cylch ar frys wedi lansio (cyllideb 60 req).', to_launch: '[GO] mode {m} (CWE {c}) ar {p} - cylch lleol wedi lansio',
    to_ai_ok: 'config wedi\'i gadw', to_ai_no: 'methoddiad cadw',
    to_ai_no_cfg: 'DA heb ei gyflunio - gosodwch yn y tab DA', to_ai_head: 'DADANSODDI DA',
    to_ai_bad: 'DADANSODDI DA WEDI METHU', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'DA',
    w_launch: '⚡ LANSIO', navar: 'Arsena',
    ar_h2: 'ARSENAL - CVE, EPSS a manteisadau ar yr wyneb a ddarganfuwyd', ar_sync: 'SYNC CRONFEYDD',
    ar_btn: 'CAMRAU', ar_exec: 'EXEC',
    ar_none: 'dim camrau: rhedwch RECON yn gyntaf, wedyn SYNC i lwytho KEV/EPSS', ar_loading: 'crynodeb y cronfeydd yn llwytho...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'rhaglen demo - dim sganio : creu dy raglen dy hun', pip_noprog: 'dim rhaglen : creu dy un di yn y Rhaglenni',
    pip_next: 'cam nesaf :', fnd_n: 'darganfyddiadau: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  ga: {
    pl_title: 'Plean oibre', pl_empty: 'fós gan phlean: cuir RECON ar siúl sa chárta thuas, titfidh na hipitéisí anseo (seasann na stádasanna)',
    pl_run: 'Rith', pl_reflect: 'canary frithchaite',
    st_do: 'le déanamh', st_test: 'tástáilte',
    st_signal: 'comhartha', st_valid: 'bailí',
    st_void: 'faic', atk_btn: 'ATTACK',
    atk_start: 'ionsaí ar an dromchla: endpoints, doiciméid nochta, JWT, rúin...', atk_fail: 'ní féidir ionsaí a dhéanamh: cuir RECON ar siúl ar dtús',
    atk_none: 'gan chomhartha', atk_findings: 'iarrthóirí',
    atk_done: 'ATTACK: {n} iarrthóirí P1/P2 ionchurtha sna findings le cruthúnas', atk_empty: 'fós gan ionsaí: cuir RECON ar siúl agus ansin ATTACK - titfidh na hiarrthóirí le cruthúnas req/res anseo',
    navh: 'HUNT', h2hunt: 'HUNT - dromchla fíor agus cruthúnas',
    h_ready: 'réidh', h_empty: 'gan dromchla aitheanta: cuir RECON ar siúl chun léarscáil leathanaigh, endpoints API, paraiméadair, pacáistí JS agus fo-fhearainn a dhéanamh',
    h_fnd: 'Findings an chláir', h_nofnd: 'gan findings sa chlár seo',
    rc_btn: 'RECON', rc_start: 'recon ar an dromchla ar siúl: leathanaigh, pacáistí JS, endpoints, paraiméadair...',
    rc_done: 'dromchla mapáilte: endpoints, paraiméadair agus fo-fhearann liostáilte i gcárta an chláir', rc_fail: 'theip ar an recon: host nár bhfuarthas nó scope folamh',
    rc_surface: 'dromchla:', snd_on: 'FUAIM: ON',
    snd_off: 'FUAIM: OFF', snd_ok: 'fuaimeanna comhéadan gníomhach - leabharlann: clic, cluaisín, cóipeáil, foláirimh',
    snd_stop: 'balbhú iomlán curtha i ngníomh: gan fuaimeanna C2FF ar aon', amb_on: 'ATMÓSFÉAR: ON',
    amb_off: 'ATMÓSFÉAR: OFF', amb_ok: 'atmaisféar beo - sleamhnaíonn an t-úal go snua ar fud na dteaghlach (glas, gorm, buí...)',
    amb_stop: 'atmaisféar reoite ar an mbunghlas', nt_on: 'NOTIFS: ON',
    nt_off: 'NOTIFS: OFF', nt_ok: 'fógraí brabhsálaí cumasaithe - tinc ar P1 agus P2',
    nt_denied: 'fógraí bacaithe ag an mbrabhsálaí: ceadaigh iad sna socruithe an tsuímh', term_denied: 'teirminéal diúltaíodh nó gan fáil air: tá localhost de dhíth, nó seomra OSCAILTE mar riarthóir',
    term_p: 'bash fíor - stair le saigheada, cuireann Ctrl+C deireadh, dúnann Ctrl+D', term_restart: 'Athshocraigh',
    navtrm: 'TERM', term_h2: 'Teirminéal - blaois oibre, díreach sa chonsól',
    fl_off: 'FLEET: STADTA', fl_paused: 'FLEET: AR SOS',
    fl_active: 'FLEET: GNÍOMHACH ({n} timthriall)', fl_last: 'an timthriall deireanach',
    fl_none: 'gan timthriall fós', fl_info: 'eatramh {i} nóimeád, buiséad {b} req/timthriall',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Seisiúin ghrúpa - seilg le chéile, fiú as líonra', tm_p: 'Oscail seomra comhroinnte: feicfidh do ghrúpa an FLEET agus na findings agus is féidir leo triage a dhéanamh beo. Comhrá seisiúin ar leith thíos. Trí leibhéal rochtana: LOCAL (aonarach), LAN tr OSCAILT DON LÍONRA, agus DOMHAN tr OSCAILT DON DOMHAN - cuireann tollán poiblí (cloudflared má suiteáilte é) an nasc cuir ar fáil ó aon líonra, gan do mheaisín a nochtadh go díreach. Téann gach rud tr eochair an tseomra - athghin í chun gach duine a ruaigeadh ag an am céanna.',
    tm_handle: 'Do ainm cleite (16 carachtar ar a mhéad)', tm_save_h: 'Roghnaigh',
    tm_room_ph: 'ainm an tseomra (ex: c2ff-core)', tm_save: 'Cuir i gceangal',
    tm_on: 'SEOMRA OSCAILTE: {r} - {n} ar líne', tm_off: 'MÓD TEAM MÚCHTA - seisiún logánta aonarach',
    tm_room: 'Seomra', tm_key: 'Eochair an tseomra',
    tm_regen: 'Athghin an eochrach', tm_regen_ok: 'eochair nua ginte - tá na seannascanna marbh',
    tm_invite: 'Nasc cuireadh (cóipeáil chuig do fhoireann)', tm_copy: 'Cóipeáil',
    tm_copied: 'cóipeáladh chuig an ngearrthaisce', tm_members: 'Comhaltaí',
    tm_nobody: 'duine ar bith fós - seol an nasc chuig do fhoireann', tm_you: '(tú)',
    tm_here: 'i láthair', tm_saved: 'ainm cleite sábháilte',
    tm_no_handle: 'ainm cleite folamh', tm_cfg_ok: 'seomra curtha in eagar',
    tm_cfg_no: 'crash', tm_live: 'OSCAILT DON LÍONRA',
    tm_shore: 'FILL AR LOGÁIN', tm_need_on: 'cumasaigh an seomra ar dtús (ON)',
    tm_bind_lan: 'LÍONRA: {a}', tm_bind_lo: 'LOGÁNTA: localhost amháin',
    to_team_live: '[GO-LIVE] freastalaí ath-thosai le rochtain líonra - nasc LAN feicthe, nasc arís laistigh de 2 s', to_team_shore: 'freastalaí ath-thosai logánta (127.0.0.1)',
    tm_tun_open: 'OSCAILT DON DOMHAN (tollán)', tm_tun_close: 'DÚN AN TOLLÁN',
    tm_tun_wait: 'tollán poiblí á oscailt (cúpla soicind)…', tm_tun_on: 'SESIÚN OSCAILT DON DOMHAN: {u} - an nasc cuir o áit ar bith, níl de dhíth leis an líonra céanna',
    tm_tun_closed: 'tollán dúnta - fill ar ais go LAN/logáin', tm_chat_empty: 'cáinél seisiún oscailte - léann comhaltaí an tseomra an ceann eile anseo',
    tm_chat_h2: 'Comhrá seisiún', tm_msg_ph: 'teachtaireacht chuig an seisiún…',
    tm_admin: 'riarthóir', tm_guest: 'aí',
    tm_kick: 'KICK', tm_kick_ok: 'ball amach as an seomra (clicéil arís le haghaidh dífhiostú)',
    tm_role_ok: 'ról nuashonraithe', tm_mic_on: 'CUMASAIGH MICREAFÓN',
    tm_mic_off: 'BALBHAIGH MICREAFÓN', tm_mic_denied: 'micreafón diúltaíodh nó gan fáil air: tá HTTPS de dhíth (tollán DOMHAN nó localhost) agus ceadaigh an micreafón',
    navf: 'FLEET', navfd: 'FINDINGS',
    navp: 'Cláir', navai: 'IA',
    navc: 'Comhordnú', st_runs: 'Rithe',
    st_beacons: 'Beacons gníomhach', st_sig: 'Comharthaí',
    h2f: 'FLEET - gach clár, gníomhairí ar siúl ar dtús', h2fd: 'Bunachar FINDINGS - lipéadú triage seasmhach',
    h2eng: 'Inneall FLEET - timthriallta áitiúla gan tokens', h2prog: 'Cláir - scope, ceanntásc riachtanach, seoladh',
    h2new: 'Clár nua', h2ai: 'Gníomhaire IA - comhtháthú 100% roghnach',
    h2c: 'Comhordnú - cainéal breifata', fl_start: 'Tosaigh',
    fl_pause: 'Sos', fl_cycle: 'Timthriall anois',
    f_add: 'Cuir leis', f_none: 'gan chomhartha fós',
    f_ph: 'finding den láimh: endpoint + cruthúnas + tosca deimhnithe…', st_sig_off: 'comhartha',
    st_sig_an: 'anailís', st_sig_sub: 'seolta',
    st_sig_dup: 'dup', st_sig_ref: 'diúltaíodh',
    st_sig_cl: 'dúnta', r_none: 'gan run a bhrath',
    r_live: '{n} AR SIÚL', r_done: 'CRIOCHNAITHE',
    r_feed: '▽ sruth ({n} ev)', r_close: '△ fill',
    p_name_ph: 'Ainm an chláir (ex: PayPal)', p_hdr_ph: 'ceannásca taighdeora riachtanacha (ex: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: fearann1, fearann2, …', p_save: 'Sábháil',
    p_local: 'modúin, 100% logánta', ai_p: 'Oibríonn C2FF go hiomlán gan IA: is braite áitiúla cinntitheacha na modúin. Ní úsáidtear an pasaire seachas chun <b>tí</b> IA a cheangal (féin-óstáil nó API) chun anailís a dhéanamh ar fhinding amháin: cnaipe <span style="color:var(--green)">IA »</span> i FINdings, freagra taispeánta i COORDINATION. Ní imeoidh aon sonraí ó do mheaisín gan na socruithe seo.',
    ai_off: 'múchta', ai_on: 'cumasaithe',
    ai_st_off: 'IA MÚCHTA - reáchtálann an fráma 100% áitiúla gan í', ai_st_ready: 'IA CEANGAISTE: {p} · {m}',
    ai_st_inc: 'IA CUMASAITHE ACH NEAMHIOMLÁN: tá baseURL agus model de dhíth', ai_url_ph: 'base URL - ex: http://localhost:11434 nó https://api.MIA.tld/v1',
    ai_model_ph: 'model - ex: llama3.1:8b', ai_key_ph: 'eochair API (fág folamh do fhreastalaithe áitiúla)',
    ai_save: 'Sábháil', ai_test: 'Tástáil an nasc',
    ai_testing: 'tástáil ar siúl…', ai_ok: 'OK - freagra: ',
    ai_fail: 'TEIPE: ', ai_note: 'cumraíocht sábháilte áitiúla i data/ai.json - ní sheoltar chuig aon áit seachas an endpoint a chuirfidh tú ann',
    ch_ph: 'root@c2ff:~# teachtaireacht chuig an gníomhaire anailíse…', ch_send: 'Seol',
    ch_empty: 'Tá an cainéal oscailte. Scríobh anseo, dúisíonn an monitor mé láithreach.', ft: '100% áitiúla - braite cinntitheacha, gan tokens ná dibenachta seachtracha - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE GNÍOMHACH: timthriallta áitiúla gach 30 nóim, 0 token.', to_fl_pa: 'FLEET AR SOS - lean ar aghaidh nuair is mian leat.',
    to_fl_cy: 'Timthriall láithreach curtha ar siúl (buiséad 60 req).', to_launch: '[GO] modh {m} (CWE {c}) ar {p} - timthriall áitiúil curtha ar siúl',
    to_ai_ok: 'cumraíocht sábháilte', to_ai_no: 'theip ar shábháil',
    to_ai_no_cfg: 'IA gan cumraíocht - socraigh sa tab IA', to_ai_head: 'ANALÍS IA',
    to_ai_bad: 'ANALÍS IA theip', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'IA',
    w_launch: '⚡ SEOL', navar: 'Arsaenal',
    ar_h2: 'ARSENAL - CVE, EPSS agus ionsaithe ar an dromchla a aimsiodh', ar_sync: 'SYNC BUNACHAIR',
    ar_btn: 'GLUAISEACHTAI', ar_exec: 'EXEC',
    ar_none: 'gan ghluaiseacht: seol RECON ar dtus, ansin SYNC chun KEV/EPSS a lodail', ar_loading: 'achoimre ar na bunachair a lodail...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'clar taispeana - gan scanadh : scriobh do chlar fein', pip_noprog: 'nil aon clar ann : scriobh do cheann fein i gClaranna',
    pip_next: 'an chead cheim eile :', fnd_n: 'aimsithe: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  is: {
    pl_title: 'Vinnuáætlun', pl_empty: 'engin áætlun enn: keyrðu RECON í spjaldið hér að ofan, tilgátur falla hér (stöðurnir vistast)',
    pl_run: 'Keyra', pl_reflect: 'canary speglað',
    st_do: 'ógert', st_test: 'prófað',
    st_signal: 'merki', st_valid: 'staðfest',
    st_void: 'ekkert', atk_btn: 'ATTACK',
    atk_start: 'árás á yfirborðið: endpoints, opnar docs, JWT, leynilyklar...', atk_fail: 'árás mótuð ekki: keyrðu RECON fyrst',
    atk_none: 'ekkert merki', atk_findings: 'frambjóðendur',
    atk_done: 'ATTACK: {n} frambjóðendur P1/P2 sprautaðir í findings með sönnun', atk_empty: 'engin árás enn: keyrðu RECON og síðan ATTACK - frambjóðendur með sönnun req/res falla hér',
    navh: 'HUNT', h2hunt: 'HUNT - raunverulegt yfirborð og sönnun',
    h_ready: 'tilbúið', h_empty: 'ekkert þekkt yfirborð: keyrðu RECON til að kortleggja síður, endpoints API, params, JS búnt og undirlén',
    h_fnd: 'Findings forritsins', h_nofnd: 'engin findings á þessu forriti',
    rc_btn: 'RECON', rc_start: 'recon af yfirborðinu í gangi: síður, JS búnt, endpoints, params...',
    rc_done: 'yfirborð kortlagt: endpoints, params og undirlén skráð á spjaldið forritsins', rc_fail: 'recon brást: host ónægt eða scope tómt',
    rc_surface: 'yfirborð:', snd_on: 'HLJÓÐ: ON',
    snd_off: 'HLJÓÐ: OFF', snd_ok: 'hljóð viðmóts virk - safn: smellur, flipi, afritun, viðvaranir',
    snd_stop: 'full hljóðlétt virk: engin C2FF hljóð lengur', amb_on: 'STEMNING: ON',
    amb_off: 'STEMNING: OFF', amb_ok: 'lifandi stemning - liturinn sleikist varlega í gegnum fjölskyldurnar (grænt, blátt, gult...)',
    amb_stop: 'stemning fryst á upphaflega græna', nt_on: 'NOTIFS: ON',
    nt_off: 'NOTIFS: OFF', nt_ok: 'vafratilkynningar virkjaðar - pip á P1 og P2',
    nt_denied: 'tilkynningar læstar af vafranum: leyfðu þær í stillingum síðunnar', term_denied: 'terminal hafnað eða ekki tiltækt: localhost krafist, eða stofa OPIN sem admin',
    term_p: 'alvöru bash - saga með örvum, Ctrl+C stöðvar, Ctrl+D lokar', term_restart: 'Endurstilla',
    navtrm: 'TERM', term_h2: 'Terminal - vinnuskel, beint í stjórnborðið',
    fl_off: 'FLEET: LOKAÐ', fl_paused: 'FLEET: Í HLEIÐ',
    fl_active: 'FLEET: VIRKT ({n} hringir)', fl_last: 'síðasti hringur',
    fl_none: 'enginn hringur enn', fl_info: 'millibil {i} mín, fjárlög {b} req/hring',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Samnýttar setur - veiðar saman, jafnvel án nettengingar', tm_p: 'Opnaðu samnýtt herbergi: hópurinn sér flotann og findings og getur flokkað beint. Einkaspjall setunnar hér fyrir neðan. Þrjú aðgangsstig: LOCAL (einstaklingur), LAN í gegnum OPNA Á NET, og HEIMUR í gegnum OPNA TIL HEIMS - opinleg göng (cloudflared ef sett upp) gera innbóðarhlekkinn gildan frá hvaða neti sem er, án þess að tölva þín sé beint útsett. Allt fer í gegnum lykil herbergisins - endurgerðu hann til að henda öllum út í einu.',
    tm_handle: 'Nafn þitt (16 stafir að hámarki)', tm_save_h: 'Velja',
    tm_room_ph: 'heiti herbergis (ex: c2ff-core)', tm_save: 'Virkja',
    tm_on: 'HERBERGI OPNA: {r} - {n} nettengdur', tm_off: 'SAMSkiPTA AFBUNDIN - staðbundin stakur seta',
    tm_room: 'Herbergi', tm_key: 'Lykill herbergis',
    tm_regen: 'Endurgera lykilinn', tm_regen_ok: 'nýr lykill búinn til - gamlir hlekkir eru dauðir',
    tm_invite: 'Boðshlekkur (afritaðu til liðs þíns)', tm_copy: 'Afrita',
    tm_copied: 'afritað á klippiborð', tm_members: 'Meðlimir',
    tm_nobody: 'enginn enn - sendu hlekkinn á liðið þitt', tm_you: '(þú)',
    tm_here: 'viðstaddur', tm_saved: 'notandanafn vistað',
    tm_no_handle: 'nafn tómt', tm_cfg_ok: 'herbergi uppfært',
    tm_cfg_no: 'bilað', tm_live: 'OPNA Á NET',
    tm_shore: 'TIL BAKA STAÐBUNI', tm_need_on: 'virkjaðu herbergið fyrst (ON)',
    tm_bind_lan: 'NET: {a}', tm_bind_lo: 'STAÐBUNDIÐ: aðeins localhost',
    to_team_live: '[GO-LIVE] þjónn endurræstur með net aðgangi - LAN hlekkur sýnilegur, endurtenging eftir 2 s', to_team_shore: 'þjónn endurræstur staðbundið (127.0.0.1)',
    tm_tun_open: 'OPNA TIL HEIMS (göng)', tm_tun_close: 'LOKA GÖNGUM',
    tm_tun_wait: 'opinber göng opnast (nokkrar sekúndur)…', tm_tun_on: 'SETA OPIN TIL HEIMS: {u} - innbóðarhlekkurinn virkar allstaðar, ekki þörf fyrir sama net',
    tm_tun_closed: 'göng lokuð - til baka á LAN/staðbundið', tm_chat_empty: 'seturrás opin - meðlimir herbergisins lesa hvert annað hér',
    tm_chat_h2: 'Setaspjall', tm_msg_ph: 'skilaboð til setunnar…',
    tm_admin: 'stjórnandi', tm_guest: 'gestur',
    tm_kick: 'KICK', tm_kick_ok: 'meðlimur fjarlægður úr stofunni (smelltu aftur til að aflæsa)',
    tm_role_ok: 'hlutverk uppfært', tm_mic_on: 'VIRKJA HLJÓÐNEMA',
    tm_mic_off: 'SLÖKKVA Á HLJÓÐNEMA', tm_mic_denied: 'hljóðnemi hafnað eða ónaumur: HTTPS krafist (göng HEIMS eða localhost) og nauðsynlegt að leyfa hljóðnemann',
    navf: 'FLEET', navfd: 'FINDINGS',
    navp: 'Verkefni', navai: 'GG',
    navc: 'Samhæfing', st_runs: 'Keyrslur',
    st_beacons: 'Beacon virkir', st_sig: 'Merki',
    h2f: 'FLEET - öll forrit, agents í gangi fyrst', h2fd: 'Grunnur FINDINGS - varanleg flokkun',
    h2eng: 'Vél FLEET - staðbundnir hringir án tokens', h2prog: 'Forrit - scope, nauðsynlegur haus, ræsing',
    h2new: 'Nýtt forrit', h2ai: 'Fulltrúi GG - 100% valkvæð uppsetning',
    h2c: 'Samhæfing - einkarás', fl_start: 'Hefja',
    fl_pause: 'Hlé', fl_cycle: 'Hringur núna',
    f_add: 'Bæta við', f_none: 'ekkert merki enn',
    f_ph: 'handvirkt finding: endpoint + sönnun + málsvaranlegt álag…', st_sig_off: 'merki',
    st_sig_an: 'greining', st_sig_sub: 'sendur inn',
    st_sig_dup: 'dup', st_sig_ref: 'hafnað',
    st_sig_cl: 'lokað', r_none: 'engin keyrsla greind',
    r_live: '{n} Í GANGI', r_done: 'KLÁRAÐ',
    r_feed: '▽ straumur ({n} ev)', r_close: '△ fella saman',
    p_name_ph: 'Heiti forrits (ex: PayPal)', p_hdr_ph: 'nauðsynlegur rannsakanda-haus (ex: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: lén1, lén2, …', p_save: 'Vista',
    p_local: 'eining(ar), 100% staðbundið', ai_p: 'C2FF keyrir að fullu án GG.: hamarnir eru ákvarðanakenndar staðbundnar prófanir. Þessi port sér aðeins um að tengja <b>itt</b> GG (sjálf-hýst eða API) fyrir stakgreiningu finding: hnappur <span style="color:var(--green)">GG »</span> í FINDINGS, svarið birtist í COORDINATION. Engin götur fara af tölvunni án þessarar skilgreiningar.',
    ai_off: 'slökkt', ai_on: 'virkjað',
    ai_st_off: 'GG SLEKT - ramminn keyrir 100% staðbundið án þess', ai_st_ready: 'GG TENGT: {p} · {m}',
    ai_st_inc: 'GG VIRKT EN ÓKLÁRT: baseURL og model nauðsynleg', ai_url_ph: 'base URL - ex: http://localhost:11434 eða https://api.MittGG.tld/v1',
    ai_model_ph: 'model - ex: llama3.1:8b', ai_key_ph: 'API lykill (skildu tómt fyrir staðbundna þjóna)',
    ai_save: 'Vista', ai_test: 'Prófa tengingu',
    ai_testing: 'prófun í gangi…', ai_ok: 'OK - svar: ',
    ai_fail: 'MISTÓKST: ', ai_note: 'uppsetning vistuð staðbundið í data/ai.json - aldrei sent annað en endpointið sem þú setur þar',
    ch_ph: 'root@c2ff:~# skilaboð til greiningarfulltrúa…', ch_send: 'Senda',
    ch_empty: 'Rásin er opin. Skrifaðu hér, skjárinn vekur mig samstundis.', ft: '100% staðbundið - prófanir ákvarðanakenndar, engir token né utanaðkomandi tengingar - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE VIRKT: staðbundnir hringir á 30 mín fresti, 0 token.', to_fl_pa: 'FLEET Í HLEIÐ - haltu áfram hvenær sem þú vilt.',
    to_fl_cy: 'Tafarlaus hringur ræstur (fjárlög 60 req).', to_launch: '[GO] hamur {m} (CWE {c}) á {p} - staðbundinn hringur ræstur',
    to_ai_ok: 'uppsetning vistuð', to_ai_no: 'mistókst að vista',
    to_ai_no_cfg: 'GG ekki stillt - stilltu það í GG flipanum', to_ai_head: 'GG GREINING',
    to_ai_bad: 'GG GREINING mistókst', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'GG',
    w_launch: '⚡ FLUG', navar: 'Vopnabúr',
    ar_h2: 'VOPNABÚR - CVE, EPSS og exploits á yfirborði sem greindist', ar_sync: 'SYNC GRUNNAR',
    ar_btn: 'SKREF', ar_exec: 'EXEC',
    ar_none: 'engin skref: keyrðu RECON fyrst, svo SYNC til að hlaða KEV/EPSS', ar_loading: 'yfirlit grunna í hleðslu...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'prufuforrit - enginn skann : bu til ditt eigið forrit', pip_noprog: 'ekkert forrit til : bu til ditt i Forrit',
    pip_next: 'naesta skref :', fnd_n: 'niourstodur: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  bs: {
    pl_title: 'Plan rada', pl_empty: 'još nema plana: pokreni RECON na karti iznad, hipoteze padaju ovdje (statusi se čuvaju)',
    pl_run: 'Pokreni', pl_reflect: 'canary odražen',
    st_do: 'za uraditi', st_test: 'testirano',
    st_signal: 'signal', st_valid: 'vrijedi',
    st_void: 'ništa', atk_btn: 'ATTACK',
    atk_start: 'napad na površinu: endpointi, izloženi docs, JWT, tajne...', atk_fail: 'napad nemoguć: pokreni prvo RECON',
    atk_none: 'nema signala', atk_findings: 'kandidati',
    atk_done: 'ATTACK: {n} kandidata P1/P2 ubačeno u findings sa dokazom', atk_empty: 'nema još napada: pokreni RECON pa ATTACK - kandidati sa dokazom req/res padaju ovdje',
    navh: 'HUNT', h2hunt: 'HUNT - prava površina i dokazi',
    h_ready: 'spremno', h_empty: 'nema poznate površine: pokreni RECON da mapiraš stranice, API endpointe, parametre, JS pakete i poddomene',
    h_fnd: 'Findings programa', h_nofnd: 'nema findings na ovom programu',
    rc_btn: 'RECON', rc_start: 'recon površine u toku: stranice, JS paketi, endpointi, parametri...',
    rc_done: 'površina mapirana: endpointi, parametri i poddomene na listi u karti programa', rc_fail: 'recon pao: host nedostupan ili prazan scope',
    rc_surface: 'površina:', snd_on: 'ZVUK: ON',
    snd_off: 'ZVUK: OFF', snd_ok: 'zvukovi sučelja aktivni - biblioteka: klik, tab, kopija, upozorenja',
    snd_stop: 'uključeno potpuno utišavanje: više nikakvih C2FF zvukova', amb_on: 'AMBIJENT: ON',
    amb_off: 'AMBIJENT: OFF', amb_ok: 'živi ambijent - nijansa nježno klizi kroz porodice (zeleno, plavo, žuto...)',
    amb_stop: 'ambijent zamrznut na originalno zeleno', nt_on: 'NOTIFS: ON',
    nt_off: 'NOTIFS: OFF', nt_ok: 'notifikacije preglednika aktivirane - zvižduk na P1 i P2',
    nt_denied: 'notifikacije blokirane od strane preglednika: dozvoli ih u postavkama stranice', term_denied: 'terminal odbijen ili nedostupan: potreban je localhost, ili OTVORENA soba kao admin',
    term_p: 'pravi bash - historija sa strelicama, Ctrl+C prekida, Ctrl+D zatvara', term_restart: 'Resetuj',
    navtrm: 'TERM', term_h2: 'Terminal - radni shell, direktno u konzoli',
    fl_off: 'FLEET: ZAUSTAVLJENO', fl_paused: 'FLEET: NA PAUZI',
    fl_active: 'FLEET: AKTIVNO ({n} ciklusa)', fl_last: 'posljednji ciklus',
    fl_none: 'još nema ciklusa', fl_info: 'interval {i} min, budžet {b} req/ciklus',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Grupne sesije - lov zajedno, čak i bez mreže', tm_p: 'Otvori dijeljenu sobu: tvoja grupa vidi flotu, findings i može sortirati uživo. Zaseban chat sesije ispod. Tri nivoa pristupa: LOCAL (solo), LAN kroz OTVORI NA MREŽU, i SVIJET kroz OTVORI ZA SVIJET - javni tunel (cloudflared ako je instaliran) čini pozivni link važećim s bilo koje mreže, bez direktnog izlaganja tvoje mašine. Sve ide preko ključa sobe - regeneriši ga da svima oduzmeš pristup odjednom.',
    tm_handle: 'Tvoj nadimak (maks 16 znakova)', tm_save_h: 'Izaberi',
    tm_room_ph: 'ime sobe (ex: c2ff-core)', tm_save: 'Primijeni',
    tm_on: 'SOBA OTVORENA: {r} - {n} online', tm_off: 'TEAM MOD ISKLJUČEN - lokalna solo sesija',
    tm_room: 'Soba', tm_key: 'Ključ sobe',
    tm_regen: 'Regeneriši ključ', tm_regen_ok: 'novi ključ generisan - stari linkovi su mrtvi',
    tm_invite: 'Pozivni link (kopiraj svom timu)', tm_copy: 'Kopiraj',
    tm_copied: 'kopirano u međuspremnik', tm_members: 'Članovi',
    tm_nobody: 'još nikoga - pošalji link svom timu', tm_you: '(ti)',
    tm_here: 'prisutan', tm_saved: 'nadimak sačuvan',
    tm_no_handle: 'prazan nadimak', tm_cfg_ok: 'soba ažurirana',
    tm_cfg_no: 'nije uspjelo', tm_live: 'OTVORI NA MREŽU',
    tm_shore: 'NAZAD NA LOKALNO', tm_need_on: 'prvo aktiviraj sobu (ON)',
    tm_bind_lan: 'MREŽA: {a}', tm_bind_lo: 'LOKALNO: samo localhost',
    to_team_live: '[GO-LIVE] server ponovno pokrenut s pristupom mreži - LAN link prikazan, ponovno povezivanje za 2 s', to_team_shore: 'server ponovno pokrenut lokalno (127.0.0.1)',
    tm_tun_open: 'OTVORI ZA SVIJET (tunel)', tm_tun_close: 'ZATVORI TUNEL',
    tm_tun_wait: 'javni tunel se otvara (nekoliko sekundi)…', tm_tun_on: 'SESIJA OTVORENA ZA SVIJET: {u} - pozivni link radi odakle god, nije potrebna ista mreža',
    tm_tun_closed: 'tunel zatvoren - povratak na LAN/lokalno', tm_chat_empty: 'kanal sesije otvoren - članovi sobe se međusobno čitaju ovdje',
    tm_chat_h2: 'Chat sesije', tm_msg_ph: 'poruka ka sesiji…',
    tm_admin: 'admin', tm_guest: 'gost',
    tm_kick: 'KICK', tm_kick_ok: 'član izbačen iz sobe (klikni ponovo da odblokiraš)',
    tm_role_ok: 'uloga ažurirana', tm_mic_on: 'UKLJUČI MIKROFON',
    tm_mic_off: 'UGASI MIKROFON', tm_mic_denied: 'mikrofon odbijen ili nedostupan: potreban je HTTPS (tunel SVIJET ili localhost) i treba dozvoliti mikrofon',
    navf: 'FLEET', navfd: 'FINDINGS',
    navp: 'Programi', navai: 'AI',
    navc: 'Koordinacija', st_runs: 'Kretanja',
    st_beacons: 'Beacons aktivni', st_sig: 'Signali',
    h2f: 'FLEET - svi programi, agenti u toku prvo', h2fd: 'Baza FINDINGS - trajno označavanje trijade',
    h2eng: 'Motor FLEET - lokalni ciklusi bez tokens', h2prog: 'Programi - scope, obavezno zaglavlje, lansiranje',
    h2new: 'Novi program', h2ai: 'AI agent - 100% opciona integracija',
    h2c: 'Koordinacija - privatni kanal', fl_start: 'Pokreni',
    fl_pause: 'Pauza', fl_cycle: 'Ciklus sada',
    f_add: 'Dodaj', f_none: 'još nema signala',
    f_ph: 'ručni finding: endpoint + dokaz + branljiva ozbiljnost…', st_sig_off: 'signal',
    st_sig_an: 'analiza', st_sig_sub: 'predano',
    st_sig_dup: 'dup', st_sig_ref: 'odbijeno',
    st_sig_cl: 'zatvoreno', r_none: 'nema run-a detektovanog',
    r_live: '{n} U TOKU', r_done: 'GOTOVO',
    r_feed: '▽ tok ({n} ev)', r_close: '△ sabij',
    p_name_ph: 'Ime programa (ex: PayPal)', p_hdr_ph: 'obavezno zaglavlje istraživača (ex: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domena1, domena2, …', p_save: 'Sačuvaj',
    p_local: 'modul(a), 100% lokalno', ai_p: 'C2FF radi potpuno bez AI: modovi su determinističke lokalne probe. Ovaj prolaz služi samo da se prikači <b>tvoj</b> AI (self-hosted ili API) za analizu jednog findinga: dugme <span style="color:var(--green)">AI »</span> u FINDINGS, odgovor prikazan u COORDINATION. Nijedan podatak ne napušta tvoju mašinu bez ove postavke.',
    ai_off: 'isključeno', ai_on: 'uključeno',
    ai_st_off: 'AI ISKLJUČEN - framework radi 100% lokalno bez nje', ai_st_ready: 'AI POVEZAN: {p} · {m}',
    ai_st_inc: 'AI UKLJUČEN ALI NEPOTPUN: potrebni su baseURL i model', ai_url_ph: 'base URL - ex: http://localhost:11434 ili https://api.MojaAI.tld/v1',
    ai_model_ph: 'model - ex: llama3.1:8b', ai_key_ph: 'API ključ (ostavi prazno za lokalne servere)',
    ai_save: 'Sačuvaj', ai_test: 'Testiraj vezu',
    ai_testing: 'testiranje u toku…', ai_ok: 'OK - odgovor: ',
    ai_fail: 'NEUSPJEH: ', ai_note: 'config sačuvan lokalno u data/ai.json - nikad se ne šalje nikud osim na endpoint koji tamo postaviš',
    ch_ph: 'root@c2ff:~# poruka ka agentu za analizu…', ch_send: 'Pošalji',
    ch_empty: 'Kanal je otvoren. Kucaj ovdje, monitor me budi trenutno.', ft: '100% lokalno - determinističke probe, bez tokena niti vanjskih zavisnosti - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE AKTIVAN: lokalni ciklusi svakih 30 min, 0 tokena.', to_fl_pa: 'FLEET NA PAUZI - nastavi kad god hoćeš.',
    to_fl_cy: 'Ciklus pokrenut odmah (budžet 60 req).', to_launch: '[GO] mod {m} (CWE {c}) na {p} - lokalni ciklus pokrenut',
    to_ai_ok: 'config sačuvan', to_ai_no: 'neuspješno spremanje',
    to_ai_no_cfg: 'AI nije konfigurisan - podesi u tabu AI', to_ai_head: 'ANALIZA AI',
    to_ai_bad: 'ANALIZA AI neuspjela', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ LANSIRANJE', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS i exploit na otkrivenoj površini', ar_sync: 'SYNC BAZE',
    ar_btn: 'POTEZI', ar_exec: 'EXEC',
    ar_none: 'nema poteza: prvo pokreni RECON, pa SYNC da učitaš KEV/EPSS', ar_loading: 'pregled baza se učitava...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demo program - skeniranje nije moguce : napravi svoj program', pip_noprog: 'nema programa : napravi svoj u Programi',
    pip_next: 'sljedeci korak :', fnd_n: 'nalazi: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  mk: {
    pl_title: 'Работен план', pl_empty: 'сè уште нема план: пушти RECON во картата горе, хипотезите паѓаат тука (статусите се зачувуваат)',
    pl_run: 'Пушти', pl_reflect: 'canary рефлектирано',
    st_do: 'за правење', st_test: 'тестирано',
    st_signal: 'сигнал', st_valid: 'валидно',
    st_void: 'ништо', atk_btn: 'ATTACK',
    atk_start: 'напад на површината: endpoints, изложени docs, JWT, тајни...', atk_fail: 'напад неможен: прво пушти RECON',
    atk_none: 'никаков сигнал', atk_findings: 'кандидати',
    atk_done: 'ATTACK: {n} кандидати P1/P2 вбризкани во findings со доказ', atk_empty: 'сè уште нема attack: пушти RECON потоа ATTACK - кандидатите со доказ req/res паѓаат тука',
    navh: 'HUNT', h2hunt: 'HUNT - реална површина и докази',
    h_ready: 'подготвено', h_empty: 'непозната површина: пушти RECON за да мапираш страници, endpoints API, параметри, JS бандли и поддомени',
    h_fnd: 'Findings од програмата', h_nofnd: 'нема findings за оваа програма',
    rc_btn: 'RECON', rc_start: 'recon на површината во тек: страници, JS бандли, endpoints, параметри...',
    rc_done: 'површината мапирана: endpoints, параметри и поддомени прикажани во картата на програмата', rc_fail: 'recon неуспешен: хост недостапен или празен scope',
    rc_surface: 'површина:', snd_on: 'ЗВУК: ON',
    snd_off: 'ЗВУК: OFF', snd_ok: 'звуци на интерфејсот активни - библиотека: клик, таб, копирање, предупредувања',
    snd_stop: 'целосно исклучување на звукот вклучено: повеќе никакви C2FF звуци', amb_on: 'АМБИЕНТ: ON',
    amb_off: 'АМБИЕНТ: OFF', amb_ok: 'жив амбиент - тонот нежно лизга низ групите (зелено, сино, жолто...)',
    amb_stop: 'амбиентот замрзнат на оригиналната зелена', nt_on: 'NOTIFS: ON',
    nt_off: 'NOTIFS: OFF', nt_ok: 'нотификации од прелистувачот активирани - пип на P1 и P2',
    nt_denied: 'нотификации блокирани од прелистувачот: дозволи ги во поставките на сајтот', term_denied: 'терминалот одбиен или недостапен: потребен е localhost, или ОТВОРЕНА соба како админ',
    term_p: 'реален bash - историја со стрелки, Ctrl+C прекинува, Ctrl+D затвора', term_restart: 'Рестартирај',
    navtrm: 'TERM', term_h2: 'Терминал - работен шел, директно во конзолата',
    fl_off: 'FLEET: СТОП', fl_paused: 'FLEET: ПАУЗА',
    fl_active: 'FLEET: АКТИВЕН ({n} циклуси)', fl_last: 'последен циклус',
    fl_none: 'сè уште нема циклуси', fl_info: 'интервал {i} мин, буџет {b} req/циклус',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Групни сесии - лов заедно, дури и без мрежа', tm_p: 'Отвори споделена соба: твојата група ја гледа флотата, findings и може да тријажува во живо. Засебен сесиски чат подолу. Три нивоа на пристап: LOCAL (соло), LAN преку ОТВОРИ НА МРЕЖАТА, и СВЕТ преку ОТВОРИ КОН СВЕТОТ - јавен тунел (cloudflared ако е инсталиран) го прави линкот-покана валиден од која било мрежа, без директно излагање на твојата машина. Сè поминува преку клучот за соба - регенерирај го да ги исфрлиш сите одеднаш.',
    tm_handle: 'Твојот псевдоним (макс 16 знаци)', tm_save_h: 'Избери',
    tm_room_ph: 'име на собата (напр: c2ff-core)', tm_save: 'Примени',
    tm_on: 'СОБАТА ОТВОРЕНА: {r} - {n} онлајн', tm_off: 'TEAM МОДА ИСКЛУЧЕНА - локална соло сесија',
    tm_room: 'Соба', tm_key: 'Клуч за собата',
    tm_regen: 'Регенерирај го клучот', tm_regen_ok: 'нов клуч креиран - старите линкови се мртви',
    tm_invite: 'Линк-покана (копирај до свој тим)', tm_copy: 'Копирај',
    tm_copied: 'копирано во клипбордот', tm_members: 'Членови',
    tm_nobody: 'сè уште никој - испрати го линкот до тимот', tm_you: '(ти)',
    tm_here: 'присутен', tm_saved: 'псевдоним снимен',
    tm_no_handle: 'празен псевдоним', tm_cfg_ok: 'собата ажурирана',
    tm_cfg_no: 'неуспех', tm_live: 'ОТВОРИ НА МРЕЖАТА',
    tm_shore: 'НАЗАД ЛОКАЛНО', tm_need_on: 'првo активирај ja собата (ON)',
    tm_bind_lan: 'МРЕЖА: {a}', tm_bind_lo: 'ЛОКАЛНО: само localhost',
    to_team_live: '[GO-LIVE] серверот повторно стартиран со мрежен пристап - LAN линк покажан, повторна врска во 2 s', to_team_shore: 'серверот повторно стартиран локално (127.0.0.1)',
    tm_tun_open: 'ОТВОРИ КОН СВЕТОТ (тунел)', tm_tun_close: 'ЗАТВОРИ ТУНЕЛ',
    tm_tun_wait: 'јавен тунел се отвора (неколку секунди)…', tm_tun_on: 'СЕСИЈАТА ОТВОРЕНА КОН СВЕТОТ: {u} - линкот-покана работи од секаде, не треба иста мрежа',
    tm_tun_closed: 'тунелот затворен - назад на LAN/локално', tm_chat_empty: 'каналот на сесијата отворен - членовите на собата се читаат меѓусебно овде',
    tm_chat_h2: 'Чат на сесијата', tm_msg_ph: 'порака до сесијата…',
    tm_admin: 'админ', tm_guest: 'гостин',
    tm_kick: 'KICK', tm_kick_ok: 'членот избекан од собата (кликни повторно за деблокирање)',
    tm_role_ok: 'ролата ажурирана', tm_mic_on: 'АКТИВИРАЈ МИКРОФОН',
    tm_mic_off: 'ИСКЛУЧИ МИКРОФОН', tm_mic_denied: 'микрофонот одбиен или недостапен: потребен е HTTPS (СВЕТ тунел или localhost) и треба да се дозволи микрофонот',
    navf: 'FLEET', navfd: 'FINDINGS',
    navp: 'Програми', navai: 'ВИ',
    navc: 'Координација', st_runs: 'Извршувања',
    st_beacons: 'Beacons активни', st_sig: 'Сигнали',
    h2f: 'FLEET - сите програми, агентите во тек прво', h2fd: 'База FINDINGS - тагови тријажа постојани',
    h2eng: 'Мотор FLEET - локални циклуси без токени', h2prog: 'Програми - scope, задолжителен header, стартување',
    h2new: 'Нова програма', h2ai: 'ВИ агент - 100% опциона интеграција',
    h2c: 'Координација - приватен канал', fl_start: 'Стартувај',
    fl_pause: 'Пауза', fl_cycle: 'Циклус сега',
    f_add: 'Додај', f_none: 'сè уште нема сигнали',
    f_ph: 'рачно внесен finding: endpoint + доказ + одбранлива сериозност…', st_sig_off: 'сигнал',
    st_sig_an: 'анализа', st_sig_sub: 'испратено',
    st_sig_dup: 'dup', st_sig_ref: 'одбиено',
    st_sig_cl: 'затворено', r_none: 'не е детектиран run',
    r_live: '{n} ВО ТЕК', r_done: 'ГОТОВО',
    r_feed: '▽ тек ({n} ev)', r_close: '△ собери',
    p_name_ph: 'Име на програмата (напр: PayPal)', p_hdr_ph: 'задолжителен header на истражувачот (напр: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: домен1, домен2, …', p_save: 'Зачувај',
    p_local: 'модул(и), 100% локално', ai_p: 'C2FF работи целосно без ВИ: модовите се детерминистички локални проби. Оваа капија служи само да се поврзе <b>твојата</b> ВИ (self-hosted или API) за анализа на еден finding: копче <span style="color:var(--green)">ВИ »</span> во FINDINGS, одговорот прикажан во COORDINATION. Никакви податоци не ја напуштаат твојата машина без оваа конфигурација.',
    ai_off: 'исклучено', ai_on: 'активирано',
    ai_st_off: 'ВИ ИСКЛУЧЕНО - фрејмворкот работи 100% локално без неа', ai_st_ready: 'ВИ ПОВРЗАН: {p} · {m}',
    ai_st_inc: 'ВИ АКТИВИРАНО АЛИ НЕКОМПЛЕТНО: потребни се baseURL и model', ai_url_ph: 'base URL - напр: http://localhost:11434 или https://api.MojaVI.tld/v1',
    ai_model_ph: 'model - напр: llama3.1:8b', ai_key_ph: 'API клуч (остави празно за локални сервери)',
    ai_save: 'Зачувај', ai_test: 'Тестирај врска',
    ai_testing: 'тестирање во тек…', ai_ok: 'OK - одговор: ',
    ai_fail: 'НЕУСПЕШНО: ', ai_note: 'конфигот зачуван локално во data/ai.json - никогаш не се праќа другаде освен до endpoint-от што таму го ставиш',
    ch_ph: 'root@c2ff:~# порака до агентот за анализа…', ch_send: 'Праќај',
    ch_empty: 'Каналот е отворен. Пишуваj тука, мониторот ме буди веднаш.', ft: '100% локално - детерминистички проби, без токени ниту надворешни зависности - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE AKTИВЕН: локални циклуси na секои 30 мин, 0 токена.', to_fl_pa: 'FLEET BO ПАУЗА - продолжи кога ќе сакаш.',
    to_fl_cy: 'Циклусот пуштен веднаш (буџет 60 req).', to_launch: '[GO] мод {m} (CWE {c}) на {p} - локален циклус пуштен',
    to_ai_ok: 'конфиг зачуван', to_ai_no: 'неуспешно зачувување',
    to_ai_no_cfg: 'ВИ неконфигурирано - постави во табот ВИ', to_ai_head: 'АНАЛИЗА ВИ',
    to_ai_bad: 'АНАЛИЗА ВИ неуспешна', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'ВИ',
    w_launch: '⚡ СТАРТУВАЊЕ', navar: 'Арсенал',
    ar_h2: 'АРСЕНАЛ - CVE, EPSS и експлоити на откриената површина', ar_sync: 'SYNC БАЗИ',
    ar_btn: 'ПОТЕЗИ', ar_exec: 'EXEC',
    ar_none: 'нема потези: прво пушти RECON, па SYNC за да вчита KEV/EPSS', ar_loading: 'преглед на базите се вчитува...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'демо програм - без скенирање: креирај свој програм', pip_noprog: 'нема програми: креирај свој во табот Програми',
    pip_next: 'следна фаза:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  ka: {
    pl_title: 'სამუშაო გეგმა', pl_empty: 'ჯერ არ არის გეგმა: გაუშვი RECON ზედა ბარათში, ჰიპოთეზები აქ ჩამოცვივდება (სტატუსები ინახება)',
    pl_run: 'გაუშვი', pl_reflect: 'canary ასახული',
    st_do: 'შესასრულებელი', st_test: 'შემოწმებული',
    st_signal: 'სიგნალი', st_valid: 'ვალიდური',
    st_void: 'არაფერი', atk_btn: 'ATTACK',
    atk_start: 'შეტევა ზედაპირზე: endpoints, გამოაშკარავებული docs, JWT, საიდუმლოები...', atk_fail: 'შეტევა შეუძლებელია: ჯერ RECON გაუშვი',
    atk_none: 'არცერთი სიგნალი', atk_findings: 'კანდიდატები',
    atk_done: 'ATTACK: {n} კანდიდატი P1/P2 მტკიცებით findings-ში ჩასმული', atk_empty: 'ჯერ შეტევა არ არის: გაუშვი RECON შემდეგ ATTACK - კანდიდატები მტკიცებით req/res აქ ჩამოცვივდებიან',
    navh: 'HUNT', h2hunt: 'HUNT - რეალური ზედაპირი და მტკიცებულებები',
    h_ready: 'მზად', h_empty: 'ცნობილი ზედაპირი არ არის: გაუშვი RECON რომ დაამაპო გვერდები, API endpoints, პარამეტრები, JS ბანდლები და ქვედომენები',
    h_fnd: 'პროგრამის findings', h_nofnd: 'ამ პროგრამაში findings არ არის',
    rc_btn: 'RECON', rc_start: 'ზედაპირის recon მიმდინარეა: გვერდები, JS ბანდლები, endpoints, პარამეტრები...',
    rc_done: 'ზედაპირი დამაპებულია: endpoints, პარამეტრები და ქვედომენები ჩამოთვლილია პროგრამის ბარათში', rc_fail: 'recon ჩავარდა: host მიუწვდომელია ან scope ცარიელია',
    rc_surface: 'ზედაპირი:', snd_on: 'ხმა: ON',
    snd_off: 'ხმა: OFF', snd_ok: 'ინტერფეისის ხმები აქტიურია - ბიბლიოთეკა: დაწკაპუნება, ტაბი, კოპირება, გაფრთხილებები',
    snd_stop: 'სრული დადუმება ჩართულია: C2FF ხმა აღარ იქნება', amb_on: 'ატმოსფერო: ON',
    amb_off: 'ატმოსფერო: OFF', amb_ok: 'ცოცხალი ატმოსფერო - ფერი რბილად სრიალებს ოჯახებში (მწვანე, ლურჯი, ყვითელი...)',
    amb_stop: 'ატმოსფერო გაყინულია პირვანდელ მწვანეზე', nt_on: 'NOTIFS: ON',
    nt_off: 'NOTIFS: OFF', nt_ok: 'ბრაუზერის შეტყობინებები ჩართულია - ხმა P1 და P2-ზე',
    nt_denied: 'შეტყობინებები ბრაუზერმა დაბლოკა: დაუშვი ისინი საიტის პარამეტრებში', term_denied: 'ტერმინალი უარყოფილია ან მიუწვდომელია: საჭიროა localhost, ან ოთახი გახსნილია ადმინად',
    term_p: 'ნამდვილი bash - ისტორია ისრებით, Ctrl+C აწყვევს, Ctrl+D ხურავს', term_restart: 'გადატვირთვა',
    navtrm: 'TERM', term_h2: 'ტერმინალი - სამუშაო გარსი, პირდაპირ კონსოლში',
    fl_off: 'FLEET: შეჩერებული', fl_paused: 'FLEET: პაუზა',
    fl_active: 'FLEET: აქტიური ({n} ციკლი)', fl_last: 'უკანასკნელი ციკლი',
    fl_none: 'ჯერ ციკლი არ არის', fl_info: 'ინტერვალი {i} წთ, ბიუჯეტი {b} req/ციკლი',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'ჯგუფური სესიები - ნადირობა ერთად, ქსელის გარეშეც', tm_p: 'გახსენი საერთო ოთახი: შენი ჯგუფი ხედავს ფლოტს და findings-ს, შეუძლია რეალურ დროში დახარისხება. სესიის ცალკე ჩეტი ქვემოთ. წვდომის სამი დონე: LOCAL (მარტო), LAN ქსელზე გახსნით, და სამყარო სამყაროსკენ გახსნით - საჯარო ტუნელი (cloudflared თუ დაყენებულია) მოწვევის ლინკს ნებისმიერი ქსელიდან მოქმედად აქცევს, შენი კომპიუტერი პირდაპირ არ ჟღავნდება. ყველაფერი ოთახის გასაღებზეა დამოკიდებული - ახლებური გასაღები ყველას ერთი მოძრაობით გააძევებს.',
    tm_handle: 'შენი სახელი (მაქს 16 სიმბოლო)', tm_save_h: 'აირჩიე',
    tm_room_ph: 'ოთახის სახელი (ნიმ: c2ff-core)', tm_save: 'გამოყენება',
    tm_on: 'ოთახი გახსნილია: {r} - {n} ონლაინ', tm_off: 'TEAM რეჟიმი გამორთულია - ლოკალური სოლო სესია',
    tm_room: 'ოთახი', tm_key: 'ოთახის გასაღები',
    tm_regen: 'გასაღების განახლება', tm_regen_ok: 'ახალი გასაღები დაგენერირდა - ძველი ლინკები მკვდარია',
    tm_invite: 'მოწვევის ლინკი (დააკოპირე შენს გუნდს)', tm_copy: 'კოპირება',
    tm_copied: 'კოპირებულია ბუფერში', tm_members: 'წევრები',
    tm_nobody: 'ჯერ არავინ - გაუგზავნე ლინკი შენს გუნდს', tm_you: '(შენ)',
    tm_here: 'აქაა', tm_saved: 'სახელი შენახულია',
    tm_no_handle: 'სახელი ცარიელია', tm_cfg_ok: 'ოთახი განახლდა',
    tm_cfg_no: 'ჩავარდა', tm_live: 'ქსელზე გახსნა',
    tm_shore: 'დაბრუნდი ლოკალზე', tm_need_on: 'ჯერ გააქტიურე ოთახი (ON)',
    tm_bind_lan: 'ქსელი: {a}', tm_bind_lo: 'ლოკალური: მხოლოდ localhost',
    to_team_live: '[GO-LIVE] სერვერი ხელახლა გაშვებულია ქსელის წვდომით - LAN ლინკი ნაჩვენები, ხელახალი კავშირი 2 წმ-ში', to_team_shore: 'სერვერი ხელახლა გაშვებულია ლოკალურად (127.0.0.1)',
    tm_tun_open: 'სამყაროზე გახსნა (ტუნელი)', tm_tun_close: 'ტუნელის დახურვა',
    tm_tun_wait: 'საჯარო ტუნელი იხსნება (რამდენიმე წამი)…', tm_tun_on: 'სესია სამყაროზე გახსნილია: {u} - მოწვევის ლინკი ყველგან მუშაობს, ერთი ქსელი არ არის საჭირო',
    tm_tun_closed: 'ტუნელი დაიხურა - დაბრუნება LAN/ლოკალზე', tm_chat_empty: 'სესიის არხი გახსნილია - ოთახის წევრები ერთმანეთს აქ კითხულობენ',
    tm_chat_h2: 'სესიის ჩეტი', tm_msg_ph: 'შეტყობინება სესიისკენ…',
    tm_admin: 'ადმინი', tm_guest: 'სტუმარი',
    tm_kick: 'KICK', tm_kick_ok: 'წევრი ოთახიდან გააძევეს (ხელახლა დაკლიკება დაბლოკვის მოხდა)',
    tm_role_ok: 'როლი განახლებულია', tm_mic_on: 'მიკროფონის ჩართვა',
    tm_mic_off: 'მიკროფონის გამორთვა', tm_mic_denied: 'მიკროფონი უარყოფილია ან მიუწვდომელია: საჭიროა HTTPS (სამყაროს ტუნელი ან localhost) და მიკროფონი უნდა დაიშვას',
    navf: 'FLEET', navfd: 'FINDINGS',
    navp: 'პროგრამები', navai: 'ხი',
    navc: 'კოორდინაცია', st_runs: 'გაშვებები',
    st_beacons: 'Beacons აქტიური', st_sig: 'სიგნალები',
    h2f: 'FLEET - ყველა პროგრამა, გაშვებული აგენტები ჯერ', h2fd: 'FINDINGS-ის ბაზა - მუდმივი ტრიაჟის ლეიბლები',
    h2eng: 'FLEET ძრავა - ლოკალური ციკლები ტოკენების გარეშე', h2prog: 'პროგრამები - scope, სავალდებულო header, გაშვება',
    h2new: 'ახალი პროგრამა', h2ai: 'ხი აგენტი - 100% არასავალდებულო ინტეგრაცია',
    h2c: 'კოორდინაცია - კერძო არხი', fl_start: 'გაშვება',
    fl_pause: 'პაუზა', fl_cycle: 'ციკლი ახლა',
    f_add: 'დამატება', f_none: 'ჯერ არცერთი სიგნალი',
    f_ph: 'ხელით finding: endpoint + მტკიცება + დაცვადი სიმწირე…', st_sig_off: 'სიგნალი',
    st_sig_an: 'ანალიზი', st_sig_sub: 'გაგზავნილი',
    st_sig_dup: 'dup', st_sig_ref: 'უარყოფილი',
    st_sig_cl: 'დახურული', r_none: 'გაშვება არ არის აღმოჩენილი',
    r_live: '{n} მიმდინარე', r_done: 'დასრულდა',
    r_feed: '▽ ნაკადი ({n} ev)', r_close: '△ დაკეცვა',
    p_name_ph: 'პროგრამის სახელი (ნიმ: PayPal)', p_hdr_ph: 'სავალდებულო ჰედერი მკვლევარისთვის (ნიმ: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: დომენი1, დომენი2, …', p_save: 'შენახვა',
    p_local: 'მოდულ(ები), 100% ლოკალური', ai_p: 'C2FF მუშაობს სრულად ხი-ს გარეშე: რეჟიმები ლოკალური დეტერმინისტული ზონდებია. ეს შესასვლელი მხოლოდ <b>შენი</b> ხი-ს (self-hosted ან API) მისაერთებლად გამოიყენება ერთი finding-ის ანალიზისთვის: ღილაკი <span style="color:var(--green)">ხი »</span> FINDINGS-ში, პასუხი COORDINATION-ში აისახება. ამ კონფიგურაციის გარეშე არცერთი მონაცემი არ ტოვებს შენს კომპიუტერს.',
    ai_off: 'გამორთული', ai_on: 'ჩართული',
    ai_st_off: 'ხი გამორთულია - ჩარჩო 100% ლოკალურად მუშაობს მას გარეშე', ai_st_ready: 'ხი დაკავშირებულია: {p} · {m}',
    ai_st_inc: 'ხი ჩართულია მაგრამ არასრულია: საჭიროა baseURL და model', ai_url_ph: 'base URL - ნიმ: http://localhost:11434 ან https://api.ChemiKhI.tld/v1',
    ai_model_ph: 'model - ნიმ: llama3.1:8b', ai_key_ph: 'API გასაღები (დატოვე ცარიელი ლოკალური სერვერებისთვის)',
    ai_save: 'შენახვა', ai_test: 'კავშირის ტესტი',
    ai_testing: 'ტესტირება მიმდინარეობს…', ai_ok: 'OK - პასუხი: ',
    ai_fail: 'ჩავარდა: ', ai_note: 'კონფიგი ლოკალურად ინახება data/ai.json ფაილში - არასდროს იგზავნება სხვაგან, მხოლოდ იქ მითითებულ endpoint-ზე',
    ch_ph: 'root@c2ff:~# შეტყობინება ანალიზის აგენტს…', ch_send: 'გაგზავნა',
    ch_empty: 'არხი გახსნილია. ჩაწერე აქ, მონიტორი მაშინვე მაღვიძლებს.', ft: '100% ლოკალური - დეტერმინისტული ზონდები, ტოკენებისა და გარე დამოკიდებულებების გარეშე - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE აქტიური: ლოკალური ციკლები ყოველ 30 წთ-ში, 0 ტოკენა.', to_fl_pa: 'FLEET პაუზაზე - გააგრძელე როცა გინდა.',
    to_fl_cy: 'დაუყოვნებლივი ციკლი გაშვებულია (ბიუჯეტი 60 req).', to_launch: '[GO] რეჟიმი {m} (CWE {c}) {p}-ზე - ლოკალური ციკლი გაშვებულია',
    to_ai_ok: 'კონფიგი შენახულია', to_ai_no: 'შენახვა ჩავარდა',
    to_ai_no_cfg: 'ხი არ არის კონფიგურირებული - დააყენე ხი ტაბში', to_ai_head: 'ანალიზი ხი',
    to_ai_bad: 'ხი ანალიზი ჩავარდა', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'ხი',
    w_launch: '⚡ გაშვება', navar: 'არსენალი',
    ar_h2: 'არსენალი - CVE, EPSS და ექსპლოიტები აღმოჩენილ ზედაპირზე', ar_sync: 'SYNC ბაზები',
    ar_btn: 'სვლები', ar_exec: 'EXEC',
    ar_none: 'სვლები არაა: ჯერ გაუშვი RECON, შემდეგ SYNC KEV/EPSS-ის ჩასატვირთად', ar_loading: 'ბაზების მიმოხილვა იტვირთება...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'დემო პროგრამა - სკანირება არ ხდება: შექმენი შენი პროგრამა', pip_noprog: 'პროგრამა არ არსებობს: შექმენი შენი პროგრამების ჩანართში',
    pip_next: 'შემდეგი ეტაპი:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  hy: {
    pl_title: 'Աշխատանքի պլան', pl_empty: 'դեռ պլան չկա՝ գործարկի RECON վերևի քարտում, հիպոթեզները այստեղ են ընկնում (կարգավիճակները պահվում են)',
    pl_run: 'Գործարկել', pl_reflect: 'canary արտացոլված',
    st_do: 'կատարելու', st_test: 'ստուգված',
    st_signal: 'ազդանշան', st_valid: 'վավեր',
    st_void: 'ոչինչ', atk_btn: 'ATTACK',
    atk_start: 'հարձակում մակերեսի վրա՝ endpoints, բացահայտված docs, JWT, գաղտնիքներ...', atk_fail: 'հարձակում անհնար է՝ նախ գործարկի RECON',
    atk_none: 'ազդանշան չկա', atk_findings: 'թեկնածուներ',
    atk_done: 'ATTACK: {n} թեկնածու P1/P2 ապացույցով ավելացված են findings-ում', atk_empty: 'դեռ հարձակում չկա՝ գործարկի RECON, հետո ATTACK - թեկնածուները՝ req/res ապացույցով, այստեղ են ընկնում',
    navh: 'HUNT', h2hunt: 'HUNT - իրական մակերես և ապացույցներ',
    h_ready: 'պատրաստ', h_empty: 'հայտնի մակերես չկա՝ գործարկի RECON, որ քարտեզագրես էջերը, API endpoint-ները, պարամետրերը, JS bundle-ները և ենթադոմենները',
    h_fnd: 'Ծրագրի findings', h_nofnd: 'այս ծրագրի համար findings չկա',
    rc_btn: 'RECON', rc_start: 'մակերեսի recon-ը ընթացքում է՝ էջեր, JS bundle-ներ, endpoints, պարամետրեր...',
    rc_done: 'մակերեսը քարտեզագրված է՝ endpoints, պարամետրեր և ենթադոմեններ թվարկված են ծրագրի քարտում', rc_fail: 'recon-ը ձախողվեց՝ host հասանելի չէ կամ scope-ը դատարկ է',
    rc_surface: 'մակերես՝', snd_on: 'ՁԱՅՆ: ON',
    snd_off: 'ՁԱՅՆ: OFF', snd_ok: 'ինտերֆեյսի ձայները ակտիվ են - գրադարան՝ սեղմում, ներդիր, պատճենում, զգուշացումներ',
    snd_stop: 'լիակատար անձայնացում միացված է՝ այլևս ոչ մի C2FF ձայն', amb_on: 'ՄԹՆՈԼՈՐՏ: ON',
    amb_off: 'ՄԹՆՈԼՈՐՏ: OFF', amb_ok: 'կենդանի մթնոլորտ - երանգը փափուկ սահում է ընտանիքների միջով (կանաչ, կապույտ, դեղին...)',
    amb_stop: 'մթնոլորտը սառեցված է սկզբնական կանաչի վրա', nt_on: 'NOTIFS: ON',
    nt_off: 'NOTIFS: OFF', nt_ok: 'դիտարկչի ծանուցումները միացված են - զանգ P1 և P2-ի վրա',
    nt_denied: 'ծանուցումները արգելափակված են դիտարկչի կողմից՝ թույլատրիր կայքի կարգավորումներում', term_denied: 'տերմինալը մերժված է կամ հասանելի չէ՝ պահանջվում է localhost, կամ ԲԱՑ սենյակ՝ որպես ադմին',
    term_p: 'իրական bash - պատմություն սլաքներով, Ctrl+C ընդհատում է, Ctrl+D փակում է', term_restart: 'Վերագործարկել',
    navtrm: 'TERM', term_h2: 'Տերմինալ - աշխատանքային shell, ուղղակի կոնսոլում',
    fl_off: 'FLEET: ԿԱՆԳՆԱԾ', fl_paused: 'FLEET: ԴԱԴԱՐ',
    fl_active: 'FLEET: ԱԿՏԻՎ ({n} ցիկլ)', fl_last: 'վերջին ցիկլը',
    fl_none: 'դեռ ոչ մի ցիկլ', fl_info: 'միջակայք {i} րոպե, բյուջե {b} req/ցիկլ',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Խմբային սեսիաներ - որս միասին, նույնիսկ ցանցից դուրս', tm_p: 'Բաց արա ընդհանուր սենյակը՝ քո խումբը տեսնում է ֆլոտը և findings-ը, կարող է տեսակավորել ուղիղ. սեսիայի չատը ներքևում է. մուտքի երեք մակարդակ՝ LOCAL (մենակ), LAN ԲԱՑԵԼ ՑԱՆՑՈՒՄ, և ԲԱՑԵԼ ԱՇԽԱՐՀՈՒՄ - հանրային թունելը (cloudflared, եթե տեղադրված է) հրավերի հղումը վավեր է դարձնում ցանկացած ցանցից, առանց քո մեքենան ուղղակի բացելու. ամեն ինչ գնում է սենյակի բանալիով - վերականգնիր այն, որ բոլորին դուրս նետես միանգամից.',
    tm_handle: 'Քո մականունը (առավելագույնը 16 նշան)', tm_save_h: 'Ընտրել',
    tm_room_ph: 'սենյակի անունը (ex: c2ff-core)', tm_save: 'Կիրարկել',
    tm_on: 'ՍԵՆՅԱԿԸ ԲԱՑ Է՝ {r} - {n} օնլայն', tm_off: 'TEAM ռեժիմը անջատված է - լոկալ սոլո սեսիա',
    tm_room: 'Սենյակ', tm_key: 'Սենյակի բանալին',
    tm_regen: 'Նորից ստեղծել բանալին', tm_regen_ok: 'նոր բանալի ստեղծված է - հին հղումները մահացած են',
    tm_invite: 'Հրավերի հղում (պատճենիր քո թիմին)', tm_copy: 'Պատճենել',
    tm_copied: 'պատճենված է clipboard-ում', tm_members: 'Անդամներ',
    tm_nobody: 'դեռ ոչ ոք - ուղարկիր հղումը քո թիմին', tm_you: '(դու)',
    tm_here: 'ներկա', tm_saved: 'մականունը պահվել է',
    tm_no_handle: 'դատարկ մականուն', tm_cfg_ok: 'սենյակը թարմացվել է',
    tm_cfg_no: 'ձախողում', tm_live: 'ԲԱՑԵԼ ՑԱՆՑՈՒՄ',
    tm_shore: 'ՎԵՐԱԴԱՐՁ ԼՈԿԱԼ', tm_need_on: 'նախ միացրու սենյակը (ON)',
    tm_bind_lan: 'ՑԱՆԳ: {a}', tm_bind_lo: 'ԼՈԿԱԼ․ միայն localhost',
    to_team_live: '[GO-LIVE] սերվերը վերագործարկված է ցանցի մուտքով - LAN հղումը ցուցադրված է, վերամիացում 2 վրկ-ում', to_team_shore: 'սերվերը վերագործարկված է լոկալ (127.0.0.1)',
    tm_tun_open: 'ԲԱՑԵԼ ԱՇԽԱՐՀ (թունել)', tm_tun_close: 'ՓԱԿԵԼ ԹՈՒՆԵԼԸ',
    tm_tun_wait: 'հանրային թունելը բացվում է (մի քանի վայրկյան)…', tm_tun_on: 'ՍԵՍԻԱՆ ԲԱՑ Է ԱՇԽԱՐՀՈՒՄ՝ {u} - հրավերի հղումը աշխատում է ցանկացածուտից, միևնույն ցանցը պետք չէ',
    tm_tun_closed: 'թունելը փակված է - վերադարձ LAN/լոկալ', tm_chat_empty: 'սեսիայի ալիքը բաց է - սենյակի անդամները այստեղ միմյանց են կարդում',
    tm_chat_h2: 'Սեսիայի չատ', tm_msg_ph: 'հաղորդագրություն դեպի սեսիան…',
    tm_admin: 'ադմին', tm_guest: 'հյուր',
    tm_kick: 'KICK', tm_kick_ok: 'անդամը դուրս է մղված սենյակից (սեղմիր կրկին՝ ապաարգելափակելու համար)',
    tm_role_ok: 'դերը թարմացված է', tm_mic_on: 'ՄԻԱՑՆԵԼ ՄԻԿՐՈՖՈՆԸ',
    tm_mic_off: 'ԱՆՋԱՏԵԼ ՄԻԿՐՈՖՈՆԸ', tm_mic_denied: 'միկրոֆոնը մերժված է կամ հասանելի չէ՝ պահանջվում է HTTPS (Աշխարհի թունել կամ localhost) և միկրոֆոնը պետք է թույլատրվի',
    navf: 'FLEET', navfd: 'FINDINGS',
    navp: 'Ծրագրեր', navai: 'ԱԻ',
    navc: 'Կոորդինացիա', st_runs: 'Գործարկումներ',
    st_beacons: 'Beacon-ներ ակտիվ', st_sig: 'Ազդանշաններ',
    h2f: 'FLEET - բոլոր ծրագրերը, գործարկվող գործակալները առաջ', h2fd: 'FINDINGS բազա - մշտական տրիաժի պիտակներ',
    h2eng: 'FLEET շարժիչ - լոկալ ցիկլեր առանց token-ների', h2prog: 'Ծրագրեր - scope, պարտադիր header, գործարկում',
    h2new: 'Նոր ծրագիր', h2ai: 'ԱԻ գործակալ - 100% կամավոր ինտեգրացիա',
    h2c: 'Կոորդինացիա - մասնավոր ալիք', fl_start: 'Գործարկել',
    fl_pause: 'Դադար', fl_cycle: 'Ցիկլ հիմա',
    f_add: 'Ավելացնել', f_none: 'դեռ ոչ մի ազդանշան',
    f_ph: 'ձեռքի finding՝ endpoint + ապացույց + պաշտպանելի լրջություն…', st_sig_off: 'ազդանշան',
    st_sig_an: 'վերլուծություն', st_sig_sub: 'ներկայացված',
    st_sig_dup: 'dup', st_sig_ref: 'մերժված',
    st_sig_cl: 'փակված', r_none: 'գործարկում չի հայտնաբերված',
    r_live: '{n} ԸՆԹԱՑՔՈՒՄ', r_done: 'ԱՎԱՐՏՎԱԾ',
    r_feed: '▽ հոսք ({n} ev)', r_close: '△ ծալել',
    p_name_ph: 'Ծրագրի անունը (ex: PayPal)', p_hdr_ph: 'պարտադիր researcher header (ex: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: դոմեն1, դոմեն2, …', p_save: 'Պահպանել',
    p_local: 'մոդուլ(ներ), 100% լոկալ', ai_p: 'C2FF-ը գործում է ամբողջովին ԱԻ-ից դուրս՝ ռեժիմները լոկալ դետերմինիստական զոնդեր են. այս դարպասը միայն քո <b>ԱԻ</b>-ն է (self-hosted կամ API) միացնում մեկ finding-ի վերլուծության համար՝ սեղմակ <span style="color:var(--green)">ԱԻ »</span> FINDINGS-ում, պատասխանը COORDINATION-ում է ցուցադրվում. առանց այս կոնֆիգի ոչ մի տվյալ դուրս չի գալիս քո մեքենայից.',
    ai_off: 'անջատված', ai_on: 'միացված',
    ai_st_off: 'ԱԻ ԱՆՋԱՏՎԱԾ Է - շրջանակը 100% լոկալ է գործում առանց նրա', ai_st_ready: 'ԱԻ ՄԻԱՑՎԱԾ Է՝ {p} · {m}',
    ai_st_inc: 'ԱԻ ՄԻԱՑՎԱԾ ԲԱՅՑ ՈՉ ԼՐԻՎ՝ պահանջվում են baseURL և model', ai_url_ph: 'base URL - ex: http://localhost:11434 կամ https://api.ImAI.tld/v1',
    ai_model_ph: 'model - ex: llama3.1:8b', ai_key_ph: 'API բանալի (դատարկ թող լոկալ սերվերների համար)',
    ai_save: 'Պահպանել', ai_test: 'Թեստ կապը',
    ai_testing: 'թեստը ընթացքի մեջ…', ai_ok: 'OK - պատասխան՝ ',
    ai_fail: 'ՁԱԽՈՒՄ՝ ', ai_note: 'կոնֆիգը պահվում է լոկալ՝ data/ai.json - չի ուղարկվում ոչ մի տեղ, միայն քո տեղադրած endpoint-ին',
    ch_ph: 'root@c2ff:~# հաղորդագրություն վերլուծության գործակալին…', ch_send: 'Ուղարկել',
    ch_empty: 'Ալիքը բաց է. մուտքագրիր այստեղ, մոնիտորը միանգամից արթնացնում է ինձ.', ft: '100% լոկալ - դետերմինիստական զոնդեր, առանց token ոչ էլ արտաքին կախվածությունների - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ԱԿՏԻՎ՝ լոկալ ցիկլեր 30 րոպեն մեկ, 0 token.', to_fl_pa: 'FLEET ԴԱԴԱՐ - վերսկսի, երբ ուզես.',
    to_fl_cy: 'Անմիջապես ցիկլ գործարկված է (բյուջե 60 req).', to_launch: '[GO] մոդ {m} (CWE {c}) {p}-ում - լոկալ ցիկլ գործարկված է',
    to_ai_ok: 'կոնֆիգը պահված է', to_ai_no: 'պահպանումը ձախողվեց',
    to_ai_no_cfg: 'ԱԻ-ն կոնֆիգուրացված չէ - կարգավորիր ԱԻ թաբում', to_ai_head: 'ՎԵՐԼՈՒԾՈՒԹՅՈՒՆ ԱԻ',
    to_ai_bad: 'ԱԻ ՎԵՐԼՈՒԾՈՒԹՅՈՒՆ ձախողված', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'ԱԻ',
    w_launch: '⚡ ԳՈՐԾԱՐԿՈՒՄ', navar: 'Արսենալ',
    ar_h2: 'ԱՐՍԵՆԱԼ - CVE, EPSS և էքսպլոիտներ հայտնաբերված մակերեսին', ar_sync: 'SYNC ԲԱԶԱՆԵՐ',
    ar_btn: 'ՔԱՅԼԵՐ', ar_exec: 'EXEC',
    ar_none: 'քայլեր չկան. նախ գործարկիր RECON, հետո SYNC՝ KEV/EPSS բեռնելու համար', ar_loading: 'բազաների ամփոփումը բեռնվում է...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'դեմո ծրագիր - սկանավորում չկա: ստեղծիր քո ծրագիրը', pip_noprog: 'ծրագիր չկա: ստեղծիր քոնը Ծրագրեր ներդիպում',
    pip_next: 'հաջորդ քայլը:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  az: {
    pl_title: 'İş planı', pl_empty: 'hələ plan yoxdur: yuxarıdakı kartda RECON işə sal, hipotezlər burada düşür (statuslar saxlanılır)',
    pl_run: 'İşə sal', pl_reflect: 'canary əks olunub',
    st_do: 'ediləcək', st_test: 'yoxlanıldı',
    st_signal: 'siqnal', st_valid: 'etibarlı',
    st_void: 'heç nə', atk_btn: 'ATTACK',
    atk_start: 'səthə hücum: endpoints, aşkar edilmiş docs, JWT, sirrlər...', atk_fail: 'hücum mümkün deyil: əvvəlcə RECON işə sal',
    atk_none: 'siqnal yoxdur', atk_findings: 'namizədlər',
    atk_done: 'ATTACK: {n} namizəd P1/P2 sübut ilə findings-ə əlavə edildi', atk_empty: 'hələ hücum yoxdur: RECON işə sal, sonra ATTACK - req/res sübutlu namizədlər burada düşür',
    navh: 'HUNT', h2hunt: 'HUNT - real səth və sübutlar',
    h_ready: 'hazır', h_empty: 'məlum səth yoxdur: səhifələri, API endpoint-lərini, parametrləri, JS paketlərini və subdomenləri xəritələmək üçün RECON işə sal',
    h_fnd: 'Proqramın findings-ləri', h_nofnd: 'bu proqramda findings yoxdur',
    rc_btn: 'RECON', rc_start: 'səthin recon-u davam edir: səhifələr, JS paketləri, endpoint-lər, parametrlər...',
    rc_done: 'səth xəritələndi: endpoint-lər, parametrlər və subdomenlər proqram kartında sıralanıb', rc_fail: 'recon alınmadı: host əlçatmazdır və ya scope boşdur',
    rc_surface: 'səth:', snd_on: 'SƏS: ON',
    snd_off: 'SƏS: OFF', snd_ok: 'interfeys səsləri aktivdir - kitabxana: klik, tab, kopyalama, xəbərdarlıqlar',
    snd_stop: 'tam səssizlik aktivdir: C2FF səsi artıq olmayacaq', amb_on: 'AMBIENT: ON',
    amb_off: 'AMBIENT: OFF', amb_ok: 'canlı ambient - ton ailələr arasında yumşaq sürüşür (yaşıl, mavi, sarı...)',
    amb_stop: 'ambient ilkin yaşılda dondurulub', nt_on: 'NOTIFS: ON',
    nt_off: 'NOTIFS: OFF', nt_ok: 'brauzer bildirişləri aktivdir - P1 və P2-də pip',
    nt_denied: 'bildirişlər brauzer tərəfindən bloklanıb: sayt parametrlərində icazə ver', term_denied: 'terminal imtina edildi və ya əlçatmazdır: localhost tələb olunur, və ya admin kimi AÇIQ otaq',
    term_p: 'əsl bash - oxlarla tarixcə, Ctrl+C kəsir, Ctrl+D bağlayır', term_restart: 'Yenidən qur',
    navtrm: 'TERM', term_h2: 'Terminal - iş qabığı, birbaşa konsolda',
    fl_off: 'FLEET: DURUR', fl_paused: 'FLEET: PAUZADA',
    fl_active: 'FLEET: AKTİV ({n} sikl)', fl_last: 'son sikl',
    fl_none: 'hələ sikl yoxdur', fl_info: 'intervallar {i} dəqiqə, büdcə {b} req/sikl',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Qrup sessiyaları - birlikdə ov et, şəbəkə olmasa belə', tm_p: 'Birgə otaq aç: qrupun flota və findings-ləri görür, canlı olaraq çeşidləyə bilir. Sessiya üçün ayrı çat aşağıda. Girişin üç səviyyəsi: LOCAL (tək), LAN vasitəsilə ŞƏBƏKƏYƏ AÇ və DÜNYAYA AÇ - ictimai tunel (cloudflared quraşdırılıbsa) dəvət linkini istənilən şəbəkədən etibarlı edir, sənin maşın birbaşa oğurlanmir. Hər şey otaq açarına bağlıdır - hamını bir anda qovmaq üçün onu yenilə.',
    tm_handle: 'Sənin ləqəbin (ən çox 16 simvol)', tm_save_h: 'Seç',
    tm_room_ph: 'otaq adı (məs: c2ff-core)', tm_save: 'Tətbiq et',
    tm_on: 'OTAQ AÇIQ: {r} - {n} onlayn', tm_off: 'TEAM MODE SÖNDÜRÜLDÜ - yerli solo sessiya',
    tm_room: 'Otaq', tm_key: 'Otaq açarı',
    tm_regen: 'Açarı yenilə', tm_regen_ok: 'yeni açar yaradıldı - köhnə linklər ölüdür',
    tm_invite: 'Dəvət linki (komandana kopyala)', tm_copy: 'Kopyala',
    tm_copied: 'keçid buferinə kopyalandı', tm_members: 'Üzvlər',
    tm_nobody: 'hələ heç kim - linki komandana göndər', tm_you: '(sən)',
    tm_here: 'buradadır', tm_saved: 'ləqəb saxlanıldı',
    tm_no_handle: 'boş ləqəb', tm_cfg_ok: 'otaq yeniləndi',
    tm_cfg_no: 'baş tutmadı', tm_live: 'ŞƏBƏKƏYƏ AÇ',
    tm_shore: 'YERLİYƏ QAYIT', tm_need_on: 'əvvəlcə otağı aktivləşdir (ON)',
    tm_bind_lan: 'ŞƏBƏKƏ: {a}', tm_bind_lo: 'YERLİ: yalnız localhost',
    to_team_live: '[GO-LIVE] server şəbəkə girişi ilə yenidən işə salındı - LAN link göstərilir, 2 s-də yenidən qoşulma', to_team_shore: 'server yerli olaraq yenidən işə salındı (127.0.0.1)',
    tm_tun_open: 'DÜNYAYA AÇ (tunel)', tm_tun_close: 'TUNELİ BAĞLA',
    tm_tun_wait: 'ictimai tunel açılır (bir neçə saniyə)…', tm_tun_on: 'SESSİYA DÜNYAYA AÇIQ: {u} - dəvət linki hər yerdən işləyir, eyni şəbəkə lazım deyil',
    tm_tun_closed: 'tunel bağlandı - LAN/yerliyə qayıdış', tm_chat_empty: 'sessiya kanalı açıqdır - otaqdan olanlar burada bir-birini oxuyur',
    tm_chat_h2: 'Sessiya çatı', tm_msg_ph: 'sessiyaya mesaj…',
    tm_admin: 'admin', tm_guest: 'mehman',
    tm_kick: 'KICK', tm_kick_ok: 'üzv otaqdan çıxarıldı (kilidi açmaq üçün yenidən kliklə)',
    tm_role_ok: 'rol yeniləndi', tm_mic_on: 'MİKROFONU AKTİVLƏŞDİR',
    tm_mic_off: 'MİKROFONU SÖNDÜR', tm_mic_denied: 'mikrofon imtina edildi və ya əlçatmazdır: HTTPS tələb olunur (DÜNYA tuneli və ya localhost) və mikrofona icazə verilməlidir',
    navf: 'FLEET', navfd: 'FINDINGS',
    navp: 'Proqramlar', navai: 'AI',
    navc: 'Koordinasiya', st_runs: 'İşləmələr',
    st_beacons: 'Beacons aktiv', st_sig: 'Siqnallar',
    h2f: 'FLEET - bütün proqramlar, işləyən agentlər önce', h2fd: 'FINDINGS bazası - daimi etiketləmə (triage)',
    h2eng: 'FLEET mühərriki - tokenlərsiz yerli sikllar', h2prog: 'Proqramlar - scope, tələb olunan header, başlatma',
    h2new: 'Yeni proqram', h2ai: 'AI agent - 100% ixtiyari inteqrasiya',
    h2c: 'Koordinasiya - şəxsi kanal', fl_start: 'Başlat',
    fl_pause: 'Pauza', fl_cycle: 'Sikl indi',
    f_add: 'Əlavə et', f_none: 'hələ siqnal yoxdur',
    f_ph: 'əl ilə finding: endpoint + sübut + müdafiə olunan dərəcə…', st_sig_off: 'siqnal',
    st_sig_an: 'təhlil', st_sig_sub: 'təqdim olunub',
    st_sig_dup: 'dup', st_sig_ref: 'imtina edilib',
    st_sig_cl: 'bağlı', r_none: 'run aşkarlanmadı',
    r_live: '{n} İŞLƏYİR', r_done: 'TƏMAM',
    r_feed: '▽ axın ({n} ev)', r_close: '△ yığ',
    p_name_ph: 'Proqramın adı (məs: PayPal)', p_hdr_ph: 'tələb olunan tədqiqatçı header-i (məs: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domen1, domen2, …', p_save: 'Saxla',
    p_local: 'modul(lar), 100% yerli', ai_p: 'C2FF tamamilə AI olmadan işləyir: rejimlər yerli determinist zondlardır. Bu keçid yalnız <b>sənin</b> AI-nı (self-hosted və ya API) bir finding-i nöqtəli təhlil etmək üçün birləşdirir: FINDINGS-də düymə <span style="color:var(--green)">AI »</span>, cavab COORDINATION-da göstərilir. Bu tənzimləmə olmadan heç bir data sənin maşından çıxmır.',
    ai_off: 'söndürülmüş', ai_on: 'aktivləşdirilmiş',
    ai_st_off: 'AI SÖNDÜRÜLDÜ - framework 100% yerli işləyir onsuz', ai_st_ready: 'AI QOŞULUB: {p} · {m}',
    ai_st_inc: 'AI AKTİVDİR, ANCAQ NATAMAMDIR: baseURL və model tələb olunur', ai_url_ph: 'base URL - məs: http://localhost:11434 və ya https://api.MenimAI.tld/v1',
    ai_model_ph: 'model - məs: llama3.1:8b', ai_key_ph: 'API açarı (yerli serverlər üçün boş burax)',
    ai_save: 'Saxla', ai_test: 'Bağlantını yoxla',
    ai_testing: 'test davam edir…', ai_ok: 'OK - cavab: ',
    ai_fail: 'UĞURSUZ: ', ai_note: 'konfiq yerli şəkildə data/ai.json-da saxlanılır - heç vaxt başqa yerə göndərilmir, yalnız qoyduğun endpoint-ə',
    ch_ph: 'root@c2ff:~# mesaj təhlil agentinə…', ch_send: 'Göndər',
    ch_empty: 'Kanal açıqdır. Burada yaz, monitor dərhal məni oyaadır.', ft: '100% yerli - determinist zondlar, token və xarici asılılıq yoxdur - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE AKTİV: yerli sikllar hər 30 dəq-də, 0 token.', to_fl_pa: 'FLEET PAUZADA - istəndiyi anda davam et.',
    to_fl_cy: 'Sikl dərhal başladıldı (büdcə 60 req).', to_launch: '[GO] {m} rejimi (CWE {c}) {p} üzrə - yerli sikl başladıldı',
    to_ai_ok: 'konfiq saxlanıldı', to_ai_no: 'saxlama alınmadı',
    to_ai_no_cfg: 'AI tənzimlənməyib - AI tabında təyin et', to_ai_head: 'AI TƏHLİLİ',
    to_ai_bad: 'AI TƏHLİLİ alınmadı', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ BAŞLATMA', navar: 'Arsenal',
    ar_h2: 'ARSENAL - aşkarlanan səthdə CVE, EPSS və eksploitlər', ar_sync: 'SYNC BAZALAR',
    ar_btn: 'ADDIMLAR', ar_exec: 'EXEC',
    ar_none: 'addım yoxdur: əvvəlcə RECON işlət, sonra KEV/EPSS yükləmək üçün SYNC et', ar_loading: 'bazaların xülasəsi yüklənir...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demo proqram - skan yoxdur: öz proqramını yarat', pip_noprog: 'proqram yoxdur: Proqramlar bölməsində öz proqramını yarat',
    pip_next: 'növbəti mərhələ:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  kk: {
    pl_title: 'Жұмыс жоспары', pl_empty: 'әзірге жоспар жоқ: жоғарыдағы картаға RECON қос, болжамдар осында түседі (күйлер сақталады)',
    pl_run: 'Қосу', pl_reflect: 'canary көрсетілген',
    st_do: 'жасалатын', st_test: 'сыналған',
    st_signal: 'белгі', st_valid: 'расталған',
    st_void: 'ештеңе', atk_btn: 'ATTACK',
    atk_start: 'бетке шабуыл: endpoints, ашылған docs, JWT, құпиялар...', atk_fail: 'шабуыл мүмкін емес: алдымен RECON қос',
    atk_none: 'белгі жоқ', atk_findings: 'үміткерлер',
    atk_done: 'ATTACK: {n} үміткер P1/P2 дәлелімен findings-ке қосылды', atk_empty: 'әзірге шабуыл жоқ: RECON қос, кейін ATTACK - req/res дәлелі бар үміткерлер осында түседі',
    navh: 'HUNT', h2hunt: 'HUNT - нақты бет және дәлелдер',
    h_ready: 'дайын', h_empty: 'белгілі бет жоқ: беттерды, API endpoint-терін, параметрлерді, JS бандлдарды және сесдомендерді карталау үшін RECON қос',
    h_fnd: 'Бағдарламаның findings-тері', h_nofnd: 'осы бағдарламада findings жоқ',
    rc_btn: 'RECON', rc_start: 'беттің recon-ы жүріп жатыр: беттер, JS бандлдар, endpoints, параметрлер...',
    rc_done: 'бет картаға түсірілді: endpoints, параметрлер және сесдомендер бағдарлама картасында тізімде', rc_fail: 'recon сәтсіз: host қолжетімсіз немесе scope бос',
    rc_surface: 'бет:', snd_on: 'ДЫБЫС: ON',
    snd_off: 'ДЫБЫС: OFF', snd_ok: 'интерфейс дыбыстары қосулы - кітапхана: шерту, бет, көшіру, ескертулер',
    snd_stop: 'толық үнсіздік қосылды: C2FF дыбысы болмайды', amb_on: 'АТМОСФЕРА: ON',
    amb_off: 'АТМОСФЕРА: OFF', amb_ok: 'тірі атмосфера - түс отбасылар бойымен жай сырғанайды (жасыл, көк, сары...)',
    amb_stop: 'атмосфера бастапқы жасылда қатып қалды', nt_on: 'NOTIFS: ON',
    nt_off: 'NOTIFS: OFF', nt_ok: 'браузер хабарландырулары қосылған - P1 және P2-де дыбыс',
    nt_denied: 'хабарландырулар браузермен блокталған: сайт параметрлерінде рұқсат ет', term_denied: 'терминал қабылданбады немесе жоқ: localhost талап етіледі, немесе админ ретінде АШЫҚ бөлме',
    term_p: 'нақты bash - жебелермен тарих, Ctrl+C үзеді, Ctrl+D жабады', term_restart: 'Қайта қосу',
    navtrm: 'TERM', term_h2: 'Терминал - жұмыс қабыршағы, тікелей консольде',
    fl_off: 'FLEET: ТОҚТАТЫЛҒАН', fl_paused: 'FLEET: КҮТІРІЛГЕН',
    fl_active: 'FLEET: БЕЛСЕНДІ ({n} цикл)', fl_last: 'соңғы цикл',
    fl_none: 'әзірге цикл жоқ', fl_info: 'аралық {i} мин, бюджет {b} req/цикл',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Топтық сессиялар - бірге аң аулау, желі болмаса да', tm_p: 'Ортақ бөлме аш: топтың флот пен findings көреді, тіркелген қызметте іріктеуге болады. Сессияға арналған чат төменде. Кірудің үш деңгейі: LOCAL (жеке), LAN арқылы ЖЕЛІГЕ АШУ, және ӘЛЕМГЕ АШУ - қоғамдық туннель (cloudflared орнатылған болса) шақыру сілтемесін кез келген желіден жарамды етеді, сенің машинаң тікелей ашылмайды. Барлығы бөлме кілтіне байланысты - бәрін бір мезгілде қуып шығу үшін оны жаңарт.',
    tm_handle: 'Сенің лақап атың (ең көбі 16 белгі)', tm_save_h: 'Таңдау',
    tm_room_ph: 'бөлме аты (мыс: c2ff-core)', tm_save: 'Қолдану',
    tm_on: 'БӨЛМЕ АШЫҚ: {r} - {n} онлайн', tm_off: 'TEAM РЕЖИМІ ӨШІРУЛГЕН - жергілікті соло сессия',
    tm_room: 'Бөлме', tm_key: 'Бөлме кілті',
    tm_regen: 'Кілтті жаңарту', tm_regen_ok: 'жаңа кілт жасалды - ескі сілтемелер өлі',
    tm_invite: 'Шақыру сілтемесі (командаңа көшір)', tm_copy: 'Көшір',
    tm_copied: 'көшіру буферіне көшірілген', tm_members: 'Мүшелер',
    tm_nobody: 'әзірге ешкім жоқ - сілтемені командаңа жібер', tm_you: '(сен)',
    tm_here: 'осында', tm_saved: 'лақап аты сақталды',
    tm_no_handle: 'лақап аты бос', tm_cfg_ok: 'бөлме жаңартылды',
    tm_cfg_no: 'сәтсіз', tm_live: 'ЖЕЛІГЕ АШУ',
    tm_shore: 'ЖЕРГІЛІККЕ ҚАЙТУ', tm_need_on: 'алдымен бөлмені қосу (ON)',
    tm_bind_lan: 'ЖЕЛІ: {a}', tm_bind_lo: 'ЛОКАЛ: тек localhost',
    to_team_live: '[GO-LIVE] сервер желілік қолжетіммен қайта іске қосылды - LAN сілтеме көрсетілді, 2 с-та қайта жалғанады', to_team_shore: 'сервер жергілікті қайта іске қосылды (127.0.0.1)',
    tm_tun_open: 'ӘЛЕМГЕ АШУ (туннель)', tm_tun_close: 'ТУННЕЛЬДІ ЖАБУ',
    tm_tun_wait: 'қоғамдық туннель ашылып жатыр (бірнеше секунд)…', tm_tun_on: 'СЕССИЯ ӘЛЕМГЕ АШЫҚ: {u} - шақыру сілтемесі әр жерден жұмыс істейді, бір желі қажет емес',
    tm_tun_closed: 'туннель жабық - LAN/жергіліктіге қайту', tm_chat_empty: 'сессия арнасы ашық - бөлмедегілер осында бірін-бірі оқиды',
    tm_chat_h2: 'Сессия чаты', tm_msg_ph: 'сессияға хабарлама…',
    tm_admin: 'админ', tm_guest: 'қонақ',
    tm_kick: 'KICK', tm_kick_ok: 'мүше бөлмеден шығарылды (бұғаттан шығару үшін қайта шерт)',
    tm_role_ok: 'рөл жаңартылды', tm_mic_on: 'МИКРОФОНДЫ ҚОСУ',
    tm_mic_off: 'МИКРОФОНДЫ ӨШІРУ', tm_mic_denied: 'микрофон қабылданбады немесе жоқ: HTTPS талап етіледі (Әлем туннелі немесе localhost) және микрофонға рұқсат беру керек',
    navf: 'FLEET', navfd: 'FINDINGS',
    navp: 'Бағдарламалар', navai: 'ЖИ',
    navc: 'Координация', st_runs: 'Іске қосулар',
    st_beacons: 'Beacons белсенді', st_sig: 'Белгілер',
    h2f: 'FLEET - барлық бағдарламалар, жүріп жатқан агенттер алғаш', h2fd: 'FINDINGS базасы - тұрақты іріктеу белгілері',
    h2eng: 'FLEET қозғалтқышы - токенсіз жергілікті циклдар', h2prog: 'Бағдарламалар - scope, міндетті header, іске қосу',
    h2new: 'Жаңа бағдарлама', h2ai: 'ЖИ агент - 100% еркін интеграция',
    h2c: 'Координация - жеке арна', fl_start: 'Бастау',
    fl_pause: 'Күттіру', fl_cycle: 'Цикл қазір',
    f_add: 'Қосу', f_none: 'әзірге белгі жоқ',
    f_ph: 'қолмен finding: endpoint + дәлел + қорғаныш дәреже…', st_sig_off: 'белгі',
    st_sig_an: 'талдау', st_sig_sub: 'жіберілген',
    st_sig_dup: 'dup', st_sig_ref: 'қабылданбаған',
    st_sig_cl: 'жабық', r_none: 'run анықталмады',
    r_live: '{n} ЖҮРІП ЖАТЫР', r_done: 'АЯҚТАЛГАН',
    r_feed: '▽ ағын ({n} ev)', r_close: '△ бүктеу',
    p_name_ph: 'Бағдарлама атауы (мыс: PayPal)', p_hdr_ph: 'міндетті зерттеуші header-і (мыс: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: домен1, домен2, …', p_save: 'Сақтау',
    p_local: 'модульдер, 100% жергілікті', ai_p: 'C2FF AI-сыз толық жұмыс істейді: режимдер жергілікті детерминистік зондтар. Бұл қақпа тек <b>сенің</b> ЖИ-іңді (self-hosted немесе API) бір finding-қа талдау үшін қосады: FINDINGS-те түйме <span style="color:var(--green)">ЖИ »</span>, жауап COORDINATION-да көрінеді. Осы конфигурациясыз ешбір дерек сенің машинаңнан шықпайды.',
    ai_off: 'өшіл', ai_on: 'қосылған',
    ai_st_off: 'ЖИ ӨШІРУЛГЕН - фреймворк 100% жергілікті онысыз жұмыс істейді', ai_st_ready: 'ЖИ ҚОСЫЛҒАН: {p} · {m}',
    ai_st_inc: 'ЖИ ҚОСЫЛҒАН, БІРАҚ ТОЛЫҚ ЕМЕС: baseURL және model қажет', ai_url_ph: 'base URL - мыс: http://localhost:11434 немесе https://api.MeninZhI.tld/v1',
    ai_model_ph: 'model - мыс: llama3.1:8b', ai_key_ph: 'API кілт (жергілікті серверлерге бос қалдыр)',
    ai_save: 'Сақтау', ai_test: 'Байланысты сынау',
    ai_testing: 'сынақ жүріп жатыр…', ai_ok: 'OK - жауап: ',
    ai_fail: 'СӘТСІЗ: ', ai_note: 'конфиг жергілікті сақталады data/ai.json - ешқашан басқа жерге жіберілмейді, тек сен қойған endpoint-ке',
    ch_ph: 'root@c2ff:~# талдау агентіне хабарлама…', ch_send: 'Жіберу',
    ch_empty: 'Арна ашық. Мұнда жаз, монитор маған бірден оятады.', ft: '100% жергілікті - детерминистік зондтар, токен және сыртқы тәуелділік жоқ - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE БЕЛСЕНДІ: жергілікті циклдар әр 30 мин сайын, 0 токен.', to_fl_pa: 'FLEET КҮТІРІЛГЕН - қалаған кезде жалғастыр.',
    to_fl_cy: 'Цикл бірден іске қосылды (бюджет 60 req).', to_launch: '[GO] {m} режим (CWE {c}) {p} үшін - жергілікті цикл іске қосылды',
    to_ai_ok: 'конфиг сақталды', to_ai_no: 'сақтау сәтсіз болды',
    to_ai_no_cfg: 'ЖИ теңшелмеген - ЖИ қойындысында орнат', to_ai_head: 'ЖИ ТАЛДАУЫ',
    to_ai_bad: 'ЖИ ТАЛДАУЫ сәтсіз', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'ЖИ',
    w_launch: '⚡ ІСКЕ ҚОСУ', navar: 'Арсенал',
    ar_h2: 'АРСЕНАЛ - анықталған беттегі CVE, EPSS және эксплойттар', ar_sync: 'SYNC БАЗАЛАР',
    ar_btn: 'ЖҮРІСТЕР', ar_exec: 'EXEC',
    ar_none: 'жүріс жоқ: алдымен RECON қос, сосын KEV/EPSS жүктеу үшін SYNC жаса', ar_loading: 'базалардың түйіні жүктелуде...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'демо бағдарлама - сканерлеу жоқ: өз бағдарламаңды жаса', pip_noprog: 'бағдарлама жоқ: Бағдарламалар қойындысында өзіңдікін жаса',
    pip_next: 'келесі қадам:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  uz: {
    pl_title: 'Ish rejasi', pl_empty: 'hali reja yo\'q: yuqoridagi kartada RECON ishga tushir, gipotezalar bu yerga tushadi (holatlar saqlanadi)',
    pl_run: 'Ishga tushirish', pl_reflect: 'canary aks ettirilgan',
    st_do: 'qilinadigan', st_test: 'tekshirilgan',
    st_signal: 'signal', st_valid: 'tasdiqlangan',
    st_void: 'hech nima', atk_btn: 'ATTACK',
    atk_start: 'sirtga hujum: endpointlar, ochilgan docs, JWT, sirlar...', atk_fail: 'hujum mumkin emas: avval RECON ishga tushir',
    atk_none: 'signal yo\'q', atk_findings: 'nomzodlar',
    atk_done: 'ATTACK: {n} nomzod P1/P2 dalil bilan findings-ga kiritildi', atk_empty: 'hali hujum yo\'q: RECON ishga tushir, keyin ATTACK - req/res dalillangan nomzodlar bu yerga tushadi',
    navh: 'HUNT', h2hunt: 'HUNT - haqiqiy sirt va dalillar',
    h_ready: 'tayyor', h_empty: 'ma\'lum sirt yo\'q: sahifalarni, API endpointlarini, parametrlarni, JS paketlarni va subdomenlarni xaritalash uchun RECON ishga tushir',
    h_fnd: 'Dasturning findings-lari', h_nofnd: 'bu dasturda findings yo\'q',
    rc_btn: 'RECON', rc_start: 'sirtning recon-i davom etmoqda: sahifalar, JS paketlar, endpointlar, parametrlar...',
    rc_done: 'sirt xaritalandi: endpointlar, parametrlar va subdomenlar dastur kartasida ro\'yxatda', rc_fail: 'recon muvaffaqiyatsiz tugadi: host erishilmayapti yoki scope bo\'sh',
    rc_surface: 'sirt:', snd_on: 'OVOZ: ON',
    snd_off: 'OVOZ: OFF', snd_ok: 'interfeys tovushlari faol - kutubxona: bosish, tab, nusxalash, ogohlantirishlar',
    snd_stop: 'to\'liq jimlik yoqildi: boshqa C2FF tovushlari chiqmaydi', amb_on: 'ATMOSFERA: ON',
    amb_off: 'ATMOSFERA: OFF', amb_ok: 'tirik atmosfera - rang oilalar bo\'ylab yumshoq sirg\'aladi (yashil, ko\'k, sarg\'ish...)',
    amb_stop: 'atmosfera boshlang\'ich yashilda muzlatilgan', nt_on: 'NOTIFS: ON',
    nt_off: 'NOTIFS: OFF', nt_ok: 'brauzer bildirishnomalari yoqilgan - P1 va P2 da pip',
    nt_denied: 'bildirishnomalar brauzer tomonidan bloklangan: sayt sozlamalarida ruxsat ber', term_denied: 'terminal rad etildi yoki mavjud emas: localhost kerak, yoki admin sifatida OCHIQ xona',
    term_p: 'haqiqiy bash - strelkalar bilan tarix, Ctrl+C to\'xtatadi, Ctrl+D yopadi', term_restart: 'Qayta o\'rnatish',
    navtrm: 'TERM', term_h2: 'Terminal - ish qobig\'i, to\'g\'ridan-to\'g\'ri konsolda',
    fl_off: 'FLEET: TO\'XTATILGAN', fl_paused: 'FLEET: PAUZADA',
    fl_active: 'FLEET: FAOL ({n} sikl)', fl_last: 'oxirgi sikl',
    fl_none: 'hali sikl yo\'q', fl_info: 'intervallar {i} daqiqa, byudjet {b} req/sikl',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Guruh sessiyalari - birga ov qilish, tarmoqsiz ham shu', tm_p: 'Umumiy xona och: guruhing flotani va findingslarni ko\'radi, jonli holatda guruhlay oladi. Sessiya chati pastda alohida. Kirish uch darajali: LOCAL (yolg\'iz), LAN orqali TARMOQQA OCHIQ va DUNYOGA OCHIQ - ochiq tunel (cloudflared o\'rnatilgan bo\'lsa) taklif havolasini har qanday tarmoqdan ishlatadi, mashinangiz to\'g\'ridan-to\'g\'ri ochildi emas. Hammasi xona kalitiga bog\'liq - bir turtkida hammni chiqarish uchun uni qayta yarating.',
    tm_handle: 'Senning taxallus (eng ko\'pi 16 belgi)', tm_save_h: 'Tanlash',
    tm_room_ph: 'xona nomi (mas: c2ff-core)', tm_save: 'Qo\'llash',
    tm_on: 'XONA OCHIQ: {r} - {n} onlayn', tm_off: 'TEAM REJIMI O\'CHIRILGAN - mahalliy yolg\'iz sessiya',
    tm_room: 'Xona', tm_key: 'Xona kaliti',
    tm_regen: 'Kalitni yangilash', tm_regen_ok: 'yangi kalit yaratildi - eski havolalar o\'lik',
    tm_invite: 'Taklif havolasi (komandanga nusxalash)', tm_copy: 'Nusxalash',
    tm_copied: 'clipboard-ga nusxalandi', tm_members: 'A\'zolar',
    tm_nobody: 'hali hech kim - havolani komandanga yubor', tm_you: '(sen)',
    tm_here: 'shu yerda', tm_saved: 'taxallus saqlandi',
    tm_no_handle: 'bo\'sh taxallus', tm_cfg_ok: 'xona yangilandi',
    tm_cfg_no: 'amalga oshmadi', tm_live: 'TARMOQQA OCH',
    tm_shore: 'MAHALLIYGA QAYT', tm_need_on: 'avval xonani yoq (ON)',
    tm_bind_lan: 'TARMOQ: {a}', tm_bind_lo: 'MAHALLIY: faqat localhost',
    to_team_live: '[GO-LIVE] server tarmoq kirishi bilan qayta ishga tushirildi - LAN havolasi ko\'rsatilgan, 2 s ichida qayta ulanish', to_team_shore: 'server mahalliy ravishda qayta ishga tushirildi (127.0.0.1)',
    tm_tun_open: 'DUNYOGA OCH (tunnel)', tm_tun_close: 'TUNELNI YOP',
    tm_tun_wait: 'ommaviy tunel ochilmoqda (bir necha soniya)…', tm_tun_on: 'SESSIYA DUNYOGA OCHIQ: {u} - taklif havolasi har joydan ishlaydi, bir tarmoq shart emas',
    tm_tun_closed: 'tunnel yopildi - LAN/mahalliyga qaytish', tm_chat_empty: 'sessiya kanali ochiq - xonadagilar bu yerda bir-birlarini o\'qishadi',
    tm_chat_h2: 'Sessiya chati', tm_msg_ph: 'sessiyaga xabar…',
    tm_admin: 'admin', tm_guest: 'mehmon',
    tm_kick: 'KICK', tm_kick_ok: 'a\'zo xonadan chiqarildi (blokdan chiqarish uchun yana bosing)',
    tm_role_ok: 'rol yangilandi', tm_mic_on: 'MIKROFONNI YOQISH',
    tm_mic_off: 'MIKROFONNI O\'CHIRISH', tm_mic_denied: 'mikrofon rad etilgan yoki mavjud emas: HTTPS kerak (DUNYO tunneli yoki localhost) va mikrofonga ruxsat berilishi kerak',
    navf: 'FLEET', navfd: 'FINDINGS',
    navp: 'Dasturlar', navai: 'AI',
    navc: 'Koordinatsiya', st_runs: 'Ishga tushirishlar',
    st_beacons: 'Beacons faol', st_sig: 'Signallar',
    h2f: 'FLEET - barcha dasturlar, ishlayotgan agentlar oldin', h2fd: 'FINDINGS bazasi - doimiy guruhlash belgilari',
    h2eng: 'FLEET dvigateli - tokensiz mahalliy sikllar', h2prog: 'Dasturlar - scope, majburiy header, ishga tushirish',
    h2new: 'Yangi dastur', h2ai: 'AI agent - 100% ixtiyoriy integratsiya',
    h2c: 'Koordinatsiya - shaxsiy kanal', fl_start: 'Ishga tushirish',
    fl_pause: 'Pauza', fl_cycle: 'Sikl hozir',
    f_add: 'Qo\'shish', f_none: 'hali signal yo\'q',
    f_ph: 'qo\'lda finding: endpoint + dalil + himoya qilinadigan daraja…', st_sig_off: 'signal',
    st_sig_an: 'tahlil', st_sig_sub: 'yuborilgan',
    st_sig_dup: 'dup', st_sig_ref: 'rad etilgan',
    st_sig_cl: 'yopilgan', r_none: 'run aniqlanmadi',
    r_live: '{n} ISHLAYAPTI', r_done: 'BITTI',
    r_feed: '▽ oqim ({n} ev)', r_close: '△ yig\'',
    p_name_ph: 'Dastur nomi (mas: PayPal)', p_hdr_ph: 'majburiy tadqiqotchi header (mas: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domen1, domen2, …', p_save: 'Saqlash',
    p_local: 'modul(lar), 100% mahalliy', ai_p: 'C2FF sun\'iy intellektsiz to\'liq ishlaydi: rejimlar mahalliy deterministik zondlardir. Bu darvoza faqat <b>sening</b> AI (self-hosted yoki API) bitta findingni tahlil qilish uchun ulaydi: FINDINGS ichida tugma <span style="color:var(--green)">AI »</span>, javob COORDINATION-da ko\'rsatiladi. Bu sozlama bo\'lmasa hech qanday ma\'lumot mashinadan chiqmaydi.',
    ai_off: 'o\'chirilgan', ai_on: 'yoqilgan',
    ai_st_off: 'AI O\'CHIRILGAN - freymvork 100% mahalliy ishlaydi unsiz', ai_st_ready: 'AI ULANGAN: {p} · {m}',
    ai_st_inc: 'AI YOQILGAN, LEKIN TO\'LIQ EMAS: baseURL va model kerak', ai_url_ph: 'base URL - mas: http://localhost:11434 yoki https://api.MenimAI.tld/v1',
    ai_model_ph: 'model - mas: llama3.1:8b', ai_key_ph: 'API kalit (mahalliy serverlar uchun bo\'sh qoldir)',
    ai_save: 'Saqlash', ai_test: 'Ulanishni sinash',
    ai_testing: 'sinov davom etmoqda…', ai_ok: 'OK - javob: ',
    ai_fail: 'OMADSIZ: ', ai_note: 'konfig mahalliy saqlanadi data/ai.json - hech qachon boshqa yerga yuborilmaydi, faqat qo\'ygandingan endpointga',
    ch_ph: 'root@c2ff:~# xabar tahlil agentiga…', ch_send: 'Yuborish',
    ch_empty: 'Kanal ochiq. Bu yerga yoz, monitor menga bir zumda uyg\'otadi.', ft: '100% mahalliy - deterministik zondlar, token va tashqi kutubxona yo\'q - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE FAOL: har 30 daqiqada mahalliy sikllar, 0 token.', to_fl_pa: 'FLEET PAUZADA - xohlaganda davom et.',
    to_fl_cy: 'Sikl dastavval ishga tushirildi (byudjet 60 req).', to_launch: '[GO] {m} rejim (CWE {c}) {p} uchun - mahalliy sikl ishga tushirildi',
    to_ai_ok: 'konfig saqlandi', to_ai_no: 'saqlash muvaffaqiyatsiz',
    to_ai_no_cfg: 'AI sozlanmagan - AI tabida sozla', to_ai_head: 'AI TAHLILI',
    to_ai_bad: 'AI TAHLILI amalga oshmadi', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ ISHGA TUSHIRISH', navar: 'Arsenal',
    ar_h2: 'ARSENAL - aniqlangan sirtlarda CVE, EPSS va eksploytlar', ar_sync: 'SYNC BAZALAR',
    ar_btn: 'QADAMLAR', ar_exec: 'EXEC',
    ar_none: 'qadam yo\'q: avval RECON ishga tushir, so\'ng KEV/EPSS yuklash uchun SYNC qil', ar_loading: 'bazalar xulosasi yuklanmoqda...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demo dastur - skan yo\'q: o\'z dasturingni yarat', pip_noprog: 'dastur yo\'q: Dasturlar bo\'limida o\'z dasturingni yarat',
    pip_next: 'keyingi qadam:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  mn: {
    pl_title: 'Ажлын төлөвлөгөө', pl_empty: 'план одоогоор байхгүй: дээрх карт дээр RECON ажиллуул, таамаглалууд энд орж ирнэ (статусууд хадгалагдана)',
    pl_run: 'Ажиллуулах', pl_reflect: 'канар тусгал хүлээлээ',
    st_do: 'хийх', st_test: 'тестлэгдсэн',
    st_signal: 'сигнал', st_valid: 'баталгаажсан',
    st_void: 'юу ч байхгүй', atk_btn: 'ATTACK',
    atk_start: 'талбай руу довтолж байна: endpoints, задгай docs, JWT, нууцууд...', atk_fail: 'довтолгоо боломгүй: эхлээд RECON ажиллуул',
    atk_none: 'сигнал байхгүй', atk_findings: 'нэр дэвшигчид',
    atk_done: 'ATTACK: {n} P1/P2 нэр дэвшигч нотолгоотойгоор findings рүү оруулагдлаа', atk_empty: 'довтолгоо одоогоор байхгүй: эхлээд RECON, дараа нь ATTACK - req/res нотолгоо бүхий нэр дэвшигчид энд унана',
    navh: 'HUNT', h2hunt: 'HUNT - жинхэнэ талбай, нотолгоо',
    h_ready: 'бэлэн', h_empty: 'талбай одоогоор байхгүй: хуудсууд, API endpoints, параметрүүд, JS bundles, дэд домайнуудыг зураглахын тулд RECON ажиллуул',
    h_fnd: 'Программын олдворууд', h_nofnd: 'энэ программын олдвор байхгүй',
    rc_btn: 'RECON', rc_start: 'талбайн recon явж байна: хуудсууд, JS bundles, endpoints, параметрүүд...',
    rc_done: 'талбай зураглагдлаа: endpoints, параметрүүд, дэд домайнууд программын картонд жагсаалтлав', rc_fail: 'recon бүтэлгүй: host холбогдохгүй эсвэл scope хоосон',
    rc_surface: 'талбай:', snd_on: 'ДУУ: ON',
    snd_off: 'ДУУ: OFF', snd_ok: 'интерфейсийн дуу идэвхтэй - сан: товч, таб, хуулбар, сэрэмжлүүлэг',
    snd_stop: 'бүрэн чимээгүйжүүлэлт идэвхтэй: C2FF-ийн дуу хэрэгсэхгүй', amb_on: 'АТМОСФЕР: ON',
    amb_off: 'АТМОСФЕР: OFF', amb_ok: 'амьд атмосфер - өнгө гэр бүлүүдээр (ногоон, цэнхэр, шар...) зөөлөн гулсана',
    amb_stop: 'атмосфер анхны ногоон дээр хөлдсөн', nt_on: 'МЕДЭЭ: ON',
    nt_off: 'МЕДЭЭ: OFF', nt_ok: 'хөтчийн мэдэгдэл идэвхжсэн - P1, P2 дээр бип',
    nt_denied: 'мэдэгдлийг хөтөч хаасан: сайтын тохиргооноос зөвшөөр', term_denied: 'терминал татгалзсан эсвэл боломжгүй: localhost шаардлагатай, эсвэл админ байхдаа НЭЭЛТТЭЙ өрөө',
    term_p: 'жинхэнэ bash - сумаар түүх, Ctrl+C тасалдана, Ctrl+D хаана', term_restart: 'Дахин эхлүүлэх',
    navtrm: 'TERM', term_h2: 'Терминал - ажлын shell, консол дотор шууд',
    fl_off: 'FLEET: ЗОГССОН', fl_paused: 'FLEET: ТҮР ЗОГССОН',
    fl_active: 'FLEET: ИДЭВХТЭЙ ({n} мөчлөг)', fl_last: 'сүүлийн мөчлөг',
    fl_none: 'мөчлөг одоогоор байхгүй', fl_info: 'завсарлага {i} мин, төсөв {b} req/мөчлөг',
    sub_ttl: 'command & control framework', navt: 'СЕАНС',
    tm_h2: 'Хамтарсан сеансууд - бүлгээрээ ан, сүлжээ байхгүй ч', tm_p: 'Хуваалцсан өрөө нээ: бүлэг чинь флот болон олдворуудыг харж, шууд triage хийж чадна. Доор зориулалтын сеанс чат. Хандалтын гурван түвшин: LOCAL (гүйц нэг цөм), СҮЛЖЭЭНД НЭЭХ-ээр LAN, ДЕЛХИЙНД НЭЭХ-ээр Ертөнц - олон нийтийн туннель (суулгасан бол cloudflared) урилгын холбоосыг дурын сүлжээнээс хүчинтэй болгодог, чиний машиныг шууд илчилсэнгүй. Бүх зүйл өрөөний түлхүүрээр хязгаарлагдана - бүгдийг нэг дор хөөхийн тулд түлхүүрийг дахин үүсгэ.',
    tm_handle: 'Чиний нэр (16 тэмдэгт хүртэл)', tm_save_h: 'Сонгох',
    tm_room_ph: 'өрөөний нэр (жишээ: c2ff-core)', tm_save: 'Хэрэгжүүлэх',
    tm_on: 'ӨРӨӨ НЭЭЛТТЭЙ: {r} - {n} онлайн', tm_off: 'БАГИЙН ГОРИМ ИДЭВХГҮЙ - локал ганцаарын сеанс',
    tm_room: 'Өрөө', tm_key: 'Өрөөний түлхүүр',
    tm_regen: 'Түлхүүр шинэчлэх', tm_regen_ok: 'шинэ түлхүүр үүсгэлээ - хуучин холбоосууд үхсэн',
    tm_invite: 'Урилгын холбоос (багтаа хуулах)', tm_copy: 'Хуулах',
    tm_copied: 'клипборд руу хуулагдлаа', tm_members: 'Гишүүд',
    tm_nobody: 'одоогоор хэн ч байхгүй - урилгын холбоосыг багт илгээ', tm_you: '(чи)',
    tm_here: 'байгаа', tm_saved: 'нэр хадгалагдлаа',
    tm_no_handle: 'нэр хоосон', tm_cfg_ok: 'өрөө шинэчлэгдлээ',
    tm_cfg_no: 'бүтэлгүйтэв', tm_live: 'СҮЛЖЭЭНД НЭЭХ',
    tm_shore: 'ЛОКАЛ БУЦАХ', tm_need_on: 'эхлээд өрөөг нээ (ON)',
    tm_bind_lan: 'СҮЛЖЭЭ: {a}', tm_bind_lo: 'ЛОКАЛ: зөвхөн localhost',
    to_team_live: '[GO-LIVE] сервер сүлжээний хандалттай дахин ажиллав - LAN холбоос харагдана, 2 с дотор дахин холбогдоно', to_team_shore: 'сервер локал горимд дахин ажиллав (127.0.0.1)',
    tm_tun_open: 'ДЕЛХИЙНД НЭЭХ (туннель)', tm_tun_close: 'ТУННЕЛЬ ХААХ',
    tm_tun_wait: 'олон нийтийн туннель нээгдэж байна (хэдэн секунд)…', tm_tun_on: 'СЕАНС ДЕЛХИЙНД НЭЭЛТТЭЙ: {u} - урилгын холбоос хаанаас ч ажиллана, ижил сүлжээ шаардлагагүй',
    tm_tun_closed: 'туннель хаагдлаа - LAN/локал руу буцав', tm_chat_empty: 'сеансын суваг нээлттэй - өрөөний гишүүд энд бие биеэ уншина',
    tm_chat_h2: 'Сеансын чат', tm_msg_ph: 'сеанс руу мессеж…',
    tm_admin: 'админ', tm_guest: 'зочин',
    tm_kick: 'KICK', tm_kick_ok: 'гишүүнийг өрөөнөөс хасав (дахин дарвал буцаана)',
    tm_role_ok: 'үүрэг шинэчлэгдлээ', tm_mic_on: 'МИКРОФОН ИДЭВХЖҮҮЛЭХ',
    tm_mic_off: 'МИКРОФОН ХААХ', tm_mic_denied: 'микрофон татгалзсан эсвэл хүртэхгүй: HTTPS шаардлагатай (ДЕЛХИЙ туннель эсвэл localhost), микро зөвшөөрсөн байх ёстой',
    navf: 'Флот', navfd: 'Олдвор',
    navp: 'Программууд', navai: 'ХИ',
    navc: 'Зохицол', st_runs: 'Гүйлтүүд',
    st_beacons: 'Идэвхтэй beacons', st_sig: 'Сигналууд',
    h2f: 'Флот - бүх программ, гүйж байгаа агент тэргүүнээ', h2fd: 'Олдворын сан - тогтмол triage тэмдэглэгээ',
    h2eng: 'Флотын хөдөлгүүр - token-гүй локал мөчлөг', h2prog: 'Программууд - scope, шаардлагатай header, эхлүүлэлт',
    h2new: 'Шинэ программ', h2ai: 'ХИ агент - бүрэн дурын нэгжлэг',
    h2c: 'Зохицол - хувийн суваг', fl_start: 'Эхлүүлэх',
    fl_pause: 'Түр зогсоох', fl_cycle: 'Одоо мөчлөг',
    f_add: 'Нэмэх', f_none: 'сигнал одоогоор байхгүй',
    f_ph: 'гар олдвор: endpoint + нотолгоо + зөвтгөгдөх severity…', st_sig_off: 'сигнал',
    st_sig_an: 'шинжилгээ', st_sig_sub: 'илгээсэн',
    st_sig_dup: 'давхар', st_sig_ref: 'татгалзсан',
    st_sig_cl: 'хаалттай', r_none: 'гүйлт илрүүлээгүй',
    r_live: '{n} ГҮЙЖ БАЙНА', r_done: 'ДУУСЛАА',
    r_feed: '▽ урсгал ({n} ev)', r_close: '△ эвхэх',
    p_name_ph: 'Программын нэр (жишээ: PayPal)', p_hdr_ph: 'шаардлагатай судлаачийн header (жишээ: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: домайн1, домайн2, …', p_save: 'Хадгалах',
    p_local: 'модуль(ууд), 100% локал', ai_p: 'C2FF нь ХИ-гүйгээр бүрэн ажиллана: горимууд тодорхой локал probes юм. Энэ гарц нь зөвхөн <b>чиний</b> ХИ (өөрөө хостолсон эсвэл API) -ийг нэг олдворын шинжилгээнд холбоход хэрэглэнэ: FINDINGS доторх <span style="color:var(--green)">ХИ »</span> товч, хариултыг COORDINATION-д харуулна. Энэ тохиргоогүйгээр ямар ч өгөгдөл чиний машинаас гарахгүй.',
    ai_off: 'идэвхгүй', ai_on: 'идэвхтэй',
    ai_st_off: 'ХИ ИДЭВХГҮЙ - framework түүнгүй 100% локал ажиллана', ai_st_ready: 'ХИ ХОЛБОГДСОН: {p} · {m}',
    ai_st_inc: 'ХИ ИДЭВХТЭЙ ГЭВЧ ДУТАГУЙ: baseURL болон model шаардлагатай', ai_url_ph: 'base URL - жишээ: http://localhost:11434 эсвэл https://api.MyAI.tld/v1',
    ai_model_ph: 'model - жишээ: llama3.1:8b', ai_key_ph: 'API түлхүүр (локал сервер байвал хоосон үлдээ)',
    ai_save: 'Хадгалах', ai_test: 'Холболт шалгах',
    ai_testing: 'шалгаж байна…', ai_ok: 'OK - хариулт: ',
    ai_fail: 'БУТАРЛАА: ', ai_note: 'тохиргоо data/ai.json дотор локал хадгалагдана - чи тавьсан endpoint-оос өөр зүйл рүү хэзээ ч илгээгдэхгүй',
    ch_ph: 'root@c2ff:~# шинжилгээний агент руу зурвас…', ch_send: 'Илгээх',
    ch_empty: 'Суваг нээлттэй. Энд бич, монитор намайг сэндэр буулгана.', ft: '100% локал - тодорхой probes, token болоод гадны хамааралгүй - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-ГОРИМ ИДЭВХТЭЙ: 30 мин тутамд локал мөчлөг, 0 token.', to_fl_pa: 'FLEET ТҮР ЗАОГСАН - хүссэн үедээ үргэлжлүүл.',
    to_fl_cy: 'Шуурхай мөчлөг эхэллээ (төсөв 60 req).', to_launch: '[GO] {m} горим (CWE {c}) {p} дээр - локал мөчлөг эхэллээ',
    to_ai_ok: 'тохиргоо хадгалагдлаа', to_ai_no: 'хадгалахад алдаа гарлаа',
    to_ai_no_cfg: 'ХИ тохируулагдаагүй - ХИ таб дээр тохируул', to_ai_head: 'ХИЫ ШИНЖИЛГЭЭ',
    to_ai_bad: 'ХИЫ ШИНЖИЛГЭЭ БҮТЭЛГҮЙТЭВ', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'ХИ',
    w_launch: '⚡ ЭХЛҮҮЛЭЛТ', navar: 'Арсенал',
    ar_h2: 'АРСЕНАЛ - илэрсэн гадаргуугийн CVE, EPSS, эксплойтууд', ar_sync: 'SYNC БАЗА',
    ar_btn: 'ХОДУУД', ar_exec: 'EXEC',
    ar_none: 'ход байхгүй: эхлээд RECON ажиллуул, дараа нь KEV/EPSS ачаалахын тулд SYNC ажиллуул', ar_loading: 'базуудын хураангуй ачигдаж байна...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'демо хөтөлбөр - скан хийхгүй: өөрийн хөтөлбөрөө үүсгэ', pip_noprog: 'хөтөлбөр байхгүй: Программууд таб дээр шинэ хөтөлбөр үүсгэ',
    pip_next: 'дараагийн шат:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  ne: {
    pl_title: 'कामको योजना', pl_empty: 'अझै योजना छैन: माथिको कार्डमा RECON चलाऊ, अनुमानहरू यहाँ आउँछन् (स्थितिहरू सुरक्षित रहन्छन्)',
    pl_run: 'चलाऊ', pl_reflect: 'क्यानारी प्रतिबिम्बित भयो',
    st_do: 'गर्नुपर्ने', st_test: 'जाँचिएको',
    st_signal: 'संकेत', st_valid: 'पुष्टि',
    st_void: 'केही छैन', atk_btn: 'ATTACK',
    atk_start: 'सतहमा आक्रमण: endpoints, खुला docs, JWT, गोप्य कुराहरू...', atk_fail: 'आक्रमण सम्भव छैन: पहिले RECON चलाऊ',
    atk_none: 'कुनै संकेत छैन', atk_findings: 'उम्मेदवारहरू',
    atk_done: 'ATTACK: {n} P1/P2 उम्मेदवारहरू प्रमाणसहित findings मा हालिए', atk_empty: 'अझै आक्रमण छैन: RECON चलाऊ अनि ATTACK - req/res प्रमाणसहितका उम्मेदवारहरू यहाँ आउँछन्',
    navh: 'HUNT', h2hunt: 'HUNT - वास्तविक सतह र प्रमाणहरू',
    h_ready: 'तयार', h_empty: 'अझै कुनै सतह छैन: पृष्ठ, API endpoints, प्यारामिटर, JS bundles र सबडोमेनहरू म्याप गर्न RECON चलाऊ',
    h_fnd: 'प्रोग्रामका फेलाहरू', h_nofnd: 'यो प्रोग्राममा कुनै फेला छैन',
    rc_btn: 'RECON', rc_start: 'सतहको recon चलिरहेको छ: पृष्ठ, JS bundles, endpoints, प्यारामिटरहरू...',
    rc_done: 'सतह म्याप भयो: endpoints, प्यारामिटर र सबडोमेनहरू प्रोग्राम कार्डमा सूचीबद्ध', rc_fail: 'recon असफल: host पुग्दैन वा scope खाली',
    rc_surface: 'सतह:', snd_on: 'ध्वनि: ON',
    snd_off: 'ध्वनि: OFF', snd_ok: 'इन्टरफेस ध्वनि चालू - लाइब्रेरी: क्लिक, ट्याब, कपी, सतर्कता',
    snd_stop: 'पूर्ण मूक सक्रिय: अब कुनै C2FF ध्वनि आउँदैन', amb_on: 'वातावरण: ON',
    amb_off: 'वातावरण: OFF', amb_ok: 'जीवन्त वातावरण - रङ परिवारहरूभर (हरियो, नीलो, पहेँलो...) बिस्तारै तैरिन्छ',
    amb_stop: 'वातावरण रोकिएर पहिलेकै हरियोमा खडा भयो', nt_on: 'सूचना: ON',
    nt_off: 'सूचना: OFF', nt_ok: 'ब्राउजर सूचना चालू - P1 र P2 मा बिप',
    nt_denied: 'ब्राउजरले सूचना रोक्यो: साइट सेटिङबाट अनुमति देऊ', term_denied: 'टर्मिनल निषेध वा अनुपलब्ध: localhost चाहिन्छ, वा एडमिनका रूपमा खुला कोठा',
    term_p: 'वास्तविक bash - तीरमाथि इतिहास, Ctrl+C ले रोक्छ, Ctrl+D ले बन्द गर्छ', term_restart: 'रिसेट',
    navtrm: 'TERM', term_h2: 'टर्मिनल - काम गर्ने shell, कन्सोलमै सिधै',
    fl_off: 'FLEET: रोकिएको', fl_paused: 'FLEET: ठहरिएको',
    fl_active: 'FLEET: सक्रिय ({n} चक्र)', fl_last: 'अन्तिम चक्र',
    fl_none: 'अझै कुनै चक्र छैन', fl_info: 'अन्तराल {i} मिनेट, बजेट {b} req/चक्र',
    sub_ttl: 'command & control framework', navt: 'सत्र',
    tm_h2: 'समूह सत्रहरू - नेटवर्क बाहिर पनि सँगै शिकार', tm_p: 'साझा कोठा खोल: तिम्रो समूहले फ्लीट, फेलाहरू देख्छ र लाइभ triage गर्न सक्छ। तल समर्पित सत्र च्याट। पहुँचका तीन स्तर: LOCAL (एक्लो), नेटवर्कमा खोलेर LAN, र संसारमा खोलेर WORLD - सार्वजनिक टनेल (स्थापित भए cloudflared) ले निमन्त्रणा लिङ्कलाई कुनै पनि नेटवर्कबाट मान्य बनाउँछ, तिम्रो मेसिन सिधै देखिँदैन। सबै कुरा कोठाको कुञ्जीले नियन्त्रित हुन्छ - एकै पटक सबैलाई निकाल्न कुञ्जी पुनः बनाऊ।',
    tm_handle: 'तिम्रो नाम (अधिकतम 16 अक्षर)', tm_save_h: 'सेट गर्नुहोस्',
    tm_room_ph: 'कोठाको नाम (जस्तै: c2ff-core)', tm_save: 'लागू गर्नुहोस्',
    tm_on: 'कोठा खुला: {r} - {n} अनलाइन', tm_off: 'TEAM मोड बन्द - स्थानीय एक्लो सत्र',
    tm_room: 'कोठा', tm_key: 'कोठा कुञ्जी',
    tm_regen: 'कुञ्जी पुनः बनाउनुहोस्', tm_regen_ok: 'नयाँ कुञ्जी बन्यो - पुराना लिङ्कहरू मरे',
    tm_invite: 'निमन्त्रणा लिङ्क (टिमलाई कपी गर्ने)', tm_copy: 'कपी',
    tm_copied: 'क्लिपबोर्डमा कपी भयो', tm_members: 'सदस्यहरू',
    tm_nobody: 'अझै कोही छैन - टिमलाई लिङ्क पठाऊ', tm_you: '(तिमी)',
    tm_here: 'उपस्थित', tm_saved: 'नाम सेभ भयो',
    tm_no_handle: 'नाम खाली', tm_cfg_ok: 'कोठा अद्यावधिक भयो',
    tm_cfg_no: 'असफल', tm_live: 'नेटवर्कमा खोल्नुहोस्',
    tm_shore: 'स्थानीयमा फर्कनुहोस्', tm_need_on: 'पहिले कोठा चालू गर (ON)',
    tm_bind_lan: 'नेटवर्क: {a}', tm_bind_lo: 'LOCAL: localhost मात्र',
    to_team_live: '[GO-LIVE] सर्भर नेटवर्क पहुँचसहित पुनः सुरु - LAN लिङ्क देखिन्छ, 2 सेकेन्डमा फेरि जोडिन्छ', to_team_shore: 'सर्भर स्थानीयमा पुनः सुरु भयो (127.0.0.1)',
    tm_tun_open: 'संसारमा खोल्नुहोस् (टनेल)', tm_tun_close: 'टनेल बन्द गर्नुहोस्',
    tm_tun_wait: 'सार्वजनिक टनेल सुरु हुँदैछ (केही सेकेन्ड)…', tm_tun_on: 'सत्र संसारभर खुला: {u} - निमन्त्रणा लिङ्क जहाँबाट पनि चल्छ, एउटै नेटवर्क चाहिँदैन',
    tm_tun_closed: 'टनेल बन्द - LAN/स्थानीयमा फर्कियो', tm_chat_empty: 'सत्र च्यानल खुला - कोठाका सदस्यहरू यहाँ एकअर्कालाई पढ्छन्',
    tm_chat_h2: 'सत्र च्याट', tm_msg_ph: 'सत्रतर्फ सन्देश…',
    tm_admin: 'एडमिन', tm_guest: 'अतिथि',
    tm_kick: 'KICK', tm_kick_ok: 'सदस्य कोठाबाट हटाइयो (फेरि क्लिक गरे खुल्छ)',
    tm_role_ok: 'भूमिका अद्यावधिक भयो', tm_mic_on: 'माइक्रोफोन चालू गर्नुहोस्',
    tm_mic_off: 'माइक्रोफोन बन्द गर्नुहोस्', tm_mic_denied: 'माइक्रोफोन निषेध वा अनुपलब्ध: HTTPS चाहिन्छ (WORLD टनेल वा localhost) र माइक्रोफोन स्वीकृत गर्नुपर्छ',
    navf: 'फ्लीट', navfd: 'फेला',
    navp: 'प्रोग्रामहरू', navai: 'AI',
    navc: 'समन्वय', st_runs: 'दौडहरू',
    st_beacons: 'सक्रिय beacons', st_sig: 'संकेतहरू',
    h2f: 'फ्लीट - सबै प्रोग्राम, दौडिरहेका एजेन्टपहिला', h2fd: 'फेला डेटाबेस - दिगो triage चिनो',
    h2eng: 'फ्लीट इन्जिन - टोकनविहीन स्थानीय चक्र', h2prog: 'प्रोग्रामहरू - scope, आवश्यक हेडर, लन्च',
    h2new: 'नयाँ प्रोग्राम', h2ai: 'AI एजेन्ट - पूर्ण रूपमा ऐच्छिक एकीकरण',
    h2c: 'समन्वय - निजी च्यानल', fl_start: 'सुरु',
    fl_pause: 'पज', fl_cycle: 'अहिले चक्र',
    f_add: 'थप्नुहोस्', f_none: 'अझै कुनै संकेत छैन',
    f_ph: 'हस्तगत फेला: endpoint + प्रमाण + रक्षणीय severity…', st_sig_off: 'संकेत',
    st_sig_an: 'विश्लेषण', st_sig_sub: 'पेश',
    st_sig_dup: 'डुप्लिकेट', st_sig_ref: 'अस्वीकृत',
    st_sig_cl: 'बन्द', r_none: 'कुनै दौड पत्ता लागेन',
    r_live: '{n} दौडिरहेका', r_done: 'समाप्त',
    r_feed: '▽ फिड ({n} ev)', r_close: '△ खुम्च्याऊ',
    p_name_ph: 'प्रोग्रामको नाम (जस्तै: PayPal)', p_hdr_ph: 'आवश्यक अनुसन्धानकर्ता हेडर (जस्तै: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: डोमेन1, डोमेन2, …', p_save: 'सेभ गर्नुहोस्',
    p_local: 'मोड्युल(हरू), 100% स्थानीय', ai_p: 'C2FF AI बिना नै पूर्ण चल्छ: मोडहरू निश्चित स्थानीय प्रोबहरू हुन्। यो गेटवे एउटा फेलालाई अन मागमा विश्लेषण गर्न <b>तिम्रो</b> AI (स्व-होस्टेड वा API) जोड्न मात्र हो: FINDINGS भित्रको <span style="color:var(--green)">AI »</span> बटन, जवाफ COORDINATION मा देखिन्छ। यो सेटअपबिना कुनै डेटा तिम्रो मेसिनबाट बाहिर जाँदैन।',
    ai_off: 'बन्द', ai_on: 'चालू',
    ai_st_off: 'AI बन्द - फ्रेमवर्क यसबिना 100% स्थानीय चल्छ', ai_st_ready: 'AI जोडियो: {p} · {m}',
    ai_st_inc: 'AI चालू तर अपूर्ण: baseURL र model आवश्यक', ai_url_ph: 'base URL - जस्तै: http://localhost:11434 वा https://api.MyAI.tld/v1',
    ai_model_ph: 'model - जस्तै: llama3.1:8b', ai_key_ph: 'API कुञ्जी (स्थानीय सर्भरमा खाली छोड्नुहोस्)',
    ai_save: 'सेभ गर्नुहोस्', ai_test: 'जडान जाँच्नुहोस्',
    ai_testing: 'जाँच हुँदै…', ai_ok: 'ठीक - जवाफ: ',
    ai_fail: 'असफल: ', ai_note: 'कन्फिग data/ai.json मा स्थानीय रूपमा सेभ - तिमीले राखेको endpoint बाहेक अन्यत्र कहिल्यै पठाइँदैन',
    ch_ph: 'root@c2ff:~# विश्लेषण एजेन्टलाई सन्देश…', ch_send: 'पठाउनुहोस्',
    ch_empty: 'च्यानल खुला छ। यहाँ लेख, मोनिटरले मलाई तत्कालै ब्यूँझाउँछ।', ft: '100% स्थानीय - निश्चित प्रोब, टोकन वा बाह्य निर्भरता बिना - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-मोड सक्रिय: 30 मिनेटमा स्थानीय चक्र, 0 टोकन।', to_fl_pa: 'FLEET PAUSE मा - जहिले चाहे पुनः सुरु गर।',
    to_fl_cy: 'तत्काल चक्र सुरु गरियो (बजेट 60 req)।', to_launch: '[GO] {m} मोड (CWE {c}) {p} मा - स्थानीय चक्र सुरु',
    to_ai_ok: 'कन्फिग सेभ भयो', to_ai_no: 'सेभ असफल',
    to_ai_no_cfg: 'AI कन्फिगर छैन - AI ट्याबमा मिलाऊ', to_ai_head: 'AI विश्लेषण',
    to_ai_bad: 'AI विश्लेषण असफल', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ सुरु', navar: 'आर्सेनल',
    ar_h2: 'आर्सेनल - पत्ता लागेको सतहमा CVE, EPSS र एक्सप्लोइट', ar_sync: 'SYNC डाटाबेस',
    ar_btn: 'चाल', ar_exec: 'EXEC',
    ar_none: 'कुनै चाल छैन: पहिले RECON चलाउनुहोस्, त्यसपछि KEV/EPSS लोड गर्न SYNC चलाउनुहोस्', ar_loading: 'डाटाबेसको सारांश लोड हुँदै...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'डेमो कार्यक्रम - स्क्यान छैन: आफ्नै कार्यक्रम बनाउनुहोस्', pip_noprog: 'कुनै कार्यक्रम छैन: कार्यक्रमहरू ट्याबमा आफ्नै बनाउनुहोस्',
    pip_next: 'अर्को चरण:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  si: {
    pl_title: 'වැඩ සැලැස්ම', pl_empty: 'තවම සැලැස්මක් නැහැ: ඉහත කාඩ්පතේ RECON ධාවනය කරන්න, උපකල්පන මෙතනට එනවා (තත්වයන් රැඳේ)',
    pl_run: 'ධාවනය කරන්න', pl_reflect: 'කැනරි පිළිබිඹු විය',
    st_do: 'කළ යුතු', st_test: 'පරීක්ෂිත',
    st_signal: 'සංඥාව', st_valid: 'තහවුරු',
    st_void: 'කිසිවක් නැහැ', atk_btn: 'ATTACK',
    atk_start: 'මතුපිටට ප්‍රහාරය: endpoints, හෙළි කළ docs, JWT, රහස්...', atk_fail: 'ප්‍රහාරය විය නොහැක: පළමුව RECON ධාවනය කරන්න',
    atk_none: 'සංඥා නැහැ', atk_findings: 'අපේක්ෂකයෝ',
    atk_done: 'ATTACK: {n} P1/P2 අපේක්ෂකයෝ සාක්ෂි සමඟ findings වෙත ඇතුළු විය', atk_empty: 'තවම ප්‍රහාර නැහැ: RECON ධාවනය කර ඉන් පසු ATTACK - req/res සාක්ෂි සමඟ අපේක්ෂකයෝ මෙතනට එනවා',
    navh: 'HUNT', h2hunt: 'HUNT - සැබෑ මතුපිට සහ සාක්ෂි',
    h_ready: 'සූදානම්', h_empty: 'තවම මතුපිටක් නැහැ: පිටු, API endpoints, params, JS bundles සහ subdomains සිතියම් කිරීමට RECON ධාවනය කරන්න',
    h_fnd: 'මෙහෙවරේ findings', h_nofnd: 'මේ මෙහෙවරට findings නැහැ',
    rc_btn: 'RECON', rc_start: 'මතුපිටේ recon ධාවනය වෙමින්: පිටු, JS bundles, endpoints, params...',
    rc_done: 'මතුපිට සිතියම් විය: endpoints, params සහ subdomains මෙහෙවර කාඩ්පතේ ලැයිස්තුගත විය', rc_fail: 'recon අසාර්ථක: host ළඟා විය නොහැක හෝ scope හිස්',
    rc_surface: 'මතුපිට:', snd_on: 'හඬ: ON',
    snd_off: 'හඬ: OFF', snd_ok: 'අතුරුමුහුණත හඬ සක්‍රිය - පුස්තකාලය: ක්ලික්, ටැබ්, පිටපත්, අඟවන්නන්',
    snd_stop: 'සම්පූර්ණ නිශ්ශබ්දකරණය සක්‍රිය කළා: තව C2FF හඬ නැහැ', amb_on: 'වාතාවරණය: ON',
    amb_off: 'වාතාවරණය: OFF', amb_ok: 'සජීවී වාතාවරණය - පාට පවුල්වලින් (කොළ, නිල්, කහ...) ලිහිසියේ මෘදුව ලිස්සයි',
    amb_stop: 'වාතාවරණය මුල් කොළම පාටේ හිම විය', nt_on: 'දැනුම්දීම්: ON',
    nt_off: 'දැනුම්දීම්: OFF', nt_ok: 'බ්‍රව්සර දැනුම්දීම් සක්‍රිය - P1 සහ P2 දී බීප්',
    nt_denied: 'බ්‍රව්සරයේ දැනුම්දීම් අවහිරයි: අඩවි සැකසුම්වල ඉඩ දෙන්න', term_denied: 'ටර්මිනල් ප්‍රතික්ෂේප හෝ නොතිබුණි: localhost අවශ්‍යයි, නැතහොත් පරිපාලක ලෙස විවෘත කාමරයක්',
    term_p: 'සැබෑ bash - ඊතිරින ඉතිහාසය, Ctrl+C නවතී, Ctrl+D වසයි', term_restart: 'නැවත සකසන්න',
    navtrm: 'TERM', term_h2: 'ටර්මිනල් - වැඩ shell, කොන්සෝලයේම කෙලින්ම',
    fl_off: 'FLEET: නවතියි', fl_paused: 'FLEET: විරාමයේ',
    fl_active: 'FLEET: සක්‍රිය ({n} චක්‍ර)', fl_last: 'අවසන් චක්‍රය',
    fl_none: 'තවම චක්‍ර නැහැ', fl_info: 'පරතරය {i} මිනි, අයවැය {b} req/චක්‍රය',
    sub_ttl: 'command & control framework', navt: 'සැසිය',
    tm_h2: 'කණ්ඩායම් සැසි - ජාලයෙන් පිට වුණත් එකට දඩයම්', tm_p: 'බෙදාගත් කාමරයක් විවෘත කරන්න: ඔයාගේ කණ්ඩායමට බලඇණිය, findings පෙනේ, සජීවීව triage කළ හැක. පහළ සැසි චැට් ඇත. ප්‍රවේශ මට්ටම් තුනක්: LOCAL (තනිව), ජාලයට විවෘත කිරීමෙන් LAN, ලෝකයට විවෘත කිරීමෙන් WORLD - ප්‍රසිද්ධ උමං (ස්ථාපිත නම් cloudflared) නම් ආරාධනා සබැඳිය ඕනෑම ජාලයකින් වලංගු, ඔයාගේ යන්ත්‍රය කෙලින්ම හෙළි නොවේ. සියල්ල කාමර යතුරෙන් පාලන වේ - එකම විටෙක හැමෝවම ඉවත් කිරීමට යතුර නැවත උත්පාදනය කරන්න.',
    tm_handle: 'ඔයාගේ නම (උපරිම අකුරු 16)', tm_save_h: 'සකසන්න',
    tm_room_ph: 'කාමරයේ නම (උදා: c2ff-core)', tm_save: 'අදාළ කරන්න',
    tm_on: 'කාමරය විවෘත: {r} - {n} සම්බන්ධයි', tm_off: 'TEAM ප්‍රකාරය අක්‍රිය - දේශීය තනි සැසිය',
    tm_room: 'කාමරය', tm_key: 'කාමර යතුර',
    tm_regen: 'යතුර නැවත උත්පාදනය', tm_regen_ok: 'නව යතුර උත්පාදනය විය - පරණ සබැඳි මිය ගියා',
    tm_invite: 'ආරාධනා සබැඳිය (කණ්ඩායමට පිටපත් කරන්න)', tm_copy: 'පිටපත්',
    tm_copied: 'ක්ලිප්බෝඩ් වෙත පිටපත් විය', tm_members: 'සාමාජිකයෝ',
    tm_nobody: 'තවම කිසිවෙක් නැහැ - කණ්ඩායමට සබැඳිය යවන්න', tm_you: '(ඔයා)',
    tm_here: 'සිටියි', tm_saved: 'නම සුරැකිණි',
    tm_no_handle: 'නම හිස්', tm_cfg_ok: 'කාමරය යාවත්කාලීන විය',
    tm_cfg_no: 'අසාර්ථකයි', tm_live: 'ජාලයට විවෘත කරන්න',
    tm_shore: 'දේශීයට ආපසු', tm_need_on: 'පළමුව කාමරය සක්‍රිය කරන්න (ON)',
    tm_bind_lan: 'ජාලය: {a}', tm_bind_lo: 'LOCAL: localhost පමණයි',
    to_team_live: '[GO-LIVE] සර්වරය ජාල ප්‍රවේශයත් සමඟ නැවත ඇරණි - LAN සබැඳිය පෙනේ, තත්පර 2 න් නැවත සම්බන්ධ වෙන්න', to_team_shore: 'සර්වරය දේශීයව නැවත ඇරණි (127.0.0.1)',
    tm_tun_open: 'ලෝකයට විවෘත කරන්න (උමං මාර්ගය)', tm_tun_close: 'උමං මාර්ගය වසන්න',
    tm_tun_wait: 'ප්‍රසිද්ධ උමං මාර්ගය ඇරෙමින් (තත්පර කිහිපයක්)…', tm_tun_on: 'සැසිය ලෝකයට විවෘත: {u} - ආරාධනා සබැඳිය ඕනෑම තැනකින් වැඩ කරයි, එකම ජාලය අවශ්‍ය නැහැ',
    tm_tun_closed: 'උමං මාර්ගය වැසුණි - LAN/දේශීයට පසු', tm_chat_empty: 'සැසි නාලිකාව විවෘත - කාමර සාමාජිකයෝ මෙතන එකිනෙකා කියවති',
    tm_chat_h2: 'සැසි චැට්', tm_msg_ph: 'සැසියට පණිවිඩයක්…',
    tm_admin: 'පරිපාලක', tm_guest: 'අමුත්තා',
    tm_kick: 'KICK', tm_kick_ok: 'සාමාජිකයා කාමරයෙන් ඉවත් විය (නැවත ක්ලික් කිරීමෙන් අගුලු විවේ)',
    tm_role_ok: 'භූමිකාව යාවත්කාලීන විය', tm_mic_on: 'මයික් සක්‍රිය කරන්න',
    tm_mic_off: 'මයික් නිශ්ශබ්ද කරන්න', tm_mic_denied: 'මයික් ප්‍රතික්ෂේප හෝ නොමැත: HTTPS අවශ්‍ය (WORLD උමං මාර්ගය හෝ localhost) නැතහොත් මයික් අවසර දිය යුතුය',
    navf: 'බලකාය', navfd: 'පරීක්ෂණ',
    navp: 'මෙහෙවර්', navai: 'AI',
    navc: 'සමායෝජනය', st_runs: 'ධාවන',
    st_beacons: 'සක්‍රිය beacons', st_sig: 'සංඥා',
    h2f: 'බලකාය - සියලු මෙහෙවර්, ධාවන නියෝජිතයෝ ඉහළින්', h2fd: 'පරීක්ෂණ දත්තසමුදාය - ස්ථිර triage ලේබල්',
    h2eng: 'බලකාය එන්ජිම - token නොමැති දේශීය චක්‍ර', h2prog: 'මෙහෙවර් - scope, අවශ්‍ය header, එළිදැක්වීම',
    h2new: 'නව මෙහෙවර', h2ai: 'AI නියෝජිතයා - සම්පූර්ණයෙන් විකල්ප ඒකාබද්ධතාව',
    h2c: 'සමායෝජනය - පෞද්ගලික නාලිකාව', fl_start: 'ඇරඹන්න',
    fl_pause: 'විරාමය', fl_cycle: 'දැන් චක්‍රය',
    f_add: 'එකතු කරන්න', f_none: 'තවම සංඥා නැහැ',
    f_ph: 'අතින් පරීක්ෂණය: endpoint + සාක්ෂි + ආරක්ෂිත severity…', st_sig_off: 'සංඥා',
    st_sig_an: 'විශ්ලේෂණ', st_sig_sub: 'යොමු කළේය',
    st_sig_dup: 'ද්විත්වය', st_sig_ref: 'ප්‍රතික්ෂේපයි',
    st_sig_cl: 'වසා ඇත', r_none: 'ධාවනයක් හමු වුණේ නැහැ',
    r_live: '{n} ධාවනය වෙමින්', r_done: 'ඉවරයි',
    r_feed: '▽ ප්‍රවාහය ({n} ev)', r_close: '△ හැකිළිය',
    p_name_ph: 'මෙහෙවරේ නම (උදා: PayPal)', p_hdr_ph: 'අවශ්‍ය පර්යේෂක header (උදා: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: වසම1, වසම2, …', p_save: 'සුරකින්න',
    p_local: 'මොඩියුල(ස්), 100% දේශීය', ai_p: 'C2FF AI නැතුවම සම්පූර්ණයෙන් ක්‍රියා කරයි: ප්‍රකාර නිශ්චිත දේශීය ප්‍රෝබෝ වේ. මෙම දොරටුව <b>ඔයාගේ</b> AI (self-hosted හෝ API) එකක් එක් පරීක්ෂණයක් ඉල්ලුම මත විශ්ලේෂණයට පමණයි සම්බන්ධ කරයි: FINDINGS තුළ <span style="color:var(--green)">AI »</span> බොත්තම, පිළිතුර COORDINATION තුළ දැක්වේ. මෙම සැකසුම නොමැතිව ඕනෑම දත්තයක් ඔයාගේ යන්ත්‍රයෙන් පිටතට නොයයි.',
    ai_off: 'අක්‍රිය', ai_on: 'සක්‍රිය',
    ai_st_off: 'AI අක්‍රිය - රාමුව එය නොමැතිව 100% දේශීයව ක්‍රියා කරයි', ai_st_ready: 'AI සම්බන්ධයි: {p} · {m}',
    ai_st_inc: 'AI සක්‍රිය නමුත් අසම්පූර්ණයි: baseURL සහ model අවශ්‍යයි', ai_url_ph: 'base URL - උදා: http://localhost:11434 හෝ https://api.MyAI.tld/v1',
    ai_model_ph: 'model - උදා: llama3.1:8b', ai_key_ph: 'API යතුර (දේශීය සර්වරයට හිස්ව තියන්න)',
    ai_save: 'සුරකින්න', ai_test: 'සම්බන්ධතාව පරීක්ෂා කරන්න',
    ai_testing: 'පරීක්ෂණය වෙමින්…', ai_ok: 'හරි - පිළිතුර: ',
    ai_fail: 'අසාර්ථක: ', ai_note: 'වින්‍යාසය data/ai.json තුළ දේශීයව ගබඩා වේ - ඔයා දැමූ endpoint හැර වෙන කිසිම තැනකට කවදාවත් යවන්නේ නැහැ',
    ch_ph: 'root@c2ff:~# විශ්ලේෂණ නියෝජිතයාට පණිවිඩයක්…', ch_send: 'යවන්න',
    ch_empty: 'නාලිකාව විවෘතයි. මෙතන ලියන්න, මොනිටරය මාව ක්ෂණිකව අවදි කරයි.', ft: '100% දේශීය - නිශ්චිත ප්‍රෝබෝ, token හෝ බාහිර යැපීම් නැහැ - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-ප්‍රකාරය සක්‍රිය: මිනිත්තු 30 ට වරක් දේශීය චක්‍ර, token 0යි.', to_fl_pa: 'FLEET විරාමයේ - ඕනෑම වෙලාවක නැවත අරගන්න.',
    to_fl_cy: 'ක්ෂණික චක්‍රය ඇරණි (අයවැය 60 req).', to_launch: '[GO] {m} ප්‍රකාරය (CWE {c}) {p} මත - දේශීය චක්‍රය ඇරණි',
    to_ai_ok: 'වින්‍යාසය සුරැකිණි', to_ai_no: 'සුරැකීම අසාර්ථකයි',
    to_ai_no_cfg: 'AI වින්‍යාස නැහැ - AI ටැබ් එකේ සකසන්න', to_ai_head: 'AI විශ්ලේෂණය',
    to_ai_bad: 'AI විශ්ලේෂණය අසාර්ථකයි', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ ඇරඹුම', navar: 'අවි ගබඩාව',
    ar_h2: 'අවි ගබඩාව - හඳුනාගත් මතුපිට මත CVE, EPSS සහ එක්ස්ප්ලෝයිට්', ar_sync: 'SYNC දත්ත ගබඩාව',
    ar_btn: 'පිමුම්', ar_exec: 'EXEC',
    ar_none: 'පිමුම් නැත: පළමුව RECON ධාවනය කරන්න, පසුව KEV/EPSS පූරණයට SYNC ධාවනය කරන්න', ar_loading: 'දත්ත ගබඩා සාරාංශය පූරණය වෙමින්...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'නිදර්ශන වැඩසටහන - ස්කෑන් කිරීමක් නැත: ඔබේ වැඩසටහන සාදන්න', pip_noprog: 'වැඩසටහන් නැත: වැඩසටහන් ටැබ් තුළ ඔබේ සාදන්න',
    pip_next: 'ඊළඟ පියවර:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  km: {
    pl_title: 'ផែនការងារ', pl_empty: 'មិនទាន់មានផែនការទេ៖ ដំណើរការ RECON នៅលើកាតខាងលើ សម្មតិកម្មធ្លាក់មកទីនេះ (ស្ថានភាពរក្សាទុកជាប់)',
    pl_run: 'ដំណើរការ', pl_reflect: 'កាណារីបានឆ្លុះបញ្ចាំង',
    st_do: 'ត្រូវធ្វើ', st_test: 'បានសាកល្បង',
    st_signal: 'សញ្ញា', st_valid: 'ត្រឹមត្រូវ',
    st_void: 'គ្មានអ្វីទេ', atk_btn: 'ATTACK',
    atk_start: 'វាយប្រហារលើផ្ទៃ៖ endpoints, docs ដែលបានបង្ហាញ, JWT, កូនសោសម្ងាត់...', atk_fail: 'វាយប្រហារមិនបាន៖ ដំណើរការ RECON ជាដំបូងសិន',
    atk_none: 'គ្មានសញ្ញាទេ', atk_findings: 'បេក្ខជន',
    atk_done: 'ATTACK៖ {n} បេក្ខជន P1/P2 បានបញ្ចូលទៅ findings ជាមួយភស្តុតាង', atk_empty: 'មិនទាន់មានការវាយប្រហារទេ៖ ដំណើរការ RECON បន្ទាប់មក ATTACK - បេក្ខជនមានភស្តុតាង req/res ធ្លាក់មកទីនេះ',
    navh: 'HUNT', h2hunt: 'HUNT - ផ្ទៃពិត និងភស្តុតាង',
    h_ready: 'រួចរាល់', h_empty: 'មិនទាន់មានផ្ទៃទេ៖ ដំណើរការ RECON ដើម្បីគំនូសទំព័រ, API endpoints, params, JS bundles និង subdomains',
    h_fnd: 'Findings របស់កម្មវិធី', h_nofnd: 'គ្មាន finding សម្រាប់កម្មវិធីនេះទេ',
    rc_btn: 'RECON', rc_start: 'កំពុង recon ផ្ទៃ៖ ទំព័រ, JS bundles, endpoints, params...',
    rc_done: 'ផ្ទៃបានគំនូស៖ endpoints, params និង subdomains រាយក្នុងកាតកម្មវិធី', rc_fail: 'recon បរាជ័យ៖ host មិនអាចដល់បាន ឬ scope ទំនេរ',
    rc_surface: 'ផ្ទៃ៖', snd_on: 'សំឡេង៖ ON',
    snd_off: 'សំឡេង៖ OFF', snd_ok: 'សំឡេងចុងក្រោយចាប់ផ្តើម - បណ្ណាល័យ៖ ចុច, ផ្ទាំង, ចម្លង, សំឡេងជូនដំណឹង',
    snd_stop: 'បិទសំឡេងទាំងស្រុង៖ គ្មានសំឡេង C2FF ទៀតទេ', amb_on: 'បរិយាកាស៖ ON',
    amb_off: 'បរិយាកាស៖ OFF', amb_ok: 'បរិយាកាសមានជីវិត - ពណ៌រសាត់ទន់ៗឆ្លងកាត់ក្រុមពណ៌ (បៃតង, ខៀវ, លឿង...)',
    amb_stop: 'បរិយាកាសគាំងនៅលើពណ៌បៃតងដើម', nt_on: 'ការជូនដំណឹង៖ ON',
    nt_off: 'ការជូនដំណឹង៖ OFF', nt_ok: 'ការជូនដំណឹងកម្មវិធីរុករកបានបើក - សំឡេងប៊ីបនៅ P1 និង P2',
    nt_denied: 'ការជូនដំណឹងត្រូវបានកម្មវិធីរុករកទប់ស្កាត់៖ អនុញ្ញាតក្នុងការកំណត់របស់តំបន់បណ្តាញ', term_denied: 'terminal ត្រូវបដិសេធ ឬមិនមាន៖ ត្រូវការ localhost ឬបើកបន្ទប់ជា admin',
    term_p: 'bash ពិត - ប្រវត្តិតាមស្នាដៃឡើង, Ctrl+C ផ្តាច់, Ctrl+D បិទ', term_restart: 'កំណត់ឡើងវិញ',
    navtrm: 'TERM', term_h2: 'Terminal - shell ធ្វើការ ដោយផ្ទាល់ក្នុងកុងសូល',
    fl_off: 'FLEET៖ ឈប់', fl_paused: 'FLEET៖ ផ្អាក',
    fl_active: 'FLEET៖ សកម្ម ({n} វដ្ត)', fl_last: 'វដ្តចុងក្រោយ',
    fl_none: 'មិនទាន់មានវដ្តទេ', fl_info: 'ចន្លោះ {i} នាទី, ថវិកា {b} req/វដ្ត',
    sub_ttl: 'command & control framework', navt: 'វេន',
    tm_h2: 'វេនជាក្រុម - បរបាញ់ជាមួយគ្នា ទោះក្រៅបណ្តាញ', tm_p: 'បើកបន្ទប់រួម៖ ក្រុមអ្នកឃើញ Fleet, findings និងអាច triage ផ្ទាល់។ ជជែកវេនដាច់ដោយឡែកនៅខាងក្រោម។ កម្រិតចូលបី៖ LOCAL (តែម្នាក់ឯង), LAN តាមរយៈបើកទៅបណ្តាញ, និងពិភពលោកតាមរយៈបើកទៅពិភពលោក - ផ្លូវរូងសាធារណៈ (cloudflared បើបានដំឡើង) ធ្វើឱ្យតំណអញ្ជើញមានសុពលភាពពីបណ្តាញណាមួយ ដោយមិនបង្ហាញម៉ាស៊ីនអ្នកដោយផ្ទាល់។ អ្វីៗទាំងអស់ឆ្លងកាត់កូនសោបន្ទប់ - បង្កើតឡើងវិញដើម្បីបណ្តេញមនុស្សគ្រប់គ្នាចេញម្តង។',
    tm_handle: 'ឈ្មោះរបស់អ្នក (អតិបរមា 16 តួអក្សរ)', tm_save_h: 'កំណត់',
    tm_room_ph: 'ឈ្មោះបន្ទប់ (ឧទាហរណ៍៖ c2ff-core)', tm_save: 'អនុវត្ត',
    tm_on: 'បន្ទប់បើក៖ {r} - {n} នៅលើអ៊ីនធឺណិត', tm_off: 'របៀប TEAM បិទ - វេនមូលដ្ឋានតែម្នាក់',
    tm_room: 'បន្ទប់', tm_key: 'កូនសោបន្ទប់',
    tm_regen: 'បង្កើតកូនសោឡើងវិញ', tm_regen_ok: 'កូនសោថ្មីបានបង្កើត - តំណចាស់ក្លាយជាមិនដំណើរការ',
    tm_invite: 'តំណអញ្ជើញ (ចម្លងទៅក្រុម)', tm_copy: 'ចម្លង',
    tm_copied: 'ចម្លងទៅ clipboard រួចរាល់', tm_members: 'សមាជិក',
    tm_nobody: 'មិនទាន់មានអ្នកណាទេ - ផ្ញើតំណអញ្ជើញទៅក្រុម', tm_you: '(អ្នក)',
    tm_here: 'វត្តមាន', tm_saved: 'ឈ្មោះបានរក្សាទុក',
    tm_no_handle: 'ឈ្មោះទំនេរ', tm_cfg_ok: 'បន្ទប់បានធ្វើបច្ចុប្បន្នភាព',
    tm_cfg_no: 'បរាជ័យ', tm_live: 'បើកទៅបណ្តាញ',
    tm_shore: 'ត្រឡប់ទៅមូលដ្ឋាន', tm_need_on: 'បើកបន្ទប់ជាដំបូងសិន (ON)',
    tm_bind_lan: 'បណ្តាញ៖ {a}', tm_bind_lo: 'មូលដ្ឋាន៖ localhost តែប៉ុណ្ណោះ',
    to_team_live: '[GO-LIVE] ម៉ាស៊ីនបម្រើបានចាប់ផ្តើមឡើងវិញជាមួយចូលបណ្តាញ - តំណ LAN បង្ហាញ, តភ្ជាប់ឡើងវិញក្នុង 2 វិនាទី', to_team_shore: 'ម៉ាស៊ីនបម្រើបានចាប់ផ្តើមឡើងវិញជាមូលដ្ឋាន (127.0.0.1)',
    tm_tun_open: 'បើកទៅពិភពលោក (ផ្លូវរូង)', tm_tun_close: 'បិទផ្លូវរូង',
    tm_tun_wait: 'ផ្លូវរូងសាធារណៈកំពុងបើក (ប៉ុន្មានវិនាទី)…', tm_tun_on: 'វេនបើកទៅពិភពលោក៖ {u} - តំណអញ្ជើញដំណើរការពីគ្រប់កន្លែង មិនត្រូវការបណ្តាញដូចគ្នាទេ',
    tm_tun_closed: 'ផ្លូវរូងបានបិទ - ត្រឡប់ទៅ LAN/មូលដ្ឋាន', tm_chat_empty: 'ឆ្នាំងវេនបើក - សមាជិកបន្ទប់អានគ្នាទៅវិញទៅមកទីនេះ',
    tm_chat_h2: 'ជជែកវេន', tm_msg_ph: 'សារទៅវេន…',
    tm_admin: 'អ្នកគ្រប់គ្រង', tm_guest: 'ភ្ញៀវ',
    tm_kick: 'KICK', tm_kick_ok: 'សមាជិកត្រូវបានបណ្តេញចេញពីបន្ទប់ (ចុចឡើងវិញដើម្បីដោះស្រាយ)',
    tm_role_ok: 'តួនាទីបានធ្វើបច្ចុប្បន្នភាព', tm_mic_on: 'បើកមីក្រូហូន',
    tm_mic_off: 'បិទមីក្រូហូន', tm_mic_denied: 'មីក្រូហូនត្រូវបដិសេធ ឬមិនមាន៖ ត្រូវការ HTTPS (ផ្លូវរូងពិភពលោកឬlocalhost) និងត្រូវអនុញ្ញាតមីក្រូហូន',
    navf: 'ហ្វលីត', navfd: 'Findings',
    navp: 'កម្មវិធី', navai: 'AI',
    navc: 'សហការណ៍', st_runs: 'ការរត់',
    st_beacons: 'Beacons សកម្ម', st_sig: 'សញ្ញា',
    h2f: 'ហ្វ្លៀត - កម្មវិធីទាំងអស់ ភ្នាក់ងារកំពុងរត់នៅមុខ', h2fd: 'មូលដ្ឋាន findings - ស្លាក triage រក្សាជាប់',
    h2eng: 'ម៉ាស៊ីនហ្វ្លៀត - វដ្តមូលដ្ឋាន គ្មាន tokens', h2prog: 'កម្មវិធី - scope, header ទាមទារ, ដំណើរការ',
    h2new: 'កម្មវិធីថ្មី', h2ai: 'ភ្នាក់ងារ AI - ការបញ្ចូល ១០០% ស្ម័គ្រចិត្ត',
    h2c: 'សហការណ៍ - ឆ្នាំងឯកជន', fl_start: 'ចាប់ផ្តើម',
    fl_pause: 'ផ្អាក', fl_cycle: 'វដ្តឥឡូវនេះ',
    f_add: 'បន្ថែម', f_none: 'មិនទាន់មានសញ្ញាទេ',
    f_ph: 'finding ដោយដៃ៖ endpoint + ភស្តុតាង + severity ការពារបាន…', st_sig_off: 'សញ្ញា',
    st_sig_an: 'ការវិភាគ', st_sig_sub: 'បានដាក់ស្នើ',
    st_sig_dup: 'ស្ទួន', st_sig_ref: 'បដិសេធ',
    st_sig_cl: 'បានបិទ', r_none: 'រកមិនឃើញការរត់ទេ',
    r_live: '{n} កំពុងរត់', r_done: 'រួចរាល់',
    r_feed: '▽ អ្យកាស ({n} ev)', r_close: '△ បង្រួម',
    p_name_ph: 'ឈ្មោះកម្មវិធី (ឧទាហរណ៍៖ PayPal)', p_hdr_ph: 'header ថ្នាក់កំណត់ទាមទារ (ឧទាហរណ៍៖ X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope៖ domain1, domain2, …', p_save: 'រក្សាទុក',
    p_local: 'ម៉ូឌុល(ស់), ១០០% មូលដ្ឋាន', ai_p: 'C2FF ដំណើរការពេញលេញដោយគ្មាន AI៖ របៀបគឺ probes តក្កវិជ្ជាមូលដ្ឋានល្អិតល្អន់។ ទ្វារនេះគ្រាន់តែភ្ជាប់ <b>AI របស់អ្នក</b> (ដោយខ្លួនឯងឬAPI) ដើម្បីវិភាគ finding មួយតាមសំណើ៖ ប៊ូតុង <span style="color:var(--green)">AI »</span> ក្នុង FINDINGS, ចម្លើយបង្ហាញក្នុង COORDINATION. គ្មានទិន្នន័យណាមួយចេញពីម៉ាស៊ីនអ្នកដោយគ្មានការកំណត់រចនាសម្ព័ន្ធនេះទេ។',
    ai_off: 'បិទ', ai_on: 'បើក',
    ai_st_off: 'AI បិទ - ក្របខ័ណ្ឌដំណើរការ ១០០% មូលដ្ឋានដោយគ្មានវា', ai_st_ready: 'AI ភ្ជាប់៖ {p} · {m}',
    ai_st_inc: 'AI បើកប៉ុន្តែមិនពេញលេញ៖ ត្រូវការ baseURL និង model', ai_url_ph: 'base URL - ឧទាហរណ៍៖ http://localhost:11434 ឬ https://api.MyAI.tld/v1',
    ai_model_ph: 'model - ឧទាហរណ៍៖ llama3.1:8b', ai_key_ph: 'កូនសោ API (ទុកទំនេរសម្រាប់ម៉ាស៊ីនបម្រើមូលដ្ឋាន)',
    ai_save: 'រក្សាទុក', ai_test: 'សាកល្បងការភ្ជាប់',
    ai_testing: 'កំពុងសាកល្បង…', ai_ok: 'អី - ចម្លើយ៖ ',
    ai_fail: 'បរាជ័យ៖ ', ai_note: 'ការកំណត់រក្សាទុកក្នុង data/ai.json - មិនផ្ញើទៅកន្លែងផ្សេងក្រៅពី endpoint ដែលអ្នកដាក់ឡើយ',
    ch_ph: 'root@c2ff:~# សារទៅភ្នាក់ងារវិភាគ…', ch_send: 'ផ្ញើ',
    ch_empty: 'ឆ្នាំងបើកហើយ។ ចុះទីនេះ, monitor ភ្ញាក់ខ្ញុំភ្លាមៗ។', ft: '១០០% មូលដ្ឋាន - probes តក្កវិជ្ជា, គ្មាន tokens គ្មានការពឹងផ្អែកខាងក្រៅ - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-របៀបសកម្ម៖ វដ្តមូលដ្ឋានរាល់ ៣០ នាទី, 0 token.', to_fl_pa: 'FLEET ផ្អាក - បន្តពេលណាដែលចង់។',
    to_fl_cy: 'វដ្តភ្លាមៗចាប់ផ្តើម (ថវិកា ៦០ req).', to_launch: '[GO] របៀប {m} (CWE {c}) លើ {p} - វដ្តមូលដ្ឋានក្បៀស',
    to_ai_ok: 'ការកំណត់រក្សាទុកហើយ', to_ai_no: 'ការរក្សាទុកបរាជ័យ',
    to_ai_no_cfg: 'AI មិនបានកំណត់ - កំណត់ក្នុងផ្ទាំង AI', to_ai_head: 'វិភាគ AI',
    to_ai_bad: 'វិភាគ AI បរាជ័យ', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ ដំណើរការ', navar: 'ឃ្លាំងអាវុធ',
    ar_h2: 'ឃ្លាំងអាវុធ - CVE, EPSS និង exploit លើផ្ទៃដែលរកឃើញ', ar_sync: 'SYNC មូលដ្ឋានទិន្នន័យ',
    ar_btn: 'ជំហាន', ar_exec: 'EXEC',
    ar_none: 'គ្មានជំហាន: ដំណើរការ RECON ជាមុនសិន បន្ទាប់មក SYNC ដើម្បីផ្ទុក KEV/EPSS', ar_loading: 'កំពុងផ្ទុកការសង្ខេបមូលដ្ឋានទិន្នន័យ...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'កម្មវិធីសាកល្បង - គ្មានការស្កេន: បង្កើតកម្មវិធីរបស់អ្នក', pip_noprog: 'មិនមានកម្មវិធីទេ: បង្កើតរបស់អ្នកក្នុងផ្ទាំង កម្មវិធី',
    pip_next: 'ជំហានបន្ទាប់:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  lo: {
    pl_title: 'ແຜນວຽກ', pl_empty: 'ຍັງບໍ່ມີແຜນ: ເປີດ RECON ໃນບັດຂ້າງເທິງ, ຄາດຄະເນຕົກມາທີ່ນີ້ (ສະຖານະບັນທຶກໄວ້)',
    pl_run: 'ເປີດ', pl_reflect: 'canary ສະທ້ອນແລ້ວ',
    st_do: 'ຕ້ອງເຮັດ', st_test: 'ທົດສອບແລ້ວ',
    st_signal: 'ສັນຍານ', st_valid: 'ຢືນຢັນແລ້ວ',
    st_void: 'ບໍ່ມີຫຍັງ', atk_btn: 'ATTACK',
    atk_start: 'ໂຈມຕີພື້ນທີ່: endpoints, docs ທີ່ເປີດເຜີຍ, JWT, ຄວາມລັບ...', atk_fail: 'ໂຈມຕີບໍ່ໄດ້: ເປີດ RECON ກ່ອນ',
    atk_none: 'ບໍ່ມີສັນຍານ', atk_findings: 'ຜູ້ສະໝັງ',
    atk_done: 'ATTACK: {n} ຜູ້ສະໝັງ P1/P2 ໃສ່ findings ພ້ອມຫຼັກຖານແລ້ວ', atk_empty: 'ຍັງບໍ່ມີການໂຈມຕີ: ເປີດ RECON ແລ້ວ ATTACK - ຜູ້ສະໝັງພ້ອມຫຼັກຖານ req/res ຕົກມາທີ່ນີ້',
    navh: 'HUNT', h2hunt: 'HUNT - ພື້ນທີ່ຕົວຈິງ ແລະ ຫຼັກຖານ',
    h_ready: 'ພ້ອມ', h_empty: 'ຍັງບໍ່ມີພື້ນທີ່: ເປີດ RECON ເພື່ອ map ໜ້າ, API endpoints, params, JS bundles ແລະ subdomains',
    h_fnd: 'Findings ຂອງໂຄງການ', h_nofnd: 'ບໍ່ມີ finding ສຳລັບໂຄງການນີ້',
    rc_btn: 'RECON', rc_start: 'ກຳລັງ recon ພື້ນທີ່: ໜ້າ, JS bundles, endpoints, params...',
    rc_done: 'map ພື້ນທີ່ແລ້ວ: endpoints, params ແລະ subdomains ລາຍການໃນບັດໂຄງການ', rc_fail: 'recon ລົ້ມເຫຼວ: host ຕິດຕໍ່ບໍ່ໄດ້ ຫຼື scope ຫວ່າງ',
    rc_surface: 'ພື້ນທີ່:', snd_on: 'ສຽງ: ON',
    snd_off: 'ສຽງ: OFF', snd_ok: 'ສຽງໜ້າຈໍເປີດ - ຫໍສະໝຸດ: ກົດ, ແທັບ, ສຳເນົາ, ເຕືອນ',
    snd_stop: 'ປິດສຽງທັງໝົດ: ບໍ່ມີສຽງ C2FF ອີກ', amb_on: 'ບັນຍາກາດ: ON',
    amb_off: 'ບັນຍາກາດ: OFF', amb_ok: 'ບັນຍາກາດມີຊີວິດ - ສີໄຫຼນຸ່ມຜ່ານຕະກູນສີ (ຂຽວ, ຟ້າ, ເຫຼືອງ...)',
    amb_stop: 'ບັນຍາກາດຢຸດຢູ່ສີຂຽວເດີມ', nt_on: 'ແຈ້ງເຕືອນ: ON',
    nt_off: 'ແຈ້ງເຕືອນ: OFF', nt_ok: 'ແຈ້ງເຕືອນ browser ເປີດແລ້ວ - ສຽງ beep ເມື່ອ P1 ແລະ P2',
    nt_denied: 'ແຈ້ງເຕືອນຖືກ browser ບລັອກ: ອະນຸຍາດໃນການຕັ້ງຄ່າເວັບໄຊ', term_denied: 'terminal ປະຕິເສດ ຫຼື ບໍ່ມີ: ຕ້ອງມີ localhost, ຫຼື ຫ້ອງເປີດໃນຖານະ admin',
    term_p: 'bash ຕົວຈິງ - ປະຫວັດດ້ວຍລູກສອນ, Ctrl+C ຢຸດ, Ctrl+D ປິດ', term_restart: 'ຕັ້ງໃໝ່',
    navtrm: 'TERM', term_h2: 'Terminal - shell ເຮັດວຽກ, ກົງໃນຄອນໂຊນ',
    fl_off: 'FLEET: ຢຸດ', fl_paused: 'FLEET: ພັກຊົ່ວຄາວ',
    fl_active: 'FLEET: ເຮັດວຽກ ({n} ຮອບ)', fl_last: 'ຮອບທ້າຍ',
    fl_none: 'ຍັງບໍ່ມີຮອບ', fl_info: 'ໄລຍະຫ່າງ {i} ນາທີ, ງົບປະມານ {b} req/ຮອບ',
    sub_ttl: 'command & control framework', navt: 'ຄັ້ງ',
    tm_h2: 'ຄັ້ງແບບກຸ່ມ - ລ່າສັດຮ່ວມກັນ ເຖິງແມ່ນນອກເຄືອຂ່າຍ', tm_p: 'ເປີດຫ້ອງແບ່ງປັນ: ກຸ່ມຂອງເຈົ້າເຫັນ fleet, findings ແລະ triage ໄດ້ສົດໆ. ແຊັດຄັ້ງສະເພາະຢູ່ຂ້າງລຸ່ມ. ສາມລະດັບເຂົ້າເຖິງ: LOCAL (ດ່ຽວ), LAN ຜ່ານເປີດຫາເຄືອຂ່າຍ, ແລະ ໂລກຜ່ານເປີດຫາໂລກ - ອຸທອງສາທາລະນະ (cloudflared ຖ້າຕິດຕັ້ງແລ້ວ) ເຮັດໃຫ້ລິ້ງເຊື້ອສະໝັກໃຊ້ໄດ້ຈາກທຸກເຄືອຂ່າຍ ໂດຍບໍ່ເປີດເຜີຍເຄື່ອງຂອງເຈົ້າໂດຍກົງ. ທຸກຢ່າງຜ່ານກຸນແຈຫ້ອງ - ສ້າງໃໝ່ເພື່ອໄລ່ທຸກຄົນພ້ອມກັນ.',
    tm_handle: 'ຊື່ຂອງເຈົ້າ (ສູງສຸດ 16 ຕົວອັກສອນ)', tm_save_h: 'ຕັ້ງ',
    tm_room_ph: 'ຊື່ຫ້ອງ (ເຊັ່ນ: c2ff-core)', tm_save: 'ນຳໃຊ້',
    tm_on: 'ຫ້ອງເປີດ: {r} - {n} ອອນລາຍ', tm_off: 'ໂໝດ TEAM ປິດ - ຄັ້ງທ້ອງຖິ່ນດ່ຽວ',
    tm_room: 'ຫ້ອງ', tm_key: 'ກຸນແຈຫ້ອງ',
    tm_regen: 'ສ້າງກຸນແຈໃໝ່', tm_regen_ok: 'ສ້າງກຸນແຈໃໝ່ແລ້ວ - ລິ້ງເກົ່າຕາຍໝົດ',
    tm_invite: 'ລິ້ງເຊື້ອສະໝັກ (ສຳເນົາໃຫ້ທີມ)', tm_copy: 'ສຳເນົາ',
    tm_copied: 'ສຳເນົາເຂົ້າ clipboard ແລ້ວ', tm_members: 'ສະມາຊິກ',
    tm_nobody: 'ຍັງບໍ່ມີໃຜ - ສົ່ງລິ້ງໃຫ້ທີມ', tm_you: '(ເຈົ້າ)',
    tm_here: 'ຢູ່ນີ້', tm_saved: 'ບັນທຶກຊື່ແລ້ວ',
    tm_no_handle: 'ຊື່ຫວ່າງ', tm_cfg_ok: 'ອັບເດດຫ້ອງແລ້ວ',
    tm_cfg_no: 'ລົ້ມເຫຼວ', tm_live: 'ເປີດຫາເຄືອຂ່າຍ',
    tm_shore: 'ກັບຄືນທ້ອງຖິ່ນ', tm_need_on: 'ເປີດຫ້ອງກ່ອນ (ON)',
    tm_bind_lan: 'ເຄືອຂ່າຍ: {a}', tm_bind_lo: 'ທ້ອງຖິ່ນ: localhost ເທົ່ານັ້ນ',
    to_team_live: '[GO-LIVE] ເຊີບເວີຣີເປີດໃໝ່ພ້ອມເຂົ້າເຄືອຂ່າຍ - ສະແດງລິ້ງ LAN, ເຊື່ອມຕໍ່ໃໝ່ໃນ 2 ວິນາທີ', to_team_shore: 'ເຊີບເວີຣີເປີດໃໝ່ເປັນທ້ອງຖິ່ນ (127.0.0.1)',
    tm_tun_open: 'ເປີດຫາໂລກ (ອຸທອງ)', tm_tun_close: 'ປິດອຸທອງ',
    tm_tun_wait: 'ກຳລັງເປີດອຸທອງສາທາລະນະ (ບໍ່ດົນ)…', tm_tun_on: 'ຄັ້ງເປີດຫາໂລກ: {u} - ລິ້ງເຊື້ອສະໝັກໃຊ້ໄດ້ທຸກບ່ອນ, ບໍ່ຕ້ອງເຄືອຂ່າຍດຽວກັນ',
    tm_tun_closed: 'ອຸທອງປິດແລ້ວ - ກັບໄປ LAN/ທ້ອງຖິ່ນ', tm_chat_empty: 'ຊ່ອງຄັ້ງເປີດແລ້ວ - ສະມາຊິກຫ້ອງອ່ານກັນຢູ່ນີ້',
    tm_chat_h2: 'ແຊັດຄັ້ງ', tm_msg_ph: 'ຂໍ້ຄວາມໄປຄັ້ງ…',
    tm_admin: 'ຜູ້ຄຸ້ມຄອງ', tm_guest: 'ແຂກ',
    tm_kick: 'KICK', tm_kick_ok: 'ໄລ່ສະມາຊິກອອກຈາກຫ້ອງແລ້ວ (ກົດອີກເທື່ອເພື່ອປົດລັອກ)',
    tm_role_ok: 'ອັບເດດບົດບາດແລ້ວ', tm_mic_on: 'ເປີດໄມ',
    tm_mic_off: 'ປິດໄມ', tm_mic_denied: 'ໄມຖືກປະຕິເສດ ຫຼື ບໍ່ມີ: ຕ້ອງມີ HTTPS (ອຸທອງໂລກ ຫຼື localhost) ແລະ ຕ້ອງອະນຸຍາດໄມ',
    navf: 'Fleet', navfd: 'Findings',
    navp: 'ໂຄງການ', navai: 'AI',
    navc: 'ປະສານງານ', st_runs: 'ການເຮັດວຽກ',
    st_beacons: 'Beacons ເຮັດວຽກ', st_sig: 'ສັນຍານ',
    h2f: 'Fleet - ທຸກໂຄງການ, ເອ���ເຈັນທ໌ທີ່ກຳລັງເຮັດວຽກຢູ່ເທິງສຸດ', h2fd: 'ຖານ Findings - ປ້າຍ triage ຄົງທີ່',
    h2eng: 'ເຄື່ອງຍົນ Fleet - ຮອບທ້ອງຖິ່ນບໍ່ມີ token', h2prog: 'ໂຄງການ - scope, header ທີ່ຕ້ອງມີ, ການເປີດ',
    h2new: 'ໂຄງການໃໝ່', h2ai: 'ເອເຈັນ AI - ເຊື່ອມຕໍ່ 100% ຕາມໃຈ',
    h2c: 'ປະສານງານ - ຊ່ອງເອກະຊົນ', fl_start: 'ເລີ່ມ',
    fl_pause: 'ພັກຊົ່ວຄາວ', fl_cycle: 'ຮອບດຽວນີ້',
    f_add: 'ເພີ່ມ', f_none: 'ຍັງບໍ່ມີສັນຍານ',
    f_ph: 'manual finding: endpoint + ຫຼັກຖານ + severity ປ້ອງກັນໄດ້…', st_sig_off: 'ສັນຍານ',
    st_sig_an: 'ວິເຄາະ', st_sig_sub: 'ສົ່ງແລ້ວ',
    st_sig_dup: 'ຊ້ຳ', st_sig_ref: 'ປະຕິເສດ',
    st_sig_cl: 'ປິດແລ້ວ', r_none: 'ບໍ່ພົບການເຮັດວຽກ',
    r_live: '{n} ກຳລັງເຮັດ', r_done: 'ສຳເລັດ',
    r_feed: '▽ flow ({n} ev)', r_close: '△ ຫົດ',
    p_name_ph: 'ຊື່ໂຄງການ (ເຊັ່ນ: PayPal)', p_hdr_ph: 'header ນັກສຶກສາທີ່ຕ້ອງມີ (ເຊັ່ນ: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domain1, domain2, …', p_save: 'ບັນທຶກ',
    p_local: 'module(s), 100% ທ້ອງຖິ່ນ', ai_p: 'C2FF ເຮັດວຽກໄດ້ທັງໝົດໂດຍບໍ່ມີ AI: modes ແມ່ນການທົ​ດສອບທ້ອງຖິ່ນຕາຍແລ້ວ. ປະຕູນີ້ໃຊ້ພຽງເພື່ອເຊື່ອມ <b>AI ຂອງເຈົ້າ</b> (self-hosted ຫຼື API) ວິເຄາະ finding ດຽວຕົວໜຶ່ງ: ປຸ່ມ <span style="color:var(--green)">AI »</span> ໃນ FINDINGS, ຄຳຕອບສະແດງໃນ COORDINATION. ບໍ່ມີຂໍ້ມູນໃດອອກຈາກເຄື່ອງໂດຍບໍ່ມີການຕັ້ງຄ່ານີ້.',
    ai_off: 'ປິດ', ai_on: 'ເປີດ',
    ai_st_off: 'AI ປິດ - framework ເຮັດວຽກ 100% ທ້ອງຖິ່ນໂດຍບໍ່ມີມັນ', ai_st_ready: 'AI ເຊື່ອມຕໍ່ແລ້ວ: {p} · {m}',
    ai_st_inc: 'AI ເປີດແຕ່ຍັງບໍ່ຄົບ: ຕ້ອງມີ baseURL ແລະ model', ai_url_ph: 'base URL - ເຊັ່ນ: http://localhost:11434 ຫຼື https://api.MyAI.tld/v1',
    ai_model_ph: 'model - ເຊັ່ນ: llama3.1:8b', ai_key_ph: 'ກຸນແຈ API (ຫວ່າງຖ້າເປັນເຊີບເວີທ້ອງຖິ່ນ)',
    ai_save: 'ບັນທຶກ', ai_test: 'ທົດສອບການເຊື່ອມຕໍ່',
    ai_testing: 'ກຳລັງທົດສອບ…', ai_ok: 'OK - ຄຳຕອບ: ',
    ai_fail: 'ລົ້ມເຫຼວ: ', ai_note: 'config ບັນທຶກຢູ່ທ້ອງຖິ່ນ data/ai.json - ບໍ່ເຄີຍສົ່ງໄປທີ່ອື່ນນອກຈາກ endpoint ທີ່ເຈົ້າໃສ່',
    ch_ph: 'root@c2ff:~# ຂໍ້ຄວາມໄປຫາເອເຈນກະວິເລາະ…', ch_send: 'ສົ່ງ',
    ch_empty: 'ຊ່ອງເປີດແລ້ວ. ພິມທີ່ນີ້, monitor ຕື່ນຂ້ອຍໄວໆນີ້.', ft: '100% ທ້ອງຖິ່ນ - probes ຕາຍແລ້ວ, ບໍ່ມີ token ບໍ່ມີເອກະສານອ້າງອີງນອກ - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ເຮັດວຽກ: ຮອບທ້ອງຖິ່ນທຸກ 30 ນາທີ, 0 token.', to_fl_pa: 'FLEET ພັກຊົ່ວຄາວ - ສືບຕໍ່ໄດ້ຍາມໃດກໍໄດ້.',
    to_fl_cy: 'ເປີດຮອບດຽວແລ້ວ (ງົບ 60 req).', to_launch: '[GO] ໂໝດ {m} (CWE {c}) ໃສ່ {p} - ຮອບທ້ອງຖິ່ນເລີ່ມແລ້ວ',
    to_ai_ok: 'config ບັນທຶກແລ້ວ', to_ai_no: 'ບັນທຶກລົ້ມເຫຼວ',
    to_ai_no_cfg: 'AI ຍັງບໍ່ໄດ້ຕັ້ງຄ່າ - ຕັ້ງຄ່າໃນບັດ AI', to_ai_head: 'ວິເຄາະ AI',
    to_ai_bad: 'ວິເຄາະ AI ລົ້ມເຫຼວ', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ ເປີດເລີ່ມການສະແດງ', navar: 'ຄັງອາວຸດ',
    ar_h2: 'ຄັງອາວຸດ - CVE, EPSS ແລະ exploit ຢູ່ພື້ນຜິວທີ່ກວດພົບ', ar_sync: 'SYNC ຖານຂໍ້ມູນ',
    ar_btn: 'ຈັງຫວະ', ar_exec: 'EXEC',
    ar_none: 'ບໍ່ມີຈັງຫວະ: ເຮັດ RECON ກ່ອນ, ຫຼັງຈາກນັ້ນ SYNC ເພື່ອໂຫຼດ KEV/EPSS', ar_loading: 'ກຳລັງໂຫຼດສະຫຼຸບຖານຂໍ້ມູນ...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'ໂຄງການຕົວຢ່າງ - ບໍ່ມີການສະແກນ: ສ້າງໂຄງການຂອງເຈົ້າ', pip_noprog: 'ບໍ່ມີໂຄງການ: ສ້າງຂອງເຈົ້າໃນແທັບ ໂຄງການ',
    pip_next: 'ຂັ້ນຕອນຕໍ່ໄປ:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  my: {
    pl_title: 'အလုပ်အစီအစဉ်', pl_empty: 'အစီအစဉ် မရှိသေး: အထက်ကဒ်မှာ RECON စတင်ပါ၊ အယူအဆ များ ဒီမှာ ရောက်လာမယ် (အခြေအနေများ သိမ်းဆည်းထား)',
    pl_run: 'စတင်', pl_reflect: 'canary ပြန်ကျော့ပြီး',
    st_do: 'လုပ်ရမည်', st_test: 'စစ်ဆေးပြီး',
    st_signal: 'အချက်ပြ', st_valid: 'အတည်ပြု',
    st_void: 'ဘာမှမရှိ', atk_btn: 'ATTACK',
    atk_start: 'မျက်နှာပြင်ကို တိုက်ခိုက်: endpoints, ဖွင့်ထားသော docs, JWT, လျှို့ဝှက်ချက်များ...', atk_fail: 'တိုက်ခိုက်မရ: အရင် RECON စတင်ပါ',
    atk_none: 'အချက်ပြမရှိ', atk_findings: 'ကိုယ်စားလှယ်',
    atk_done: 'ATTACK: {n} ကိုယ်စားလှယ် P1/P2 သက်သေပြနှင့် findings ထဲသို့ ထည့်ပြီး', atk_empty: 'တိုက်ခိုက်မှု မရှိသေး: RECON စတင် ပြီးမှ ATTACK - req/res သက်သေပြနှင့် ကိုယ်စားလှယ်များ ဒီမှာ ရောက်လာမည်',
    navh: 'HUNT', h2hunt: 'HUNT - တကယ့်မျက်နှာပြင်နှင့် သက်သေပြ',
    h_ready: 'အသင့်', h_empty: 'မျက်နှာပြင် မရှိသေး: စာမျက်နှာများ, API endpoints, params, JS bundles နှင့် subdomains များကို map လုပ်ရန် RECON စတင်ပါ',
    h_fnd: 'ပရိုဂရမ်၏ findings', h_nofnd: 'ဤပရိုဂရမ်အတွက် finding မရှိ',
    rc_btn: 'RECON', rc_start: 'မျက်နှာပြင် recon လုပ်နေပါသည်: စာမျက်နှာများ, JS bundles, endpoints, params...',
    rc_done: 'မျက်နှာပြင် map ပြီး: endpoints, params နှင့် subdomains များကို ပရိုဂရမ်ကဒ်တွင် စာရင်းပြုစုပြီး', rc_fail: 'recon မအောင်မြင်: host ဆက်သွယ်မရ သို့မဟုတ် scope အလွတ်',
    rc_surface: 'မျက်နှာပြင်:', snd_on: 'အသံ: ON',
    snd_off: 'အသံ: OFF', snd_ok: 'interface အသံ ဖွင့်ထား - စာကြည့်တိုက်: နှိပ်, tab, ကူးယူ, သတိပေး',
    snd_stop: 'အသံအားလုံး ပိတ်ထား: C2FF အသံ မရှိတော့', amb_on: 'လေထု: ON',
    amb_off: 'လေထု: OFF', amb_ok: 'အသက်ဝင်လေထု - အရောင်မိသားစုများထဲမှ (အစိမ်း, အပြာ, အဝါ...) နှေးကွေးစွာ ရွှေ့လျော',
    amb_stop: 'လေထုကို မူလအစိမ်းရောင်၌ ရပ်တန့်ထား', nt_on: 'အသိပေးချက်: ON',
    nt_off: 'အသိပေးချက်: OFF', nt_ok: 'browser အသိပေးချက် ဖွင့်ထား - P1 နှင့် P2 တွင် beep',
    nt_denied: 'browser က အသိပေးချက်များ ပိတ်ထား: site ဆက်တင်များတွင် ခွင့်ပြုပါ', term_denied: 'terminal ငြင်းပယ် သို့ မရှိ: localhost လိုအပ်, သို့မဟုတ် admin အနေနှင့် room ဖွင့်ထား',
    term_p: 'စစ်မှန် bash - မြှားနှင့် မှတ်တမ်း, Ctrl+C ဖြတ်, Ctrl+D ပိတ်', term_restart: 'ပြန်စ',
    navtrm: 'TERM', term_h2: 'Terminal - အလုပ်လုပ် shell, console ထဲ တိုက်ရိုက်',
    fl_off: 'FLEET: ရပ်နား', fl_paused: 'FLEET: ခဏရပ်',
    fl_active: 'FLEET: လှုပ်ရှား ({n} အကြိမ်)', fl_last: 'နောက်ဆုံး အကြိမ်',
    fl_none: 'အကြိမ် မရှိသေး', fl_info: 'အကြားအလပ် {i} မိနစ်, ဘတ်ဂျက် {b} req/အကြိမ်',
    sub_ttl: 'command & control framework', navt: 'အချိန်ကာလ',
    tm_h2: 'အများသုံးချိန်ခွင် - ညီအကိုများ အတူလိုက်ပါ, network ပြင်ပဖြစ်စေ', tm_p: 'မျှဝေ room ဖွင့်ပါ: မင်းရဲ့အဖွဲ့ Fleet, findings များကိုမြင်ပြီး တိုက်ရိုက် triage လုပ်နိုင်။ အောက်တွင် ချိတ်ဆက် chat ရှိသည်။ ဝင်ရောက်ခွင့်သုံးဆင့်: LOCAL (တစ်ကိုယ်တော်), LAN ကို NETWORK ဖွင့်ခြင်းဖြင့်၊ WORLD ကို WORLD ဖွင့်ခြင်းဖြင့် - public tunnel (cloudflared ရှိပါက) ဖိတ်ကြားချက် link ကို မည်သည့် network မှမဆို သုံးနိုင်စေပြီး မင်းကွန်ပျူတာကို တိုက်ရိုက် မဖော်ပြဘဲ။ အားလုံး room key နဲ့သာ ဖြစ်သည် - လူအားလုံးကို တစ်ပြိုင်တည်းထုတ်ရန် key ပြန်ဖန်တီးပါ။',
    tm_handle: 'မင်းရဲ့နာမည် (အက္ခရာ 16 အများဆုံး)', tm_save_h: 'ရွေး',
    tm_room_ph: 'room နာမည် (ဥပမာ: c2ff-core)', tm_save: 'လိုက်နာ',
    tm_on: 'ROOM ဖွင့်ထား: {r} - {n} online', tm_off: 'TEAM MODE ပိတ် - ဒေသခံတစ်ကိုယ်တော်',
    tm_room: 'Room', tm_key: 'Room key',
    tm_regen: 'Key ပြန်ဖန်တီး', tm_regen_ok: 'key အသစ်ပြုလုပ်ပြီး - link ဟောင်းများ သေသွား',
    tm_invite: 'ဖိတ်ကြားချက် link (အဖွဲ့သို့ ကူးယူ)', tm_copy: 'ကူးယူ',
    tm_copied: 'clipboard သို့ ကူးယူပြီး', tm_members: 'အဖွဲ့ဝင်',
    tm_nobody: 'မရှိသေး - link ကို အဖွဲ့သို့ ပို့', tm_you: '(မင်း)',
    tm_here: 'တက်ရောက်', tm_saved: 'နာမည် သိမ်းဆည်းပြီး',
    tm_no_handle: 'နာမည်အလွတ်', tm_cfg_ok: 'room ပြင်ဆင်ပြီး',
    tm_cfg_no: 'မအောင်မြင်', tm_live: 'NETWORK ဖွင့်',
    tm_shore: 'ဒေသခံ ပြန်သွား', tm_need_on: 'အရင် room ဖွင့် (ON)',
    tm_bind_lan: 'NETWORK: {a}', tm_bind_lo: 'ဒေသခံ: localhost တည်း',
    to_team_live: '[GO-LIVE] server network access ဖြင့် ပြန်လည်စတင် - LAN link ပြသပြီး, 2 စက္ကန့်တွင် ပြန်ချိတ်', to_team_shore: 'server ဒေသခံ (127.0.0.1) ပြန်လည်စတင်ပြီး',
    tm_tun_open: 'WORLD ဖွင့် (tunnel)', tm_tun_close: 'TUNNEL ပိတ်',
    tm_tun_wait: 'public tunnel ဖွင့်နေ (စက္ကန့်အနည်းငယ်)…', tm_tun_on: 'ချိတ်ဆက် WORLD ဖွင့်ထား: {u} - ဖိတ်ကြားချက် link ဘယ်နေရာမှမဆို အလုပ်လုပ်, network တူရန်မလို',
    tm_tun_closed: 'tunnel ပိတ်ပြီး - LAN/ဒေသခံ ပြန်', tm_chat_empty: 'ချိတ်ဆက် channel ဖွင့်ထား - room အဖွဲ့ဝင်များ ဒီမှာ ဖတ်',
    tm_chat_h2: 'ချိတ်ဆက် chat', tm_msg_ph: 'ချိတ်ဆက်မှုသို့ စာ…',
    tm_admin: 'admin', tm_guest: 'ဧည့်သည်',
    tm_kick: 'KICK', tm_kick_ok: 'room မှ အဖွဲ့ဝင် ထုတ်ပြီး (နောက်တစ်ခါနှိပ်ရင် ပြန်ဖွင့်)',
    tm_role_ok: 'အခန်းကဏ္ဍ ပြင်ဆင်ပြီး', tm_mic_on: 'microphone ဖွင့်',
    tm_mic_off: 'microphone ပိတ်', tm_mic_denied: 'microphone ငြင်းပယ် သို့ မရှိ: HTTPS လိုအပ် (WORLD tunnel သို့ localhost) နှင့် microphone ခွင့်ပြုရန်',
    navf: 'Fleet', navfd: 'Findings',
    navp: 'ပရိုဂရမ်', navai: 'AI',
    navc: 'ညှိနှိုင်း', st_runs: 'Run',
    st_beacons: 'Beacons လှုပ်ရှား', st_sig: 'အချက်ပြ',
    h2f: 'Fleet - ပရိုဂရမ်အားလုံး, လှုပ်ရှားနေသော agent များ ရှေ့', h2fd: 'Findings စုဆောင်းမှု - တည်ငြိမ် triage အမှတ်အသား',
    h2eng: 'Fleet ဇကာမော်တာ - token မပါ ဒေသခံ အကြိမ်', h2prog: 'ပရိုဂရမ်များ - scope, လိုအပ် header, စတင်',
    h2new: 'ပရိုဂရမ်အသစ်', h2ai: 'AI agent - အလုံးစုံ ရွေးချယ်စရာ ချိတ်ဆက်',
    h2c: 'ညှိနှိုင်း - ကိုယ်ပိုင် channel', fl_start: 'စတင်',
    fl_pause: 'ခဏရပ်', fl_cycle: 'အခု အကြိမ်',
    f_add: 'ထည့်', f_none: 'အချက်ပြ မရှိသေး',
    f_ph: 'လက်ဖြင့် finding: endpoint + သက်သေ + ခံနိုင်ရည်ရှိ severity…', st_sig_off: 'အချက်ပြ',
    st_sig_an: 'စစ်ဆေးခြင်း', st_sig_sub: 'တင်ပြပြီး',
    st_sig_dup: 'ထပ်နေ', st_sig_ref: 'ငြင်းပယ်',
    st_sig_cl: 'ပိတ်ပြီး', r_none: 'run မတွေ့ရ',
    r_live: '{n} လှုပ်ရှားနေ', r_done: 'ပြီးပြည့်',
    r_feed: '▽ flow ({n} ev)', r_close: '△ လျှော့ချ',
    p_name_ph: 'ပရိုဂရမ်နာမည် (ဥပမာ: PayPal)', p_hdr_ph: 'လိုအပ်သော သုတေသီ header (ဥပမာ: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domain1, domain2, …', p_save: 'သိမ်းဆည်း',
    p_local: 'module(s), 100% ဒေသခံ', ai_p: 'C2FF သည် AI မပါဘဲ အပြည့်အဝလည်ပတ်သည်: modes များကို ဒေသခံ probes ဖြင့် အဓိပ္ပာယ်ပရောဂျက်လုပ်ထားသည်။ ဤ gateway သည် finding တစ်ခုကို လိုအပ်သည့်အခါ <b>မင်းရဲ့</b> AI (self-hosted သို့ API) ချိတ်ဆက်ရုံသာ။ FINDINGS တွင် <span style="color:var(--green)">AI »</span> ခလုတ်, အဖြေ COORDINATION တွင်။ ဤ setting မရှိပါက data များ မင်းရဲ့စက်မှ မထွက်ဘဲ။',
    ai_off: 'ပိတ်', ai_on: 'ဖွင့်',
    ai_st_off: 'AI ပိတ် - framework ကို မပါဘဲ 100% ဒေသခံလည်ပတ်', ai_st_ready: 'AI ချိတ်ဆက်ပြီး: {p} · {m}',
    ai_st_inc: 'AI ဖွင့်ထားသော်လည်း မပြည့်စုံ: baseURL နှင့် model လိုအပ်', ai_url_ph: 'base URL - ဥပမာ: http://localhost:11434 သို့ https://api.MyAI.tld/v1',
    ai_model_ph: 'model - ဥပမာ: llama3.1:8b', ai_key_ph: 'API key (ဒေသခံ server အတွက် အလွတ်ထား)',
    ai_save: 'သိမ်းဆည်း', ai_test: 'ချိတ်ဆက်မှု စစ်ဆေး',
    ai_testing: 'စစ်ဆေးနေ…', ai_ok: 'OK - အဖြေ: ',
    ai_fail: 'မအောင်မြင်: ', ai_note: 'config ကို data/ai.json တွင် ဒေသခံသိမ်း - မင်းထည့်ထားတဲ့ endpoint မှတစ်ပါး ဘယ်နေရာမှ မပို့ဘဲ',
    ch_ph: 'root@c2ff:~# စစ်ဆေး agent သို့ စာ…', ch_send: 'ပို့',
    ch_empty: 'Channel ဖွင့်ထား။ ဒီမှာရိုက်, monitor က ချက်ချင်း နှိုးလိမ့်မည်။', ft: '100% ဒေသခံ - probes အားလုံး အဆုံးသတ်ထား, token မပါ ပြင်ပမှီခိုမှု မရှိ - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE လှုပ်ရှား: ဒေသခံ အကြိမ် ၃၀ မိနစ်တစ်ကြိမ်, 0 token.', to_fl_pa: 'FLEET ခဏရပ် - မင်းလိုချင်တဲ့အခါ ဆက်လက်။',
    to_fl_cy: 'အခုတော့ အကြိမ် စတင်ပြီး (ဘတ်ဂျက် 60 req)။', to_launch: '[GO] {m} mode (CWE {c}) on {p} - ဒေသခံအကြိမ် စတင်ပြီး',
    to_ai_ok: 'config သိမ်းဆည်းပြီး', to_ai_no: 'သိမ်းဆည်းခြင်း မအောင်မြင်',
    to_ai_no_cfg: 'AI မဖွင့်ရသေး - AI tab တွင် ပြင်ဆင်', to_ai_head: 'AI စစ်ဆေး',
    to_ai_bad: 'AI စစ်ဆေးခြင်း မအောင်မြင်', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ စတင်', navar: 'လက်နက်တိုက်',
    ar_h2: 'လက်နက်တိုက် - တွေ့ရှိထားသော မျက်နှာပြင်ပေါ်ရှိ CVE, EPSS နှင့် exploit များ', ar_sync: 'SYNC ဒေတာဘေ့စ်',
    ar_btn: 'ခြေလှမ်းများ', ar_exec: 'EXEC',
    ar_none: 'ခြေလှမ်း မရှိပါ - RECON ကို အရင်လည်ပတ်ပါ၊ ပြီးလျှင် KEV/EPSS တင်ရန် SYNC ကို လည်ပတ်ပါ', ar_loading: 'ဒေတာဘေ့စ် အနှစ်ချုပ် တင်နေသည်...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'ဒီမို အစီအစဉ် - စကင်န် မရှိ: ကိုယ်ပိုင် အစီအစဉ် ဖန်တီးပါ', pip_noprog: 'အစီအစဉ် မရှိသေးပါ: အစီအစဉ်များ တက်ဘ်တွင် ကိုယ်ပိုင် ဖန်တီးပါ',
    pip_next: 'နောက်အဆင့်:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  ps: {
    pl_title: 'د کار پلان', pl_empty: 'تر اوسه پلان نشته: په پورتني کارت کې RECON پیل کړه، فرضیې دلته راځي (حالات ثابت دي)',
    pl_run: 'پیل', pl_reflect: 'canary منعکس شو',
    st_do: 'ترسره کول', st_test: 'تست شوی',
    st_signal: 'سیګنال', st_valid: 'تصدیق شوی',
    st_void: 'هیڅ نه', atk_btn: 'ATTACK',
    atk_start: 'برید پر سطحه: endpoints، ښکاره شوي docs، JWT، رازونه...', atk_fail: 'برید ناشونی: لومړی RECON پیل کړه',
    atk_none: 'سیګنال نشته', atk_findings: 'کانديدان',
    atk_done: 'ATTACK: {n} کانديدان P1/P2 له ثبوت سره findings ته ورننوتل', atk_empty: 'تر اوسه برید نشته: RECON پیل کړه بیا ATTACK - کانديدان له req/res ثبوت سره دلته راځي',
    navh: 'HUNT', h2hunt: 'HUNT - حقیقي سطحه او ثبوت',
    h_ready: 'چمتو', h_empty: 'تر اوسه سطحه نشته: pages، API endpoints، params، JS bundles او subdomains نقشه کولو لپاره RECON پیل کړه',
    h_fnd: 'پروګرام findings', h_nofnd: 'د دې پروګرام لپاره findings نشته',
    rc_btn: 'RECON', rc_start: 'د سطحې recon روان دی: pages، JS bundles، endpoints، params...',
    rc_done: 'سطحه نقشه شوه: endpoints، params او subdomains د پروګرام کارت کې لیست شول', rc_fail: 'recon پاتې راغی: host ته لاسرسی نشته یا scope تش دی',
    rc_surface: 'سطحه:', snd_on: 'غږ: ON',
    snd_off: 'غږ: OFF', snd_ok: 'انټرفیس غږ فعال - کتابتون: کلیک، ټۍب، کاپي، خبرتیاوې',
    snd_stop: 'بشپړ موسیقي بند: نور هیڅ C2FF غږ نشته', amb_on: 'فضا: ON',
    amb_off: 'فضا: OFF', amb_ok: 'ژوندۍ فضا - رنګ د کورنیو پر مخ (زه‌ر، آبي، ژیژن...) نرم ښګیږي',
    amb_stop: 'په اصل زه‌ر رنګ کې فضا وده کړې', nt_on: 'خبرتیاوې: ON',
    nt_off: 'خبرتیاوې: OFF', nt_ok: 'براوزر خبرتیاوې فعال - په P1 او P2 کې بیپ',
    nt_denied: 'براوزر خبرتیاوې بندې کړې: په site تنظیماتو کې اجازه ورکړه', term_denied: 'terminal رد شو یا نشته: localhost اړین دی، یا خونې admin په توګه خلاصې',
    term_p: 'حقیقي bash - د تېرو تاریخ، Ctrl+C وقفه، Ctrl+D تړل', term_restart: 'بیا تنظیم کړه',
    navtrm: 'TERM', term_h2: 'Terminal - کار shell، مستقیم په کانسول کې',
    fl_off: 'FLEET: ودريږ', fl_paused: 'FLEET: ودريږ',
    fl_active: 'FLEET: فعال ({n} سیکلونه)', fl_last: 'وروستی سایکل',
    fl_none: 'تر اوسه سایکل نشته', fl_info: 'وقفه {i} دقیقې، بودجه {b} req/سایکل',
    sub_ttl: 'command & control framework', navt: 'غونډه',
    tm_h2: 'د ګروپ غونډې - د شبکې بهر هم یوځای ښکار', tm_p: 'مشترکه خونه پرانیزه: ستا کوربه fleet، findings ګوري او ژوندي triage کولی شي. لاندې ځانګړې غونډه چټ. د لاسرسي درې ډولونه: LOCAL (یوازې)، د NETWORK پرانیستلو له لارې LAN، او د WORLD پرانیستلو له لارې نړۍ - عامه تونل (که cloudflared نصب وي) د بلنې لینک له هرې شبکې کار کوي، ستا ماشین مستقیم نه ښکاري. ټول څه د خونې کیلي سره دي - ټول کسان یوځای ایستلو لپاره کیلي بیا جوړه کړه.',
    tm_handle: 'ستا نوم (تر ۱۶ تورو)', tm_save_h: 'ټاکل',
    tm_room_ph: 'د خونې نوم (بېلګه: c2ff-core)', tm_save: 'پلي کول',
    tm_on: 'خونه خلاصه: {r} - {n} آنلاین', tm_off: 'TEAM موډ بند - ځایی یوځلی غونډه',
    tm_room: 'خونه', tm_key: 'د خونې کیلي',
    tm_regen: 'کیلي بیا جوړول', tm_regen_ok: 'نوې کیلي جوړه شوه - زوړ لینکونه مړه دي',
    tm_invite: 'د بلنې لینک (ستا ټیم ته کاپي کړه)', tm_copy: 'کاپي',
    tm_copied: 'کلیپ بورډ ته کاپي شو', tm_members: 'غړي',
    tm_nobody: 'تر اوسه څوک نشته - لینک ټیم ته ولیږه', tm_you: '(ته)',
    tm_here: 'حاضر', tm_saved: 'نوم خوندي شو',
    tm_no_handle: 'نوم تش دی', tm_cfg_ok: 'خونه اپډېټ شوه',
    tm_cfg_no: 'پاتې راغی', tm_live: 'شبکه ته خلاصه کړه',
    tm_shore: 'ځایی ته بېرته', tm_need_on: 'لومړی خونې فعال کړه (ON)',
    tm_bind_lan: 'شبکه: {a}', tm_bind_lo: 'ځایی: یوازې localhost',
    to_team_live: '[GO-LIVE] سرور د شبکې لاسرسي سره بیا پیل شو - LAN لینک ښکاري، ۲ ثانیو کې بیا رابطه', to_team_shore: 'سرور ځایی (127.0.0.1) بیا پیل شو',
    tm_tun_open: 'نړۍ ته خلاصه کړه (تونل)', tm_tun_close: 'تونل بند کړه',
    tm_tun_wait: 'عامه تونل پرانیستل کیږي (څو دقیقې)…', tm_tun_on: 'غونډه نړۍ ته خلاصه: {u} - د بلنې لینک له هر ځایه کار کوي، ورته شبکه اړینه نده',
    tm_tun_closed: 'تونل بند شو - LAN/ځایي ته بېرته', tm_chat_empty: 'غونډه چینل خلاصه - د خونې غړي دلته یوبل لولي',
    tm_chat_h2: 'غونډه چټ', tm_msg_ph: 'غونډې ته پیغام…',
    tm_admin: 'ادمین', tm_guest: 'میلمه',
    tm_kick: 'KICK', tm_kick_ok: 'غړی له خونې ويستل شو (بیا کلیک دې خلاصولي)',
    tm_role_ok: 'رول اپډېټ شو', tm_mic_on: 'مایک فعال',
    tm_mic_off: 'مایک بند', tm_mic_denied: 'مایک رد شو یا نشته: HTTPS اړین دی (تونل WORLD یا localhost) او باید اجازه ورکړه',
    navf: 'Flot', navfd: 'Findings',
    navp: 'پروګرامونه', navai: 'AI',
    navc: 'همغږي', st_runs: 'Runs',
    st_beacons: 'فعال beacons', st_sig: 'سیګنالونه',
    h2f: 'Flot - ټول پروګرامونه، روان agent لومړی', h2fd: 'د findings اساسه - ثابت triage نښه',
    h2eng: 'د Flot ماشین - بې token ځایي سایکلونه', h2prog: 'پروګرامونه - scope، لازمي header، پیل کول',
    h2new: 'نوی پروګرام', h2ai: 'AI ایجنټ - ۱۰۰٪ اختیاري چلول',
    h2c: 'همغږي - خصوصي چینل', fl_start: 'پیل',
    fl_pause: 'وقفه', fl_cycle: 'اوس سایکل',
    f_add: 'اضافه کړه', f_none: 'تر اوسه سیګنال نشته',
    f_ph: 'لاسي finding: endpoint + ثبوت + دفاع وړ severity…', st_sig_off: 'سیګنال',
    st_sig_an: 'تحلیل', st_sig_sub: 'وسپارل شو',
    st_sig_dup: 'دوبل', st_sig_ref: 'رد شو',
    st_sig_cl: 'تړل شوی', r_none: 'هېڅ run نه موندل شو',
    r_live: '{n} روان', r_done: 'پای',
    r_feed: '▽ feed ({n} ev)', r_close: '△ تړل',
    p_name_ph: 'د پروګرام نوم (بېلګه: PayPal)', p_hdr_ph: 'لازمي پلټونکي header (بېلګه: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domain1, domain2, …', p_save: 'خوندي کول',
    p_local: 'module(s)، ۱۰۰٪ ځایی', ai_p: 'C2FF پرته له AI بشپړ کار کوي: موډونه دقیق ځایي probes دي. دا دروازه یوازې <b>ستا</b> AI (self-hosted یا API) د یو finding غوښتنې تحلیل سره نښلوي: FINDINGS کې <span style="color:var(--green)">AI »</span> بټن، ځواب COORDINATION کې. له دې تنظیم پرته هیڅ معلومات ستا ماشینه نه وتل.',
    ai_off: 'بند', ai_on: 'فعال',
    ai_st_off: 'AI بند - فریم ورک بې دې ۱۰۰٪ ځایي کار کوي', ai_st_ready: 'AI وصل دی: {p} · {m}',
    ai_st_inc: 'AI فعال خو نیمګړی: baseURL او model اړین دي', ai_url_ph: 'base URL - بېلګه: http://localhost:11434 یا https://api.MyAI.tld/v1',
    ai_model_ph: 'model - بېلګه: llama3.1:8b', ai_key_ph: 'API کیلي (ځایي سرور ته تش پرېږده)',
    ai_save: 'خوندي کول', ai_test: 'اتصال ازمویل',
    ai_testing: 'ازمویل کیږي…', ai_ok: 'OK - ځواب: ',
    ai_fail: 'پاتې راغی: ', ai_note: 'تنظیم data/ai.json کې ځایي خوندي شي - پرته له هغه endpoint چې ته یې ایښي بل هیڅ ځای ته نه لیږل کیږي',
    ch_ph: 'root@c2ff:~# د تحلیل ایجنټ ته پیغام…', ch_send: 'لېږل',
    ch_empty: 'چینل خلاص دی. دلته ولیکه، monitor زه فوري ویښ کړي.', ft: '۱۰۰٪ ځایلې - دقیق probes، بې tokens بې بهرنۍ اړتیاوې - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE فعال: ځایي سایکلونه هرې ۳۰ دقیقې، 0 token.', to_fl_pa: 'FLEET ودريږ - هر کله چې غوښتل بیا پیل کړه.',
    to_fl_cy: 'فوري سایکل پیل شو (بودجه ۶۰ req).', to_launch: '[GO] {m} موډ (CWE {c}) پر {p} - ځایي سایکل پیل شو',
    to_ai_ok: 'تنظیم خوندي شو', to_ai_no: 'خوندي کول پاتې راغل',
    to_ai_no_cfg: 'AI تنظیم ندی شوی - په AI ټاب کې ورکه کړه', to_ai_head: 'AI تحلیل',
    to_ai_bad: 'AI تحلیل پاتې راغی', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ پیل', navar: 'آرسنال',
    ar_h2: 'آرسنال - د پېژندل شوې سطح CVE، EPSS او ایکسپلويټونه', ar_sync: 'SYNC ډېټابیسونه',
    ar_btn: 'ګامه', ar_exec: 'EXEC',
    ar_none: 'ګام نشته: لومړی RECON چلوه، بیا د KEV/EPSS بارولو لپاره SYNC چلوه', ar_loading: 'د ډېټابیسونو لنډیز بارېږي...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'ډیمو پروګرام - سکن نشته: خپل پروګرام جوړ کړه', pip_noprog: 'پروګرام نشته: په پروګرامونو ټب کې خپل پروګرام جوړ کړه',
    pip_next: 'بل پړاو:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  ku: {
    pl_title: 'پلانی کار', pl_empty: 'هێشتا پلان نیە: RECON لە کارتی سەرەوە ڕەوانە کە، گریمانەکان لێرە دەکەون (دۆخەکان پەیدا دەبن)',
    pl_run: 'بەجوێکردن', pl_reflect: 'canary دەنگی وەرگرت',
    st_do: 'بکردنی', st_test: 'تاقیکراوە',
    st_signal: 'سەیری', st_valid: 'دڵنیاکراوە',
    st_void: 'هیچ', atk_btn: 'ATTACK',
    atk_start: 'هێرش بۆ ڕەوەت: endpoints، دۆکیومێنت کراوەکان، JWT، نهەنییەکان...', atk_fail: 'هێرش نەکرا: یەکەم RECON ڕەوانە کە',
    atk_none: 'هیچ سەیرێک نیە', atk_findings: 'باڵوێژەکان',
    atk_done: 'ATTACK: {n} باڵوێژەکان P1/P2 بە بەڵگە دەبن بە findings', atk_empty: 'هێرش نیە تێوەشتی: RECON ڕەوانە کە دواتر ATTACK - باڵوێژەکان بە بەڵگە req/res لێرە دەکەون',
    navh: 'HUNT', h2hunt: 'HUNT - ڕەوەتی ڕەسەن و بەڵگە',
    h_ready: 'ئامادە', h_empty: 'ڕەوەت نیە: RECON ڕەوانە کە بۆ دیاریکردنی پەڕەکان، API endpoints، params، JS bundles و subdomains',
    h_fnd: 'د ئەوەی بەرنامەکە', h_nofnd: 'بۆ ئەم بەرنامەیە هیچ dọk نیە',
    rc_btn: 'RECON', rc_start: 'recon ڕەوەت کار دەکات: پەڕەکان، JS bundles، endpoints، params...',
    rc_done: 'ڕەوەت نەخشە خرا: endpoints، params و subdomains لێتکران لە کارتی بەرنامە', rc_fail: 'recon شکێت خوارد: host بەردەست نیە یان scope بەتاڵە',
    rc_surface: 'ڕەوەت:', snd_on: 'دە‌نگ: ON',
    snd_off: 'دە‌نگ: OFF', snd_ok: 'دە‌نگەکانی interface چالاک - کتێبەخانە: کلیک، tab، کۆپچی‌بڕین، فەرمانە',
    snd_stop: 'هەموو دە‌نگ بەند: هیچ C2FF دە‌نگ نیە', amb_on: 'گە‌شە: ON',
    amb_off: 'گە‌شە: OFF', amb_ok: 'گە‌شەی زیندو - ڕەنگ بە نرمی لە بنەماڵە ڕەنگا (سەوز، شین، زەرد...) دە‌سووشێت',
    amb_stop: 'گە‌شە لە سەر سەوزی سەرەکی وتووە', nt_on: 'ئاگادارەکان: ON',
    nt_off: 'ئاگادارەکان: OFF', nt_ok: 'ئاگاداری براوزەر چالاک - P1 و P2 دە‌نگی bip',
    nt_denied: 'براوزەر ئاگاداری بەند کردە: لە رێکخستنەکانی site ڕێپێبدە', term_denied: 'terminal وەڵام درا یان نیە: localhost پێویستە، یان ژوور وەک admin کراوە',
    term_p: 'bash ڕەسەن - مێژوو بە تێرنێڕ، Ctrl+C وە‌دە‌ستان، Ctrl+D دادە‌خات', term_restart: 'ڕێک‌خستن',
    navtrm: 'TERM', term_h2: 'Terminal - shellی کار، راستەوخۆ لە کۆنسۆڵ',
    fl_off: 'FLEET: وە‌ستاو', fl_paused: 'FLEET: ڕاگیراو',
    fl_active: 'FLEET: کارا ({n} سووک)', fl_last: 'دوا سووک',
    fl_none: 'هێشتا هیچ سووک نیە', fl_info: 'ماوە {i} خولەک، بووجەی {b} req/سووک',
    sub_ttl: 'command & control framework', navt: 'کۆبوونەوە',
    tm_h2: 'کۆبوونەوەی گروپ - پالە‌کردن پێکەوە، تەنانەت لە درەوە نیاوە', tm_p: 'ژوره هونەکردە: گروپی تۆ fleet، findings دە‌بینیت و triage ی زیندو دە‌کات. چاتی تایبەتی دانیشتن لە خوارەوە. سێ ئاستی چوونە ژوورەوە: LOCAL (تاکە)، LAN بە کردنەوە بۆ تۆڕ، و جیهان بە کردنەوە بۆ جیهان - تۆنێلی گشتی (cloudflared ئەگەر دانراوە) لینکی بانگکردن لە هەر تۆڕێک بەکار دەهێنێت، ماکینی تۆ راستەوخۆ دیاری ناکات. هەموو شت دە‌گەل کیلی ژوورە - لە بەیانکەردن هەموو کەس لە یەک کاتدا بۆ دووبارا دروستکردنی کیلی.',
    tm_handle: 'ناوی تۆ (تر ١٦ پیت)', tm_save_h: 'دانان',
    tm_room_ph: 'ناوی ژوور (نمونە: c2ff-core)', tm_save: 'جێبەجێ کردن',
    tm_on: 'ژوور کراوە: {r} - {n} آنلاین', tm_off: 'حالت TEAM بەزاو - دانیشتنی ڕەسمی تاکە',
    tm_room: 'ژوور', tm_key: 'کیلی ژوور',
    tm_regen: 'دووبارا دروستکردنی کیلی', tm_regen_ok: 'کیلی نوێ دروست کرا - لینکە کهوەتەوە مەر',
    tm_invite: 'لینکی بانگکردن (بۆ تیمەوە کۆپچی‌بڕ)', tm_copy: 'کۆپچی‌برکردن',
    tm_copied: 'کۆپ لە کلیپبۆرد کرا', tm_members: 'ئە‌ندام',
    tm_nobody: 'هێشتا هیچ کەسی نیە - لینکە بنێرە بۆ تیم', tm_you: '(تۆ)',
    tm_here: 'ئە‌وێدا', tm_saved: 'ناو خە‌زێنە کرا',
    tm_no_handle: 'ناو بەتاڵە', tm_cfg_ok: 'ژوور ناوازە کرا',
    tm_cfg_no: 'شکست', tm_live: 'کراوی تۆڕ',
    tm_shore: 'بەرەو ڕە‌زمی', tm_need_on: 'یە‌کەم ژوور ڕە‌زە بکە (ON)',
    tm_bind_lan: 'تۆڕە: {a}', tm_bind_lo: 'ڕە‌زمە: بەشکە‌رە localhostی',
    to_team_live: '[GO-LIVE] سێرڤەر لە‌دوێندەوە لە‌گە‌ل دە‌ستگی‌تنی تۆڕ - لینکی LAN دیاره، ٢ چرکە دووبارا پە‌یوەندی', to_team_shore: 'سێرڤەر دووبارا ڕە‌زە بۆ ڕە‌زم (127.0.0.1)',
    tm_tun_open: 'کراوی جیهان (تۆنیڵ)', tm_tun_close: 'دادە‌خستنی تۆنیل',
    tm_tun_wait: 'تۆنیلی گشتی لە‌دە‌ردەوە (چەند چرکە)…', tm_tun_on: 'دانیشتن کراوی جیهان: {u} - لینکی بانگکردن لە هەر شوێن کاردەکات، پێویست ناکات هەمان تۆڕ بێت',
    tm_tun_closed: 'تۆنیل داخرا - بەرەو LAN/ڕە‌زم', tm_chat_empty: 'کاناڵی دانیشتن کراوە - ئە‌ندامانی ژوور لێرە بە یەکو دیار دە‌خوێنن',
    tm_chat_h2: 'چاتی دانیشتن', tm_msg_ph: 'پە‌یام بۆ دانیشتن…',
    tm_admin: 'ئە‌دمین', tm_guest: 'مێ‌مان',
    tm_kick: 'KICK', tm_kick_ok: 'ئە‌ندام لە ژوورەوە ڕاژاوە (دووبارا کلیک بکە بۆ کراوەکردن)',
    tm_role_ok: 'ڕۆڵ نوێ‌کراوە', tm_mic_on: 'مایک کارا بکە',
    tm_mic_off: 'مایک داخە بکە', tm_mic_denied: 'مایک ڕاوێژا یان نیە: HTTPS پێویستە (تۆنیلی جیهان یان localhost) و پێویستە مایک ڕێپە‌ی بێت',
    navf: 'Flot', navfd: 'Findings',
    navp: 'بەرنامەکان', navai: 'AI',
    navc: 'هاوکاری', st_runs: 'Runs',
    st_beacons: 'بەکەار beacons', st_sig: 'سەیرەکان',
    h2f: 'Flot - هەموو بەرنامەکان، ئە‌گە‌نتەکانی کاری یە‌کەم', h2fd: 'بنەمای findings - نە‌گە‌راندنی triage',
    h2eng: 'مە‌شینەی Flot - سووکی ڕە‌زە بە بێ token', h2prog: 'بەرنامەکان - scope، ناوی ژووری پێویست، بە‌رە‌پە‌ردن',
    h2new: 'بەرنامەی نوێ', h2ai: 'ئە‌گە‌نتی AI - ١٠٠% ویسترا‌وی',
    h2c: 'هاوکار - کاناڵی ناوازە', fl_start: 'وە‌رە',
    fl_pause: 'ڕاو‌گەهە‌کە', fl_cycle: 'سووکی ئێستا',
    f_add: 'زیاد بکە', f_none: 'هێشتا هیچ سەیر نیە',
    f_ph: 'دە‌ستکردی dọk: endpoint + بەڵگە + severityی بەرگە‌گرتەوە…', st_sig_off: 'سەیر',
    st_sig_an: 'شیکردنەوە', st_sig_sub: 'ناردراوە',
    st_sig_dup: 'دووبارە', st_sig_ref: 'ڕە‌ت کراوە',
    st_sig_cl: 'داخەکراوە', r_none: 'هیچ run دیال نەکراوە',
    r_live: '{n} کاردە‌کات', r_done: 'تە‌واو',
    r_feed: '▽ flow ({n} ev)', r_close: '△ داخە‌کردن',
    p_name_ph: 'ناوی بەرنامە (نمونە: PayPal)', p_hdr_ph: 'ناوی ژووری لێکۆ‌لینەوەی پێویست (نمونە: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domain1, domain2, …', p_save: 'پاشە‌کەوت',
    p_local: 'module(s)، ١٠٠% ڕە‌زە', ai_p: 'C2FF هەموو بێ AI کار دەکات: مودەکان لێ‌پردنی ڕە‌زمی ناوازە. ئە‌م دە‌رگا تە‌نها بە‌کاردێ لە بە‌دە‌روونی <b>خودی تۆ</b> (self-hosted یان API) بۆ شیکردنەوە یە‌ک dọk: بە‌تتنی <span style="color:var(--green)">AI »</span> لە FINDINGS، وە‌لام لە COORDINATION. هیچ داتا لە ماکینی تۆ ناکەفت بۆ دە‌ر بێ ئە‌م ڕێ‌خستن.',
    ai_off: 'داخەکراو', ai_on: 'کارا',
    ai_st_off: 'AI داخەکراوە - framework ١٠٠% ڕە‌زە کار دەکات بێ ئە‌م', ai_st_ready: 'AI بە‌ستراوە: {p} · {m}',
    ai_st_inc: 'AI کارا بەڵام ناکاوە: baseURL و model پێویستن', ai_url_ph: 'base URL - نمونە: http://localhost:11434 یان https://api.MyAI.tld/v1',
    ai_model_ph: 'model - نمونە: llama3.1:8b', ai_key_ph: 'کیلی API (بەتاڵ بۆ سێرڤەری ڕە‌زم)',
    ai_save: 'پاشە‌کەوت', ai_test: 'تاقیکردنی پە‌یوەندی',
    ai_testing: 'تاقیکردن…', ai_ok: 'OK - وە‌لام: ',
    ai_fail: 'شکست: ', ai_note: 'ڕێ‌خستن لە data/ai.json ڕە‌زمی خە‌زێنە دە‌کات - هەرگیز ناونرێ چێکی تۆ جگە لە endpoint کە خودی‌ت داناوە',
    ch_ph: 'root@c2ff:~# پە‌یام بۆ ئە‌گە‌نتی شیکردنەوە…', ch_send: 'بە‌ردە‌ر بە',
    ch_empty: 'کاناڵ کراوە. لێرە بنوسە، monitor بە خێرایی من ڕە‌وانە دەکات.', ft: '١٠٠% ڕە‌زە - probesی ناوازە، بە بێ tokens بە بێ پە‌چە‌رە وە‌ند - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE کارا: سووکی ڕە‌زم هەر ٣٠ خولەک، 0 token.', to_fl_pa: 'FLEET ڕاو‌گە - هەر کات کە دە‌تە‌وەت دە‌ست پێبکە.',
    to_fl_cy: 'سووکی خوێی پە‌یپە‌ی دە‌ست پێ کرد (بودجە ٦٠ req).', to_launch: '[GO] مودی {m} (CWE {c}) لە {p} - سووکی ڕە‌زم دە‌ست پێ کرد',
    to_ai_ok: 'ڕێ‌خستن خە‌زێنە کرا', to_ai_no: 'خە‌زێنەکردن شکست',
    to_ai_no_cfg: 'AI ڕێ‌نەخستراوە - لە ئاب AI ڕێ‌ی بنێرە', to_ai_head: 'شیکردنەوەی AI',
    to_ai_bad: 'شیکردنەوەی AI شکست', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ پە‌رە‌کردن', navar: 'Arsenal',
    ar_h2: 'ARSENAL - CVE, EPSS û exploitên li ser rûyê hatî dîtin', ar_sync: 'SYNC BAZA DANEYAN',
    ar_btn: 'TEVGER', ar_exec: 'EXEC',
    ar_none: 'tevger tune ye: pêşî RECON bimeşîne, paşê ji bo barkirina KEV/EPSS SYNC bimeşîne', ar_loading: 'kurtpeya bazan tê barkirin...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'bernameya demo - skan tune ye: bernameya xwe biafirîne', pip_noprog: 'tu bername tune ye: di taba Bernameyan de ya xwe biafirîne',
    pip_next: 'gava pêş:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  sd: {
    pl_title: 'ڪم جو پلان', pl_empty: 'اڃا پلان ناهي: مٿين ڪارڊ تي RECON هلاءِ، مفروضا هتي اچن (حالتون محفوظ رهندا)',
    pl_run: 'هلاءِ', pl_reflect: 'canary عڪس',
    st_do: 'ڪرڻو', st_test: 'تست ڪيل',
    st_signal: 'ئشارو', st_valid: 'موثق',
    st_void: 'ڪجهه بہ ناهي', atk_btn: 'ATTACK',
    atk_start: 'سطح تي حملا: endpoints، نمايان docs، JWT، راز...', atk_fail: 'حملا ناممڪن: پهرين RECON هلاءِ',
    atk_none: 'ڪوبہ ئشارو ناهي', atk_findings: 'عامريدار',
    atk_done: 'ATTACK: {n} عامريدار P1/P2 ثبوت سان findings ۾ داخل ٿيا', atk_empty: 'اڃا حملا ناهي: RECON هلاءِ پوءِ ATTACK - req/res ثبوت سان عامريدار هتي اچن',
    navh: 'HUNT', h2hunt: 'HUNT - حقيقي سطح ۽ ثبوت',
    h_ready: 'تيار', h_empty: 'ڪوبہ سطح ناهي: صفحا، API endpoints، params، JS bundles ۽ subdomains نقشن ڪرڻ لاءِ RECON هلاءِ',
    h_fnd: 'پروگرام جا findings', h_nofnd: 'ھن پروگرام لاءِ ڪوبہ finding ناهي',
    rc_btn: 'RECON', rc_start: 'سطح جو recon هلando رهيو: صفحا، JS bundles، endpoints، params...',
    rc_done: 'سطح نقشن ٿي: endpoints، params ۽ subdomains پروگرام ڪارڊ ۾ لسٽ ٿيا', rc_fail: 'recon ناڪام: host رجوع نه ٿيندو يا scope خالي',
    rc_surface: 'سطح:', snd_on: 'آواز: ON',
    snd_off: 'آواز: OFF', snd_ok: 'انٽرفيس آواز فعال - ڪتابتون: ڪلڪ، ۽تاب، ڪاپي، خبرداري',
    snd_stop: 'مڪمل خاموشي: هاڻي ڪوبہ C2FF آواز ناهي', amb_on: 'ماحول: ON',
    amb_off: 'ماحول: OFF', amb_ok: 'زنده ماحول - رنگ گهرن مان (سائو، نيرو، پيلو...) نرمي سان گذري',
    amb_stop: 'ماحول اصل سائو رنگ تي بيٺو', nt_on: 'اطلاعات: ON',
    nt_off: 'اطلاعات: OFF', nt_ok: 'برائوزر اطلاعات فعال - P1 ۽ P2 تي بيپ',
    nt_denied: 'برائوزر اطلاعات بند ڪيون: site جي سيٽنگن ۾ اجازو ڏجو', term_denied: 'ٽرمنل انڪار ٿيو يا موجود ناهي: localhost ضروري، يا ائڊمن ٽپالي تي خالي حاصلو',
    term_p: 'حقيقي bash - ايرڙ تاريخ، Ctrl+C ڇاھي، Ctrl+D بند', term_restart: 'ٻيهر سيٽ',
    navtrm: 'TERM', term_h2: 'ٽرمنل - ڪم جو shell، ڪنسول ۾ سڌو',
    fl_off: 'FLEET: بند', fl_paused: 'FLEET: محدود',
    fl_active: 'FLEET: فعال ({n} چڪر)', fl_last: 'آخري چڪر',
    fl_none: 'اڃا ڪوبہ چڪر ناهي', fl_info: 'فاصلو {i} منٽ، بجيٽ {b} req/چڪر',
    sub_ttl: 'command & control framework', navt: 'سيشن',
    tm_h2: 'گروپ سيشنون - ڪل بز رلائي، نيٽ ورڪ ٻاهر بہ', tm_p: 'حصيدار ڪمرو کليو: تنهنجو ٽيم Fleet، findings ڏسندا ۽ ساهيو triage ڪري سگهندا. هيٺ سيشن چيٽ. ٽي درجا داخل: LOCAL (اڪيلي)، LAN NETWORK کلي ڪرڻ سان، ۽ دنيا WORLD کلي ڪرڻ سان - عالمي سرنگ (cloudflared رڳو) اڏايل لاڊ ڪنهن ۽ به نيٽ ورڪ مان ڪم ڪندو، تنهنجي مشين سڌي ظاهر ناهي. هر شئ چمرو چاٻي سان آهي - ٽم کليو پنهنجي وڌيڪ هڻڪراءِ چاٻي ٺاهيو.',
    tm_handle: 'تنهنجو نالو (حد ۱۶ الفاظ)', tm_save_h: 'رکڻ',
    tm_room_ph: 'ڪمري جو نالو (مثال: c2ff-core)', tm_save: 'لاڳو ڪرڻ',
    tm_on: 'ڪمرو کليل: {r} - {n} آن لائن', tm_off: 'TEAM موڊ بند - ڊمي يڪيڙو سيشن',
    tm_room: 'ڪمرو', tm_key: 'ڪمري جي چاٻي',
    tm_regen: 'چاٻي ٻيھر ٺاهڻ', tm_regen_ok: 'نئين چاٻي ٺاهي - پراني لڪ ويرجي ڀڳا',
    tm_invite: 'دعوت جو لنڪ (تانمين ڪاپي ڪرڻ)', tm_copy: 'ڪاپي',
    tm_copied: 'ڪلپ بورڊ ۾ ڪاپي ٿيو', tm_members: 'ميلون',
    tm_nobody: 'اڃا ڪوبہ ناهي - دعوت جو لنڪ ٽيم اڇو پاٺو', tm_you: '(تون)',
    tm_here: 'موجود', tm_saved: 'نالو محفوظ ٿيو',
    tm_no_handle: 'نالو خالي', tm_cfg_ok: 'ڪمرو بدلايو ويو',
    tm_cfg_no: 'ناڪام', tm_live: 'نيٽ ورڪ لاءِ کليل ڪر',
    tm_shore: 'به وري لوڪل اچي', tm_need_on: 'پهرين ڪمرو چاڻ ڪر (ON)',
    tm_bind_lan: 'نيٽ ورڪ: {a}', tm_bind_lo: 'لوڪل: رڳو localhost',
    to_team_live: '[GO-LIVE] سرور نيٽ ورڪ ڇڏڻ جي حوالي ٻيهر اهيو - LAN لنڪ ڏيکاريل، 2 سيڪنڊن ۾ ٻيهر جڙڻ', to_team_shore: 'سرور وري لوڪل (127.0.0.1) تي اهاڻ ڪيو',
    tm_tun_open: 'دنيا لاءِ کليل ڪر (ٽونل)', tm_tun_close: 'ٽونل بند ڪر',
    tm_tun_wait: 'علمي ٽونل کليو رهيو (ڪجھ سيڪنڊ)…', tm_tun_on: 'سيشن دنيا لاءِ کليل: {u} - دعوت جو لنڪ هر جاءِ مان ڪم ڪندو، هڪجهڙيه نيٽ ورڪ جي ضرورت ناهي',
    tm_tun_closed: 'ٽونل بند - وري LAN/لوڪل اچي', tm_chat_empty: 'سيشن چينل کليل - ڪمري ملون هتي اوندو پڙهندا',
    tm_chat_h2: 'سيشن چيٽ', tm_msg_ph: 'سيشن ڏانهن ميساج…',
    tm_admin: 'ايڊمن', tm_guest: 'مهمان',
    tm_kick: 'KICK', tm_kick_ok: 'ميمبر کمر مان ڪڍي ويو (وري ڪلڪ ڪرڻ سان کُليندو)',
    tm_role_ok: 'رول اپڊيٽ ٿيو', tm_mic_on: 'مائڪرفون چاڻ ڪر',
    tm_mic_off: 'مائڪرفون بند ڪر', tm_mic_denied: 'مائڪرفون انڪار ٿيو يا ناهي: HTTPS ضروري (دنيا ٽونل يا localhost) ۽ مائڪ جي اجازو ڏيڻ لازمي',
    navf: 'Beḍu', navfd: 'Findings',
    navp: 'پروگرام', navai: 'AI',
    navc: 'ڪمپڻي جو حصو', st_runs: 'چالائي',
    st_beacons: 'فعال beacons', st_sig: 'ئشارا',
    h2f: 'Beḍu - سڀ پروگرام، هلندڙ ايجنٽ پهرين', h2fd: 'Findings بنياد - ثابت ڪرڻ جي تگداري',
    h2eng: 'Beḍu انجن - بغير token لوڪل چڪر', h2prog: 'پروگرام - scope، ضروري هيڊر، ڇاھڙاڻ',
    h2new: 'نئون پروگرام', h2ai: 'AI ايجنٽ - 100% اختياري',
    h2c: 'جوڙي - نج چينل', fl_start: 'ڇوھرڻ',
    fl_pause: 'مونجهاري', fl_cycle: 'هاڻي چڪر',
    f_add: 'وڌايو', f_none: 'اڃا ڪوبہ ئشارو ناهي',
    f_ph: 'هٿ سان finding: endpoint + ثبوت + آڙندي severity…', st_sig_off: 'ئشارو',
    st_sig_an: 'جانچ', st_sig_sub: 'پيش ڪيل',
    st_sig_dup: 'وريه', st_sig_ref: 'رد ڪيل',
    st_sig_cl: 'بند ڪيل', r_none: 'ڪوبہ چلاءِ نه لٽيو',
    r_live: '{n} هلنا', r_done: 'پورو',
    r_feed: '▽ ڇڏ ({n} ev)', r_close: '△ ٿڪاٽو',
    p_name_ph: 'پروگرام جو نالو (مثال: PayPal)', p_hdr_ph: 'ضروري هيڊر تحقيق (مثال: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domain1, domain2, …', p_save: 'محفوظ ڪرڻ',
    p_local: 'ماڊيول(س)، 100% لوڪل', ai_p: 'C2FF AI سان پورو هلندڙ آهي: موڊن ۽ ثابت لوڪل پروب آهن. هي دروازي <b>تنهنجي</b> AI (self-hosted يا API) رابطو ڪرڻ لاءِ آهي: FINDINGS ۾ <span style="color:var(--green)">AI »</span> بٽڻ، جواب COORDINATION ۾. هن سيٽنگ کان سواءِ ڪوبہ ڊيٽا تنهنجي مشين کان نه نڪرندو آهي',
    ai_off: 'بند', ai_on: 'چاڻ',
    ai_st_off: 'AI بند - فريم ورڪ 100% لوڪل هلندڙ آهي', ai_st_ready: 'AI جڙيل: {p} · {m}',
    ai_st_inc: 'AI چاريو پرت اڌوري: baseURL ۽ model ضروري', ai_url_ph: 'base URL - مثال: http://localhost:11434 يا https://api.MyAI.tld/v1',
    ai_model_ph: 'model - مثال: llama3.1:8b', ai_key_ph: 'API چاٻي (لوڪل سرور لاءِ خالي ڇڏ)',
    ai_save: 'محفوظ ڪرڻ', ai_test: 'جڙڻ جي جانچ',
    ai_testing: 'جانچ ٿي رهي…', ai_ok: 'ٺيب - جواب: ',
    ai_fail: 'ناڪام: ', ai_note: 'سيٽنگ data/ai.json ۾ لوڪل محفوظ - تون ڍڪيل endpoint کان سواءِ ٻي ڪنهن جاءِ تي ڪڏهن به موڪل ناهي',
    ch_ph: 'root@c2ff:~# جانچ ايجنٽ ڏانهن نياپو…', ch_send: 'موڪل',
    ch_empty: 'چينل کليل آهي. هتي لک، مانيٽر مون کي فوري جڳايو.', ft: '100% لوڪل - ثابت پروب، token يا ٻاهرين لاڳاپا ڪونه - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-موڊ فعال: هر 30 منٽن ۾ لوڪل چڪر، 0 token.', to_fl_pa: 'FLEET محدود - جڏهن چاهيين تڏهن وري شروع ڪر.',
    to_fl_cy: 'فوري چڪر شروع ڪيو ويو (بجيٽ 60 req).', to_launch: '[GO] {m} موڊ (CWE {c}) {p} تي - لوڪل چڪر شروع ٿيو',
    to_ai_ok: 'سيٽنگ محفوظ ٿي', to_ai_no: 'محفوظ ڪرڻ ناڪام',
    to_ai_no_cfg: 'AI سيٽ ناهي - AI ٽئب ۾ سيٽ ڪر', to_ai_head: 'AI جانچ',
    to_ai_bad: 'AI جانچ ناڪام', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ ڇوھرڻ', navar: 'آرسينال',
    ar_h2: 'آرسينال - سڃاتل سطح تي CVE، EPSS ۽ اڪسپلائٽس', ar_sync: 'SYNC ڊيٽابيس',
    ar_btn: 'قدم', ar_exec: 'EXEC',
    ar_none: 'ڪوبه قدم ناهي: پهريان RECON هلايو، پوءِ KEV/EPSS لوڊ ڪرڻ لاءِ SYNC هلايو', ar_loading: 'ڊيٽابيس جو خلاصو لوڊ ٿي رهيو آهي...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'ڊيمو پروگرام - اسڪين ناهي: پنهون پروگرام ٺاهيو', pip_noprog: 'ڪوبه پروگرام ناهي: پروگرام ٽيب ۾ پنهون پروگرام ٺاهيو',
    pip_next: 'ايندڙ مرحلو:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  as: {
    pl_title: 'কামৰ পৰিকল্পনা', pl_empty: 'এতিয়াও পৰিকল্পনা নাই: ওপৰৰ কাৰ্ডটোত RECON চলাওক, অনুমানবোৰ ইয়ালৈ আহে (স্থিতিবোৰ সংৰক্ষিত)',
    pl_run: 'চলাওক', pl_reflect: 'canary প্ৰতিফলিত',
    st_do: 'কৰিব লাগে', st_test: 'পৰীক্ষিত',
    st_signal: 'সংকেত', st_valid: 'নিশ্চিত',
    st_void: 'কিছু নাই', atk_btn: 'ATTACK',
    atk_start: 'পৃষ্ঠলৈ আক্ৰমণ: endpoints, উন্মুক্ত docs, JWT, ৰহস্য...', atk_fail: 'আক্ৰমণ সম্ভৱ নহয়: প্ৰথমে RECON চলাওক',
    atk_none: 'কোনো সংকেত নাই', atk_findings: 'প্ৰাৰ্থী',
    atk_done: 'ATTACK: {n} প্ৰাৰ্থী P1/P2 প্ৰমাণৰ সৈতে findings লৈ সুমুৱাই', atk_empty: 'এতিয়াও আক্ৰমণ নাই: RECON চলাওক তাৰ পিছত ATTACK - req/res প্ৰমাণৰ সৈতে প্ৰাৰ্থী ইয়ালৈ আহে',
    navh: 'HUNT', h2hunt: 'HUNT - প্ৰকৃত পৃষ্ঠ আৰু প্ৰমাণ',
    h_ready: 'সাজু', h_empty: 'এতিয়াও পৃষ্ঠ নাই: পৃষ্ঠা, API endpoints, params, JS bundles আৰু subdomains নক্সা কৰিবলৈ RECON চলাওক',
    h_fnd: 'প্ৰগ্ৰামৰ findings', h_nofnd: 'এই প্ৰগ্ৰামৰ বাবে কোনো finding নাই',
    rc_btn: 'RECON', rc_start: 'পৃষ্ঠৰ recon চলি আছে: পৃষ্ঠা, JS bundles, endpoints, params...',
    rc_done: 'পৃষ্ঠ নক্সা কৰা হল: endpoints, params আৰু subdomains প্ৰগ্ৰাম কাৰ্ডত তালিকাভুক্ত', rc_fail: 'recon ব্যৰ্থ: host অনুপ্ৰৱেশযোগ্য নহয় বা scope ৰিক্ত',
    rc_surface: 'পৃষ্ঠ:', snd_on: 'শব্দ: ON',
    snd_off: 'শব্দ: OFF', snd_ok: 'ইণ্টাৰফে\'চ শব্দ সক্ৰিয় - লাইব্ৰেৰী: ক্লিক, টেব, কপি, সতৰ্কবাণী',
    snd_stop: 'সম্পূৰ্ণ নীৰব কৰা হ\'ল: আৰু কোনো C2FF শব্দ নাথাকিব', amb_on: 'পৰিৱেশ: ON',
    amb_off: 'পৰিৱেশ: OFF', amb_ok: 'জীৱন্ত পৰিৱেশ - ৰংটো পৰিয়ালবোৰত (সেউজীয়া, নীলা, হালধীয়া...) কোমলভাৱে গড়ে',
    amb_stop: 'পৰিৱেশ মূল সেউজীয়া ৰঙত জমা হ\'ল', nt_on: 'জাননী: ON',
    nt_off: 'জাননী: OFF', nt_ok: 'ব্ৰাউজাৰ জাননী সক্ৰিয় - P1 আৰু P2 ত beep',
    nt_denied: 'ব্ৰাউজাৰে জাননী অৱৰুদ্ধ কৰিছে: চাইটৰ ছেটিঙত অনুমতি দিয়ক', term_denied: 'টাৰ্মিনেল অস্বীকৃত বা নাই: localhost প্ৰয়োজন, বা এডমিন হিচাপে মুকলি ৰুম',
    term_p: 'প্ৰকৃত bash - তীৰেৰে ইতিহাস, Ctrl+C বাধা দিয়ে, Ctrl+D বন্ধ কৰে', term_restart: 'ৰিছেট',
    navtrm: 'TERM', term_h2: 'টাৰ্মিনেল - কামৰ shell, কনছ\'লত পোনপটীয়া',
    fl_off: 'FLEET: বন্ধ', fl_paused: 'FLEET: বিৰতিত',
    fl_active: 'FLEET: সক্ৰিয় ({n} চক্ৰ)', fl_last: 'শেষ চক্ৰ',
    fl_none: 'এতিয়াও কোনো চক্ৰ নাই', fl_info: 'ব্যৱধান {i} মিনিট, বাজেট {b} req/চক্ৰ',
    sub_ttl: 'command & control framework', navt: 'ছেচন',
    tm_h2: 'দলীয়া ছেচন - নেটৱৰ্কৰ বাহিৰতো একেলগে শিকাৰ', tm_p: 'ভাগ কৰা কোঠা খোলক: তোমাৰ গোটে fleet, findings দেখে আৰু পোনেই triage কৰিব পাৰে। তলত ছেচন চেট। তিনিটা প্ৰৱেশ স্তৰ: LOCAL (একাকী), NETWORK খোলাৰ জৰিয়তে LAN, আৰু WORLD খোলাৰ জৰিয়তে পৃথিৱী - ৰাজহুৱা সুৰংগ (cloudflared থাকিলে) আমন্ত্ৰণ লিংকক যিকোনো নেটৱৰ্কৰ পৰা বৈধ কৰে, তোমাৰ মেচিনে পোনে দেখুৱাই নথকাকৈ। সকলো কিবাৰ্ড ঘটাৰ চাবিৰ দ্বাৰা - সকলোকে একেলগে উলিয়াবলৈ চাবি পুনৰ তৈয়াৰ কৰা।',
    tm_handle: 'তোমাৰ ৰূপ (সৰ্বোচ্চ 16 শব্দ)', tm_save_h: 'আঁতৰাওক',
    tm_room_ph: 'কোঠাৰ নাম (উদাহৰণ: c2ff-core)', tm_save: 'প্ৰয়োগ কৰক',
    tm_on: 'কোঠা মুকলি: {r} - {n} অনলাইন', tm_off: 'TEAM মোড অফ - লোকেল একক ছেচন',
    tm_room: 'কোঠা', tm_key: 'কোঠাৰ চাবি',
    tm_regen: 'চাবি পুনৰ তৈয়াৰ কৰক', tm_regen_ok: 'নতুন চাবি তৈয়াৰ হ\'ল - পুৰণা লিংক মৃত',
    tm_invite: 'আমন্ত্ৰণ লিংক (টিমলৈ কপি কৰিবলৈ)', tm_copy: 'কপি',
    tm_copied: 'ক্লিপবোৰ্ডলৈ কপি হ\'ল', tm_members: 'সদস্য',
    tm_nobody: 'এতিয়াও কোনো নাই - টিমলৈ লিংক পঠিয়াও', tm_you: '(তুমি)',
    tm_here: 'উপস্থিত', tm_saved: 'ৰূপ সংৰক্ষিত',
    tm_no_handle: 'ৰূপ ৰিক্ত', tm_cfg_ok: 'কোঠা আধুনিক কৰা হ\'ল',
    tm_cfg_no: 'ব্যৰ্থ', tm_live: 'নেটৱৰ্কত মুকলি কৰক',
    tm_shore: 'লোকেললৈ ঘূৰি অহা', tm_need_on: 'প্ৰথমে কোঠা চালু কৰক (ON)',
    tm_bind_lan: 'নেটৱৰ্ক: {a}', tm_bind_lo: 'লোকেল: কেৱল localhost',
    to_team_live: '[GO-LIVE] ছাৰ্ভাৰ নেটৱৰ্ক প্ৰৱেশৰ সৈতে পুনৰ আৰম্ভ - LAN লিংক দেখুওৱা হ\'ল, 2 ছেকেণ্ডত পুনৰ সংযোগ', to_team_shore: 'ছাৰ্ভাৰ লোকেল (127.0.0.1) হিচাপে পুনৰ আৰম্ভ হ\'ল',
    tm_tun_open: 'পৃথিৱীৰ বাবে মুকলি কৰক (সুৰংগ)', tm_tun_close: 'সুৰংগ বন্ধ কৰক',
    tm_tun_wait: 'ৰাজহুৱা সুৰংগ মুকলি হৈ আছে (কিছু ছেকেণ্ড)…', tm_tun_on: 'ছেচন পৃথিৱীৰ বাহিৰত মুকলি: {u} - আমন্ত্ৰণ লিংক যিকোনো ঠাইৰ পৰা কাম কৰে, একেই নেটৱৰ্কৰ প্ৰয়োজন নাই',
    tm_tun_closed: 'সুৰংগ বন্ধ - LAN/লোকেললৈ ঘূৰি আহিল', tm_chat_empty: 'ছেচন চেনেল মুকলি - কোঠাৰ সদস্যসকলে ইয়াত ইজনে সিজনক পঢ়িব',
    tm_chat_h2: 'ছেচন চেট', tm_msg_ph: 'ছেচনলৈ বাৰ্তা…',
    tm_admin: 'এডমিন', tm_guest: 'অতিথি',
    tm_kick: 'KICK', tm_kick_ok: 'কোঠাৰ পৰা সদস্য উলিয়াই দিয়া হ\'ল (আকৌ ক্লিক কৰিলে খুলি দিয়ে)',
    tm_role_ok: 'ভূমিকা আধুনিক কৰা হ\'ল', tm_mic_on: 'মাইক চালু কৰক',
    tm_mic_off: 'মাইক বন্ধ কৰক', tm_mic_denied: 'মাইক অস্বীকৃত বা নাই: HTTPS প্ৰয়োজন (WORLD সুৰংগ বা localhost) আৰু মাইকৰ অনুমতি দিব লাগিব',
    navf: 'Beḍu', navfd: 'Findings',
    navp: 'প্ৰগ্ৰাম', navai: 'AI',
    navc: 'সমন্বয়', st_runs: 'Runs',
    st_beacons: 'সক্ৰিয় beacons', st_sig: 'সংকেত',
    h2f: 'Beḍu - সকলো প্ৰগ্ৰাম, চলি থকা এজেন্ট প্ৰথমে', h2fd: 'Findings বেচ - স্থায়ী triage চিহ্ন',
    h2eng: 'Beḍu ইঞ্জিন - ট\'কেনবিহীন লোকেল চক্ৰ', h2prog: 'প্ৰগ্ৰাম - scope, প্ৰয়োজনীয় header, উদ্বোধন',
    h2new: 'নতুন প্ৰগ্ৰাম', h2ai: 'AI এজেন্ট - 100% ইচ্ছাধীন সংযোগ',
    h2c: 'সমন্বয় - ব্যক্তিগত চেনেল', fl_start: 'আৰম্ভ',
    fl_pause: 'বিৰতি', fl_cycle: 'এতিয়া চক্ৰ',
    f_add: 'যোগ কৰক', f_none: 'এতিয়াও কোনো সংকেত নাই',
    f_ph: 'হাতৰ finding: endpoint + প্ৰমাণ + ৰক্ষণীয়া severity…', st_sig_off: 'সংকেত',
    st_sig_an: 'বিশ্লেষণ', st_sig_sub: 'দাখিল',
    st_sig_dup: 'ডুপ', st_sig_ref: 'প্ৰত্যাখ্যান',
    st_sig_cl: 'বন্ধ', r_none: 'কোনো run ধৰা নপৰিল',
    r_live: '{n} চলি আছে', r_done: 'শেষ',
    r_feed: '▽ প্ৰবাহ ({n} ev)', r_close: '△ ভাঁজ',
    p_name_ph: 'প্ৰগ্ৰামৰ নাম (উদাহৰণ: PayPal)', p_hdr_ph: 'প্ৰয়োজনীয় গৱেষক header (উদাহৰণ: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domain1, domain2, …', p_save: 'সংৰক্ষণ কৰক',
    p_local: 'মডিউল(s), 100% লোকেল', ai_p: 'C2FF AI অবিহনে সম্পূৰ্ণ চলে: মোডবোৰ নিৰ্ধাৰিত লোকেল probes। এই গেটৱে <b>তোমাৰ</b> AI (self-hosted বা API) ক এটা finding বিশ্লেষণলৈ কেৱল সংযোগ কৰে: FINDINGS-ত <span style="color:var(--green)">AI »</span> বুটাম, উত্তৰ COORDINATION-ত। এই ছেটিং নোহোৱাকৈ কোনো ডেটা তোমাৰ মেচিনৰ পৰা বাহিৰলৈ নাযায়',
    ai_off: 'অফ', ai_on: 'চালু',
    ai_st_off: 'AI অফ - ফ্ৰেমৱৰ্ক 100% লোকেল চলে', ai_st_ready: 'AI সংযুক্ত: {p} · {m}',
    ai_st_inc: 'AI চালু কিন্তু অসম্পূৰ্ণ: baseURL আৰু model প্ৰয়োজন', ai_url_ph: 'base URL - উদাহৰণ: http://localhost:11434 বা https://api.MyAI.tld/v1',
    ai_model_ph: 'model - উদাহৰণ: llama3.1:8b', ai_key_ph: 'API চাবি (লোকেল ছাৰ্ভাৰৰ বাবে ৰিক্ত থাকক)',
    ai_save: 'সংৰক্ষণ কৰক', ai_test: 'সংযোগ পৰীক্ষা কৰক',
    ai_testing: 'পৰীক্ষা চলি আছে…', ai_ok: 'OK - উত্তৰ: ',
    ai_fail: 'ব্যৰ্থ: ', ai_note: 'ছেটিং data/ai.json-ত লোকেলভাৱে সংৰক্ষিত - তুমি দিয়া endpointৰ বাহিৰে আন কোনো ঠাইলৈ কেতিয়াও পঠিয়াই নহয়',
    ch_ph: 'root@c2ff:~# বিশ্লেষণ এজেণ্টলৈ বাৰ্তা…', ch_send: 'পঠাওক',
    ch_empty: 'চেনেল মুকলি। ইয়াত লিখক, মনিটৰে মোক তৎক্ষণাৎ জগাই তোলে।', ft: '100% লোকেল - নিৰ্ধাৰিত probes, token বা বহিৰাগত নিৰ্ভৰতা নাই - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-মোড সক্ৰিয়: প্ৰতি 30 মিনিটত লোকেল চক্ৰ, 0 token.', to_fl_pa: 'FLEET বিৰতিত - যেতিয়া বিচাৰা তেতিয়া আৰম্ভ কৰা।',
    to_fl_cy: 'তাৎক্ষণিক চক্ৰ আৰম্ভ হ\'ল (বাজেট 60 req)।', to_launch: '[GO] {m} মোড (CWE {c}) {p}-ত - লোকেল চক্ৰ আৰম্ভ হ\'ল',
    to_ai_ok: 'ছেটিং সংৰক্ষিত', to_ai_no: 'সংৰক্ষণ ব্যৰ্থ',
    to_ai_no_cfg: 'AI ছেট নহয় - AI টেবত ছেট কৰক', to_ai_head: 'AI বিশ্লেষণ',
    to_ai_bad: 'AI বিশ্লেষণ ব্যৰ্থ', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ মুকলি কৰক', navar: 'আৰ্চেনাল',
    ar_h2: 'আৰ্চেনাল - চিনাক্ত কৰা পৃষ্ঠতলত CVE, EPSS আৰু এক্সপ্লইট', ar_sync: 'SYNC ডাটাবেছ',
    ar_btn: 'পদক্ষেপ', ar_exec: 'EXEC',
    ar_none: 'কোনো পদক্ষেপ নাই: প্ৰথমে RECON চলাওক, তাৰ পিছত KEV/EPSS লোড কৰিবলৈ SYNC চলাওক', ar_loading: 'ডাটাবেছৰ সাৰাংশ লোড হৈ আছে...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'ডেমো প্ৰগ্ৰাম - স্কেন নহয়: নিজৰ প্ৰগ্ৰাম বনাওক', pip_noprog: 'এতিয়াও কোনো প্ৰগ্ৰাম নাই: প্ৰগ্ৰামসমূহ টেবত নিজৰটো বনাওক',
    pip_next: 'পৰৱৰ্তী পদক্ষেপ:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  or: {
    pl_title: 'କାର୍ଯ୍ୟ ଯୋଜନା', pl_empty: 'ଏପର୍ଯ୍ୟନ୍ତ କୌଣସି ଯୋଜନା ନାହିଁ: ଉପର କାର୍ଡରେ RECON ଚଲାଅ, ଅନୁମାନଗୁଡ଼ିକ ଏଠାକୁ ଆସେ (ସ୍ଥିତିଗୁଡ଼ିକ ସଂରକ୍ଷିତ)',
    pl_run: 'ଚଲାନ୍ତୁ', pl_reflect: 'canary ପ୍ରତିଫଳିତ',
    st_do: 'କରିବା ଉଚିତ', st_test: 'ପରୀକ୍ଷିତ',
    st_signal: 'ସଙ୍କେତ', st_valid: 'ନିଶ୍ଚିତ',
    st_void: 'କିଛି ନାହିଁ', atk_btn: 'ATTACK',
    atk_start: 'ପୃଷ୍ଠକୁ ଆକ୍ରମଣ: endpoints, ଉନ୍ମୁକ୍ତ docs, JWT, ରହସ୍ୟ...', atk_fail: 'ଆକ୍ରମଣ ଅସମ୍ଭବ: ପ୍ରଥମେ RECON ଚଲାନ୍ତୁ',
    atk_none: 'କୌଣସି ସଙ୍କେତ ନାହିଁ', atk_findings: 'ପ୍ରାର୍ଥୀମାନେ',
    atk_done: 'ATTACK: {n} ପ୍ରାର୍ଥୀ P1/P2 ପ୍ରମାଣ ସହ findings କୁ ଭର୍ତ୍ତି ହେଲେ', atk_empty: 'ଏପର୍ଯ୍ୟନ୍ତ ଆକ୍ରମଣ ନାହିଁ: RECON ଚଲାନ୍ତୁ ତାପରେ ATTACK - req/res ପ୍ରମାଣ ସହ ପ୍ରାର୍ଥୀମାନେ ଏଠାକୁ ଆସନ୍ତି',
    navh: 'HUNT', h2hunt: 'HUNT - ପ୍ରକୃତ ପୃଷ୍ଠ ଏବଂ ପ୍ରମାଣ',
    h_ready: 'ପ୍ରସ୍ତୁତ', h_empty: 'କୌଣସି ପୃଷ୍ଠ ନାହିଁ: ପୃଷ୍ଠା, API endpoints, params, JS bundles ଏବଂ subdomains ମ୍ୟାପ କରିବାକୁ RECON ଚଲାନ୍ତୁ',
    h_fnd: 'ପ୍ରୋଗ୍ରାମର findings', h_nofnd: 'ଏହି ପ୍ରୋଗ୍ରାମ ପାଇଁ କୌଣସି finding ନାହିଁ',
    rc_btn: 'RECON', rc_start: 'ପୃଷ୍ଠର recon ଚାଲିଛି: ପୃଷ୍ଠା, JS bundles, endpoints, params...',
    rc_done: 'ପୃଷ୍ଠ ମ୍ୟାପ ହୋଇଛି: endpoints, params ଏବଂ subdomains ପ୍ରୋଗ୍ରାମ କାର୍ଡରେ ତାଲିକାଭୁକ୍ତ', rc_fail: 'recon ବିଫଳ: host ପହଞ୍ଚୁନାହିଁ କିମ୍ବା scope ଖାଲି',
    rc_surface: 'ପୃଷ୍ଠ:', snd_on: 'ଶବ୍ଦ: ON',
    snd_off: 'ଶବ୍ଦ: OFF', snd_ok: 'ଇଣ୍ଟରଫେସ ଶବ୍ଦ ସକ୍ରିୟ - ପାଠାଗାର: କ୍ଲିକ୍, ଟ୍ୟାବ, ପ୍ରତିଲିପି, ଚେତାବନୀ',
    snd_stop: 'ପୂର୍ଣ୍ଣ ନିଃଶବ୍ଦ ସକ୍ରିୟ: ଆଉ କୌଣସି C2FF ଶବ୍ଦ ନାହିଁ', amb_on: 'ପରିବେଶ: ON',
    amb_off: 'ପରିବେଶ: OFF', amb_ok: 'ଜୀବନ୍ତ ପରିବେଶ - ରଙ୍ଗ ପରିବାର ମଧ୍ୟରେ (ସବୁଜ, ନୀଳ, ହଳଦିଆ...) ଧୀରେ ଧୀରେ ଗଡ଼େ',
    amb_stop: 'ପରିବେଶ ମୂଳ ସବୁଜ ରଙ୍ଗରେ ଥିର ହେଲା', nt_on: 'ବିଜ୍ଞପ୍ତି: ON',
    nt_off: 'ବିଜ୍ଞପ୍ତି: OFF', nt_ok: 'ବ୍ରାଉଜର ବିଜ୍ଞପ୍ତି ସକ୍ରିୟ - P1 ଏବଂ P2 ରେ beep',
    nt_denied: 'ବ୍ରାଉଜର ବିଜ୍ଞପ୍ତି ଅବରୋଧ କରିଛି: ସାଇଟ ସେଟିଂସରେ ଅନୁମତି ଦିଅନ୍ତୁ', term_denied: 'ଟର୍ମିନାଲ୍ ଅସ୍ୱୀକୃତ କିମ୍ବା ଉପଲବ୍ଧ ନାହିଁ: localhost ଆବଶ୍ୟକ, କିମ୍ବା ଆଡମିନ୍ ଭାବରେ ଖୋଲା କକ୍ଷ',
    term_p: 'ପ୍ରକୃତ bash - ତୀର ଇତିହାସ, Ctrl+C ବାଧା ଦିଏ, Ctrl+D ବନ୍ଦ କରେ', term_restart: 'ପୁନଃସ୍ଥାପନ',
    navtrm: 'TERM', term_h2: 'ଟର୍ମିନାଲ୍ - କାର୍ଯ୍ୟ shell, କନ୍ସୋଲରେ ସିଧା',
    fl_off: 'FLEET: ବନ୍ଦ', fl_paused: 'FLEET: ବିରାମ',
    fl_active: 'FLEET: ସକ୍ରିୟ ({n} ଚକ୍ର)', fl_last: 'ଶେଷ ଚକ୍ର',
    fl_none: 'ଏପର୍ଯ୍ୟନ୍ତ କୌଣସି ଚକ୍ର ନାହିଁ', fl_info: 'ବ୍ୟବଧାନ {i} ମିନିଟ୍, ବଜେଟ୍ {b} req/ଚକ୍ର',
    sub_ttl: 'command & control framework', navt: 'ସେସନ୍',
    tm_h2: 'ଦଳଗତ ସେସନ୍ - ନେଟୱାର୍କ ବାହାରେ ମଧ୍ୟ ଏକାଠି ଶିକାର', tm_p: 'ସାଝା କକ୍ଷ ଖୋଲ: ତୁମ ଦଳ ଫ୍ଲିଟ୍, findings ଦେଖିପାରିବେ ଏବଂ ଲାଇଭ୍ triage କରିପାରିବେ। ତଳେ ଉତ୍ସର୍ଗୀକୃତ ସେସନ୍ ଚାଟ୍। ତିନୋଟି ପ୍ରବେଶ ସ୍ତର: LOCAL (ଏକାକୀ), NETWORK ଖୋଲି ହୋଇଥିବା LAN, ଏବଂ WORLD ଖୋଲି ହୋଇଥିବା ପୃଥିବୀ - ସାର୍ବଜନିକ ଟନେଲ୍ (cloudflared ସ୍ଥାପିତ ଥିଲେ) ଆମନ୍ତ୍ରଣ ଲିଙ୍କକୁ ଯେକୌଣସି ନେଟୱାର୍କରୁ ବୈଧ କରେ, ତୁମ ମେସିନ ସିଧାସଳଖ ପ୍ରକାଶ ନକରି। ସବୁ କିଛି କକ୍ଷ ଚାବିଦ୍ୱାରା ନିୟନ୍ତ୍ରିତ - ଏକାଠି ସବୁଙ୍କୁ ବାହାର କରିବାକୁ ଚାବି ପୁନଃ ସୃଷ୍ଟି କର।',
    tm_handle: 'ତୁମ ନାମ (ସର୍ବାଧିକ 16 ଅକ୍ଷର)', tm_save_h: 'ସେଟ୍',
    tm_room_ph: 'କକ୍ଷର ନାମ (ଉଦା: c2ff-core)', tm_save: 'ପ୍ରୟୋଗ',
    tm_on: 'କକ୍ଷ ଖୋଲା: {r} - {n} ଅନଲାଇନ', tm_off: 'TEAM ମୋଡ୍ ଅଫ୍ - ଲୋକାଲ୍ ଏକକ ସେସନ୍',
    tm_room: 'କକ୍ଷ', tm_key: 'କକ୍ଷ ଚାବି',
    tm_regen: 'ଚାବି ପୁନଃ ସୃଷ୍ଟି', tm_regen_ok: 'ନୂଆ ଚାବି ସୃଷ୍ଟି ହେଲା - ପୁରୁଣା ଲିଙ୍କ ମୃତ',
    tm_invite: 'ଆମନ୍ତ୍ରଣ ଲିଙ୍କ (ଟିମକୁ କପି କରିବା)', tm_copy: 'କପି',
    tm_copied: 'କ୍ଲିପବୋର୍ଡକୁ କପି ହେଲା', tm_members: 'ସଦସ୍ୟ',
    tm_nobody: 'ଏପର୍ଯ୍ୟନ୍ତ କେହି ନାହାଁନ୍ତି - ଆମନ୍ତ୍ରଣ ଲିଙ୍କ ଟିମକୁ ପଠାଅ', tm_you: '(ତୁମେ)',
    tm_here: 'ଉପସ୍ଥିତ', tm_saved: 'ନାମ ସଂରକ୍ଷିତ',
    tm_no_handle: 'ନାମ ଖାଲି', tm_cfg_ok: 'କକ୍ଷ ଅପଡେଟ୍ ହେଲା',
    tm_cfg_no: 'ବିଫଳ', tm_live: 'ନେଟ୍ କାମରେ ଖୋଲନ୍ତୁ',
    tm_shore: 'ଲୋକାଲକୁ ଫେରନ୍ତୁ', tm_need_on: 'ପ୍ରଥମେ କକ୍ଷ ଚାଳନ କର (ON)',
    tm_bind_lan: 'ନେଟ୍ କାମ: {a}', tm_bind_lo: 'ଲୋକାଲ୍: କେବଳ localhost',
    to_team_live: '[GO-LIVE] ସର୍ଭର୍ ନେଟଵର୍କ ପାରିମାନଙ୍କ ସହ ପୁନରାରମ୍ଭ - LAN ଲିଙ୍କ ଦେଖାଯିବ, 2 ସେକଣ୍ଡରେ ପୁନଃ ସଂଯୋଗ', to_team_shore: 'ସର୍ଭର୍ ଲୋକାଲ୍ (127.0.0.1) ପୁନରାରମ୍ଭ ହେଲା',
    tm_tun_open: 'ପୃଥିବୀକୁ ଖୋଲନ୍ତୁ (ଟନେଲ)', tm_tun_close: 'ଟନେଲ୍ ବନ୍ଦ କରନ୍ତୁ',
    tm_tun_wait: 'ସାର୍ବଜନିକ ଟନେଲ୍ ଖୋଲିବାକୁ ଲାଗିଛି (କିଛି ସେକଣ୍ଡ)…', tm_tun_on: 'ସେସନ୍ ପୃଥିବୀକୁ ଖୋଲା: {u} - ଆମନ୍ତ୍ରଣ ଲିଙ୍କ ଯେକୌଣସି ଜାଗାରୁ କାମ କରେ, ସମାନ ନେଟୱାର୍କ ଆବଶ୍ୟକ ନାହିଁ',
    tm_tun_closed: 'ଟନେଲ୍ ବନ୍ଦ - LAN/ଲୋକାଲ୍ ଫେରିଲା', tm_chat_empty: 'ସେସନ୍ ଚ୍ୟାନେଲ୍ ଖୋଲା - କକ୍ଷର ସଦସ୍ୟମାନେ ଏଠାରେ ପରସ୍ପରକୁ ପଢ଼ନ୍ତି',
    tm_chat_h2: 'ସେସନ୍ ଚାଟ', tm_msg_ph: 'ସେସନ୍ ପାଇଁ ବାର୍ତ୍ତା…',
    tm_admin: 'ଆଡମିନ୍', tm_guest: 'ଅତିଥି',
    tm_kick: 'KICK', tm_kick_ok: 'କକ୍ଷରୁ ସଦସ୍ୟଙ୍କୁ ଆଉଟ୍ କରାଯାଇଛି (ପୁଣି କ୍ଲିକ କରିଲେ ଖୋଲିଯିବ)',
    tm_role_ok: 'ଭୂମିକା ଅପଡେଟ୍ ହେଲା', tm_mic_on: 'ମାଇକ୍ରୋଫୋନ୍ ଚାଳନା',
    tm_mic_off: 'ମାଇକ୍ରୋଫୋନ୍ ବନ୍ଦ', tm_mic_denied: 'ମାଇକ୍ରୋଫୋନ୍ ଅସ୍ୱୀକୃତ କିମ୍ବା ନାହିଁ: HTTPS ଆବଶ୍ୟକ (WORLD ଟନେଲ୍ କିମ୍ବା localhost) ଏବଂ ମାଇକ୍ ଅନୁମତି ଦିଆଯିବା ଆବଶ୍ୟକ',
    navf: 'Beḍu', navfd: 'Findings',
    navp: 'ପ୍ରୋଗ୍ରାମ', navai: 'AI',
    navc: 'ସମନ୍ୱୟ', st_runs: 'Runs',
    st_beacons: 'ସକ୍ରିୟ beacons', st_sig: 'ସଙ୍କେତ',
    h2f: 'Beḍu - ସମସ୍ତ ପ୍ରୋଗ୍ରାମ, ଚାଳିତ ଏଜେଣ୍ଟ ପ୍ରଥମେ', h2fd: 'Findings ପାଦ - ସ୍ଥାୟୀ triage ଚିହ୍ନ',
    h2eng: 'Beḍu ଇଞ୍ଜିନ୍ - ଟକେନ୍ ବିନା ଲୋକାଲ ଚକ୍ର', h2prog: 'ପ୍ରୋଗ୍ରାମ - scope, ଆବଶ୍ୟକ header, ଲଞ୍ଚ',
    h2new: 'ନୂଆ ପ୍ରୋଗ୍ରାମ', h2ai: 'AI ଏଜେଣ୍ଟ - 100% ଇଚ୍ଛାଧୀନ ସଂଯୋଗ',
    h2c: 'ସମନ୍ୱୟ - ବ୍ୟକ୍ତିଗତ ଚ୍ୟାନେଲ୍', fl_start: 'ଆରମ୍ଭ',
    fl_pause: 'ବିରାମ', fl_cycle: 'ଏବେ ଚକ୍ର',
    f_add: 'ଯୋଗ କର', f_none: 'ଏପର୍ଯ୍ୟନ୍ତ କୌଣସି ସଙ୍କେତ ନାହିଁ',
    f_ph: 'କାଉଣୀ finding: endpoint + ପ୍ରମାଣ + ରକ୍ଷଣୀୟ severity…', st_sig_off: 'ସଙ୍କେତ',
    st_sig_an: 'ବିଶ୍ଳେଷଣ', st_sig_sub: 'ଦାଖଲ',
    st_sig_dup: 'ଡୁପ୍', st_sig_ref: 'ଅସ୍ୱୀକୃତ',
    st_sig_cl: 'ବନ୍ଦ', r_none: 'କୌଣସି run ଧରାପଡିଲା ନାହିଁ',
    r_live: '{n} ଚାଳିତ', r_done: 'ସମାପ୍ତ',
    r_feed: '▽ ପ୍ରବାହ ({n} ev)', r_close: '△ ଭାଙ୍ଗ',
    p_name_ph: 'ପ୍ରୋଗ୍ରାମ ନାମ (ଉଦା: PayPal)', p_hdr_ph: 'ଆବଶ୍ୟକ ଗବେଷକ header (ଉଦା: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domain1, domain2, …', p_save: 'ସେଭ୍ କରନ୍ତୁ',
    p_local: 'ମଡ୍ୟୁଲ୍(s), 100% ଲୋକାଲ', ai_p: 'C2FF AI ବିନା ସମ୍ପୂର୍ଣ୍ଣ ଚାଲେ: ମୋଡ୍‌ଗୁଡ଼ିକ ନିର୍ଦ୍ଧାରିତ ଲୋକାଲ probes। ଏହି ଗେଟ୍‌ୱେ <b>ତୁମ</b> AI (self-hosted କିମ୍ବା API) କୁ ଏକ finding ବିଶ୍ଳେଷଣ ପାଇଁ କେବଳ ସଂଯୋଗ କରେ: FINDINGS ରେ <span style="color:var(--green)">AI »</span> ବଟନ୍, ଉତ୍ତର COORDINATION ରେ। ଏହି ସେଟିଂ ବିନା କୌଣସି ଡାଟା ତୁମ ମେସିନରୁ ବାହାରକୁ ଯାଏ ନାହିଁ',
    ai_off: 'ଅଫ୍', ai_on: 'ଚାଳନା',
    ai_st_off: 'AI ଅଫ୍ - ଫ୍ରେମଓ୍ୟାର୍କ 100% ଲୋକାଲ ଚାଲେ', ai_st_ready: 'AI ସଂଯୁକ୍ତ: {p} · {m}',
    ai_st_inc: 'AI ଚାଳିତ କିନ୍ତୁ ଅସମ୍ପୂର୍ଣ୍ଣ: baseURL ଏବଂ model ଆବଶ୍ୟକ', ai_url_ph: 'base URL - ଉଦା: http://localhost:11434 କିମ୍ବା https://api.MyAI.tld/v1',
    ai_model_ph: 'model - ଉଦା: llama3.1:8b', ai_key_ph: 'API ଚାବି (ଲୋକାଲ ସର୍ଭର ପାଇଁ ଖାଲି ଛାଡ)',
    ai_save: 'ସେଭ୍ କରନ୍ତୁ', ai_test: 'ସଂଯୋଗ ପରୀକ୍ଷା',
    ai_testing: 'ପରୀକ୍ଷା ଚାଲିଛି…', ai_ok: 'OK - ଉତ୍ତର: ',
    ai_fail: 'ବିଫଳ: ', ai_note: 'ସେଟିଂ data/ai.json ରେ ଲୋକାଲ ଭାବେ ସେଭ୍ - ତୁମ ଦିଆ endpoint ର ବାହାରେ ଅନ୍ୟ କେଉଁଆଡ ପଠାଯାଏ ନାହିଁ',
    ch_ph: 'root@c2ff:~# ବିଶ୍ଳେଷଣ ଏଜେଣ୍ଟ ପାଇଁ ବାର୍ତ୍ତା…', ch_send: 'ପଠାଅ',
    ch_empty: 'ଚ୍ୟାନେଲ୍ ଖୋଲା। ଏଠାରେ ଟାଇପ କର, ମନିଟର ମୋତେ ତୁରନ୍ତ ଜାଗାଇବ।', ft: '100% ଲୋକାଲ - ନିର୍ଦ୍ଧାରିତ probes, token କିମ୍ବା ବାହ୍ୟ ନିର୍ଭରତା ନାହିଁ - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-ମୋଡ୍ ସକ୍ରିୟ: ପ୍ରତି 30 ମିନିଟରେ ଲୋକାଲ ଚକ୍ର, 0 token.', to_fl_pa: 'FLEET ବିରାମ - ଯେତେବେଳେ ଚାହାଁ ତେତେବେଳେ ଆରମ୍ଭ କର।',
    to_fl_cy: 'ତତକ୍ଷଣାତ୍ ଚକ୍ର ଆରମ୍ଭ ହେଲା (ବଜେଟ୍ 60 req)।', to_launch: '[GO] {m} ମୋଡ୍ (CWE {c}) {p} ରେ - ଲୋକାଲ ଚକ୍ର ଆରମ୍ଭ ହେଲା',
    to_ai_ok: 'ସେଟିଂ ସେଭ୍ ହେଲା', to_ai_no: 'ସେଭ୍ ବିଫଳ',
    to_ai_no_cfg: 'AI ସେଟ୍ ନାହିଁ - AI ଟ୍ୟାବରେ ସେଟ୍ କର', to_ai_head: 'AI ବିଶ୍ଳେଷଣ',
    to_ai_bad: 'AI ବିଶ୍ଳେଷଣ ବିଫଳ', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ ଆରମ୍ଭ', navar: 'ଅର୍ସେନାଲ',
    ar_h2: 'ଅର୍ସେନାଲ - ଚିହ୍ନଟ ହୋଇଥିବା ପୃଷ୍ଠରେ CVE, EPSS ଏବଂ ଏକ୍ସପ୍ଲଏଟ୍', ar_sync: 'SYNC ଡାଟାବେସ୍',
    ar_btn: 'ଗତି', ar_exec: 'EXEC',
    ar_none: 'କୌଣସି ଗତି ନାହିଁ: ପ୍ରଥମେ RECON ଚଲାନ୍ତୁ, ତାପରେ KEV/EPSS ଲୋଡ୍ କରିବାକୁ SYNC ଚଲାନ୍ତୁ', ar_loading: 'ଡାଟାବେସ୍ ସାରାଂଶ ଲୋଡ୍ ହେଉଛି...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'ଡେମୋ ପ୍ରୋଗ୍ରାମ - ସ୍କାନ ନାହିଁ: ନିଜ ପ୍ରୋଗ୍ରାମ ତିଆରି କର', pip_noprog: 'ଏବେ ଯାଏଁ କୌଣସି ପ୍ରୋଗ୍ରାମ ନାହିଁ: ପ୍ରୋଗ୍ରାମ ଟ୍ୟାବରେ ନିଜର ତିଆରି କର',
    pip_next: 'ପରବର୍ତ୍ତୀ ପଦକ୍ଷେପ:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  be: {
    pl_title: 'План работ', pl_empty: 'плана яшчэ няма: запусці RECON ў картцы вышэй, гіпотэзы трапляюць сюды (статусы захоўваюцца)',
    pl_run: 'Запусціць', pl_reflect: 'canary адбіўся',
    st_do: 'трэба зрабіць', st_test: 'праверана',
    st_signal: 'сігнал', st_valid: 'пацверджана',
    st_void: 'няма нічога', atk_btn: 'ATTACK',
    atk_start: 'атака паверхні: эндпоінты, адкрытыя дакументы, JWT, сакрэты...', atk_fail: 'атака немагчымая: спачатку запусці RECON',
    atk_none: 'няма сігналаў', atk_findings: 'кандыдаты',
    atk_done: 'ATTACK: {n} кандыдатаў P1/P2 заліты ў findings з доказам', atk_empty: 'атакі яшчэ няма: запусці RECON, потым ATTACK - кандыдаты з доказам req/res трапяць сюды',
    navh: 'HUNT', h2hunt: 'HUNT - рэальная паверхня і доказы',
    h_ready: 'гатовы', h_empty: 'паверхні яшчэ няма: запусці RECON, каб замапіць старонкі, endpoints API, параметры, JS-бандлы і паддамены',
    h_fnd: 'Findings праграмы', h_nofnd: 'для гэтай праграмы findings няма',
    rc_btn: 'RECON', rc_start: 'рэкан паверхні ідзе: старонкі, JS-бандлы, эндпоінты, параметры...',
    rc_done: 'паверхня замапленая: эндпоінты, параметры і паддамены занесеныя ў картку праграмы', rc_fail: 'рэкан праваліўся: хост недасяжны альбо scope пусты',
    rc_surface: 'паверхня:', snd_on: 'ГУК: ON',
    snd_off: 'ГУК: OFF', snd_ok: 'гукі інтэрфейсу уключаны - бібліятэка: клік, таб, капіраванне, трывогі',
    snd_stop: 'поўнае маўчанне ўключанае: болей ніякіх гукаў C2FF', amb_on: 'АТМАСФЕРА: ON',
    amb_off: 'АТМАСФЕРА: OFF', amb_ok: 'жывая атмасфера - адценне плаўна плыве па сямействах (зялёнае, сіняе, жоўтае...)',
    amb_stop: 'атмасфера замацаваная на пачатковым зялёным', nt_on: 'АПАВЕШЧАННІ: ON',
    nt_off: 'АПАВЕШЧАННІ: OFF', nt_ok: 'наведвальніцкія паведамленні уключаны - біп на P1 і P2',
    nt_denied: 'паведамленні заблакаваны браўзерам: дазволь іх у наладах сайта', term_denied: 'тэрмінал адмоўлены альбо недаступны: патрэбны localhost, альбо адкрытая зала ў ролі адміна',
    term_p: 'сапраўдны bash - гісторыя стрэлкай уверх, Ctrl+C перарывае, Ctrl+D зачыняе', term_restart: 'Скінуць',
    navtrm: 'TERM', term_h2: 'Тэрмінал - працоўны shell, адразу ў кансолі',
    fl_off: 'FLEET: СПЫНЕНЫ', fl_paused: 'FLEET: НА ПАЎЗЕ',
    fl_active: 'FLEET: АКТЫЎНЫ ({n} цыклаў)', fl_last: 'апошні цыкл',
    fl_none: 'цыклаў яшчэ няма', fl_info: 'інтэрвал {i} хв, бюджэт {b} req/цыкл',
    sub_ttl: 'command & control framework', navt: 'СЭАНС',
    tm_h2: 'Групавыя сэансы - сумеснае паляванне, нават з розных сетак', tm_p: 'Адкрый агульную залу: твой гурт бачыць флот, findings і можа рабіць triage ў жывым рэжыме. Далей - асобны чат сэанса. Тры ўзроўні доступу: LOCAL (сола), LAN праз АДКРЫЦЬ ДЛЯ СЕТКІ, і СВЕТ праз АДКРЫЦЬ ДЛЯ СВЕТУ - публічны тунэль (cloudflared, калі ўстаноўлены) робіць ссылку-запрашэнне дзейнай з любой сеткі, не адкрываючы твой машыну напростку. Усё пад ключом залы - перагеняруй яго, каб адразу выкінуць усіх.',
    tm_handle: 'Твой псеўданім (макс. 16 сімвалаў)', tm_save_h: 'Выбраць',
    tm_room_ph: 'імя залы (напр.: c2ff-core)', tm_save: 'Прымяніць',
    tm_on: 'ЗАЛА АДКРЫТА: {r} - {n} онлайн', tm_off: 'РЭЖЫМ TEAM ВЫКЛЮЧАНЫ - лакальны сола-сэанс',
    tm_room: 'Зала', tm_key: 'Ключ залы',
    tm_regen: 'Перастварыць ключ', tm_regen_ok: 'новы ключ згенераваны - старыя ссылки мёртвыя',
    tm_invite: 'Ссылка-запрашэнне (скапіруй для сваёй каманды)', tm_copy: 'Капіраваць',
    tm_copied: 'скапіравалася ў буфер', tm_members: 'Удзельнікі',
    tm_nobody: 'яшчэ нікога - дашли ссылку сваёй камандзе', tm_you: '(ты)',
    tm_here: 'заўжды', tm_saved: 'псеўданім захаваны',
    tm_no_handle: 'псеўданім пусты', tm_cfg_ok: 'зала абноўлена',
    tm_cfg_no: 'няўдала', tm_live: 'АДКРЫЦЬ ДЛЯ СЕТКІ',
    tm_shore: 'ВЕРНУЦЦА ДА ЛАКАЛЬНАГА', tm_need_on: 'спачатку уключы залу (ON)',
    tm_bind_lan: 'СЕТКА: {a}', tm_bind_lo: 'ЛАКАЛЬНА: толькі localhost',
    to_team_live: '[GO-LIVE] сервер перазапушчаны з сеткавым доступам - спасылка LAN паказана, перападключэнне праз 2 с', to_team_shore: 'сервер перазапушчаны лакальна (127.0.0.1)',
    tm_tun_open: 'АДКРЫЦЬ ДЛЯ СВІТУ (тунэль)', tm_tun_close: 'ЗАКРЫЦЬ ТУНЭЛЬ',
    tm_tun_wait: 'публічны тунэль паднімаецца (некалькі секундаў)…', tm_tun_on: 'СЭАНС АДКРЫТЫ ДЛЯ СВЕТУ: {u} - спасылка-запрашэнне працуе адусюль, агульная сетка не патрэбна',
    tm_tun_closed: 'тунэль зачынены - вяртанне да LAN/лакал', tm_chat_empty: 'канал сэанса адкрыты - удзельнікі залы чытаюць адзін аднаго тут',
    tm_chat_h2: 'Чат сесіі', tm_msg_ph: 'паведамленне ў сесію…',
    tm_admin: 'адмін', tm_guest: 'госць',
    tm_kick: 'KICK', tm_kick_ok: 'удзельнік выключаны з залы (паўторны клік разблакіруе)',
    tm_role_ok: 'роля абноўена', tm_mic_on: 'УКЛЮЧЫЦЬ МІКРАФОН',
    tm_mic_off: 'ВЫКЛЮЧЫЦЬ МІКРАФОН', tm_mic_denied: 'мікрафон адмоўлены альбо недаступны: патрэбны HTTPS (тунэль СВЕТ альбо localhost) і трэба даць дазвол на мікрафон',
    navf: 'Флот', navfd: 'Findings',
    navp: 'Праграмы', navai: 'ШІ',
    navc: 'Каардынацыя', st_runs: 'Runs',
    st_beacons: 'Актыўныя beacons', st_sig: 'Сігналы',
    h2f: 'Флот - усе праграмы, агенты на бегу - першымі', h2fd: 'База findings - трывалае triage-пазначэнне',
    h2eng: 'Рухавік флота - лакальныя цыклы без токенаў', h2prog: 'Праграмы - scope, патрэбны загаловак, запуск',
    h2new: 'Новая праграма', h2ai: 'ШІ-агент - інтэграцыя 100% на выбар',
    h2c: 'Каардынацыя - прыватны канал', fl_start: 'Старт',
    fl_pause: 'Паўза', fl_cycle: 'Цыкл цяпер',
    f_add: 'Дадаць', f_none: 'няма яшчэ сігналаў',
    f_ph: 'ручной finding: endpoint + доказ + абараняльная сур\'ёзнасць…', st_sig_off: 'сігнал',
    st_sig_an: 'аналіз', st_sig_sub: 'адпраўлена',
    st_sig_dup: 'дубль', st_sig_ref: 'адклонена',
    st_sig_cl: 'закрыта', r_none: 'runs не выяўлена',
    r_live: '{n} У ХОДЗЕ', r_done: 'ЗАВЕРШЭНА',
    r_feed: '▽ паток ({n} ev)', r_close: '△ згарнуць',
    p_name_ph: 'Назва праграмы (напрыклад: PayPal)', p_hdr_ph: 'патрэбны загаловак даследчыка (напрыклад: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domain1, domain2, …', p_save: 'Захаваць',
    p_local: 'модуль(ы), 100% лакальна', ai_p: 'C2FF цалкам працуе без ШІ: рэжымы - дэтэрмінаваныя лакальныя пробы. Гэты шлюз толькі падключае <b>твой</b> ШІ (self-hosted альбо API) для пунктовага аналізу finding: кнопка <span style="color:var(--green)">ШІ »</span> ў FINDINGS, адказ у COORDINATION. Ніякія даныя не пакідаюць твой машыны без гэтай налады.',
    ai_off: 'адключана', ai_on: 'уключана',
    ai_st_off: 'ШІ АДКЛЮЧАНЫ - фрэмворк працуе на 100% лакальна без яго', ai_st_ready: 'ШІ ПАДКЛЮЧАНЫ: {p} · {m}',
    ai_st_inc: 'ШІ УКЛЮЧАНЫ, АЛЕ НЕПОЎНЫ: патрэбныя baseURL і мадэль', ai_url_ph: 'base URL - напрыклад: http://localhost:11434 альбо https://api.MyAI.tld/v1',
    ai_model_ph: 'мадэль - напрыклад: llama3.1:8b', ai_key_ph: 'ключ API (пакінуць пустым для лакальнага серверу)',
    ai_save: 'Захаваць', ai_test: 'Праверыць злучэнне',
    ai_testing: 'праверка…', ai_ok: 'ОК - адказ: ',
    ai_fail: 'ПРОВАЛ: ', ai_note: 'канфіг захоўваецца лакальна ў data/ai.json - ніколі не адсылаецца куды-небудзь, апрача endpoint, які ты туды ставіш',
    ch_ph: 'root@c2ff:~# паведамленне да агенту аналізу…', ch_send: 'Адправіць',
    ch_empty: 'Канал адкрыты. Пішы тут - манітор абуджае мяне імгненна.', ft: '100% лакальна - дэтэрмінаваныя пробы, без токенаў і знешніх залежнасцяў - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-РЭЖЫМ АКЦІЙНЫ: лакальныя цыклы кожныя 30 хв, 0 токенаў.', to_fl_pa: 'FLEET НА ПАЎЗЕ - працягні, калі захочаш.',
    to_fl_cy: 'Неадкладны цыкл запушчаны (бюджэт 60 req).', to_launch: '[GO] рэжым {m} (CWE {c}) на {p} - лакальны цыкл запушчаны',
    to_ai_ok: 'канфіг захаваны', to_ai_no: 'правал захавання',
    to_ai_no_cfg: 'ШІ не сканфігураваны - наладзь яго ва ўкладцы ШІ', to_ai_head: 'ШІ АНАЛІЗ',
    to_ai_bad: 'АНАЛІЗ ШІ праваліўся', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'ШІ',
    w_launch: '⚡ ЗАПУСК', navar: 'Арсенал',
    ar_h2: 'АРСЕНАЛ - CVE, EPSS і эксплойты на выяўленай паверхні', ar_sync: 'SYNC БАЗЫ',
    ar_btn: 'ХОДЫ', ar_exec: 'EXEC',
    ar_none: 'хадоў няма: спачатку запусці RECON, потым SYNC, каб загрузіць KEV/EPSS', ar_loading: 'зводка баз загрузаецца...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'дэма-праграма - без сканавання: стварай сваю праграму', pip_noprog: 'праграм няма: стварай сваю ва ўкладцы Праграмы',
    pip_next: 'наступны крок:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  sq: {
    pl_title: 'Plani i punës', pl_empty: 'ende pa plan: nis RECON në kartën lart, hipotezat bien këtu (statuset ruhen)',
    pl_run: 'Nis', pl_reflect: 'canary u reflektua',
    st_do: 'për bërë', st_test: 'testuar',
    st_signal: 'sinjal', st_valid: 'i konfirmuar',
    st_void: 'asgjë', atk_btn: 'ATTACK',
    atk_start: 'sulm i sipërfaqes: endpoints, docs të ekspozuara, JWT, sekrete...', atk_fail: 'sulmi dështoi: nis fillimisht RECON',
    atk_none: 'asnji sinjal', atk_findings: 'kandidatë',
    atk_done: 'ATTACK: {n} kandidatë P1/P2 u injektuan në findings me provë', atk_empty: 'ende pa sulm: nis RECON pastaj ATTACK - kandidatët me provë req/res bien këtu',
    navh: 'HUNT', h2hunt: 'HUNT - sipërfaqe reale dhe prova',
    h_ready: 'gati', h_empty: 'ende pa sipërfaqe: nis RECON për të hartuar faqet, endpoints e API, parametrat, bundles JS dhe nën-domainet',
    h_fnd: 'Findings e programit', h_nofnd: 'asnji finding për këtë program',
    rc_btn: 'RECON', rc_start: 'recon i sipërfaqes në kryerje: faqe, bundles JS, endpoints, parametra...',
    rc_done: 'sipërfaqja e hartuar: endpoints, parametra dhe nën-domaine të listuar në kartën e programit', rc_fail: 'recon dështoi: host i paarritshëm ose scope bosh',
    rc_surface: 'sipërfaqja:', snd_on: 'TINGËLLIMA: ON',
    snd_off: 'TINGËLLIMA: OFF', snd_ok: 'tingujt e ndërfaqes aktivizuar - biblioteka: klik, tab, kopjim, alarme',
    snd_stop: 'heshtje e plotë aktivizuar: më asnji tingull C2FF', amb_on: 'AMBIENTI: ON',
    amb_off: 'AMBIENTI: OFF', amb_ok: 'ambient i gjallë - nuanca rrëshqet butësisht përgjatë familjeve (jeshile, blu, e verdhë...)',
    amb_stop: 'ambienti i ngrirë në jeshilun fillestar', nt_on: 'NJOFTIME: ON',
    nt_off: 'NJOFTIME: OFF', nt_ok: 'njoftimet e browser-it aktivizuar - bip në P1 dhe P2',
    nt_denied: 'njoftimet e bllokuara nga browser-i: lejoji te cilësimet e sajtit', term_denied: 'terminali i refuzuar ose i pamundur: kërkohet localhost, ose dhomë E HAPUR si admin',
    term_p: 'bash real - historik me shigjeta, Ctrl+C ndërpret, Ctrl+D mbyll', term_restart: 'Rivendos',
    navtrm: 'TERM', term_h2: 'Terminal - shell pune, drejt në konsolë',
    fl_off: 'FLEET: NDALUR', fl_paused: 'FLEET: NË PAUZË',
    fl_active: 'FLEET: AKTIV ({n} cikle)', fl_last: 'cikli i fundit',
    fl_none: 'ende asnji cikël', fl_info: 'interval {i} min, buxhet {b} req/cikël',
    sub_ttl: 'command & control framework', navt: 'SEANSA',
    tm_h2: 'Seansa në grup - gjueti bashkë, edhe jashtë rrjetit', tm_p: 'Hap një dhomë të përbashkët: grupi yt sheh flotën, findings dhe mund të bëjë triage live. Chat i dedikuar i seansës më poshtë. Tri nivele aksesi: LOCAL (solo), LAN përmes HAP NË RRJET, dhe BOTË përmes HAP PËR BOTËN - një tunel publik (cloudflared nëse i instaluar) e bën linkun e ftesës të vlefshëm nga çfarëdo rrjeti, pa ekspozuar direkt makinën tënde. Gjithçka kalon përmes çelësit të dhomës - rigjeneroje për t\'i ndërprerë të gjithë njëherësh.',
    tm_handle: 'Pseudonimi yt (max 16 karaktere)', tm_save_h: 'Zgjidh',
    tm_room_ph: 'emri i dhomës (psh: c2ff-core)', tm_save: 'Apliko',
    tm_on: 'DHOMA HAPUR: {r} - {n} online', tm_off: 'MODI TEAM OFF - seansa lokale solo',
    tm_room: 'Dhoma', tm_key: 'Çelës i dhomës',
    tm_regen: 'Rigjenero çelësin', tm_regen_ok: 'çelës i ri i gjeneruar - linket e vjetra janë të vdekura',
    tm_invite: 'Link ftese (kopjoje për ekipin tënd)', tm_copy: 'Kopjo',
    tm_copied: 'kopjuar në clipboard', tm_members: 'Anëtarë',
    tm_nobody: 'ende askush - dërgoja linkun e ftesës ekipit', tm_you: '(ti)',
    tm_here: 'i pranishëm', tm_saved: 'pseudonimi u ruajt',
    tm_no_handle: 'pseudonim bosh', tm_cfg_ok: 'dhoma u përditësua',
    tm_cfg_no: 'dështoi', tm_live: 'HAP NË RRJET',
    tm_shore: 'KTHEHU LOKAL', tm_need_on: 'aktivizo fillimisht dhomën (ON)',
    tm_bind_lan: 'RRJET: {a}', tm_bind_lo: 'LOKAL: vetëm localhost',
    to_team_live: '[GO-LIVE] serveri u rinis me qasje rrjeti - linku LAN i shfaqur, rilidhje pas 2 s', to_team_shore: 'serveri u rinis lokal (127.0.0.1)',
    tm_tun_open: 'HAP PËR BOTËN (tunel)', tm_tun_close: 'MBYLL TUNELIN',
    tm_tun_wait: 'tuneli publik po hapet (disa sekonda)…', tm_tun_on: 'SEANSA E HAPUR PËR BOTËN: {u} - linku i ftesës punon kudo, s\'duhet i njëjti rrjet',
    tm_tun_closed: 'tuneli u mbyll - kthim në LAN/lokal', tm_chat_empty: 'kanali i seansës i hapur - anëtarët e dhomës lexojnë njëri-tjetrin këtu',
    tm_chat_h2: 'Chat i seansës', tm_msg_ph: 'mesazh drejt seansës…',
    tm_admin: 'admin', tm_guest: 'mysafir',
    tm_kick: 'KICK', tm_kick_ok: 'anëtari u përjashtua nga dhoma (kliko sërish për ta zhbllokuar)',
    tm_role_ok: 'roli u përditësua', tm_mic_on: 'AKTIVO MIKROFONIN',
    tm_mic_off: 'FIK MIKROFONIN', tm_mic_denied: 'mikrofoni i refuzuar ose i paarritshëm: kërkohet HTTPS (tuneli BOTË ose localhost) dhe duhet lejuar mikrofoni',
    navf: 'Flota', navfd: 'Findings',
    navp: 'Programet', navai: 'AI',
    navc: 'Koordinimi', st_runs: 'Runs',
    st_beacons: 'Beacons aktivë', st_sig: 'Sinjale',
    h2f: 'Flota - të gjitha programet, agjentët në punë të parët', h2fd: 'Baza e findings - shënim triage i vazhdueshëm',
    h2eng: 'Motori i flotës - cikle lokale pa tokena', h2prog: 'Programet - scope, header i kërkuar, nisja',
    h2new: 'Program i ri', h2ai: 'Agjenti AI - integrim 100% opsional',
    h2c: 'Koordinimi - kanal privat', fl_start: 'Nis',
    fl_pause: 'Pauzë', fl_cycle: 'Cikël tani',
    f_add: 'Shto', f_none: 'ende asnji sinjal',
    f_ph: 'finding manual: endpoint + provë + severity e mbrojtshme…', st_sig_off: 'sinjal',
    st_sig_an: 'analizë', st_sig_sub: 'dorëzuar',
    st_sig_dup: 'dup', st_sig_ref: 'refuzuar',
    st_sig_cl: 'mbyllur', r_none: 'asnji run i detektuar',
    r_live: '{n} NË ZHVILLIM', r_done: 'PËRFUNDOI',
    r_feed: '▽ fluksi ({n} ev)', r_close: '△ mbylle',
    p_name_ph: 'Emri i programit (rr: PayPal)', p_hdr_ph: 'header kërkuesi i kërkuar (rr: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domain1, domain2, …', p_save: 'Ruaj',
    p_local: 'module(t), 100% lokal', ai_p: 'C2FF funksionon tërësisht pa AI: modalitetet janë probes deterministe lokale. Kjo klavë shërben vetëm për të lidhur <b>AI-në tënde</b> (self-hosted ose API) për analizën episodike të një finding: butoni <span style="color:var(--green)">AI »</span> në FINDINGS, përgjigja jepet në COORDINATION. Asnjë të dhënë nuk del nga makina jote pa këtë konfigurim.',
    ai_off: 'e çaktivizuar', ai_on: 'e aktivizuar',
    ai_st_off: 'AI ÇAKTIVIZUAR - framework-i punon 100% lokal pa të', ai_st_ready: 'AI E LIDHUR: {p} · {m}',
    ai_st_inc: 'AI AKTIVE POR E PAPLOTË: kërkohen baseURL dhe model', ai_url_ph: 'base URL - rr: http://localhost:11434 ose https://api.MyAI.tld/v1',
    ai_model_ph: 'model - rr: llama3.1:8b', ai_key_ph: 'çelës API (lëre bosh për servera lokalë)',
    ai_save: 'Ruaj', ai_test: 'Testo lidhjen',
    ai_testing: 'test në kryerje…', ai_ok: 'OK - përgjigje: ',
    ai_fail: 'DESHTOI: ', ai_note: 'konfigi ruhet lokal në data/ai.json - nuk dërgohet kurrë gjetkë përveç endpoint-it që ia vendos',
    ch_ph: 'root@c2ff:~# mesazh drejt agjentit të analizës…', ch_send: 'Dërgo',
    ch_empty: 'Kanali është i hapur. Shkruaj këtu, monitori më zgjon menjëherë.', ft: '100% lokal - probes deterministe, pa tokena e pa varësi të jashtme - unrestricted · undetected · unstoppable',
    to_fl_on: 'MODI FLEET AKTIV: cikle lokale çdo 30 min, 0 token.', to_fl_pa: 'FLEET NË PAUZË - vazhdo kur të duash.',
    to_fl_cy: 'Cikli menjëherësh u nis (buxhet 60 req).', to_launch: '[GO] modi {m} (CWE {c}) në {p} - cikli lokal u nis',
    to_ai_ok: 'konfigi u ruajt', to_ai_no: 'ruajtja dështoi',
    to_ai_no_cfg: 'AI jo e konfiguruar - rregulloje në tab-in AI', to_ai_head: 'ANALIZA AI',
    to_ai_bad: 'ANALIZA AI dështoi', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'AI',
    w_launch: '⚡ NISJE', navar: 'Arsenali',
    ar_h2: 'ARSENAL - CVE, EPSS dhe exploit në sipërfaqen e zbuluar', ar_sync: 'SYNC BAZAT',
    ar_btn: 'LËVIZJE', ar_exec: 'EXEC',
    ar_none: 'asnjë lëvizje: ekzekuto fillimisht RECON, pastaj SYNC për të ngarkuar KEV/EPSS', ar_loading: 'përmbledhja e bazave po ngarkohet...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'program demo - pa skanim: krijo programin tënd', pip_noprog: 'asnjë program: krijo tëndin në skedën Programet',
    pip_next: 'hapi tjetër:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
  fi: {
    pl_title: 'Työsuunnitelma', pl_empty: 'ei suunnitelmaa vielä: aja RECON yläpuolen kortissa, hypoteesit pudotautuvat tänne (tilat pysyviä)',
    pl_run: 'Aja', pl_reflect: 'canary heijastettu',
    st_do: 'tehtävä', st_test: 'testattu',
    st_signal: 'signaali', st_valid: 'vahvistettu',
    st_void: 'ei mitään', atk_btn: 'ATTACK',
    atk_start: 'hyökätään pintaan: endpointit, avoimet dokut, JWT, salaisuudet...', atk_fail: 'hyökkäys ei onnistu: aja RECON ensin',
    atk_none: 'ei signaalia', atk_findings: 'ehdokkaat',
    atk_done: 'ATTACK: {n} P1/P2-ehdokasta syötetty findingsiin todisteineen', atk_empty: 'ei hyökkäystä vielä: aja RECON sitten ATTACK - req/res-todisteiset ehdokkaat tulevat tänne',
    navh: 'HUNT', h2hunt: 'HUNT - todellinen pinta ja todisteet',
    h_ready: 'valmis', h_empty: 'ei tunnettua pintaa: aja RECON kartoittaaksesi sivut, API-endpointit, parametrit, JS-bundlet ja subdomainit',
    h_fnd: 'Ohjelman findingsit', h_nofnd: 'ei findingsiä tälle ohjelmalle',
    rc_btn: 'RECON', rc_start: 'pinnan recon käynnissä: sivut, JS-bundlet, endpointit, parametrit...',
    rc_done: 'pinta kartoitettu: endpointit, parametrit ja subdomainit listattu ohjelmakortissa', rc_fail: 'recon epäonnistui: host saavuttamattomissa tai scope tyhjä',
    rc_surface: 'pinta:', snd_on: 'ÄÄNI: ON',
    snd_off: 'ÄÄNI: OFF', snd_ok: 'käyttöliittymän äänet päällä - kirjasto: klikkaus, välilehti, kopioi, hälytykset',
    snd_stop: 'täydellinen mykistys käytössä: ei enää C2FF-ääniä', amb_on: 'TUNNELMA: ON',
    amb_off: 'TUNNELMA: OFF', amb_ok: 'elävä tunnelma - sävy liukuu pehmeästi perheiden läpi (vihreä, sininen, keltainen...)',
    amb_stop: 'tunnelma jäädytetty alkuperäiseen vihreään', nt_on: 'ILMOITUKSET: ON',
    nt_off: 'ILMOITUKSET: OFF', nt_ok: 'selaimen ilmoitukset käytössä - piippaus P1 ja P2',
    nt_denied: 'ilmoitukset estetty selaimessa: salli ne sivuston asetuksista', term_denied: 'terminaali evätty tai ei käytettävissä: vaaditaan localhost, tai AVATTU huone adminina',
    term_p: 'oikea bash - nuoliylös-historia, Ctrl+C keskeyttää, Ctrl+D sulkee', term_restart: 'Nollaa',
    navtrm: 'TERM', term_h2: 'Terminaali - työskentelyshellä, suoraan konsolissa',
    fl_off: 'FLEET: PYSÄYTETTY', fl_paused: 'FLEET: TAUOLLA',
    fl_active: 'FLEET: AKTIIVINEN ({n} sykliä)', fl_last: 'viimeisin sykli',
    fl_none: 'ei vielä sykliä', fl_info: 'väli {i} min, budjetti {b} req/sykli',
    sub_ttl: 'command & control framework', navt: 'SESSION',
    tm_h2: 'Ryhmäsessiot - metsästys yhdessä, myös eri verkostoista', tm_p: 'Avaa jaettu huone: ryhmäsi näkee laivaston ja findingsit sekä voi triagoida reaaliajassa. Erillinen sessiokeskustelu alla. Kolme käyttötasoa: LOCAL (solo), LAN via AVAA VERKKOON ja MAAILMA via AVAA MAILMAALLE - julkinen tunneli (cloudflared jos asennettu) tekee kutsulinkistä voimassa mistä tahansa verkosta ilman suoraa altistusta koneellesi. Kaikki kulkee huoneavaimen kautta - luo se uudelleen potkaisaksesi kaikkien sisään kerralla.',
    tm_handle: 'Nimesi (enintään 16 merkkiä)', tm_save_h: 'Aseta',
    tm_room_ph: 'huoneen nimi (esim. c2ff-core)', tm_save: 'Käytä',
    tm_on: 'HUONE AVATTU: {r} - {n} paikalla', tm_off: 'TEAM-TILA POIS - paikallinen solo-sessio',
    tm_room: 'Huone', tm_key: 'Huoneavain',
    tm_regen: 'Luo avain uudelleen', tm_regen_ok: 'uusi avain luotu - vanhat linkit ovat kuolleet',
    tm_invite: 'Kutsulinkki (kopioi tiimillesi)', tm_copy: 'Kopioi',
    tm_copied: 'kopioitu leikepöydälle', tm_members: 'Jäsenet',
    tm_nobody: 'ei vielä ketään - lähetä kutsulinkki tiimillesi', tm_you: '(sinä)',
    tm_here: 'paikalla', tm_saved: 'nimi tallennettu',
    tm_no_handle: 'nimi tyhjä', tm_cfg_ok: 'huone päivitetty',
    tm_cfg_no: 'epäonnistui', tm_live: 'AVAA VERKKOON',
    tm_shore: 'PALAA PAIKALLISEKSI', tm_need_on: 'ota huone ensin käyttöön (ON)',
    tm_bind_lan: 'VERKKO: {a}', tm_bind_lo: 'PAIKALLINEN: vain localhost',
    to_team_live: '[GO-LIVE] palvelin käynnistetty uudelleen verkkokäyttöön - LAN-linkki näkyvissä, uudelleenyhdistys 2 s kuluttua', to_team_shore: 'palvelin käynnistetty uudelleen paikallisesti (127.0.0.1)',
    tm_tun_open: 'AVAA MAAILMALLE (tunneli)', tm_tun_close: 'SULJE TUNNELI',
    tm_tun_wait: 'julkinen tunneli avautuu (muutama sekunti)…', tm_tun_on: 'SESSIO AVATTU MAAILMALLE: {u} - kutsulinkki toimii mistä tahansa, samaa verkkoa ei tarvita',
    tm_tun_closed: 'tunneli suljettu - takaisin LAN/paikallinen', tm_chat_empty: 'sessiokanava avattu - huoneen jäsenet lukevat toisiaan täällä',
    tm_chat_h2: 'Sessiokeskustelu', tm_msg_ph: 'viesti sessioon…',
    tm_admin: 'admin', tm_guest: 'vieras',
    tm_kick: 'KICK', tm_kick_ok: 'jäsen poistettu huoneesta (uusi klikkaus avaa esteen)',
    tm_role_ok: 'rooli päivitetty', tm_mic_on: 'OTA MIKKI KÄYTTÖÖN',
    tm_mic_off: 'MYKISTÄ MIKKI', tm_mic_denied: 'mikki evätty tai ei saatavilla: vaaditaan HTTPS (MAAILMA-tunneli tai localhost) ja lupa on myönnettävä',
    navf: 'Laivasto', navfd: 'Findings',
    navp: 'Ohjelmat', navai: 'Tekoäly',
    navc: 'Koordinointi', st_runs: 'Ajot',
    st_beacons: 'Aktiiviset beaconit', st_sig: 'Signaalit',
    h2f: 'Laivasto - kaikki ohjelmat, ajossa olevat agentit ensin', h2fd: 'Findings-kanta - pysyvä triage-merkintä',
    h2eng: 'Laivastomoottori - paikalliset syklit ilman tokeneita', h2prog: 'Ohjelmat - scope, vaadittu header, käynnistys',
    h2new: 'Uusi ohjelma', h2ai: 'Tekoälyagentti - täysin valinnainen integraatio',
    h2c: 'Koordinointi - yksityinen kanava', fl_start: 'Käynnistä',
    fl_pause: 'Tauko', fl_cycle: 'Sykli nyt',
    f_add: 'Lisää', f_none: 'ei vielä signaalia',
    f_ph: 'manuaalinen finding: endpoint + todiste + puolustettava vakavuus…', st_sig_off: 'signaali',
    st_sig_an: 'analyysi', st_sig_sub: 'lähetetty',
    st_sig_dup: 'dup', st_sig_ref: 'hylätty',
    st_sig_cl: 'suljettu', r_none: 'ei havaittuja ajoja',
    r_live: '{n} AJOSSA', r_done: 'VALMIS',
    r_feed: '▽ syöte ({n} ev)', r_close: '△ tiivistä',
    p_name_ph: 'Ohjelman nimi (esim. PayPal)', p_hdr_ph: 'vaadittu tutkija-header (esim. X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domain1, domain2, …', p_save: 'Tallenna',
    p_local: 'moduuli(t), 100% paikallinen', ai_p: 'C2FF toimii täysin ilman tekoälyä: tilat ovat deterministisiä paikallisia probeja. Tämä yhdyskäytävä vain kytkee <b>oman</b> tekoälysi (self-hosted tai API) yksittäisen findingin pyydettävään analyysiin: painike <span style="color:var(--green)">Tekoäly »</span> FINDINGSissa, vastaus renderöidään COORDINATIONissa. Mitkään tiedot eivät lähde koneeltasi ilman tätä asetusta.',
    ai_off: 'pois käytöstä', ai_on: 'käytössä',
    ai_st_off: 'TEKOÄLY POIS KÄYTÖSTÄ - framework pyörii 100% paikallisesti ilman sitä', ai_st_ready: 'TEKOÄLY YHDESSÄ: {p} · {m}',
    ai_st_inc: 'TEKOÄLY KÄYTÖSSÄ MUTTA VAJAAINEN: baseURL ja model vaaditaan', ai_url_ph: 'base URL - esim. http://localhost:11434 tai https://api.OmaAI.tld/v1',
    ai_model_ph: 'model - esim. llama3.1:8b', ai_key_ph: 'API-avain (jätä tyhjäksi paikallisilla palvelimilla)',
    ai_save: 'Tallenna', ai_test: 'Testaa yhteys',
    ai_testing: 'testataan…', ai_ok: 'OK - vastaus: ',
    ai_fail: 'EPÄONNISTUI: ', ai_note: 'config tallennettu paikallisesti tiedostoon data/ai.json - ei koskaan lähetetä muualle kuin asettamaasi endpointiin',
    ch_ph: 'root@c2ff:~# viesti analyysianturille…', ch_send: 'Lähetä',
    ch_empty: 'Kanava on auki. Kirjoita tähän, monitori herättää minut välittömästi.', ft: '100% paikallinen - deterministiset probet, ei tokeneita eikä ulkoisia riippuvuuksia - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-TILA AKTIIVINEN: paikalliset syklit 30 min välein, 0 tokenia.', to_fl_pa: 'FLEET TAUOLLA - jatka milloin haluat.',
    to_fl_cy: 'Välitön sykli käynnistetty (budjetti 60 req).', to_launch: '[GO] tila {m} (CWE {c}) kohteessa {p} - paikallinen sykli käynnistetty',
    to_ai_ok: 'config tallennettu', to_ai_no: 'tallennus epäonnistui',
    to_ai_no_cfg: 'Tekoälyä ei ole määritetty - aseta se Tekoäly-välilehdellä', to_ai_head: 'TEKOÄLYANALYYSI',
    to_ai_bad: 'TEKOÄLYANALYYSI epäonnistui', w_me: 'ME',
    w_claude: 'CLAUDE', w_ia: 'TEKOÄLY',
    w_launch: '⚡ KÄYNNISTYS', navar: 'Arsenaali',
    ar_h2: 'ARSENAL - CVE, EPSS ja exploitit havaitulla pinnalla', ar_sync: 'SYNKRONOI KANNAT',
    ar_btn: 'LIIKKEET', ar_exec: 'EXEC',
    ar_none: 'ei liikkeitä: aja RECON ensin, sitten SYNC ladataksesi KEV/EPSS', ar_loading: 'kannat latautuvat, yhteenveto...',
    pip_scope: 'SCOPE', pip_recon: 'RECON',
    pip_attack: 'ATTACK', pip_plan: 'PLAN',
    pip_demo: 'demo-ohjelma - ei skannausta: luo oma ohjelmasi', pip_noprog: 'ei ohjelmia: luo omasi Ohjelmat-välilehdellä',
    pip_next: 'seuraava vaihe:', fnd_n: 'findings: {n}',
    ar_base: 'KEV: {k} - EPSS: {e} - XDB: {x}'
  },
};
// les autres langues du menu tombent sur l'anglais jusqu'au
// commit de leur dictionnaire (registre extensible)
function T(k) {
  const d = I18N[LANG] || I18N.en;
  return d[k] || I18N.en[k] || I18N.fr[k] || k;
}
function TF(k, vars) {
  let s = T(k);
  for (const [a, b] of Object.entries(vars || {})) s = s.replaceAll('{' + a + '}', b);
  return s;
}
let LANG = 'fr';
try { LANG = localStorage.getItem('c2ff-lang') || 'fr'; } catch (e) { LANG = 'fr'; }
function setLang(l) {
  LANG = l;
  try { localStorage.setItem('c2ff-lang', l); } catch (e) {}
  const entry = LANGS.find(x => x[0] === l);
  document.documentElement.dir = (entry && entry[2] === 'rtl') ? 'rtl' : 'ltr';
  applyI18n();
  forceDraw = true;
  refresh();
}
function applyI18n() {
  document.querySelectorAll('[data-i]').forEach(el => { el.textContent = T(el.dataset.i); });
  document.querySelectorAll('[data-ip]').forEach(el => { el.placeholder = T(el.dataset.ip); });
  const p = $('aiP'); if (p) p.innerHTML = T('ai_p'); // contient du markup
  $('langSel').value = LANG;
}

const state = { tab: 'programs', chatSeen: 0, fndSeen: 0, firstLoad: true, unread: 0, tick: 0, data: { runs: [], findings: [], programs: [], chat: [], modes: [], team: {} } };
// mode team : cle de salle capturee dans l'URL d'invitation (?k=...) puis
// envoyee sur chaque appel API ; locale on n'en a pas besoin
let TEAMKEY = '';
let HANDLE = '';
try {
  HANDLE = localStorage.getItem('c2ff-handle') || '';
  TEAMKEY = localStorage.getItem('c2ff-key') || '';
  const k = new URLSearchParams(location.search).get('k');
  if (k) { TEAMKEY = k; localStorage.setItem('c2ff-key', k); history.replaceState(null, '', location.pathname); }
} catch (e) {}
const KHEAD = () => TEAMKEY ? { 'x-c2ff-key': TEAMKEY } : {};
function jget(url) { return fetch(url, { headers: { ...KHEAD(), 'x-c2ff-handle': HANDLE || '' } }); }
function jpost(url, body) { return fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...KHEAD(), 'x-c2ff-handle': HANDLE || '' }, body: JSON.stringify(body) }); }
const expanded = new Set();
let forceDraw = true; // premier paint integral, puis re-rendu differentiel

function setTab(t) {
  if (t !== state.tab) sndPlay('tab');
  state.tab = t;
  document.querySelectorAll('.navbtn').forEach(b => b.classList.toggle('active', b.dataset.tab === t));
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === 'v-' + t));
  if (t === 'chat') { state.unread = 0; }
  if (t === 'term' && typeof termConnect === 'function') termConnect();
}

// ---------- toasts ----------
function toast(title, text, cls) {
  const el = document.createElement('div');
  el.className = 'toast ' + (cls || '');
  el.innerHTML = '<div class="th">' + esc(title) + '</div><div class="tt">' + hl(text) + '</div>';
  if (cls === 'P1' || cls === 'P2') {
    el.addEventListener('click', () => { setTab('findings'); document.querySelectorAll('.navbtn').forEach(x => { if (x.dataset.tab === 'findings') x.click(); }); });
  }
  $('toasts').appendChild(el);
  setTimeout(() => { el.classList.add('gone'); setTimeout(() => el.remove(), 350); }, cls === 'P1' ? 14000 : 8000);
}

// ---------- rendu differentiel ----------
// une vue ne se redessine que si ses donnees ont change, et jamais
// quand l'utilisateur interagit avec un element de la vue (selects, inputs)
const drawn = { runs: '', fnd: '', prog: '', chat: '', ai: '', team: '', pip: '', hunt: '', ars: '', jsi: '', urls: '', auth: '', mods: '', fast: '' };
function focusInside(sel) {
  const r = $(sel);
  const a = document.activeElement;
  return r && a && a.tagName !== 'BODY' && r.contains(a);
}
// action destructive (bouton dans la vue) : le bouton garde le focus apres le
// clic, focusInside bloque alors tout re-render de la liste - l'element supprime
// reste peint jusqu'au rechargement. Perdre le focus AVANT de rafraichir.
function blurNow() {
  const a = document.activeElement;
  if (a && a.blur) { try { a.blur(); } catch (e) {} }
}

// ---------- rendu flux ----------
function drawRuns(runs) {
  const sig = JSON.stringify(runs.map(r => [r.id, r.label, r.program, r.n, r.done, r.list.map(a => [a.base, a.name, a.status, a.last])]));
  if (sig === drawn.runs && !forceDraw) return;
  if (focusInside('runList')) return;
  drawn.runs = sig;
  $('nRun').textContent = String(runs.length);
  const act = runs.reduce((s, r) => s + (r.n - r.done), 0);
  $('sRuns').textContent = String(runs.length);
  $('sAct').textContent = String(act);
  $('sSig').textContent = String(state.data.findings.length);
  $('runList').innerHTML = runs.map(r => {
    const live = r.n - r.done;
    const cards = r.list.map(a =>
      '<div class="acard st-' + esc(a.status) + '"><span class="nm"><span class="dot ' + (a.status === 'running' ? 'run' : '') + '"></span>' + esc(a.name) + '</span>' +
      ' <span class="pill ' + (a.status === 'running' ? 'p-live' : 'p-done') + '">' + esc(a.status) + '</span>' +
      '<div class="last">' + esc(a.last || '…') + '</div>' +
      (expanded.has(r.id + ':' + a.base) ? '<div class="feed">' + a.events.slice(-10).reverse().map(e => '<div>' + esc(e.text) + '</div>').join('') + '</div>' : '') +
      '<div class="more" data-k="' + esc(r.id + ':' + a.base) + '">' + (expanded.has(r.id + ':' + a.base) ? T('r_close') : TF('r_feed', { n: a.total })) + '</div></div>'
    ).join('');
    return '<div class="card glow"><div class="fh" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
      '<span class="pill p-prog">' + esc((r.program || '?').toUpperCase()) + '</span>' +
      '<b style="color:var(--green);letter-spacing:1px">' + esc(r.label) + '</b>' +
      '<span class="pill ' + (live > 0 ? 'p-live' : 'p-done') + '">' + (live > 0 ? TF('r_live', { n: live }) : T('r_done')) + '</span>' +
      '<small style="color:var(--dim);margin-left:auto">' + esc(r.id) + '</small></div>' + cards + '</div>';
  }).join('') || '<div class="card">' + T('r_none') + '</div>';
  // wire expanders
  document.querySelectorAll('.more').forEach(m => m.addEventListener('click', () => {
    const k = m.dataset.k;
    if (expanded.has(k)) expanded.delete(k); else expanded.add(k);
    drawRuns(state.data.runs);
  }));
}

// ---------- findings ----------
const FND_STATUS = ['signal', 'analyse', 'soumis', 'dup', 'refuse', 'ferme'];
// ---------- findings ----------
function drawFindings() {
  const sig = JSON.stringify(state.data.findings.map(f => [f.id, f.sev, f.status]));
  if (sig === drawn.fnd && !forceDraw) return;
  if (focusInside('fndList')) return;
  drawn.fnd = sig;
  $('nFnd').textContent = String(state.data.findings.length);
  const progs = state.data.programs.map(p => p.id);
  if ($('nfProg').options.length !== progs.length) {
    $('nfProg').innerHTML = progs.map(p => '<option>' + p + '</option>').join('');
    if (activeProg && progs.includes(activeProg)) $('nfProg').value = activeProg;
  }
  $('fndList').innerHTML = state.data.findings.slice(0, 120).map(f => {
    const STK = { signal: 'st_sig_off', analyse: 'st_sig_an', soumis: 'st_sig_sub', dup: 'st_sig_dup', refuse: 'st_sig_ref', ferme: 'st_sig_cl' };
    const sel = FND_STATUS.map(s => '<option value="' + s + '"' + (f.status === s ? ' selected' : '') + '>' + T(STK[s] || 'st_sig_off') + '</option>').join('');
    return '<div class="fnd S-' + esc(f.sev) + '"><div class="fh">' +
      '<span class="sev">' + esc(f.sev) + '</span>' +
      '<span class="pill p-prog">' + esc((f.program || '?').toUpperCase()) + '</span>' +
      '<small style="color:var(--dim)">' + esc(f.id) + ' · ' + esc(f.run) + ' · ' + esc(f.agent) + '</small>' +
      '<small style="color:var(--dim);margin-left:auto">' + new Date(f.t).toLocaleTimeString('fr-FR') + '</small>' +
      '<select data-k="' + esc(f.key) + '" class="fstat">' + sel + '</select>' +
      '<button class="ghost pocgo" data-id="' + esc(f.id) + '">POC ⧉</button>' +
      '<button class="ghost ia-run" data-t="' + esc(f.text.slice(0, 400)) + '">IA »</button>' +
      '<button class="ghost fdel" data-k="' + esc(f.key) + '" style="color:var(--red)">✕</button></div>' +
      '<div class="txt">' + hl(f.text) + '</div></div>';
  }).join('') || '<div class="fnd">' + T('f_none') + '</div>';
  document.querySelectorAll('.fnd select').forEach(s => s.addEventListener('change', () => {
    jpost('/api/findings', { op: 'patch', key: s.dataset.k, status: s.value, name: HANDLE });
  }));
  document.querySelectorAll('.fdel').forEach(b => b.addEventListener('click', () => {
    jpost('/api/findings', { op: 'delete', key: b.dataset.k, name: HANDLE }).then(r => r.json()).then(j => {
      if (!j.ok) { toast('FINDINGS', j.error || 'echec', 'P2'); sndPlay('err'); return; }
      drawn.fnd = ''; blurNow(); refresh();
    }).catch(() => sndPlay('err'));
  }));
  document.querySelectorAll('.ia-run').forEach(b => b.addEventListener('click', () => {
    b.disabled = true; b.textContent = 'IA…';
    fetch('/api/ai', { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ op: 'analyse', text: b.dataset.t })
    }).then(r => r.json()).then(j => {
      b.disabled = false; b.textContent = 'IA »';
      if (j.ok) toast(T('to_ai_head'), j.reply, 'HIT');
      else toast(T('to_ai_bad'), T('ai_fail') + (j.error || T('to_ai_no_cfg')), 'P2');
    }).catch(() => { b.disabled = false; b.textContent = 'IA »'; });
  }));
  // export PoC : le markdown du rapport est copie, pret a coller dans la plateforme
  document.querySelectorAll('.pocgo').forEach(b => b.addEventListener('click', () => {
    fetch('/api/poc?id=' + encodeURIComponent(b.dataset.id)).then(r => { if (!r.ok) throw 0; return r.text(); }).then(md => {
      const done = () => toast('POC', 'markdown copie - colle le dans la plateforme', 'HIT');
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(md).then(done, () => fallbackCopy(md, done));
      else fallbackCopy(md, done);
    }).catch(() => toast('POC', 'export impossible', 'P2'));
  }));
}
function fallbackCopy(text, done) {
  const ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); done(); } catch (e) {}
  ta.remove();
}

// ---------- moteur fleet ----------
function drawFleet() {
  const f = state.data.fleet || {};
  const st = $('fleetSt');
  st.textContent = f.enabled ? (f.paused ? T('fl_paused') : TF('fl_active', { n: f.cycles })) : T('fl_off');
  st.className = 'pill ' + (!f.enabled ? 'p-done' : f.paused ? 'p-done' : 'p-live');
  $('fleetInfo').textContent = (f.lastCycle ? T('fl_last') + ' ' + new Date(f.lastCycle).toLocaleTimeString('fr-FR') + ' - ' : '') + (f.lastResult || T('fl_none')) + ' - ' + TF('fl_info', { i: f.intervalMin, b: f.budget });
}
$('fleetStart').addEventListener('click', () => drawFleetLater({ enabled: true, paused: false }, T('to_fl_on')));
$('fleetPause').addEventListener('click', () => drawFleetLater({ paused: true }, T('to_fl_pa')));
$('fleetCycle').addEventListener('click', () => drawFleetLater({ op: 'test' }, T('to_fl_cy')));
function drawFleetLater(body, txt) { jpost('/api/fleet', body).then(() => setTimeout(refresh, 300)); if (txt) toast('FLEET', txt, 'HIT'); }

// ---------- programmes ----------
function drawPrograms() {
  const sig = JSON.stringify([state.data.programs, state.data.modes]);
  if (sig === drawn.prog && !forceDraw) return;
  if (focusInside('progList')) return;
  drawn.prog = sig;
  $('nProg').textContent = String(state.data.programs.length);
  const modes = state.data.modes || [];
  const list = [...state.data.programs].sort((a, b) => (a.demo ? 1 : 0) - (b.demo ? 1 : 0));
  $('progList').innerHTML = list.map(p =>
    '<div class="card"><h3>' + esc(p.name) + (p.demo ? ' <small style="color:var(--warn)">[DEMO]</small>' : '') + (p.veille ? ' <small style="color:var(--amber)">(veille)</small>' : '') + '</h3>' +
    '<div class="subtle" style="color:var(--dim);font-size:10.5px">' + esc(p.platform || '') + '</div>' +
    '<div class="scope">' + esc((p.scope || []).join(' · ')) + '</div>' +
    (p.header ? '<div class="hdr">⧉ ' + esc(p.header) + '</div>' : '') +
    (p.regle ? '<div class="hdr">⌦ regle : ' + esc(p.regle) + '</div>' : '') +
    '<div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;align-items:center">' +
    '<select class="mode" data-p="' + esc(p.id) + '">' + modes.map(m => '<option value="' + esc(m.key) + '">' + esc(m.label) + ' · CWE ' + esc(m.cwes) + '</option>').join('') + '</select>' +
    '<button class="go launch" data-p="' + esc(p.id) + '">GO ›</button>' +
    '<button class="ghost huntgo" data-p="' + esc(p.id) + '" style="padding:6px 14px;font-size:11px">' + T('navh') + ' ›</button>' +
    (p.demo ? '' : '<button class="ghost progd" data-p="' + esc(p.id) + '" style="padding:6px 12px;font-size:11px;color:var(--red)">✕</button>') + '</div>' +
    '<div class="subtle" style="color:var(--dim);font-size:10.5px" id="mdesc-' + esc(p.id) + '"></div>' +
    '</div>'
  ).join('');
  document.querySelectorAll('.prog .mode').forEach(sel => {
    const upd = () => { const m = modes.find(x => x.key === sel.value); const d = $('mdesc-' + sel.dataset.p); if (d && m) d.textContent = '▸ CWE ' + m.cwes + ' - ' + m.desc + ' (' + m.n + ' module(s), 100% local)'; };
    sel.addEventListener('change', upd); upd();
  });
  document.querySelectorAll('.launch').forEach(b => b.addEventListener('click', () => {
    const p = b.dataset.p;
    if (state.data.programs.find(x => x.id === p && x.demo)) { demoErr({ demo: 1 }, 'FLEET'); return; }
    const sel = document.querySelector('.mode[data-p="' + p + '"]');
    const m = modes.find(x => x.key === sel.value);
    jpost('/api/fleet', { op: 'run', program: p, mode: sel.value });
    toast(T('w_launch'), TF('to_launch', { m: m ? m.label : sel.value, c: m ? m.cwes : '?', p: p.toUpperCase() }), 'HIT');
    setTimeout(refresh, 500);
  }));
  // raccourci : ouvre l'onglet HUNT sur ce programme
  document.querySelectorAll('.huntgo').forEach(b => b.addEventListener('click', () => {
    setProg(b.dataset.p);
    setTab('hunt'); drawHunt();
  }));
  // suppression : programme + findings + toutes ses donnees recon
  document.querySelectorAll('.progd').forEach(b => b.addEventListener('click', () => {
    const p = b.dataset.p;
    if (!confirm('Supprimer ' + p + ' ? findings + donnees recon inclus')) return;
    jpost('/api/programs', { op: 'delete', name: p, by: HANDLE }).then(r => r.json()).then(j => {
      if (!j.ok) { toast('PROGRAMMES', j.error || 'echec', 'P2'); sndPlay('err'); return; }
      toast('PROGRAMMES', p + ' supprime', 'HIT'); sndPlay('click');
      if (activeProg === p) { activeProg = ''; try { localStorage.removeItem('c2ff_prog'); } catch (e) {} }
      huntSel = arSel = '';
      SURF = {}; ATKS = {}; JSI = {};
      drawn.prog = drawn.hunt = drawn.ars = drawn.pip = ''; PIP_PROGS_SIG = '';
      blurNow(); refresh();
    }).catch(() => sndPlay('err'));
  }));
}

// ---------- HUNT tab : surface reelle + preuves du programme ----------
let huntSel = '', SURF = {}, SURF_READY = false, ATKS = {}, ATKS_READY = false;
// programme actif partage (localStorage) : le HUNT suit le choix global
try { if (typeof activeProg !== 'undefined' && activeProg) huntSel = activeProg; } catch (e) {}
function surfFor(id) {
  if (!SURF_READY && !SURF[id]) {
    SURF_READY = true;
    fetch('/api/surface').then(r => r.json()).then(s => { SURF = s || {}; if (state.tab === 'hunt') { drawn.hunt = ''; drawHunt(); } }).catch(() => {});
    fetchPipeline();
    fetch('/api/arsenal').then(r => r.json()).then(a => { ARS = a || {}; drawn.ars = ''; drawArsenal(); }).catch(() => {});
  }
  return SURF[id];
}
function atkFor(id) {
  if (!ATKS_READY && !ATKS[id]) {
    ATKS_READY = true;
    fetch('/api/attack').then(r => r.json()).then(a => { ATKS = a || {}; if (state.tab === 'hunt') { drawn.hunt = ''; drawHunt(); } }).catch(() => {});
  }
  return ATKS[id];
}
function jsiFor(id) {
  if (!JSI_READY) {
    JSI_READY = true;
    fetch('/api/jsint').then(r => r.json()).then(j => {
      if (j.ok && j.all) { JSI = j.all; if (state.tab === 'hunt') { drawn.jsi = ''; drawJsi(); } }
    }).catch(() => {});
  }
  return JSI[id];
}
function drawHunt() {
  const progs = state.data.programs;
  if (!huntSel || !progs.some(p => p.id === huntSel)) {
    const real = progs.find(p => !p.demo);
    huntSel = real ? real.id : (progs.length ? progs[0].id : '');
  }
  const sig = JSON.stringify([progs.map(p => p.id), huntSel, SURF_READY ? '1' : '0', ATKS_READY ? '1' : '0', state.data.findings.length]);
  if (sig === drawn.hunt && !forceDraw) return;
  drawn.hunt = sig;
  $('huntRecon').disabled = !huntSel;
  // surface
  const s = surfFor(huntSel);
  const box = $('huntSurf');
  if (!huntSel) { box.innerHTML = '<div class="subtle" style="color:var(--dim);font-size:11px">' + T('f_none') + '</div>'; }
  else if (!s) { box.innerHTML = '<div class="subtle" style="color:var(--dim);font-size:11px">' + T('h_empty') + '</div>'; }
  else {
    const rows = (t, arr, cut) => arr && arr.length ?
      '<div style="margin-top:7px"><b style="color:var(--green)">' + t + ' (' + arr.length + ')</b><div style="margin-top:3px;line-height:1.7;font-size:10.5px;color:var(--dim);word-break:break-all">' +
      arr.slice(0, cut || 999).map(x => '<span class="pill" style="margin:1px 2px 1px 0">' + esc(x) + '</span>').join('') + (arr.length > (cut || 999) ? '…' : '') + '</div></div>' : '';
    box.innerHTML =
      '<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:baseline">' +
      '<b style="color:var(--green);font-size:13px">' + esc(s.host || huntSel) + '</b>' +
      '<small style="color:var(--faint)">' + esc(s.reqs || 0) + ' req · ' + Math.round((s.ms || 0) / 100) / 10 + ' s · ' + esc(s.ts ? s.ts.slice(0, 16).replace('T', ' ') : '') + '</small>' +
      (s.tech && s.tech.length ? '<span class="pill">⚙ ' + esc(s.tech.join(' / ').slice(0, 80)) + '</span>' : '') + '</div>' +
      rows('API', s.apis, 30) + rows('PARAMS', s.params, 30) +
      rows('PAGES', (s.pages || []).map(x => x.replace(/^https?:\/\//, '')), 20) +
      rows('JS', (s.jsfiles || []).map(x => x.replace(/^https?:\/\//, '')), 15) +
      rows('SUBS', s.subs, 25);
  }
  // attack : candidates avec preuve
  const a = atkFor(huntSel);
  const aOut = $('huntAtkOut');
  if (a && a.findings) {
    const sevColor = { P1: 'var(--danger)', P2: 'var(--warn)' };
    aOut.innerHTML =
      '<div class="card" style="margin-top:12px">' +
      '<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:baseline">' +
      '<b style="color:var(--green);font-size:12.5px">⚔ ATTACK</b>' +
      '<small style="color:var(--faint)">' + esc(a.reqs || 0) + ' req · ' + (a.ep || 0) + ' endpoints · ' + (a.js || 0) + ' bundles · ' + Math.round((a.ms || 0) / 100) / 10 + ' s · ' + esc(a.ts ? a.ts.slice(0, 16).replace('T', ' ') : '') + '</small>' +
      '<span class="pill" style="color:' + ((a.findings || []).some(f => f.sev === 'P1' || f.sev === 'P2') ? 'var(--warn)' : 'var(--green)') + '">' + (a.findings.length ? a.findings.length + ' ' + T('atk_findings') : T('atk_none')) + '</span></div>' +
      (a.findings.map(f =>
        '<div class="fnd S-' + esc(f.sev) + '" style="margin-top:7px"><div class="fh">' +
        '<span class="sev">' + esc(f.sev) + '</span><span class="pill">' + esc(f.mod) + '</span>' +
        '<small style="color:var(--dim)">' + esc(f.title) + '</small></div>' +
        '<div class="txt" style="font-family:monospace;font-size:10px;white-space:pre-wrap">req : ' + esc(f.req) + '\nres : ' + esc(f.res) + '</div></div>').join('') || '') +
      '</div>';
  } else if (huntSel) {
    aOut.innerHTML = '<div class="card" style="margin-top:12px"><div class="subtle" style="color:var(--faint);font-size:11px">' + T('atk_empty') + '</div></div>';
  } else aOut.innerHTML = '';

  // plan de travail
  drawPlanCard();

  // arsenal (mouvements CVE) dans la vue de chasse
  drawHuntArs();

  // modes avances
  drawAdv();

  // findings du programme
  const mine = state.data.findings.filter(f => (f.program || '').toLowerCase() === huntSel.toLowerCase());
  $('huntFnd').innerHTML =
    '<h2 style="margin-top:14px">' + T('h_fnd') + (mine.length ? ' <small style="color:var(--faint)">(' + mine.length + ')</small>' : '') + '</h2>' +
    (mine.slice(0, 40).map(f =>
      '<div class="fnd S-' + esc(f.sev) + '"><div class="fh"><span class="sev">' + esc(f.sev) + '</span>' +
      '<small style="color:var(--dim)">' + esc(f.id) + ' · ' + esc(f.run) + ' · ' + esc(f.agent) + ' · ' + new Date(f.t).toLocaleTimeString('fr-FR') + '</small></div>' +
      '<div class="txt">' + hl(f.text) + '</div></div>').join('') ||
      '<div class="subtle" style="color:var(--faint);font-size:11px">' + T('h_nofnd') + '</div>');
}
// ---- plan de travail : hypotheses du recon, exec + statuts persistes ----
let PLAN_ITEMS = null, PLAN_SEL = '';
const PL_ST = () => [['', '▶ ' + T('st_do')], ['test', '⟳ ' + T('st_test')], ['signal', '⭐ ' + T('st_signal')], ['valide', '✔ ' + T('st_valid')], ['void', '✗ ' + T('st_void')]];
function renderPlan() {
  const box = $('huntPlan');
  if (!huntSel) { box.innerHTML = ''; return; }
  if (!PLAN_ITEMS) { box.innerHTML = '<div class="card" style="margin-top:12px"><div class="subtle" style="color:var(--faint);font-size:11px">⟳ ' + T('pl_title') + '…</div></div>'; return; }
  if (!PLAN_ITEMS.length) { box.innerHTML = '<div class="card" style="margin-top:12px"><div class="subtle" style="color:var(--faint);font-size:11px">' + T('pl_empty') + '</div></div>'; return; }
  box.innerHTML =
    '<h2 style="margin:14px 0 6px">☰ ' + T('pl_title') + ' <small style="color:var(--faint)">(' + PLAN_ITEMS.length + ')</small></h2>' +
    PLAN_ITEMS.map(it =>
      '<div class="card" style="padding:9px 11px;margin-bottom:7px' + (it.status === 'valide' ? ';border-color:var(--green)' : it.status === 'signal' ? ';border-color:var(--warn)' : it.status === 'void' ? ';opacity:.55' : '') + '">' +
      '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
      '<span class="pill">' + esc(it.cat) + '</span>' +
      (it.status === 'valide' ? '<span class="pill" style="color:var(--green)">✔ ' + T('st_valid') + '</span>' : '') +
      (it.status === 'signal' ? '<span class="pill" style="color:var(--warn)">⭐ ' + T('st_signal') + '</span>' : '') +
      '<small style="color:var(--dim);font-size:10.5px;flex:1;min-width:200px">' + esc(it.why) + '</small>' +
      '<select class="plstat" data-k="' + esc(it.k) + '" style="width:120px;padding:4px 6px">' +
      PL_ST().map(s => '<option value="' + s[0] + '"' + (it.status === s[0] ? ' selected' : '') + '>' + s[1] + '</option>').join('') + '</select>' +
      '<button class="ghost plcopy" data-k="' + esc(it.k) + '" style="padding:4px 8px">⧉</button>' +
      (it.run ? '<button class="go plrun" data-k="' + esc(it.k) + '" style="padding:4px 10px;font-size:10.5px">' + T('pl_run') + ' ›</button>' : '') +
      '</div>' +
      '<div style="margin-top:5px;font-family:monospace;font-size:10px;color:hsl(var(--hue) 55% 80%);word-break:break-all;cursor:pointer" class="plcopy" data-k="' + esc(it.k) + '">' + esc(it.curl) + '</div>' +
      (it.ev ? '<div style="margin-top:4px;font-family:monospace;font-size:10px;color:var(--dim);white-space:pre-wrap">' +
        (it.ev.res && it.ev.res.toLowerCase().includes('c2ff9q81z') ? '⚠ ' + T('pl_reflect') + ' - ' : '') +
        esc(it.ev.code) + ' · ' + esc(it.ev.len) + ' o<br>' + esc(it.ev.res) + '</div>' : '') +
      '</div>'
    ).join('');
}
function planItem(k) { return (PLAN_ITEMS || []).find(x => x.k === k); }
$('huntPlan').addEventListener('click', e => {
  const c = e.target.closest('.plcopy'); if (!c) return;
  const it = planItem(c.dataset.k); if (it) copyText(it.curl);
});
$('huntPlan').addEventListener('change', e => {
  const s = e.target.closest('.plstat'); if (!s) return;
  const it = planItem(s.dataset.k); if (!it) return;
  it.status = s.value;
  jpost('/api/planpatch', { name: huntSel, k: it.k, status: it.status });
  drawn.hunt = ''; renderPlan();
});
$('huntPlan').addEventListener('click', e => {
  const b = e.target.closest('.plrun'); if (!b) return;
  const it = planItem(b.dataset.k); if (!it) return;
  b.disabled = true; b.textContent = '⟳';
  jpost('/api/planrun', { name: huntSel, k: it.k }).then(r => r.json()).then(j => {
    b.disabled = false; b.textContent = T('pl_run') + ' ›';
    if (!j.ok || !j.ev) { toast('PLAN', j.err || T('atk_fail'), 'P2'); sndPlay('err'); return; }
    it.ev = j.ev;
    const refl = j.ev.res && j.ev.res.toLowerCase().includes('c2ff9q81z');
    if (refl) sndPlay('p2'); else sndPlay('click');
    drawn.hunt = ''; renderPlan();
  }).catch(() => { b.disabled = false; b.textContent = T('pl_run') + ' ›'; sndPlay('err'); });
});
function drawPlanCard() {
  // plan charge une seule fois par programme, persiste cote serveur entre les visites
  if (huntSel && PLAN_SEL !== huntSel) {
    PLAN_SEL = huntSel; PLAN_ITEMS = null;
    fetch('/api/plan?program=' + encodeURIComponent(huntSel)).then(r => r.json()).then(j => { PLAN_ITEMS = (j.items || []); drawn.hunt = ''; drawHunt(); }).catch(() => { PLAN_ITEMS = []; drawn.hunt = ''; });
  }
  if (!$('huntPlan') || (PLAN_ITEMS !== null && PLAN_SEL !== huntSel)) return;
  renderPlan();
}
// ---------- PIPELINE : fil conducteur, programme actif partage ----------
// un seul programme actif pour tous les onglets ; bandeau d'etapes 1-5
let PIP = {}, activeProg = '', PIP_PROGS_SIG = '';
try { activeProg = localStorage.getItem('c2ff_prog') || ''; } catch (e) {}
function setProg(id) {
  if (!id) return;
  activeProg = id;
  try { localStorage.setItem('c2ff_prog', id); } catch (e) {}
  huntSel = arSel = id;
  drawn.pip = drawn.hunt = drawn.ars = drawn.prog = '';
  drawPipeline();
}
// message demo : ne scanne pas le programme de demonstration, propose la creation
function demoErr(j, label) {
  if (!j || !j.demo) return false;
  sndPlay('err');
  toast(label, T('pip_demo') + ' - ' + T('h2new'), 'P2');
  setTab('programs');
  const f = $('npName'); if (f) f.focus();
  return true;
}
const PIP_STEP = {
  scope:   () => ({ tab: 'programs', lab: T('pip_scope') }),
  recon:   () => ({ tab: 'hunt', lab: T('pip_recon') }),
  attack:  () => ({ tab: 'hunt', lab: T('pip_attack') }),
  arsenal: () => ({ tab: 'hunt', lab: T('navar') }),
  plan:    () => ({ tab: 'hunt', lab: T('pip_plan') }),
};
function drawPipeline() {
  const el = $('pip');
  if (!el) return;
  // selecteur = LE bandeau : un seul endroit ou choisir le programme actif
  const progs = state.data.programs || [];
  const cur = (PIP && PIP.program || {}).id || '';
  const list = [...progs].sort((a, b) => (a.demo ? 1 : 0) - (b.demo ? 1 : 0));
  const opts = list.map(p => '<option value="' + esc(p.id) + '"' + (p.id === cur ? ' selected' : '') + '>' + esc((p.demo ? '[DEMO] ' : '') + p.name) + '</option>').join('');
  if (!PIP || !PIP.program) {
    const demo = PIP.demo;
    el.innerHTML = demo
      ? '<select id="pipProg" style="width:220px;max-width:280px"><option value="">-</option>' + opts + '</select>'
        + '<span class="pill" style="color:var(--warn)">DEMO</span> ' + esc(T('pip_demo'))
        + ' <button class="go" id="pipNew" style="padding:4px 10px">' + esc(T('h2new')) + '</button>'
      : esc(T('pip_noprog'));
    const nb = $('pipNew');
    if (nb) nb.addEventListener('click', () => { setTab('programs'); const f = $('npName'); if (f) f.focus(); });
    hookPipSel();
    return;
  }
  const mark = s => s.done ? '<span style="color:var(--green)">✓</span>'
    : (PIP.next === s.k ? '<span style="color:var(--warn)">●</span>' : '<span style="color:var(--dim)">○</span>');
  const info = s => {
    if (!s.info) return '';
    if (s.k === 'recon') return ' <span style="color:var(--dim)">' + s.info.pages + 'p·' + s.info.apis + 'api·' + s.info.params + 'prm·' + s.info.tech + 'tech</span>';
    if (s.k === 'attack') return ' <span style="color:var(--dim)">' + s.info.findings + '</span>';
    return ' <span style="color:var(--dim)">' + esc(String(s.info.moves || s.info.items || '')) + '</span>';
  };
  el.innerHTML = '<select id="pipProg" style="width:190px;max-width:260px;font-weight:700">' + opts + '</select>'
    + PIP.steps.map((s, i) => '<button class="pipStep go' + (PIP.next === s.k ? ' pipNext' : '') + '" data-k="' + esc(s.k) + '" data-tab="' + esc(s.tab) + '">'
      + s.n + '. ' + esc(PIP_STEP[s.k]().lab) + ' ' + mark(s) + info(s) + '</button>').join('')
    + '<span class="pill" style="color:var(--dim)">' + esc(TF('fnd_n', { n: String(PIP.findings || 0) })) + '</span>'
    + (PIP.next ? '<span style="font-size:12.5px">' + esc(T('pip_next')) + ' <b style="color:var(--warn)">' + esc(PIP_STEP[PIP.next]().lab) + '</b></span>' : '');
  el.querySelectorAll('.pipStep').forEach(b => b.addEventListener('click', () => setTab(b.dataset.tab)));
  hookPipSel();
}
// le select est dedans : ne pas redessiner pendant qu'il est utilise
function hookPipSel() {
  const s = $('pipProg');
  if (!s) return;
  s.addEventListener('change', () => setProg(s.value));
  const p = state.data.programs.find(x => x.id === (PIP.program || {}).id);
  if (p && p.demo) s.title = T('pip_demo');
}
fetchPipeline();
function fetchPipeline() {
  fetch('/api/pipeline' + (activeProg ? '?name=' + encodeURIComponent(activeProg) : '')).then(r => r.json()).then(j => {
    if (j && j.program && !activeProg) { activeProg = j.program.id; }
    PIP = j || {};
    if (activeProg && PIP.program && PIP.program.id !== activeProg) {
      // programme demande absent (supprime/demo) : on suit le choix serveur
      activeProg = PIP.program.id;
      try { localStorage.setItem('c2ff_prog', activeProg); } catch (e) {}
      huntSel = arSel = activeProg;
      drawn.hunt = drawn.ars = '';
    }
    drawn.pip = '';
    drawPipeline();
  }).catch(() => {});
}

// ---------- ARSENAL tab : bases CVE -> mouvements suggérés executables ----------
let ARS = {}, ARS_INIT = false, arSel = '', ARS_BUSY = false, drawn_ars_badge = '';
try { if (typeof activeProg !== 'undefined' && activeProg) arSel = activeProg; } catch (e) {}
function drawArsenal() {
  // programme = activeProg (bandeau pipeline), plus de select local
  // etat des bases + dernier calcul
  const b = ARS && ARS.bases || {};
  $('arBase').innerHTML = TF('ar_base', { k: (b.kev && b.kev.n) || '?', e: (b.epss && b.epss.n) || '?', x: (b.sdb && b.sdb.n) || '?' })
    + (ARS && ARS.log && ARS.log.length ? ' - ' + esc(ARS.log.join(' | ')) : '')
    + (ARS && ARS.syncing ? ' [sync...]' : '');
  if (ARS_BUSY) return;
  const out = $('arOut');
  const stash = ARS && ARS.stash;
  const sig = JSON.stringify([stash || null, arSel]);
  if (sig === drawn.ars && !forceDraw) return;
  drawn.ars = sig;
  if (!stash) { out.innerHTML = '<div class="card">' + esc(T('ar_none')) + '</div>'; return; }
  const moves = stash.moves || [];
  // hint si le stash est d'un autre programme
  const head = (stash.program && stash.program !== arSel)
    ? '<div class="card" style="color:var(--dim)">stash = ' + esc(stash.program) + ' - relance MOUVEMENTS pour ' + esc(arSel || '?') + '</div>' : '';
  if (!moves.length) { out.innerHTML = head + '<div class="card">' + esc(T('ar_none')) + '</div>'; return; }
  out.innerHTML = head + moves.map(m => arCard(m)).join('');
  out.querySelectorAll('.arExec').forEach(btn => btn.addEventListener('click', () => arExec(btn.dataset.id)));
}
function arCard(m) {
  const badge = [
    m.kev ? '<span class="pill" style="color:var(--red)">KEV</span>' : (m.kind === 'cve' ? '<span class="pill">CVE</span>' : '<span class="pill">XDB</span>'),
    m.ran ? '<span class="pill" style="color:var(--warn)">RANSOMWARE</span>' : '',
    m.epss !== null && m.epss !== undefined ? '<span class="pill">EPSS ' + esc(String(m.epss)) + '%</span>' : '',
    m.cvss ? '<span class="pill">CVSS ' + esc(String(m.cvss)) + '</span>' : '',
    m.kind === 'cve' && m.sev_p ? '' : '',
  ].join(' ');
  const cmd = m.cmd || (m.kind === 'cve' ? 'nuclei -u https://HOST -id ' + m.cve : '# ' + m.title);
  const exec = (m.kind === 'cve' && /^nuclei/.test(cmd.trim()))
    ? '<button class="go arExec" data-id="' + esc(m.id) + '" style="padding:4px 10px">' + esc(T('ar_exec')) + '</button>' : '';
  const link = (m.kind === 'exploit') ? 'https://www.exploit-db.com/exploits/' + esc(m.id.slice(2)) : (m.cve ? 'https://nvd.nist.gov/vuln/detail/' + esc(m.cve) : '');
  return '<div class="card" style="margin-top:10px; border-left:2px solid ' + (m.kev ? 'var(--red)' : 'var(--dim)') + '">' +
    '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
    '<b style="color:' + (m.kev ? 'var(--red)' : 'var(--text)') + '">' + esc(m.cve || '#' + m.id.slice(2)) + '</b>' + badge + '</div>' +
    '<div style="margin:6px 0">' + esc(m.title + (m.sum ? ' - ' + m.sum : '')) + '</div>' +
    '<div style="color:var(--dim);font-size:12px">' + esc(m.why || '') + (m.exploit ? ' | exploit: ' + esc(m.exploitTitle || m.exploit) : '') + '</div>' +
    (cmd ? '<pre style="margin:8px 0 6px;white-space:pre-wrap;user-select:all">' + esc(cmd) + '</pre>' : '') +
    '<div style="display:flex;gap:8px;align-items:center">' + exec +
    (link ? '<a href="' + link + '" target="_blank" rel="noopener" style="color:var(--green);font-size:12px">' + (m.kind === 'exploit' ? 'Exploit-DB' : 'NVD') + ' ></a>' : '') +
    '</div></div>';
}
function arExec(id) {
  if (ARS_BUSY) return;
  ARS_BUSY = true;
  jpost('/api/arsenal', { op: 'exec', name: arSel || (state.data.programs[0] || {}).id, id }).then(r => r.json()).then(j => {
    ARS_BUSY = false;
    if (!j.ok) { if (!demoErr(j, 'ARSENAL')) toast('ARSENAL', j.err || 'echec', 'P2'); sndPlay('err'); return; }
    if (j.manual) { toast('ARSENAL', 'commande prete : lis l exploit avant de tirer', ''); }
    else { sndPlay('p2'); toast('ARSENAL', 'nuclei termine - findings mis a jour', 'HIT'); }
    drawn.ars = ''; drawn.huntArs = '';
    fetch('/api/arsenal').then(r => r.json()).then(a => { ARS = a || {}; drawArsenal(); if (state.tab === 'hunt') drawHuntArs(); }).catch(() => {});
  }).catch(() => { ARS_BUSY = false; sndPlay('err'); });
}
$('arSync').addEventListener('click', () => {
  const b = $('arSync');
  $('arSt').textContent = '[sync]';
  b.disabled = true;
  jpost('/api/arsenal', { op: 'sync' }).then(r => r.json()).then(j => {
    b.disabled = false;
    if (j.ok) { toast('ARSENAL', 'sync KEV/EPSS/XDB lance', 'HIT'); setTimeout(() => { drawn.ars = ''; fetch('/api/arsenal').then(r => r.json()).then(a => { ARS = a || {}; drawArsenal(); $('arSt').textContent = T('h_ready'); }).catch(() => {}); }, 4000); }
    else { $('arSt').textContent = j.err || 'x'; sndPlay('err'); }
  }).catch(() => { b.disabled = false; sndPlay('err'); });
});
$('arMoves').addEventListener('click', () => {
  const p = arSel || (state.data.programs[0] || {}).id;
  if (!p) return;
  const b = $('arMoves');
  $('arSt').textContent = '⌛'; b.disabled = true;
  jpost('/api/arsenal', { op: 'moves', name: p }).then(r => r.json()).then(j => {
    b.disabled = false; $('arSt').textContent = T('h_ready');
    if (!j.ok) { $('arSt').textContent = '✖'; sndPlay('err'); if (!demoErr(j, 'ARSENAL')) toast('ARSENAL', j.err || 'echec', 'P2'); return; }
    arSel = p;
    sndPlay(j.moves && j.moves.length ? 'hit' : 'click');
    toast('ARSENAL', (j.moves || []).length + ' mouvements', 'HIT');
    fetch('/api/arsenal').then(r => r.json()).then(a => { ARS = a || {}; drawn.ars = ''; drawArsenal(); }).catch(() => {});
  }).catch(() => { b.disabled = false; $('arSt').textContent = '✖'; sndPlay('err'); });
});

// ---- FAST TARGETING : recon-lite ephemere, sans programme ----
let FAST_DATA = null, FAST_BUSY = false;
function drawFast() {
  const box = $('fastOut');
  if (!box) return;
  if (!FAST_DATA) { box.innerHTML = ''; return; }
  const sig = JSON.stringify(FAST_DATA);
  if (sig === drawn.fast && !forceDraw) return;
  drawn.fast = sig;
  const s = FAST_DATA;
  const rows = (t, arr, cut) => arr && arr.length ?
    '<div style="margin-top:7px"><b style="color:var(--green)">' + t + ' (' + arr.length + ')</b><div style="margin-top:3px;line-height:1.7;font-size:10.5px;color:var(--dim);word-break:break-all">' +
    arr.slice(0, cut || 999).map(x => '<span class="pill" style="margin:1px 2px 1px 0">' + esc(x) + '</span>').join('') + (arr.length > (cut || 999) ? '…' : '') + '</div></div>' : '';
  box.innerHTML =
    '<div class="card" style="margin-top:12px">' +
    '<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:baseline">' +
    '<b style="color:var(--green);font-size:13px">' + esc(s.host || '?') + '</b>' +
    '<small style="color:var(--faint)">' + esc(s.reqs || 0) + ' req · ' + Math.round((s.ms || 0) / 100) / 10 + ' s</small>' +
    (s.tech && s.tech.length ? '<span class="pill">⚙ ' + esc(s.tech.join(' / ').slice(0, 80)) + '</span>' : '') +
    '<button class="ghost fastToProg" style="padding:4px 10px;font-size:11px;margin-left:auto">programme ›</button></div>' +
    rows('API', s.apis, 30) + rows('PARAMS', s.params, 30) +
    rows('PAGES', (s.pages || []).map(x => x.replace(/^https?:\/\//, '')), 20) +
    rows('JS', (s.jsfiles || []).map(x => x.replace(/^https?:\/\//, '')), 15) +
    rows('SUBS', s.subs, 25) + '</div>';
  const tp = box.querySelector('.fastToProg');
  if (tp) tp.addEventListener('click', () => {
    const f = $('npName');
    jpost('/api/programs', { op: 'create', name: s.host, scope: s.host }).then(r => r.json()).then(j => {
      if (!j.ok) { toast('FAST', j.error || 'echec', 'P2'); return; }
      if (j.id) setProg(j.id);
      setTab('programs');
      drawn.prog = ''; PIP_PROGS_SIG = '';
      refresh();
      if (f) f.focus();
    }).catch(() => {});
  });
}
$('fastGo').addEventListener('click', () => {
  const t = ($('fastTarget').value || '').trim();
  if (!t || FAST_BUSY) return;
  FAST_BUSY = true;
  const b = $('fastGo');
  b.disabled = true; $('fastSt').textContent = '⟳';
  jpost('/api/fast', { target: t, by: HANDLE }).then(r => r.json()).then(j => {
    FAST_BUSY = false; b.disabled = false;
    if (!j.ok || !j.surface) { $('fastSt').textContent = '✖'; sndPlay('err'); toast('FAST', j.err || 'scan echoue', 'P2'); return; }
    $('fastSt').textContent = T('h_ready');
    FAST_DATA = j.surface; drawn.fast = '';
    sndPlay('hit'); drawFast();
  }).catch(() => { FAST_BUSY = false; b.disabled = false; $('fastSt').textContent = '✖'; sndPlay('err'); });
});
$('fastTarget').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); $('fastGo').click(); } });

// purge recon : vide surface/attack/urls/js/modules/plan/baseline/advanced du programme
$('huntPurge').addEventListener('click', () => {
  const p = huntSel; if (!p) return;
  if (!confirm('Purger le recon de ' + p + ' ? (surface, attack, urls, js, modules, plan, baseline)')) return;
  jpost('/api/programs', { op: 'purge', name: p, by: HANDLE }).then(r => r.json()).then(j => {
    if (!j.ok) { toast('PURGE', j.error || 'echec', 'P2'); sndPlay('err'); return; }
    SURF = {}; ATKS = {}; JSI = {};
    drawn.hunt = drawn.ars = '';
    toast('PURGE', 'recon purge pour ' + p, 'HIT'); sndPlay('click');
    blurNow(); refresh();
  }).catch(() => sndPlay('err'));
});
$('huntRecon').addEventListener('click', () => {
  const p = huntSel; if (!p) return;
  const b = $('huntRecon');
  $('huntSt').textContent = '⟳'; $('huntSt').setAttribute('data-i', '');
  b.disabled = true;
  jpost('/api/recon', { name: p }).then(r => r.json()).then(j => {
    b.disabled = false;
    if (!j.ok || !j.surface) { $('huntSt').textContent = '✖'; sndPlay('err'); if (!demoErr(j, 'RECON')) toast('RECON', T('rc_fail'), 'P2'); return; }
    SURF[p] = j.surface;
    sndPlay('hit'); toast('RECON', T('rc_done'), 'HIT');
    drawn.hunt = ''; drawHunt();
  }).catch(() => { b.disabled = false; $('huntSt').textContent = '✖'; sndPlay('err'); });
});
$('huntAtk').addEventListener('click', () => {
  const p = huntSel; if (!p) return;
  const b = $('huntAtk');
  $('huntSt').textContent = '⚔'; $('huntSt').setAttribute('data-i', '');
  b.disabled = true;
  jpost('/api/attack', { name: p }).then(r => r.json()).then(j => {
    b.disabled = false;
    if (!j.ok || !j.attack) { $('huntSt').textContent = '✖'; sndPlay('err'); if (!demoErr(j, 'ATTACK')) toast('ATTACK', T('atk_fail'), 'P2'); return; }
    ATKS[p] = j.attack;
    const n = (j.attack.findings || []).filter(f => f.sev === 'P1' || f.sev === 'P2').length;
    sndPlay(n ? 'p1' : 'hit'); toast('ATTACK', n ? TF('atk_done', { n : String(n) }) : T('rc_done'), n ? 'P2' : 'HIT');
    drawn.hunt = ''; drawHunt();
  }).catch(() => { b.disabled = false; $('huntSt').textContent = '✖'; sndPlay('err'); });
});
// ---- JS INTEL : endpoints + secrets + sourcemaps des bundles ----
let JSI = {}, JSI_BUSY = false, JSI_READY = false;
$('huntJs').addEventListener('click', () => {
  const p = huntSel; if (!p) return;
  if (JSI_BUSY) return;
  JSI_BUSY = true;
  const b = $('huntJs');
  b.disabled = true; b.textContent = '⟳ JS…';
  jpost('/api/jsint', { op: 'run', name: p }).then(r => r.json()).then(j => {
    JSI_BUSY = false; b.disabled = false; b.textContent = 'JS INTEL';
    if (!j.ok) { sndPlay('err'); if (!demoErr(j, 'JS INTEL')) toast('JS INTEL', j.err || 'echec', 'P2'); return; }
    JSI[p] = j.res || {};
    sndPlay('hit');
    toast('JS INTEL', j.res.files + ' fichiers - ' + (j.res.endpoints || []).length + ' endpoints - ' + (j.res.secrets || []).length + ' secrets - ' + (j.res.maps || []).filter(m => m.fetched).length + ' sourcemaps', 'HIT');
    drawn.jsi = '';
    drawJsi();
  }).catch(() => { JSI_BUSY = false; b.disabled = false; b.textContent = 'JS INTEL'; sndPlay('err'); });
});
function drawJsi() {
  const box = $('huntJsi');
  if (!box) return;
  const JS = jsiFor(huntSel) || null;
  const sig = JSON.stringify(JS);
  if (sig === drawn.jsi) return;
  drawn.jsi = sig;
  if (!JS || !JS.host) { box.innerHTML = ''; return; }
  const eps = JS.endpoints || [], secs = JS.secrets || [], maps = JS.maps || [];
  const pills = (arr, max) => arr.slice(0, max).map(x => '<span class="pill" style="margin:1px 2px 1px 0">' + esc(x) + '</span>').join('') + (arr.length > max ? ' <small style="color:var(--dim)">+' + (arr.length - max) + '</small>' : '');
  const SEC_COLOR = { 'aws-key': 'var(--danger)', 'google-key': 'var(--warn)', 'jwt': 'var(--warn)' };
  box.innerHTML =
    '<div class="card" style="margin-top:12px">' +
    '<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:baseline">' +
    '<b style="color:var(--green);font-size:12.5px">◈ JS INTEL</b>' +
    '<small style="color:var(--faint)">' + (JS.files || 0) + ' fichiers · ' + ((JS.bytes || 0) < 1024 ? (JS.bytes || 0) + ' o' : Math.round((JS.bytes || 0) / 1024) + ' Ko') + ' · ' + new Date(JS.ts).toLocaleTimeString('fr-FR') + '</small>' +
    (secs.length ? '<span class="pill" style="color:var(--danger)">' + secs.length + ' secrets</span>' : '') +
    (maps.filter(m => m.fetched).length ? '<span class="pill" style="color:var(--warn)">' + maps.filter(m => m.fetched).length + ' sourcemaps exposes</span>' : '') +
    '</div>' +
    (eps.length ? '<div style="margin-top:7px"><b style="color:var(--green)">endpoints (' + eps.length + ')</b><div style="margin-top:3px;line-height:1.7;font-size:10.5px;word-break:break-all">' + pills(eps.map(e => e.u), 40) + '</div></div>' : '') +
    (secs.length ? '<div style="margin-top:7px"><b style="color:var(--danger)">secrets (teste avant de crier - les placeholders existent)</b>' +
      secs.slice(0, 15).map(s => '<div style="font-size:11px;margin-top:3px;word-break:break-all"><span class="pill" style="color:' + (SEC_COLOR[s.k] || 'var(--warn)') + '">' + esc(s.k) + '</span> <code style="color:var(--text)">' + esc(s.v) + '</code> <small style="color:var(--dim)">' + esc(s.from.split('/').pop().slice(0, 40)) + '</small></div>').join('') + '</div>' : '') +
    (maps.length ? '<div style="margin-top:7px"><b style="color:var(--warn)">sourcemaps</b>' +
      maps.slice(0, 8).map(m => '<div style="font-size:11px;margin-top:3px;word-break:break-all">' + (m.fetched ? '<span style="color:var(--danger)">✔ 200</span>' : '<span style="color:var(--dim)">✖</span>') + ' ' + esc(m.url.slice(0, 100)) + (m.sources && m.sources.length ? ' <small style="color:var(--dim)">' + m.sources.length + ' sources</small>' : '') + '</div>').join('') + '</div>' : '') +
    '</div>';
}

// ---- URLS passives : wayback + OTX, mining de params ----
let USTORE = {}, URLS_BUSY = false, URLS_READY = false;
function ustoreFor(id) {
  if (!URLS_READY) {
    URLS_READY = true;
    fetch('/api/urls').then(r => r.json()).then(j => {
      if (j.ok && j.all) { USTORE = j.all; if (state.tab === 'hunt') { drawn.urls = ''; drawUrls(); } }
    }).catch(() => {});
  }
  return USTORE[id];
}
$('huntUrls').addEventListener('click', () => {
  const p = huntSel; if (!p) return;
  if (URLS_BUSY) return;
  URLS_BUSY = true;
  const b = $('huntUrls');
  b.disabled = true; b.textContent = '⟳ WAYBACK…';
  jpost('/api/urls', { op: 'run', name: p }).then(r => r.json()).then(j => {
    URLS_BUSY = false; b.disabled = false; b.textContent = 'URLS';
    if (!j.ok) { sndPlay('err'); if (!demoErr(j, 'URLS')) toast('URLS', j.err || 'echec', 'P2'); return; }
    USTORE[p] = j.res || {};
    sndPlay('hit');
    toast('URLS', j.res.total + ' urls uniques - ' + (j.res.params || []).length + ' params - ' + (j.res.endpoints || []).length + ' endpoints API', 'HIT');
    drawn.urls = '';
    drawUrls();
  }).catch(() => { URLS_BUSY = false; b.disabled = false; b.textContent = 'URLS'; sndPlay('err'); });
});
function drawUrls() {
  const box = $('huntUrlsOut');
  if (!box) return;
  const U = ustoreFor(huntSel) || null;
  const sig = JSON.stringify(U);
  if (sig === drawn.urls) return;
  drawn.urls = sig;
  if (!U || !U.host) { box.innerHTML = ''; return; }
  const urls = U.urls || [], ps = U.params || [], eps = U.endpoints || [], exts = U.exts || {};
  const pillList = (arr, max) => arr.slice(0, max).map(x => '<span class="pill" style="margin:1px 2px 1px 0">' + esc(x.length > 90 ? x.slice(0, 97) + '…' : x) + '</span>').join('') + (arr.length > max ? ' <small style="color:var(--dim)">+' + (arr.length - max) + '</small>' : '');
  const extsTxt = Object.keys(exts).sort((a, b) => exts[b] - exts[a]).slice(0, 10).map(e => e + ':' + exts[e]).join(' · ');
  box.innerHTML =
    '<div class="card" style="margin-top:12px">' +
    '<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:baseline">' +
    '<b style="color:var(--green);font-size:12.5px">◈ URLS PASSIVES</b>' +
    '<small style="color:var(--faint)">' + (U.total || 0) + ' urls uniques (' + esc(U.base || '') + ') · wayback + OTX · ' + new Date(U.ts).toLocaleTimeString('fr-FR') + '</small>' +
    (eps.length ? '<span class="pill" style="color:var(--warn)">' + eps.length + ' endpoints API</span>' : '') +
    '</div>' +
    (ps.length ? '<div style="margin-top:7px"><b style="color:var(--green)">params trouvés (cible tes tests de reflection/authz sur ceux-ci)</b>' +
      '<div style="margin-top:3px;line-height:1.7;font-size:10.5px">' + ps.slice(0, 40).map(p => '<span class="pill" style="margin:1px 2px 1px 0">' + esc(p.p) + ' ×' + p.n + '</span>').join('') + (ps.length > 40 ? ' <small style="color:var(--dim)">+' + (ps.length - 40) + '</small>' : '') + '</div>' +
      '<small style="color:var(--dim)">exemples de valeurs : ' + ps.slice(0, 6).map(p => esc(p.p) + '=' + esc(p.ex || '?')).join(' | ') + '</small></div>' : '') +
    (extsTxt ? '<div style="margin-top:7px"><b style="color:var(--warn)">fichiers sensibles dans l historique</b> <small style="color:var(--text)">' + esc(extsTxt) + '</small></div>' : '') +
    (eps.length ? '<div style="margin-top:7px"><b style="color:var(--green)">endpoints API historiques</b><div style="margin-top:3px;line-height:1.7;font-size:10.5px;word-break:break-all">' + pillList(eps, 40) + '</div></div>' : '') +
    (urls.length ? '<details style="margin-top:7px"><summary style="cursor:pointer;color:var(--dim);font-size:11px">toutes les urls (' + urls.length + ')</summary><div style="margin-top:3px;line-height:1.6;font-size:10px;word-break:break-all;max-height:180px;overflow-y:auto">' + pillList(urls, 200) + '</div></details>' : '') +
    '</div>';
}

// ---- MODULES a preuve : REFLECT + AUTHZ ----
let MODS = {}, MODS_READY = false, MODS_BUSY = {};
function modsFor(id) {
  if (!MODS_READY) {
    MODS_READY = true;
    fetch('/api/modules').then(r => r.json()).then(j => {
      if (j.ok && j.all) { MODS = j.all; if (state.tab === 'hunt') { drawn.mods = ''; drawMods(); } }
    }).catch(() => {});
  }
  return MODS[id];
}
function runMod(op, btnId) {
  const p = huntSel; if (!p) return;
  if (MODS_BUSY[op]) return;
  MODS_BUSY[op] = true;
  const b = $(btnId);
  const orig = b.textContent;
  b.disabled = true; b.textContent = '⟳ …';
  jpost('/api/modules', { op, name: p }).then(r => r.json()).then(j => {
    MODS_BUSY[op] = false; b.disabled = false; b.textContent = orig;
    if (!j.ok) { sndPlay('err'); if (!demoErr(j, op.toUpperCase())) toast(op.toUpperCase(), j.err || 'echec', 'P2'); return; }
    MODS[p] = Object.assign({}, MODS[p] || {}, { [op]: j.res });
    const n = (j.res.candidates || []).filter(c => (c.sev === 'P2') || (c.tests || []).some(t => t.sev === 'P2')).length;
    sndPlay(n ? 'p1' : 'hit');
    toast(op.toUpperCase(), (j.res.candidates || []).length + ' candidats' + (n ? ' dont ' + n + ' P2' : ' - ' + (j.res.checked || []).length + ' testes'), n ? 'P2' : 'HIT');
    drawn.mods = '';
    drawMods();
  }).catch(() => { MODS_BUSY[op] = false; b.disabled = false; b.textContent = orig; sndPlay('err'); });
}
$('huntReflect').addEventListener('click', () => runMod('reflect', 'huntReflect'));
$('huntAuthz').addEventListener('click', () => runMod('authz', 'huntAuthz'));
// ---- MODES AVANCES : 12 modules budgetes P1>P2>P3, baseline cache + run ----
let ADV_OPEN = false, ADV_DATA = null, ADV_BUSY = false, ADV_SEL = null, ADV_LAST = null, ADV_FETCH = '';
$('huntAdvBtn').addEventListener('click', () => {
  ADV_OPEN = !ADV_OPEN;
  drawn.adv = '';
  drawAdv();
});
function advFetch() {
  if (!huntSel || ADV_FETCH === huntSel) return;
  ADV_FETCH = huntSel;
  fetch('/api/advanced?name=' + encodeURIComponent(huntSel)).then(r => r.json()).then(j => {
    ADV_DATA = Object.assign({ prog: huntSel }, j);
    if (state.tab === 'hunt') { drawn.adv = ''; drawAdv(); }
  }).catch(() => {});
}
function drawAdv() {
  const box = $('huntAdvOut');
  if (!box) return;
  if (!ADV_OPEN) { if (drawn.adv !== 'closed') { box.innerHTML = ''; drawn.adv = 'closed'; } return; }
  if (!huntSel) { box.innerHTML = ''; return; }
  advFetch();
  const d = ADV_DATA && ADV_DATA.prog === huntSel ? ADV_DATA : null;
  const sig = JSON.stringify([d ? [d.cfg, d.baseline, d.report] : null, ADV_SEL, ADV_LAST, ADV_BUSY]);
  if (sig === drawn.adv) return;
  drawn.adv = sig;
  if (!d) { box.innerHTML = '<div class="card" style="margin-top:12px"><div class="subtle" style="color:var(--faint);font-size:11px">⟳ …</div></div>'; return; }
  const modes = d.modes || [];
  if (!ADV_SEL) ADV_SEL = {};
  const anySelStored = Object.keys(ADV_SEL).length > 0;
  const selOf = k => anySelStored ? !!ADV_SEL[k] : true;
  const sevCol = { P1: 'var(--danger)', P2: 'var(--warn)', P3: 'var(--dim)' };
  const pools = d.pools || {};
  const rem = ADV_LAST && ADV_LAST.remaining ? ADV_LAST.remaining : pools;
  const used = ADV_LAST ? (ADV_LAST.used || 0) : 0;
  const bl = d.baseline || { n: 0 };
  box.innerHTML =
    '<div class="card" style="margin-top:12px">' +
    '<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:baseline">' +
    '<b style="color:var(--green);font-size:12.5px">◈ ADVANCED MODULES</b>' +
    '<small style="color:var(--faint)">budget ' + esc(d.cfg.budget) + ' req/cycle · gap ' + esc(d.cfg.base_gap_ms) + ' ms (x2 sur 429/timeout) · baseline cache : ' + esc(bl.n) + ' endpoints</small>' +
    '<span style="flex:1"></span>' +
    ['P1', 'P2', 'P3'].map(p => '<span class="pill" style="color:' + sevCol[p] + '">' + p + ' ' + esc(rem[p] || 0) + '/' + esc(pools[p] || 0) + ' restants</span>').join(' ') +
    '</div>' +
    '<div style="margin-top:7px;display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:4px 14px">' +
    modes.map(m =>
      '<label style="display:flex;gap:6px;align-items:center;font-size:10.5px;cursor:pointer">' +
      '<input type="checkbox" class="advSel" data-k="' + esc(m.key) + '"' + (selOf(m.key) ? ' checked' : '') + '>' +
      '<span class="sev" style="background:none;color:' + (sevCol[m.riskLevel] || 'var(--dim)') + '">' + esc(m.riskLevel) + '</span>' +
      '<b>' + esc(m.key) + '</b>' +
      '<small style="color:var(--dim)">CWE ' + esc(m.cwe) + ' - ' + esc(m.desc) + '</small></label>').join('') +
    '</div>' +
    '<div style="display:flex;gap:8px;align-items:center;margin-top:8px;flex-wrap:wrap">' +
    '<button class="ghost" id="advBase"' + (ADV_BUSY ? ' disabled' : '') + '>BASELINE</button>' +
    '<button class="go" id="advRun"' + (ADV_BUSY ? ' disabled' : '') + '>' + (ADV_BUSY ? '⟳ RUN…' : 'RUN') + '</button>' +
    '<small style="color:var(--dim)">P1 : nuclei auto apres alerte · DIFF_COMPARE lit la baseline, sans nouvelle requete</small>' +
    '</div>' +
    ((ADV_LAST && ADV_LAST.used ? '<div style="margin-top:6px;font-size:10.5px;color:var(--dim)">dernier run : ' + esc(ADV_LAST.used) + ' req · ' + Math.round((ADV_LAST.ms || 0) / 100) / 10 + ' s · ' + (ADV_LAST.alerts || []).length + ' alertes</div>' : '')) +
    ((d.report || []).length ?
      '<div style="margin-top:8px;overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:10px">' +
      '<tr style="color:var(--dim);text-align:left"><th style="padding:3px 6px">mode</th><th style="padding:3px 6px">payload</th><th style="padding:3px 6px">status</th><th style="padding:3px 6px">latence</th><th style="padding:3px 6px">evidence</th></tr>' +
      d.report.map(a =>
        '<tr style="border-top:1px solid var(--line,#333)">' +
        '<td style="padding:3px 6px"><span class="pill" style="color:' + (sevCol[a.sev] || 'var(--dim)') + '">' + esc(a.sev) + '</span> ' + esc(a.mode) + '</td>' +
        '<td style="padding:3px 6px;font-family:monospace;word-break:break-all;max-width:260px">' + esc(String(a.payload || '').slice(0, 120)) + '</td>' +
        '<td style="padding:3px 6px">' + esc(a.status || 0) + '</td>' +
        '<td style="padding:3px 6px' + (a.mode === 'BLIND_SQL' ? ';color:var(--warn);font-weight:bold' : '') + '">' + esc(a.ms || 0) + ' ms</td>' +
        '<td style="padding:3px 6px;color:var(--dim);word-break:break-all;max-width:340px">' + esc(String(a.evidence || '').slice(0, 200)) + '</td>' +
        '</tr>').join('') +
      '</table></div>' :
      '<div style="margin-top:6px;font-size:10.5px;color:var(--faint)">aucun rapport - RUN pour lancer les modes selectionnes</div>') +
    '</div>';
  box.querySelectorAll('.advSel').forEach(cb => cb.addEventListener('change', () => {
    ADV_SEL[cb.dataset.k] = cb.checked;
    drawn.adv = ''; drawAdv();
  }));
  $('advBase').addEventListener('click', () => {
    const b = $('advBase'); b.disabled = true; b.textContent = '⟳ …';
    jpost('/api/advanced', { op: 'baseline', name: huntSel }).then(r => r.json()).then(j => {
      b.disabled = false; b.textContent = 'BASELINE';
      if (!j.ok) { sndPlay('err'); if (!demoErr(j, 'ADV')) toast('ADV', j.err || 'echec', 'P2'); return; }
      sndPlay('hit'); toast('ADV', j.captured.length + ' endpoints en baseline', 'HIT');
      ADV_DATA = null; ADV_FETCH = ''; drawn.adv = ''; drawAdv();
    }).catch(() => { b.disabled = false; b.textContent = 'BASELINE'; sndPlay('err'); });
  });
  $('advRun').addEventListener('click', () => {
    if (ADV_BUSY) return;
    const sel = modes.map(m => m.key).filter(k => selOf(k));
    if (!sel.length) { toast('ADV', 'aucun mode selectionne', 'P2'); return; }
    ADV_BUSY = true;
    const b = $('advRun'); b.disabled = true; b.textContent = '⟳ RUN…';
    jpost('/api/advanced', { op: 'run', name: huntSel, modes: sel }).then(r => r.json()).then(j => {
      ADV_BUSY = false; b.disabled = false; b.textContent = 'RUN';
      if (!j.ok) { sndPlay('err'); if (!demoErr(j, 'ADV')) toast('ADV', j.err || 'echec', 'P2'); return; }
      ADV_LAST = j.res; ADV_DATA = Object.assign({}, d, { report: j.report || [] });
      const p1 = (j.report || []).filter(a => a.sev === 'P1').length;
      sndPlay(p1 ? 'p1' : (j.report || []).length ? 'p2' : 'click');
      toast('ADV', (j.res.used || 0) + ' req - ' + (j.report || []).length + ' alertes', p1 ? 'P1' : 'HIT');
      drawn.adv = ''; drawAdv();
    }).catch(() => { ADV_BUSY = false; b.disabled = false; b.textContent = 'RUN'; sndPlay('err'); });
  });
}
// ARSENAL dans la vue de chasse : mouvements du programme cible, EXEC ici
let HUNT_ARS_BUSY = false;
$('huntArsBtn').addEventListener('click', () => {
  const p = huntSel; if (!p || HUNT_ARS_BUSY) return;
  HUNT_ARS_BUSY = true;
  const b = $('huntArsBtn');
  b.textContent = '⟳ CVE…';
  jpost('/api/arsenal', { op: 'moves', name: p }).then(r => r.json()).then(j => {
    HUNT_ARS_BUSY = false; b.textContent = 'ARSENAL';
    if (!j.ok) { sndPlay('err'); if (!demoErr(j, 'ARSENAL')) toast('ARSENAL', j.err || 'echec', 'P2'); return; }
    arSel = p;
    sndPlay(j.moves && j.moves.length ? 'hit' : 'click');
    toast('ARSENAL', (j.moves || []).length + ' mouvements', 'HIT');
    fetch('/api/arsenal').then(r => r.json()).then(a => { ARS = a || {}; drawn.huntArs = ''; drawHuntArs(); }).catch(() => {});
  }).catch(() => { HUNT_ARS_BUSY = false; b.textContent = 'ARSENAL'; sndPlay('err'); });
});
function drawHuntArs() {
  const box = $('huntArs');
  if (!box) return;
  const stash = ARS && ARS.stash;
  if (!stash || state.tab !== 'hunt') { if (drawn.huntArs !== 'off') { box.innerHTML = ''; drawn.huntArs = 'off'; } return; }
  const sig = JSON.stringify([stash, huntSel]);
  if (sig === drawn.huntArs) return;
  drawn.huntArs = sig;
  arSel = huntSel;
  const moves = stash.moves || [];
  const head =
    '<div class="card" style="margin-top:12px">' +
    '<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:baseline">' +
    '<b style="color:var(--green);font-size:12.5px">◈ ARSENAL - CVE/exploits matches sur la cible</b>' +
    '<small style="color:var(--faint)">' + moves.length + ' mouvements</small>' +
    (stash.program && stash.program !== huntSel ? '<span class="pill" style="color:var(--dim)">stash = ' + esc(stash.program) + ' - relance ARSENAL</span>' : '') +
    '</div>';
  if (!moves.length) { box.innerHTML = head + '<div style="margin-top:5px;color:var(--dim);font-size:11px">aucun mouvement : lance SYNC sur l onglet ARSENAL puis ARSENAL ici</div></div>'; return; }
  box.innerHTML = head + moves.map(m => arCard(m)).join('') + '</div>';
  box.querySelectorAll('.arExec').forEach(btn => btn.addEventListener('click', () => arExec(btn.dataset.id)));
}
function drawMods() {
  const box = $('huntModOut');
  if (!box) return;
  const M = modsFor(huntSel) || null;
  const sig = JSON.stringify(M);
  if (sig === drawn.mods) return;
  drawn.mods = sig;
  if (!M || (!M.reflect && !M.authz)) { box.innerHTML = ''; return; }
  const card = (title, color, m) => {
    const cands = m.candidates || [];
    const chk = m.checked || [];
    let inner =
      '<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:baseline">' +
      '<b style="color:' + color + ';font-size:12.5px">' + title + '</b>' +
      '<small style="color:var(--faint)">' + chk.length + ' testes · ' + new Date(m.ts).toLocaleTimeString('fr-FR') + '</small>' +
      (cands.length ? '<span class="pill" style="color:var(--warn)">' + cands.length + ' candidats</span>' : '') +
      '</div>';
    if (cands.length) {
      inner += cands.slice(0, 8).map(c => {
        const tests = c.tests || [{ kind: c.kind, sev: c.sev, req: c.req, res: c.res, verdict: c.kind === 'raw' ? 'reflechi brut - XSS candidat' : 'reflechi mais encode' }];
        return '<div style="margin-top:7px;padding:7px 8px;border:1px solid var(--line,#333);border-radius:6px;font-size:11px">' +
          '<span class="pill" style="color:' + (tests.some(t => t.sev === 'P2') ? 'var(--danger)' : 'var(--dim)') + '">' + esc(c.param || tests[0].kind) + '</span> ' +
          '<span style="color:var(--text)">' + tests.map(t => esc(t.verdict)).join(' · ') + '</span>' +
          '<div style="margin-top:3px;word-break:break-all;color:var(--dim)">' + esc((c.url || '').slice(0, 130)) + '</div>' +
          tests.map(t => {
            const res = t.res ? (t.res.status + ' · ' + t.res.len + ' o · ctx : ' + (t.res.excerpt || '')) : (t.with ? 'avec creds : ' + t.with.status + '/' + t.with.len + ' o vs sans : ' + t.without.status + '/' + t.without.len + ' o' : '');
            return '<div style="margin-top:3px"><code style="color:var(--text);font-size:10px;word-break:break-all">' + esc((t.req || '').slice(0, 220)) + '</code>' +
              '<div style="color:var(--dim);font-size:10px;word-break:break-all">→ ' + esc(res.slice(0, 200)) + '</div></div>';
          }).join('') +
          '</div>';
      }).join('');
    }
    if ((m.errs || []).length) inner += '<div style="margin-top:5px;color:var(--warn);font-size:11px">' + m.errs.map(e => esc(e)).join(' · ') + '</div>';
    if (!cands.length && !(m.errs || []).length) inner += '<div style="margin-top:5px;color:var(--dim);font-size:11px">aucun candidat</div>';
    return '<div class="card" style="margin-top:12px">' + inner + '</div>';
  };
  box.innerHTML =
    (M.reflect ? card('◈ REFLECT - params testes avec canary, req+res captures', 'var(--green)', M.reflect) : '') +
    (M.authz ? card('◈ AUTHZ - avec/sans creds + swap ID, BOLA/IDOR candidats', 'var(--green)', M.authz) : '');
}

// ---- AUTH : creds par programme, injectes dans RECON/JS INTEL/ATTACK ----
let AUTH_OPEN = false, AUTH_INFO = null, AUTH_TEST = null, AUTH_FETCH = false;
$('huntAuthBtn').addEventListener('click', () => {
  AUTH_OPEN = !AUTH_OPEN;
  drawn.auth = '';
  drawAuth();
});
function drawAuth() {
  const box = $('huntAuthOut');
  if (!box) return;
  if (!AUTH_OPEN) { if (drawn.auth !== 'closed') { box.innerHTML = ''; drawn.auth = 'closed'; } return; }
  const sig = JSON.stringify([huntSel, AUTH_INFO, AUTH_TEST]);
  if (sig === drawn.auth) return;
  drawn.auth = sig;
  let info = AUTH_INFO && AUTH_INFO.prog === huntSel ? AUTH_INFO : null;
  if (!info && huntSel && AUTH_FETCH !== huntSel) {
    AUTH_FETCH = huntSel;
    fetch('/api/auth?name=' + encodeURIComponent(huntSel)).then(r => r.json()).then(j => {
      if (j.ok) { AUTH_INFO = Object.assign({ prog: j.prog }, j); if (state.tab === 'hunt') { drawn.auth = ''; drawAuth(); } }
    }).catch(() => {});
  }
  const test = AUTH_TEST && AUTH_TEST.prog === huntSel ? AUTH_TEST : null;
  const VERDICT = {
    'auth-effect': ['creds actives : la reponse change avec vs sans', 'var(--green)'],
    'auth-200': ['creds acceptees (200) mais reponse identique - a verifier manuellement', 'var(--warn)'],
    'no-diff': ['aucune difference avec/sans : creds probablement mortes ou non testees ici', 'var(--danger)'],
    'no-auth': ['aucune creds definie : colle tes cookies/Authorization et sauvegarde', 'var(--dim)'],
  };
  box.innerHTML =
    '<div class="card" style="margin-top:12px">' +
    '<b style="color:var(--green);font-size:12.5px">◈ AUTH - creds du programme (une par ligne)</b>' +
    '<small style="color:var(--dim);display:block;margin:4px 0">format : <code>Authorization: Bearer …</code> · <code>Cookie: session=…; uid=…</code> · <code>Bearer …</code> · <code>user:pass</code> - injectees dans RECON, JS INTEL, ATTACK et les modules a preuve</small>' +
    '<textarea id="authTa" spellcheck="false" style="width:100%;min-height:90px;background:var(--bg2,#111);color:var(--text);border:1px solid var(--line,#333);border-radius:6px;padding:8px;font-family:var(--mono,monospace);font-size:11px" placeholder="Authorization: Bearer eyJ…\nCookie: session=…"></textarea>' +
    '<div style="display:flex;gap:8px;align-items:center;margin-top:7px;flex-wrap:wrap">' +
    '<button class="go" id="authSave">SAUVER</button>' +
    '<button class="ghost" id="authTest">TEST AVEC/SANS</button>' +
    (info && info.kinds && info.kinds.length ? '<span class="pill" style="color:var(--green)">' + info.kinds.map(k => esc(k)).join(' · ') + '</span>' : (info ? '<span class="pill" style="color:var(--dim)">aucune creds</span>' : '')) +
    '</div>' +
    (test ? '<div style="margin-top:7px;font-size:11px"><span class="pill" style="color:' + VERDICT[test.verdict][1] + '">' + VERDICT[test.verdict][0] + '</span>' +
      '<div style="margin-top:4px;color:var(--dim)">avec creds : ' + (test.with.status || 'err') + ' (' + test.with.len + ' o) · sans : ' + (test.without.status || 'err') + ' (' + test.without.len + ' o) · <span style="word-break:break-all">' + esc(test.target) + '</span></div></div>' : '') +
    '</div>';
  const ta = $('authTa');
  if (ta) ta.value = (info && info.creds) || '';
  $('authSave').addEventListener('click', () => {
    jpost('/api/auth', { op: 'save', name: huntSel, creds: $('authTa').value }).then(r => r.json()).then(j => {
      if (!j.ok) { sndPlay('err'); if (!demoErr(j, 'AUTH')) toast('AUTH', j.err || 'echec', 'P2'); return; }
      AUTH_INFO = Object.assign({ prog: huntSel }, j); sndPlay('hit'); toast('AUTH', 'creds sauvees', 'HIT'); drawn.auth = ''; drawAuth();
    }).catch(() => sndPlay('err'));
  });
  $('authTest').addEventListener('click', () => {
    const b = $('authTest'); b.disabled = true;
    jpost('/api/auth', { op: 'test', name: huntSel, creds: $('authTa').value, target: '' }).then(r => r.json()).then(j => {
      b.disabled = false;
      if (!j.ok) { sndPlay('err'); toast('AUTH', j.err || 'echec', 'P2'); return; }
      AUTH_TEST = Object.assign({ prog: huntSel }, j); sndPlay('hit'); drawn.auth = ''; drawAuth();
    }).catch(() => { b.disabled = false; sndPlay('err'); });
  });
}

// nouveau programme
$('progForm').addEventListener('submit', e => {
  e.preventDefault();
  let id = $('npName').value.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
  if (!id) return;
  const list = state.data.programs.slice();
  list.push({
    id, name: $('npName').value.trim(), platform: 'manuel', header: $('npHeader').value.trim(),
    scope: $('npScope').value.split(',').map(s => s.trim()).filter(Boolean),
    creds: '', runs: [],
  });
  jpost('/api/programs', { programs: list }).then(refresh);
  setProg(id);   // le nouveau programme devient actif : HUNT/bandeau le suivent
  $('progForm').reset();
});

// nouveau finding
$('newFinding').addEventListener('submit', e => {
  e.preventDefault();
  jpost('/api/findings', { sev: $('nfSev').value, program: $('nfProg').value, text: $('nfText').value, name: HANDLE }).then(refresh);
  $('nfText').value = '';
});

// ---------- chat ----------
function drawChat() {
  const c = state.data.chat.filter(m => m.kind !== 'team');
  const sig = c.length + ':' + (c.length ? (c[c.length - 1].t + (c[c.length - 1].text || '')).slice(-60) : '');
  if (sig === drawn.chat && !forceDraw) return;
  drawn.chat = sig;
  $('nChat').textContent = String(c.length);
  const log = $('chatlog');
  log.innerHTML = c.map(m =>
    '<div class="msg ' + esc(m.from) + (m.kind === 'queue' ? ' queue' : '') + '"><div class="who">' +
    (m.kind === 'queue' ? T('w_launch') + ' ' : '') + esc(m.name || (m.from === 'me' ? T('w_me') : m.from === 'ia' ? T('w_ia') : T('w_claude'))) + ' · ' + new Date(m.t).toLocaleTimeString('fr-FR') + '</div>' +
    esc(m.text || (m.playbook ? m.playbook + ' › ' + (m.program || '?') : '')) + '</div>'
  ).join('') || '<div class="msg claude">' + T('ch_empty') + '</div>';
  log.scrollTop = log.scrollHeight;
}
$('chatform').addEventListener('submit', e => {
  e.preventDefault();
  const t = $('chatinput').value.trim();
  if (!t) return;
  jpost('/api/chat', { text: t, name: HANDLE });
  state.chatSeen++; // optimiste : on affiche au prochain refresh de toute facon
  $('chatinput').value = '';
  setTimeout(refresh, 250);
});

// ---------- agent IA (optionnel) ----------
function drawAI() {
  const ai = state.data.ai || {};
  const sig = JSON.stringify(ai);
  if (sig === drawn.ai && !forceDraw) return;
  drawn.ai = sig;
  $('aiStatus').textContent = ai.enabled
    ? (ai.ready ? TF('ai_st_ready', { p: ai.protocol, m: ai.model }) : T('ai_st_inc'))
    : T('ai_st_off');
  $('aiStatus').className = 'pill ' + (ai.enabled && ai.ready ? 'p-live' : 'p-done');
  // sync des champs seulement hors interaction (jamais pendant la saisie)
  if (!focusInside('v-ai')) {
    const set = (id, v) => { const el = $(id); if (el) el.value = v; };
    set('aiProtocol', ai.protocol || 'openai');
    set('aiBaseURL', ai.baseURL || '');
    set('aiModel', ai.model || '');
    set('aiEnabled', ai.enabled ? 'on' : 'off');
    if (document.activeElement !== $('aiKey')) $('aiKey').value = ''; // jamais de re-echo de la cle
  }
}
$('aiSave').addEventListener('click', () => {
  jpost('/api/ai', {
    enabled: $('aiEnabled').value === 'on', protocol: $('aiProtocol').value,
    baseURL: $('aiBaseURL').value.trim(), model: $('aiModel').value.trim(),
    apiKey: $('aiKey').value.trim() || undefined,
  }).then(r => r.json()).then(j => {
    toast('AGENT IA', j.ok ? T('to_ai_ok') : T('to_ai_no'), j.ok ? 'HIT' : 'P2');
    setTimeout(refresh, 300);
  });
});
$('aiTest').addEventListener('click', () => {
  $('aiTest').disabled = true;
  jpost('/api/ai', {
    op: 'test', protocol: $('aiProtocol').value,
    baseURL: $('aiBaseURL').value.trim(), model: $('aiModel').value.trim(),
    apiKey: $('aiKey').value.trim() || undefined,
  }).then(r => r.json()).then(j => {
    $('aiTest').disabled = false;
    $('aiTestOut').textContent = j.ok ? T('ai_ok') + j.reply : T('ai_fail') + (j.error || '?');
  }).catch(e => { $('aiTest').disabled = false; $('aiTestOut').textContent = T('ai_fail') + e.message; });
});

// ---------- connexion a la session : pseudo + pin, validation par l'admin ----------
// distants uniquement : via le lien tunnel/LAN, la modal s'impose avant tout.
// signup (premiere fois) ou signin (pseudo + pin connus), puis attente de validation.
const IS_LOCAL = /^(localhost|127\.|::1|\[::1\])$/.test(location.hostname);
let JOIN_OPEN = false, JOIN_WAIT = false, PENDING_H = '';
function showJoin(wait, msg) {
  JOIN_OPEN = true;
  JOIN_WAIT = !!wait;
  const m = $('joinModal');
  if (!m) return;
  m.style.display = 'grid';
  $('jmWait').hidden = !JOIN_WAIT;
  $('jmForm').hidden = JOIN_WAIT;
  $('jmErr').textContent = msg || '';
  if (!JOIN_WAIT) setTimeout(() => { try { $('jmHandle').focus(); } catch (e) {} }, 50);
}
function hideJoin() {
  JOIN_OPEN = false;
  JOIN_WAIT = false;
  PENDING_H = '';
  const m = $('joinModal');
  if (m) m.style.display = 'none';
}
function tryJoin() {
  const h = String($('jmHandle').value || '').replace(/[^\w \-.]/g, '').trim().slice(0, 16);
  const p1 = String($('jmPin').value || '').trim(), p2 = String($('jmPin2').value || '').trim();
  const err = t => { $('jmErr').textContent = t; };
  if (h.length < 2) return err('pseudo : 2 caracteres min');
  if (!/^\d{4,8}$/.test(p1)) return err('pin : 4 a 8 chiffres');
  if (p1 !== p2) return err('les deux pins different');
  $('jmGo').disabled = true;
  jpost('/api/team', { op: 'join', handle: h, pin: p1 }).then(r => r.json()).then(j => {
    $('jmGo').disabled = false;
    if (!j.ok) return err(j.error || 'refuse');
    if (j.pending) { PENDING_H = h; return showJoin(true); }
    HANDLE = h;
    try { localStorage.setItem('c2ff-handle', h); } catch (e) {}
    hideJoin();
    toast('SESSION', 'connecte : ' + h, 'HIT');
    forceDraw = true; refresh();
  }).catch(() => { $('jmGo').disabled = false; err('serveur injoignable'); });
}
// le bouton est type submit : le submit du formulaire suffit (pas de double POST)
$('jmForm').addEventListener('submit', e => { e.preventDefault(); tryJoin(); });
$('jmEdit').addEventListener('click', () => showJoin(false, ''));
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && JOIN_OPEN && JOIN_WAIT) showJoin(false, 'autre pseudo ?');
});

// ---------- mode team : sessions de groupe a distance ----------
const TRANK = { admin: 4, coadmin: 3, hunter: 2, member: 1, viewer: 0 };
const TRLBL = { admin: 'admin', coadmin: 'co-admin', hunter: 'chasseur', member: 'membre', viewer: 'observateur' };
let SEEN_REQ = '';
function drawTeam() {
  const tm = state.data.team || {};
  const remote = tm.bind === 'lan';
  const tun = typeof tm.tunnel === 'string' ? tm.tunnel : '';
  const myRole = tm.meRole || tm.you || 'viewer';
  const rk = TRANK[myRole] || 0;
  const amAdmin = rk >= 4;
  rtcTick();
  const sig = JSON.stringify([tm.enabled, tm.room, tm.members, HANDLE, tm.bind, tm.lan, tun, tm.chat, tm.you, microOn, tm.requests]);
  if (sig === drawn.team && !forceDraw) return;
  drawn.team = sig;
  // demandes d'entree : toast + notif a l'arrivee de chaque nouveau pseudo
  const reqs = tm.requests || [];
  if (rk >= 3) {
    const prev = new Set((SEEN_REQ || '').split('|').filter(Boolean));
    reqs.filter(r => !prev.has(r.h)).forEach(r => {
      toast('DEMANDE D\'ACCES', r.h + ' veut entrer dans la session', 'P2');
      if (NOTIF.on) popNotify('DEMANDE D\'ACCES', r.h + ' veut entrer dans la session', 'P2');
    });
    SEEN_REQ = reqs.map(r => r.h).sort().join('|');
  }
  $('tmStatus').textContent = tm.enabled ? TF('tm_on', { r: tm.room || '-', n: tm.online || 0 }) : T('tm_off');
  $('tmStatus').className = 'pill ' + (tm.enabled ? 'p-live' : 'p-done');
  const bindEl = $('tmBind');
  if (bindEl) {
    bindEl.textContent = remote ? TF('tm_bind_lan', { a: tm.lan || '?' }) : T('tm_bind_lo');
    bindEl.className = 'pill ' + (remote ? 'p-live' : 'p-done');
    bindEl.hidden = !tm.enabled;
  }
  $('tmRoom').textContent = tm.room || '-';
  $('tmKey').textContent = tm.enabled ? (TEAMKEY || '-') : '-';
  // config : ne jamais ecraser pendant la saisie
  if (!focusInside('v-team')) {
    set('tmHandleEl', HANDLE ? HANDLE : '');
    set('tmRoomEl', tm.room || '');
    set('tmOn', tm.enabled ? 'on' : 'off');
  }
  const pendEl = $('tmPending');
  if (pendEl) {
    pendEl.hidden = !tm.enabled || !reqs.length;
    pendEl.innerHTML = tm.enabled && reqs.length
      ? '<div style="font-size:11px;color:var(--dim);margin-bottom:6px">DEMANDES D\'ACCES - accepter ou refuser :</div>' +
        reqs.map(r =>
          '<div class="tm-m"><b>' + esc(r.h) + '</b><span class="pill p-done" style="margin-left:8px">en attente</span>' +
          '<span style="margin-left:auto"></span>' +
          '<button class="go tmok" data-h="' + esc(r.h) + '" style="padding:4px 10px">Accepter</button>' +
          '<button class="ghost tmno" data-h="' + esc(r.h) + '" style="color:var(--red)">Refuser</button></div>'
        ).join('')
      : '';
  }
  $('tmMembers').innerHTML = (tm.members || []).map(m =>
    '<div class="tm-m"><span class="dot ' + (m.active ? 'run' : '') + '" style="' + (m.active ? 'color:var(--green)' : 'color:var(--faint)') + '"></span>' +
    '<b style="color:' + (m.h === HANDLE ? 'var(--green)' : 'var(--text)') + '">' + esc(m.h) + (m.h === HANDLE ? ' <small style="color:var(--faint)">' + T('tm_you') + '</small>' : '') + '</b>' +
    '<span class="pill ' + (m.role === 'admin' ? 'p-prog' : 'p-done') + '">' + (m.st === 'pending' ? 'en attente' : (TRLBL[m.role] || m.role || 'membre')) + '</span>' +
    '<span class="pill ' + (m.active ? 'p-live' : 'p-done') + '">' + (m.active ? T('tm_here') : Math.round(m.ms / 60000) + ' min') + '</span>' +
    (amAdmin && m.h !== HANDLE ?
      '<select class="tmrole" data-h="' + esc(m.h) + '">' + ['viewer', 'member', 'hunter', 'coadmin', 'admin'].map(r =>
        '<option value="' + r + '"' + (m.role === r ? ' selected' : '') + '>' + TRLBL[r] + '</option>').join('') + '</select>' +
      (rk >= 3 ? '<button class="ghost tmkick" data-h="' + esc(m.h) + '">' + T('tm_kick') + '</button>' : '') : '') +
    '<small style="color:var(--faint);margin-left:auto">' + m.reqs + ' req</small></div>'
  ).join('') || '<div style="color:var(--faint);font-size:11.5px">' + T('tm_nobody') + '</div>';
  const micBtn = $('tmMic');
  if (micBtn) { micBtn.textContent = microOn ? T('tm_mic_off') : T('tm_mic_on'); micBtn.classList.toggle('mic-live', microOn); micBtn.hidden = !tm.enabled; }
  // lien d'invitation : le tunnel public gagne s'il existe (universel, hors LAN), sinon LAN/localhost
  const world = tun && tun.startsWith('https://');
  const invite = tm.enabled
    ? (world ? tun : remote ? 'http://' + (tm.lan || 'IP-LAN:PORT') : location.origin)
      + '/?k=' + (TEAMKEY || 'LA_CLE') + '  (handle : ' + (HANDLE || 'choisir un pseudo') + ')'
    : '';
  $('tmInvite').textContent = invite;
  const tunInfo = $('tmTunnelInfo');
  if (tunInfo) tunInfo.textContent = !tm.enabled ? '' :
    tun === 'starting' ? T('tm_tun_wait') :
    tun.startsWith('err:') ? tun.slice(4) :
    world ? TF('tm_tun_on', { u: tun }) : '';
  const tunCopy = $('tmTunnelCopy');
  if (tunCopy) tunCopy.hidden = !(world && tm.enabled);
  const tunBtn = $('tmTunnel');
  if (tunBtn) { tunBtn.hidden = !tm.enabled; tunBtn.disabled = tun === 'starting'; tunBtn.textContent = world ? T('tm_tun_close') : T('tm_tun_open'); }
  const liveBtn = $('tmLive');
  if (liveBtn) { liveBtn.textContent = remote ? T('tm_shore') : T('tm_live'); liveBtn.hidden = !tm.enabled; }
  // chat de session : canal dedie a la room, separe de la coordination
  const blog = $('tmChatlog');
  if (blog) {
    blog.hidden = !tm.enabled;
    const bc = tm.chat || [];
    blog.innerHTML = bc.map(m =>
      '<div class="msg ' + (m.name === HANDLE ? 'me' : 'claude') + '"><div class="who">' +
      esc(m.name || '?') + ' · ' + new Date(m.t).toLocaleTimeString('fr-FR') + '</div>' + esc(m.text || '') + '</div>'
    ).join('') || '<div class="msg claude">' + T('tm_chat_empty') + '</div>';
    blog.scrollTop = blog.scrollHeight;
  }
}
$('tmTunnel').addEventListener('click', () => {
  const open = typeof (state.data.team || {}).tunnel === 'string' && (state.data.team.tunnel || '').startsWith('https://');
  jpost('/api/team', { op: 'tunnel', action: open ? 'close' : 'open', by: HANDLE }).then(r => r.json()).then(j => {
    if (!j.ok) return toast('SESSION', j.error || T('tm_need_on'), 'P2');
    toast('SESSION', open ? T('tm_tun_closed') : T('tm_tun_wait'), 'HIT');
    setTimeout(refresh, 400);
  }).catch(() => {});
});
$('tmMsgForm').addEventListener('submit', e => {
  e.preventDefault();
  const t = $('tmMsg').value.trim();
  if (!t) return;
  jpost('/api/chat', { text: t, name: HANDLE || 'invide', kind: 'team' });
  $('tmMsg').value = '';
  setTimeout(refresh, 250);
});
$('tmLive').addEventListener('click', () => {
  const remote = (state.data.team || {}).bind === 'lan';
  jpost('/api/team', { op: remote ? 'shore' : 'golive', by: HANDLE }).then(r => r.json()).then(j => {
    if (!j.ok) return toast('TEAM', j.error || T('tm_need_on'), 'P2');
    toast('TEAM', remote ? T('to_team_shore') : T('to_team_live'), 'HIT');
    // le serveur respawn : le poll rattrapera dans les 2 s
  }).catch(() => {});
});

// ---------- audio de session : WebRTC mesh, le serveur ne relaye que la signalisation ----------
let MIC = null, microOn = false;
const PCS = new Map(); // handle -> RTCPeerConnection
const RTCSEEN = new Set();
async function micToggle() {
  if (microOn) return micOff();
  if (!HANDLE) return toast('SESSION', T('tm_no_handle'), 'P2');
  try { MIC = await navigator.mediaDevices.getUserMedia({ audio: true }); }
  catch (e) { return toast('SESSION', T('tm_mic_denied'), 'P2'); }
  microOn = true;
  micProposeAll();
  forceDraw = true; refresh();
}
function micOff() {
  microOn = false;
  if (MIC) { try { MIC.getTracks().forEach(t => t.stop()); } catch (e) {} MIC = null; }
  for (const [, pc] of PCS) { try { pc.close(); } catch (e) {} }
  PCS.clear();
  document.querySelectorAll('audio.c2ffAudio').forEach(a => { try { a.pause(); a.srcObject = null; } catch (e) {} a.remove(); });
  forceDraw = true; refresh();
}
function newPC(h) {
  const pc = new RTCPeerConnection();
  if (MIC) MIC.getTracks().forEach(t => pc.addTrack(t, MIC));
  pc.onicecandidate = e => { if (e.candidate) jpost('/api/team', { op: 'rtc', from: HANDLE, to: h, typ: 'ice', data: JSON.stringify(e.candidate) }).catch(() => {}); };
  pc.ontrack = e => {
    let a = document.getElementById('c2ffAudio_' + h);
    if (!a) { a = document.createElement('audio'); a.id = 'c2ffAudio_' + h; a.className = 'c2ffAudio'; a.autoplay = true; document.body.appendChild(a); }
    a.srcObject = e.streams[0]; a.play().catch(() => {});
  };
  PCS.set(h, pc);
  return pc;
}
function micProposeAll() {
  if (!MIC || !microOn) return;
  const tm = state.data.team || {};
  (tm.members || []).forEach(m => {
    if (m.h === HANDLE || !m.active || PCS.has(m.h)) return;
    const pc = newPC(m.h);
    pc.createOffer().then(o => pc.setLocalDescription(o))
      .then(() => jpost('/api/team', { op: 'rtc', from: HANDLE, to: m.h, typ: 'sdp', data: JSON.stringify({ type: 'offer', sdp: pc.localDescription.sdp }) }))
      .catch(() => {});
  });
}
function rtcTick() {
  if (!HANDLE) return;
  const list = ((state.data.team || {}).rtc || []);
  if (RTCSEEN.size > 800) RTCSEEN.clear();
  let handled = false;
  for (const msg of list) {
    if (msg.to !== HANDLE || RTCSEEN.has(msg.id)) continue;
    RTCSEEN.add(msg.id); handled = true;
    try {
      if (msg.typ === 'sdp') {
        const d = JSON.parse(msg.data);
        if (d.type === 'offer') {
          const pc = newPC(msg.from);
          pc.setRemoteDescription(d)
            .then(() => pc.createAnswer()).then(a => pc.setLocalDescription(a))
            .then(() => jpost('/api/team', { op: 'rtc', from: HANDLE, to: msg.from, typ: 'sdp', data: JSON.stringify({ type: 'answer', sdp: pc.localDescription.sdp }) }))
            .catch(() => {});
        } else if (d.type === 'answer' && PCS.has(msg.from)) {
          PCS.get(msg.from).setRemoteDescription(d).catch(() => {});
        }
      } else if (msg.typ === 'ice' && PCS.has(msg.from)) {
        PCS.get(msg.from).addIceCandidate(JSON.parse(msg.data)).catch(() => {});
      }
    } catch (e) {}
  }
  if (microOn) micProposeAll(); // les arrives tard reçoivent une offre au prochain draw
  if (handled) { /* rien de plus : les streams declenchent eux-memes le rendu */ }
}
$('tmMic').addEventListener('click', micToggle);
// roles + kick : delegation sur la liste membres
$('tmMembers').addEventListener('change', e => {
  const sel = e.target.closest('select.tmrole');
  if (!sel) return;
  jpost('/api/team', { op: 'role.set', h: sel.dataset.h, r: sel.value, by: HANDLE }).then(r => r.json()).then(j => {
    toast('SESSION', j.ok ? T('tm_role_ok') : (j.error || T('tm_cfg_no')), j.ok ? 'HIT' : 'P2');
    setTimeout(refresh, 300);
  }).catch(() => {});
});
$('tmPending').addEventListener('click', e => {
  const ok = e.target.closest('button.tmok');
  const no = e.target.closest('button.tmno');
  if (!ok && !no) return;
  const h = (ok || no).dataset.h;
  jpost('/api/team', { op: ok ? 'approve' : 'deny', h, by: HANDLE }).then(r => r.json()).then(j => {
    if (j.team) state.data.team = j.team;
    toast('SESSION', j.ok ? (ok ? h + ' entre dans la session' : h + ' refuse et bloque') : (j.error || T('tm_cfg_no')), j.ok ? 'HIT' : 'P2');
    forceDraw = true; refresh();
  }).catch(() => {});
});
$('tmMembers').addEventListener('click', e => {
  const b = e.target.closest('button.tmkick');
  if (!b) return;
  jpost('/api/team', { op: 'kick', h: b.dataset.h, by: HANDLE }).then(r => r.json()).then(j => {
    if (j.team) state.data.team = j.team;
    toast('SESSION', j.ok ? T('tm_kick_ok') : (j.error || T('tm_cfg_no')), j.ok ? 'HIT' : 'P2');
    setTimeout(refresh, 300);
  }).catch(() => {});
});
function set(id, v) { const el = $(id); if (el) el.value = v; }
$('tmSaveHandle').addEventListener('click', () => {
  HANDLE = String($('tmHandleEl').value).replace(/[^\w \-.]/g, '').trim().slice(0, 16);
  try { localStorage.setItem('c2ff-handle', HANDLE); } catch (e) {}
  toast('TEAM', HANDLE ? T('tm_saved') + ' : ' + HANDLE : T('tm_no_handle'), HANDLE ? 'HIT' : 'P2');
  forceDraw = true; refresh();
});
$('tmSave').addEventListener('click', () => {
  jpost('/api/team', { op: 'config', enabled: $('tmOn').value === 'on', room: $('tmRoomEl').value }).then(r => r.json()).then(j => {
    // la cle de salle ne repart jamais via /api/state (guests) : on la
    // capte ici, a la creation, et on la garde dans localStorage
    if (j.ok && j.team && j.team.key) { TEAMKEY = j.team.key; try { localStorage.setItem('c2ff-key', TEAMKEY); } catch (e) {} }
    toast('TEAM', j.ok ? T('tm_cfg_ok') : T('tm_cfg_no'), j.ok ? 'HIT' : 'P2');
    setTimeout(refresh, 300);
  });
});
$('tmRegen').addEventListener('click', () => {
  jpost('/api/team', { op: 'regen' }).then(r => r.json()).then(j => {
    if (j.ok && j.team && j.team.key) { TEAMKEY = j.team.key; try { localStorage.setItem('c2ff-key', TEAMKEY); } catch (e) {} }
    toast('TEAM', T('tm_regen_ok'), 'HIT');
    setTimeout(refresh, 300);
  });
});
// copie du lien d'invitation
const copyText = t => {
  if (!t) return;
  const ok = () => { sndPlay('copy'); toast('SESSION', T('tm_copied'), 'HIT'); };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(t).then(ok).catch(() => copyFallback(t, ok));
  } else copyFallback(t, ok);
};
function copyFallback(t, ok) {
  const ta = document.createElement('textarea');
  ta.value = t; document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); ok(); } catch (e) {}
  ta.remove();
}
$('tmCopy').addEventListener('click', () => copyText($('tmInvite').textContent));
$('tmTunnelCopy').addEventListener('click', () => {
  const tun = state.data.team.tunnel;
  if (!tun || !tun.startsWith('https://')) return;
  copyText(tun + '/?k=' + (TEAMKEY || 'LA_CLE') + '  (handle : ' + (HANDLE || 'choisir un pseudo') + ')');
});

// ---------- langue / init i18n ----------
$('langSel').innerHTML = LANGS.map(l => '<option value="' + l[0] + '"' + (l[0] !== 'fr' && !I18N[l[0]] ? ' disabled' : '') + '>' + l[1] + (l[0] !== 'fr' && !I18N[l[0]] ? ' ·' : '') + '</option>').join('');
$('langSel').addEventListener('change', () => setLang($('langSel').value));
const _initEntry = LANGS.find(x => x[0] === LANG);
document.documentElement.dir = (_initEntry && _initEntry[2] === 'rtl') ? 'rtl' : 'ltr';
applyI18n();

// ---------- son & notifications (natifs, toute l'application) ----------
// popups OS + moteur de sons synthese (zero dependance). Tous deux ON par defaut,
// desactivables depuis le header. Anti-spam : 1 popup / 2,5 s (P1 toujours passe).
const NOTIF = { on: true, lastTeamT: 0 };
try { NOTIF.on = localStorage.getItem('c2ff-notifs') !== 'off'; } catch (e) {}
const SND = { on: true };
try { SND.on = localStorage.getItem('c2ff-snd') !== 'off'; } catch (e) {}
let AC = null;
// bibliotheque de sons : une signature par theme d'evenement, timbres et registres
// franchement distincts pour que l'oreille les separe sans y penser.
// chaque note = [frequence Hz, depart s, duree s, (glissando vers Hz)] ; w = onde, g = volume.
const SND_LIB = {
  click: { w: 'square',   g: 0.035, n: [[1750, 0, 0.022]] },
  tab:   { w: 'triangle', g: 0.06,  n: [[523, 0, 0.045], [784, 0.055, 0.07]] },
  copy:  { w: 'sine',     g: 0.05,  n: [[700, 0, 0.09, 1650]] },
  chat:  { w: 'triangle', g: 0.06,  n: [[659, 0, 0.11]] },
  join:  { w: 'triangle', g: 0.06,  n: [[392, 0, 0.08], [523, 0.09, 0.08], [659, 0.18, 0.13]] },
  leave: { w: 'sine',     g: 0.055, n: [[659, 0, 0.08], [523, 0.09, 0.08], [392, 0.18, 0.16]] },
  p1:    { w: 'square',   g: 0.1,   n: [[988, 0, 0.09], [1320, 0.12, 0.11], [988, 0.26, 0.09], [1320, 0.38, 0.16]] },
  p2:    { w: 'sawtooth', g: 0.07,  n: [[620, 0, 0.13], [620, 0.17, 0.09]] },
  hit:   { w: 'sine',     g: 0.06,  n: [[1319, 0, 0.14], [1568, 0.06, 0.2]] },
  err:   { w: 'sawtooth', g: 0.08,  n: [[140, 0, 0.2, 95]] },
  togg:  { w: 'triangle', g: 0.05,  n: [[880, 0, 0.03]] },
};
function sndNotes(wave, notes, gain) {
  if (!SND.on) return;
  try {
    AC = AC || new (window.AudioContext || window.webkitAudioContext)();
    if (AC.state === 'suspended') AC.resume();
    notes.forEach(([f, at, dur, slide]) => {
      const o = AC.createOscillator(), g = AC.createGain();
      o.type = wave;
      const t0 = AC.currentTime + at;
      o.frequency.setValueAtTime(f, t0);
      if (slide) o.frequency.exponentialRampToValueAtTime(slide, t0 + dur);
      o.connect(g); g.connect(AC.destination);
      g.gain.setValueAtTime(0.0001, t0);
      g.gain.exponentialRampToValueAtTime(gain, t0 + 0.015);
      g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
      o.start(t0); o.stop(t0 + dur + 0.03);
    });
  } catch (e) {}
}
const sndPlay = k => { const r = SND_LIB[k]; if (r) sndNotes(r.w, r.n, r.g); };
// compat : anciens appels beep([f1, f2]) = alarme carree sequentielle
const beep = freqs => sndNotes('square', (freqs || []).map((f, i) => [f, i * 0.16, 0.14 + i * 0.03]), 0.1);
const canNotify = () => 'Notification' in window && Notification.permission === 'granted';
let lastPopT = 0;
function popNotify(title, text, sev) {
  const now = Date.now();
  if (sev === 'P1') sndPlay('p1');
  else if (sev === 'P2') sndPlay('p2');
  else sndPlay('hit');
  if (sev !== 'P1' && now - lastPopT < 2500) return; // anti-spam (P1 toujours passe)
  lastPopT = now;
  if (!canNotify()) return;
  try {
    const n = new Notification(title + ' - C2FF', { body: (text || '').slice(0, 160) });
    n.addEventListener('click', () => { try { window.focus(); n.close(); } catch (e) {} });
    setTimeout(() => { try { n.close(); } catch (e) {} }, 8000);
  } catch (e) {}
}
function drawNotifBtn() {
  const b = $('notifBtn');
  if (!b) return;
  b.textContent = NOTIF.on ? '🔔 ' + T('nt_on') : T('nt_off');
  b.classList.toggle('mic-live', NOTIF.on && canNotify());
}
function drawSoundBtn() {
  const b = $('soundBtn');
  if (!b) return;
  b.textContent = (SND.on ? '🔊 ' : '🔇 ') + (SND.on ? T('snd_on') : T('snd_off'));
  b.classList.toggle('mic-live', SND.on);
}
$('notifBtn').addEventListener('click', () => {
  if (!NOTIF.on) {
    if (!('Notification' in window)) { toast('NOTIFS', 'Notification API absente', 'P3'); return; }
    if (Notification.permission === 'denied') { toast('NOTIFS', T('nt_denied'), 'P2'); return; }
    Notification.requestPermission().then(p => {
      if (p === 'granted') {
        NOTIF.on = true;
        try { localStorage.setItem('c2ff-notifs', 'on'); } catch (e) {}
        toast('NOTIFS', T('nt_ok'), 'HIT');
        popNotify('C2FF', T('nt_ok'), '');
      } else toast('NOTIFS', T('nt_denied'), 'P2');
      drawNotifBtn();
    });
    return;
  }
  NOTIF.on = false;
  try { localStorage.setItem('c2ff-notifs', 'off'); } catch (e) {}
  toast('NOTIFS', T('nt_off'), '');
  drawNotifBtn();
});
$('soundBtn').addEventListener('click', () => {
  SND.on = !SND.on;
  try { localStorage.setItem('c2ff-snd', SND.on ? 'on' : 'off'); } catch (e) {}
  drawSoundBtn();
  toast('SON', SND.on ? T('snd_ok') : T('snd_stop'), '');
  if (SND.on) sndPlay('togg');
});
// permission notifs demandee au premier geste utilisateur (ON natif), sans spam de demande
document.addEventListener('pointerdown', () => {
  if (NOTIF.on && 'Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission().then(() => { drawNotifBtn(); if (canNotify()) popNotify('C2FF', T('nt_ok'), ''); });
  }
}, { once: true, capture: true });
// panoplie UI : un son par theme d'evenement (click, onglet, copie, erreurs)
document.addEventListener('pointerdown', e => {
  const el = e.target.closest('button, [data-snd]');
  if (!el || el.classList.contains('navbtn')) return; // navbtn = son 'tab' dans setTab
  const k = el.getAttribute('data-snd') || 'click';
  sndPlay(k);
}, { capture: true });
drawNotifBtn();
drawSoundBtn();

// ---------- ambiance chromatique vivante ----------
// un cycle = 5 familles (SEG chacune, cf ambTick). Ordre volontairement DESORDONNE : chaque saut
// traverse la roue chromatique, toujours par le plus court chemin, easing smoothstep :
// arrivee posee, jamais de saut. Les arrêts ne tombent JAMAIS sur les teintes primaires
// (112/232/48/300/170 seraient le vert/bleu/jaune/magenta/cyan purs) : ils restent
// volontairement ENTRE deux familles, teintes mélangées, jamais primaires.
const AMB = { live: true };
const AMB_STOPS = [131, 252, 66, 330, 191]; // milieux entre les teintes primaires, jamais primaires
try { AMB.live = localStorage.getItem('c2ff-ambiance') !== 'off'; } catch (e) {}
const ambTick = () => {
  // deux teintes vivent ensemble : --hue pilote la lumiere, --hue2 (decale + respire
  // lentement) colorie l'autre bout des degrades ambiants - jamais de couleur plate.
  const reduced = matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  let h;
  if (AMB.live && !reduced) {
    const SEG = 24000, total = SEG * AMB_STOPS.length, pos = Date.now() % total;
    const i = Math.floor(pos / SEG);
    let u = (pos % SEG) / SEG;
    u = u * u * (3 - 2 * u);
    const a = AMB_STOPS[i], b = (i + 1 < AMB_STOPS.length) ? AMB_STOPS[i + 1] : AMB_STOPS[0];
    const d = ((b - a + 540) % 360) - 180; // plus court chemin sur la roue
    h = (a + d * u + 360) % 360;
  } else h = 131; // fige AMBIANCE OFF / reduced-motion : teinte entre vert et cyan
  const root = document.documentElement.style;
  root.setProperty('--hue', h.toFixed(1));
  const h2 = (h + 48 + 14 * Math.sin(Date.now() / 21000) + 360) % 360; // decalage qui respire 34-62 deg
  root.setProperty('--hue2', h2.toFixed(1));
};
setInterval(ambTick, 250);
ambTick();
function drawAmbBtn() { const b = $('ambBtn'); if (b) b.textContent = AMB.live ? T('amb_on') : T('amb_off'); }
$('ambBtn').addEventListener('click', () => {
  AMB.live = !AMB.live;
  try { localStorage.setItem('c2ff-ambiance', AMB.live ? 'on' : 'off'); } catch (e) {}
  ambTick();
  drawAmbBtn();
  toast('THEME', AMB.live ? T('amb_ok') : T('amb_stop'), '');
});
drawAmbBtn();

// ---------- affichage : ajustement auto + plein ecran ----------
// le layout est concu pour 1440 px : un zoom proportionnel a la largeur
// reelle garde les proportions et remplit tout l'ecran (grossit en grand
// ecran, se resserre en petit). OFF rend la main a l'echelle native.
let FIT_ON = true;
try { FIT_ON = localStorage.getItem('c2ff-fit') !== 'off'; } catch (e) {}
function applyFit() {
  if (!FIT_ON) { document.body.style.zoom = ''; return; }
  // ecrans etroits (telephone) : zoom neutre, le layout reflowe via @media ;
  // au-dela : zoom proportionnel a la largeur (reference 1440 px)
  const w = window.innerWidth;
  const z = w < 760 ? 1 : Math.max(0.9, Math.min(1.6, w / 1440));
  document.body.style.zoom = z === 1 ? '' : z;
}
function drawFitBtn() { const b = $('fitBtn'); if (b) b.textContent = FIT_ON ? 'AJUSTE : AUTO' : 'AJUSTE : OFF'; }
$('fitBtn').addEventListener('click', () => {
  FIT_ON = !FIT_ON;
  try { localStorage.setItem('c2ff-fit', FIT_ON ? 'on' : 'off'); } catch (e) {}
  applyFit(); drawFitBtn();
  toast('AFFICHAGE', FIT_ON ? 'ajustement automatique' : 'echelle native', '');
});
window.addEventListener('resize', applyFit);
applyFit(); drawFitBtn();
// plein ecran : toggle manuel ; la preference est rejouee au 1er clic
// (l'API exige un geste utilisateur, impossible au simple chargement)
$('fsBtn').addEventListener('click', () => {
  if (document.fullscreenElement) document.exitFullscreen();
  else document.documentElement.requestFullscreen().catch(() => {});
});
document.addEventListener('fullscreenchange', () => {
  const b = $('fsBtn');
  if (b) b.textContent = document.fullscreenElement ? '⤡' : '⛶';
  try { localStorage.setItem('c2ff-full', document.fullscreenElement ? 'on' : 'off'); } catch (e) {}
});
if ((() => { try { return localStorage.getItem('c2ff-full') === 'on'; } catch (e) { return false; } })()) {
  const reenter = () => {
    if (!document.fullscreenElement) document.documentElement.requestFullscreen().catch(() => {});
  };
  document.addEventListener('pointerdown', reenter, { once: true });
}

// ---------- terminal de travail ----------
// shell reel cote serveur (1 par identite), output en SSE, input en POST ligne par ligne.
const TERM = { es: null, errs: 0, hi: 0, hist: [] };
try { TERM.hist = JSON.parse(localStorage.getItem('c2ff-term-hist') || '[]'); } catch (e) { TERM.hist = []; }
const termHandle = () => HANDLE || 'OPERATOR';
const termClean = s => String(s)
  .replace(/\r\n/g, '\n').replace(/\r/g, '')
  .replace(/\x1b\][^\x07]*\x07/g, '')
  .replace(/\x1b\[[0-9;?]*[a-zA-Z]/g, '')
  .replace(/[\x00-\x08\x0b-\x1a\x1c-\x1f\x7f]/g, '');
function termAppend(t) {
  const el = $('termOut');
  if (!el) return;
  el.textContent += t;
  if (el.textContent.length > 60000) el.textContent = el.textContent.slice(-45000);
  el.scrollTop = el.scrollHeight;
}
function termKBody(extra) {
  return Object.assign({ handle: termHandle() }, TEAMKEY ? { _k: TEAMKEY } : {}, extra || {});
}
function termConnect() {
  if (TERM.es) return;
  if (!('EventSource' in window)) return;
  const q = '/api/term/stream?handle=' + encodeURIComponent(termHandle()) + (TEAMKEY ? '&k=' + encodeURIComponent(TEAMKEY) : '');
  TERM.es = new EventSource(q);
  TERM.es.onopen = () => { TERM.errs = 0; };
  TERM.es.onmessage = ev => {
    let t;
    try { t = termClean(JSON.parse(ev.data)); } catch (e) { return; }
    if (!t) return;
    termAppend(t);
  };
  TERM.es.onerror = () => {
    try { TERM.es.close(); } catch (e) {}
    TERM.es = null;
    TERM.errs++;
    if (TERM.errs >= 3) { sndPlay('err'); toast('TERM', T('term_denied'), 'P2'); return; }
    if (state.tab === 'term') setTimeout(termConnect, 2000);
  };
}
$('termForm').addEventListener('submit', e => {
  e.preventDefault();
  const v = $('termIn').value;
  if (!v) return;
  TERM.hist.push(v);
  if (TERM.hist.length > 200) TERM.hist.shift();
  TERM.hi = TERM.hist.length;
  try { localStorage.setItem('c2ff-term-hist', JSON.stringify(TERM.hist.slice(-100))); } catch (x) {}
  $('termIn').value = '';
  jpost('/api/term', { handle: termHandle(), op: 'write', data: v + '\n' }).catch(() => {});
});
$('termIn').addEventListener('keydown', e => {
  const h = TERM.hist;
  if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
    e.preventDefault();
    if (!h.length) return;
    TERM.hi = e.key === 'ArrowUp' ? Math.max(0, (TERM.hi || h.length) - 1) : Math.min(h.length, (TERM.hi || h.length) + 1);
    $('termIn').value = TERM.hi === h.length ? '' : h[TERM.hi] || '';
    return;
  }
  if (e.ctrlKey && e.key === 'c') { e.preventDefault(); jpost('/api/term', { handle: termHandle(), op: 'write', data: '\x03' }).catch(() => {}); }
  if (e.ctrlKey && (e.key === 'l' || e.key === 'L')) { e.preventDefault(); $('termOut').textContent = ''; }
  if (e.ctrlKey && (e.key === 'd' || e.key === 'D')) { e.preventDefault(); jpost('/api/term', { handle: termHandle(), op: 'write', data: 'exit\n' }).catch(() => {}); }
});
$('termRestart').addEventListener('click', () => {
  jpost('/api/term', { handle: termHandle(), op: 'exit' })
    .then(() => jpost('/api/term', { handle: termHandle(), op: 'start' }))
    .catch(() => {});
  $('termOut').textContent = '';
  TERM.errs = 0;
  termConnect();
});

// ---------- nav / poll ----------
document.querySelectorAll('.navbtn').forEach(b => b.addEventListener('click', () => { setTab(b.dataset.tab); if (b.dataset.tab === 'term') termConnect(); }));
document.addEventListener('keydown', e => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') { if (e.key === 'Escape') e.target.blur(); return; }
  const m = { '1': 'programs', '2': 'hunt', '3': 'findings', '4': 'fast', '5': 'ai', '6': 'term', '7': 'team', '8': 'chat' }[e.key];
  if (m) setTab(m);
});
setInterval(() => { $('clock').textContent = new Date().toLocaleTimeString('fr-FR'); }, 1000);

let inflight = false;
async function refresh() {
  if (inflight) return; inflight = true; state.tick++;
  try {
    const d = await (await jget('/api/state')).json();
    const prevChat = state.firstLoad ? null : state.data.chat.length;
    const prevFnd = state.data.findings.length;
    state.data = d;
    const topChat = d.chat[d.chat.length - 1];
    if (!state.firstLoad && d.chat.length > prevChat && topChat && topChat.kind === 'chat') {
      const who = topChat.from === 'claude' ? T('w_claude') : (topChat.name || T('w_me'));
      toast('COORDINATION', who + ' : ' + (topChat.text || ''), '');
      if (NOTIF.on) popNotify('COORDINATION · ' + who, topChat.text || '', '');
    }
    if (!state.firstLoad) {
      d.findings.slice(0, Math.max(0, d.findings.length - prevFnd)).forEach(f => {
        if (NOTIF.on) popNotify('[' + (f.program || '').toUpperCase() + '] ' + f.run + ' · ' + f.agent, (f.sev || '') + ' - ' + (f.text || ''), f.sev);
        if (['P1', 'P2', 'HIT'].includes(f.sev)) toast('[' + (f.program || '').toUpperCase() + '] ' + f.run + ' · ' + f.agent, f.text, f.sev === 'P1' ? 'P1' : f.sev);
      });
    }
    // notifications du chat de session (room active, messages des autres membres)
    const tmc = (d.team || {}).chat || [];
    const ttop = tmc[tmc.length - 1];
    if (!state.firstLoad && (d.team || {}).enabled && ttop && ttop.t > (NOTIF.lastTeamT || 0) && ttop.name !== HANDLE) {
      popNotify('SESSION · ' + (ttop.name || '?'), ttop.text || '', '');
    }
    if (ttop) NOTIF.lastTeamT = ttop.t;
    drawRuns(d.runs); drawFindings(); drawPrograms(); drawHunt(); drawJsi(); drawUrls(); drawMods(); drawAuth(); drawAdv(); drawChat(); drawFleet(); drawAI(); drawTeam(); drawArsenal(); drawFast();
    // programmes crees/supprimes : le bandeau pipeline suit (sinon message
    // demo "cree ton programme" colle jusqu'au rechargement de la page)
    const _progsSig = d.programs.map(p => p.id).join(',');
    if (_progsSig !== (PIP_PROGS_SIG || '')) { PIP_PROGS_SIG = _progsSig; fetchPipeline(); }
    // presence team : battement toutes les ~5 s (3 polls). Un visiteur en attente
    // de validation beat aussi : des que l'admin accepte, il entre automatiquement.
    if (state.tick % 3 === 0 && (HANDLE || (JOIN_OPEN && JOIN_WAIT && PENDING_H))) {
      const bh = HANDLE || PENDING_H;
      jpost('/api/team', { op: 'beat', handle: bh }).then(r => r.json()).then(j => {
        if (j.team) state.data.team = j.team;
        if (j.me === 'pending') showJoin(true);
        else if (j.me === 'approved' && !HANDLE) {
          HANDLE = bh;
          try { localStorage.setItem('c2ff-handle', bh); } catch (e) {}
          hideJoin();
          toast('SESSION', 'accepte dans la session : ' + bh, 'HIT');
          forceDraw = true;
        } else if (j.me === 'none') {
          HANDLE = '';
          PENDING_H = '';
          try { localStorage.removeItem('c2ff-handle'); } catch (e) {}
          if (!IS_LOCAL) showJoin(false, 'pseudo refuse ou supprime - choisis-en un autre');
        } else if (j.error) {
          toast('SESSION', j.error, 'P2');
          HANDLE = '';
          PENDING_H = '';
          try { localStorage.removeItem('c2ff-handle'); } catch (e) {}
          if (!IS_LOCAL) showJoin(false, j.error);
          forceDraw = true;
        }
      }).catch(() => {});
    }
    // visiteur distant sans identite + salle ouverte : la modal de connexion s'impose
    if (!HANDLE && !IS_LOCAL && (d.team || {}).enabled && !JOIN_OPEN) showJoin(false, '');
    forceDraw = false;
    state.firstLoad = false;
  } catch (e) { /* serveur occupe */ }
  inflight = false;
}
setInterval(refresh, 1500);
refresh();
// deep-link : #hunt (ou tout tab) ouvre l onglet correspondant, et chaque changement met a jour le hash
const _hashTab = (location.hash || '').replace('#', '');
const _hashOk = { findings: 1, programs: 1, hunt: 1, fast: 1, ai: 1, team: 1, term: 1, chat: 1 };
if (_hashOk[_hashTab]) setTimeout(() => setTab(_hashTab), 0);
else setTab(state.tab);
document.querySelectorAll('.navbtn').forEach(b => b.addEventListener('click', () => {
  try { history.replaceState(null, '', '#' + b.dataset.tab); } catch (e) {}
}));