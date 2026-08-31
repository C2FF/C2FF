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
  ['ku', 'Kurdî'], ['sd', 'سنڌي', 'rtl'], ['as', 'অসমীয়া'], ['or', 'ଓଡ଼ିଆ'],
  ['be', 'Беларуская'], ['sq', 'Shqip'],
];
const I18N = {
  fr: {
    snd_on: 'SON : ON', snd_off: 'SON : OFF', snd_ok: 'sons d interface actifs - bibliotheque : clic, onglet, copie, alertes',
    snd_stop: 'sourdine totale activee : plus aucun son C2FF',
    amb_on: 'AMBIANCE: ON', amb_off: 'AMBIANCE: OFF', amb_ok: 'ambiance vivante - la teinte glisse doucement a travers les familles (vert, bleu, jaune...)',
    amb_stop: 'ambiance figee sur le vert d origine',
    nt_on: 'NOTIFS : ON', nt_off: 'NOTIFS : OFF', nt_ok: 'notifications navigateur activees - bip sur P1 et P2',
    nt_denied: 'notifications bloquees par le navigateur : autorise-les dans les reglages du site',
    term_denied: 'terminal refuse ou indisponible : localhost requis, ou salle OUVERTE en tant qu admin',
    term_p: 'bash reel - history fleches, Ctrl+C interrompt, Ctrl+D ferme', term_restart: 'Reinitialiser',
    navtrm: 'TERM', term_h2: 'Terminal - shell de travail, direct dans la console',
    fl_off: 'FLEET : ARRETE', fl_paused: 'FLEET : EN PAUSE', fl_active: 'FLEET : ACTIF ({n} cycles)',
    fl_last: 'dernier cycle', fl_none: 'aucun cycle encore', fl_info: 'intervalle {i} min, budget {b} req/cycle',
    sub_ttl: 'command & control framework',
    navt: 'SESSION', tm_h2: 'Sessions a plusieurs - chasse de groupe, meme hors reseau',
    tm_p: "Ouvre une salle partagee : ton groupe voit la flotte, les findings et peut trier en direct. Chat de session dedie ci-dessous. Trois niveaux d'acces : LOCAL (solo), LAN via OUVRIR AU RESEAU, et MONDE via OUVRIR AU MONDE - un tunnel public (cloudflared si installe) rend le lien d'invitation valide depuis n'importe quel reseau, sans expose direct de ta machine. Tout passe par la cle de salle - regenere-la pour virer tout le monde d'un coup.",
    tm_handle: 'Ton pseudo (16 caracteres max)', tm_save_h: 'Choisir', tm_room_ph: 'nom de la salle (ex : c2ff-core)',
    tm_save: 'Appliquer', tm_on: 'SALLE OUVERTE : {r} - {n} en ligne', tm_off: 'MODE TEAM DESACTIVE - session locale solo',
    tm_room: 'Salle', tm_key: 'Cle de salle', tm_regen: 'Regenerer la cle', tm_regen_ok: 'nouvelle cle generee - les anciens liens sont morts',
    tm_invite: 'Lien d invitation (a copier vers ton equipe)', tm_copy: 'Copier', tm_copied: 'copie dans le presse-papiers',
    tm_members: 'Membres', tm_nobody: 'personne encore - envoie le lien a ton equipe', tm_you: '(toi)', tm_here: 'present',
    tm_saved: 'pseudo enregistre', tm_no_handle: 'pseudo vide', tm_cfg_ok: 'salle mise a jour', tm_cfg_no: 'echec',
    tm_live: 'OUVRIR AU RESEAU', tm_shore: 'REVENIR LOCAL', tm_need_on: 'active d abord la salle (ON)',
    tm_bind_lan: 'RESEAU : {a}', tm_bind_lo: 'LOCAL : localhost seulement',
    to_team_live: '[GO-LIVE] serveur relance en acces reseau - lien LAN affiche, reconnexion dans 2 s', to_team_shore: 'serveur relance en local (127.0.0.1)',
    tm_tun_open: 'OUVRIR AU MONDE (tunnel)', tm_tun_close: 'FERMER LE TUNNEL',
    tm_tun_wait: 'tunnel public en cours d ouverture (quelques secondes)…',
    tm_tun_on: 'SESSION OUVERTE AU MONDE : {u} - le lien d invitation marche partout, pas besoin du meme reseau',
    tm_tun_closed: 'tunnel ferme - retour LAN/local', tm_chat_empty: 'canal de session ouvert - les membres de la salle se lisent ici',
    tm_chat_h2: 'Chat de session', tm_msg_ph: 'message vers la session…',
    tm_admin: 'admin', tm_guest: 'invite', tm_kick: 'KICK', tm_kick_ok: 'membre exclu de la salle (re-cliquer debloque)', tm_role_ok: 'role mis a jour',
    tm_mic_on: 'ACTIVER LE MICRO', tm_mic_off: 'COUPER LE MICRO',
    tm_mic_denied: 'micro refuse ou inaccessible : le HTTPS est requis (tunnel MONDE ou localhost) et il faut autoriser le micro',
    navf: 'Flotte', navfd: 'Findings', navp: 'Programmes', navai: 'IA', navc: 'Coordination',
    st_runs: 'Runs', st_beacons: 'Beacons actifs', st_sig: 'Signaux',
    h2f: "Flotte - tous programmes, agents en course d'abord",
    h2fd: 'Base de findings - marquage triage persistant',
    h2eng: 'Moteur flotte - cycles locaux sans tokens',
    h2prog: 'Programmes - scope, header requis, lancement',
    h2new: 'Nouveau programme', h2ai: 'Agent IA - integration 100% optionnelle',
    h2c: 'Coordination - canal privé',
    fl_start: 'Démarrer', fl_pause: 'Pause', fl_cycle: 'Cycle maintenant',
    f_add: 'Ajouter', f_none: 'aucun signal encore', f_ph: 'finding manuel : endpoint + preuve + sev defendable…',
    st_sig_off: 'signal', st_sig_an: 'analyse', st_sig_sub: 'soumis', st_sig_dup: 'dup', st_sig_ref: 'refuse', st_sig_cl: 'ferme',
    r_none: 'aucun run detecte', r_live: '{n} EN COURSE', r_done: 'TERMINE', r_feed: '▽ flux ({n} ev)', r_close: '△ replier',
    p_name_ph: 'Nom du programme (ex: PayPal)', p_hdr_ph: 'header chercheur requis (ex: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domaine1, domaine2, …', p_save: 'Enregistrer', p_local: 'module(s), 100% local',
    ai_p: "C2FF fonctionne integrement sans IA : les modes sont probes deterministes locaux. Cette passerelle sert uniquement a brancher <b>ton</b> IA (self-hosted ou API) pour l'analyse ponctuelle d'un finding : bouton <span style=\"color:var(--green)\">IA »</span> dans FINDINGS, reponse rendue dans COORDINATION. Aucune donnee ne sort de ta machine sans cette configuration.",
    ai_off: 'desactivee', ai_on: 'activee',
    ai_st_off: 'IA DESACTIVEE - le framework tourne a 100% local sans elle',
    ai_st_ready: 'IA CONNECTEE : {p} · {m}', ai_st_inc: 'IA ACTIVEE MAIS INCOMPLETE : baseURL et model requis',
    ai_url_ph: 'base URL - ex: http://localhost:11434 ou https://api.MonIA.tld/v1',
    ai_model_ph: 'model - ex: llama3.1:8b', ai_key_ph: 'cle API (laisser vide si serveur local)',
    ai_save: 'Enregistrer', ai_test: 'Tester la connexion', ai_testing: 'test en cours…', ai_ok: 'OK - reponse : ', ai_fail: 'ECHEC : ',
    ai_note: "config stockee localement dans data/ai.json - jamais envoyee ailleurs que vers l'endpoint que tu y mets",
    ch_ph: "root@c2ff:~# message vers l'agent d'analyse…", ch_send: 'Envoyer',
    ch_empty: 'Le canal est ouvert. Tape ici, le monitor me revele a l instant.',
    ft: "100% local - probes déterministes, sans tokens ni dépendances externes - unrestricted · undetected · unstoppable",
    to_fl_on: 'FLEET-MODE ACTIF : cycles locaux toutes 30 min, 0 token.',
    to_fl_pa: 'FLEET EN PAUSE - reprends quand tu veux.',
    to_fl_cy: 'Cycle immediat lance (budget 60 req).',
    to_launch: '[GO] mode {m} (CWE {c}) sur {p} - cycle local lance',
    to_ai_ok: 'config enregistree', to_ai_no: 'echec de sauvegarde', to_ai_no_cfg: "IA non configuree - regle-la dans l'onglet IA",
    to_ai_head: 'ANALYSE IA', to_ai_bad: 'ANALYSE IA echec',
    w_me: 'OPERATOR', w_claude: 'CLAUDE', w_ia: 'IA', w_launch: '⚡ LANCEMENT',
  },
  en: {
    snd_on: 'SOUND: ON', snd_off: 'SOUND: OFF', snd_ok: 'interface sounds on - library: click, tab, copy, alerts',
    snd_stop: 'total mute enabled: no more C2FF sounds',
    amb_on: 'AMBIANCE: ON', amb_off: 'AMBIANCE: OFF', amb_ok: 'living ambiance - the hue glides softly across the families (green, blue, yellow...)',
    amb_stop: 'ambiance frozen on the original green',
    nt_on: 'NOTIFS: ON', nt_off: 'NOTIFS: OFF', nt_ok: 'browser notifications enabled - P1 and P2 beeped',
    nt_denied: 'notifications blocked by the browser: allow them in the site settings',
    term_denied: 'terminal denied or unavailable: localhost required, or an OPEN room as admin',
    term_p: 'real bash - arrow-up history, Ctrl+C interrupts, Ctrl+D closes', term_restart: 'Reset',
    navtrm: 'TERM', term_h2: 'Terminal - working shell, right in the console',
    fl_off: 'FLEET : STOPPED', fl_paused: 'FLEET : PAUSED', fl_active: 'FLEET : ACTIVE ({n} cycles)',
    fl_last: 'last cycle', fl_none: 'no cycle yet', fl_info: 'interval {i} min, budget {b} req/cycle',
    sub_ttl: 'command & control framework',
    navf: 'Fleet', navfd: 'Findings', navp: 'Programs', navai: 'AI', navc: 'Coordination',
    st_runs: 'Runs', st_beacons: 'Active beacons', st_sig: 'Signals',
    h2f: 'Fleet - all programs, running agents first',
    h2fd: 'Findings base - persistent triage tagging',
    h2eng: 'Fleet engine - local cycles, no tokens',
    h2prog: 'Programs - scope, required header, launch',
    h2new: 'New program', h2ai: 'AI agent - fully optional integration',
    h2c: 'Coordination - private channel',
    fl_start: 'Start', fl_pause: 'Pause', fl_cycle: 'Cycle now',
    f_add: 'Add', f_none: 'no signal yet', f_ph: 'manual finding: endpoint + proof + defensible severity…',
    st_sig_off: 'signal', st_sig_an: 'analyse', st_sig_sub: 'submitted', st_sig_dup: 'dup', st_sig_ref: 'rejected', st_sig_cl: 'closed',
    r_none: 'no run detected', r_live: '{n} RUNNING', r_done: 'DONE', r_feed: '▽ feed ({n} ev)', r_close: '△ collapse',
    p_name_ph: 'Program name (ex: PayPal)', p_hdr_ph: 'required researcher header (ex: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope: domain1, domain2, …', p_save: 'Save', p_local: 'module(s), 100% local',
    ai_p: 'C2FF runs entirely without AI: modes are deterministic local probes. This gateway only wires <b>your</b> AI (self-hosted or API) to analyse a single finding on demand: the <span style="color:var(--green)">AI »</span> button in FINDINGS, answer rendered in COORDINATION. No data leaves your machine without this configuration.',
    ai_off: 'disabled', ai_on: 'enabled',
    ai_st_off: 'AI DISABLED - framework runs 100% local without it',
    ai_st_ready: 'AI CONNECTED: {p} · {m}', ai_st_inc: 'AI ENABLED BUT INCOMPLETE: baseURL and model required',
    ai_url_ph: 'base URL - ex: http://localhost:11434 or https://api.MyAI.tld/v1',
    ai_model_ph: 'model - ex: llama3.1:8b', ai_key_ph: 'API key (leave empty for local servers)',
    ai_save: 'Save', ai_test: 'Test connection', ai_testing: 'testing…', ai_ok: 'OK - reply: ', ai_fail: 'FAILED: ',
    ai_note: 'config stored locally in data/ai.json - never sent anywhere but the endpoint you set',
    ch_ph: "root@c2ff:~# message to the analysis agent…", ch_send: 'Send',
    ch_empty: 'Channel is open. Type here, the monitor wakes me instantly.',
    ft: '100% local - deterministic probes, no tokens no external deps - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ACTIVE: local cycles every 30 min, 0 tokens.',
    to_fl_pa: 'FLEET PAUSED - resume whenever you want.',
    to_fl_cy: 'Immediate cycle launched (60 req budget).',
    to_launch: '[GO] mode {m} (CWE {c}) on {p} - local cycle launched',
    to_ai_ok: 'config saved', to_ai_no: 'save failed', to_ai_no_cfg: 'AI not configured - set it in the AI tab',
    to_ai_head: 'AI ANALYSIS', to_ai_bad: 'AI ANALYSIS failed',
    w_me: 'OPERATOR', w_claude: 'CLAUDE', w_ia: 'AI', w_launch: '⚡ LAUNCH',
    navt: 'SESSION', tm_h2: 'Group sessions - hunt together, same network or not',
    tm_p: "Open a shared room: your group sees the fleet, findings and can triage live. Dedicated session chat below. Three access levels: LOCAL (solo), LAN via OPEN TO NETWORK, and WORLD via OPEN TO WORLD - a public tunnel (cloudflared if installed) makes the invite link valid from any network, without exposing your machine directly. Everything is gated by the room key - regenerate it to kick everyone at once.",
    tm_handle: 'Your handle (16 chars max)', tm_save_h: 'Set', tm_room_ph: 'room name (ex: c2ff-core)',
    tm_save: 'Apply', tm_on: 'ROOM OPEN: {r} - {n} online', tm_off: 'TEAM MODE OFF - local solo session',
    tm_room: 'Room', tm_key: 'Room key', tm_regen: 'Regenerate key', tm_regen_ok: 'new key generated - old links are dead',
    tm_invite: 'Invite link (copy to your team)', tm_copy: 'Copy', tm_copied: 'copied to clipboard',
    tm_members: 'Members', tm_nobody: 'nobody yet - send the invite link', tm_you: '(you)', tm_here: 'here',
    tm_saved: 'handle saved', tm_no_handle: 'empty handle', tm_cfg_ok: 'room updated', tm_cfg_no: 'failed',
    tm_live: 'OPEN TO NETWORK', tm_shore: 'BACK LOCAL', tm_need_on: 'enable the room first (ON)',
    tm_bind_lan: 'NETWORK: {a}', tm_bind_lo: 'LOCAL: localhost only',
    to_team_live: '[GO-LIVE] server relaunched with network access - LAN link shown, reconnect in 2 s', to_team_shore: 'server relaunched local (127.0.0.1)',
    tm_tun_open: 'OPEN TO WORLD (tunnel)', tm_tun_close: 'CLOSE TUNNEL',
    tm_tun_wait: 'public tunnel coming up (a few seconds)…',
    tm_tun_on: 'SESSION OPEN TO WORLD: {u} - the invite link works from anywhere, no shared network needed',
    tm_tun_closed: 'tunnel closed - back to LAN/local', tm_chat_empty: 'session channel open - room members read each other here',
    tm_chat_h2: 'Session chat', tm_msg_ph: 'message to the session…',
    tm_admin: 'admin', tm_guest: 'guest', tm_kick: 'KICK', tm_kick_ok: 'member removed from the room (click again to unblock)', tm_role_ok: 'role updated',
    tm_mic_on: 'ENABLE MICROPHONE', tm_mic_off: 'MUTE MICROPHONE',
    tm_mic_denied: 'microphone denied or unavailable: HTTPS required (WORLD tunnel or localhost) and permission must be granted',
  },
  es: {
    snd_on: 'SONIDO: ON', snd_off: 'SONIDO: OFF', snd_ok: 'sonidos de interfaz activos - biblioteca: clic, pestaña, copiar, alertas',
    snd_stop: 'silencio total activado: sin más sonidos de C2FF',
    amb_on: 'AMBIENTE: ON', amb_off: 'AMBIENTE: OFF', amb_ok: 'ambiente vivo - el tono se desliza suavemente entre las familias (verde, azul, amarillo...)',
    amb_stop: 'ambiente congelado en el verde original',
    nt_on: 'NOTIFS: ON', nt_off: 'NOTIFS: OFF', nt_ok: 'notificaciones del navegador activadas - bip en P1 y P2',
    nt_denied: 'notificaciones bloqueadas por el navegador: permítelas en los ajustes del sitio',
    term_denied: 'terminal denegado o no disponible: se requiere localhost, o sala ABIERTA como admin',
    term_p: 'bash real - historial con flechas, Ctrl+C interrumpe, Ctrl+D cierra', term_restart: 'Reiniciar',
    navtrm: 'TERM', term_h2: 'Terminal - shell de trabajo, en la propia consola',
    sub_ttl: 'command & control framework',
    fl_off: 'FLOTA : DETENIDA', fl_paused: 'FLOTA : EN PAUSA', fl_active: 'FLOTA : ACTIVA ({n} ciclos)',
    fl_last: 'último ciclo', fl_none: 'ningún ciclo aún', fl_info: 'intervalo {i} min, presupuesto {b} req/ciclo',
    navf: 'Flota', navfd: 'Hallazgos', navp: 'Programas', navai: 'IA', navc: 'Coordinación',
    st_runs: 'Runs', st_beacons: 'Beacons activos', st_sig: 'Señales',
    h2f: 'Flota - todos los programas, agentes en curso primero',
    h2fd: 'Base de hallazgos - triaje persistente',
    h2eng: 'Motor de flota - ciclos locales sin tokens',
    h2prog: 'Programas - scope, header requerido, lanzamiento',
    h2new: 'Nuevo programa', h2ai: 'Agente IA - integración 100% opcional',
    h2c: 'Coordinación - canal privado',
    fl_start: 'Iniciar', fl_pause: 'Pausa', fl_cycle: 'Ciclo ahora',
    f_add: 'Añadir', f_none: 'ninguna señal aún', f_ph: 'hallazgo manual: endpoint + prueba + severidad defendible…',
    st_sig_off: 'señal', st_sig_an: 'análisis', st_sig_sub: 'enviado', st_sig_dup: 'dup', st_sig_ref: 'rechazado', st_sig_cl: 'cerrado',
    r_none: 'ningún run detectado', r_live: '{n} EN CURSO', r_done: 'TERMINADO', r_feed: '▽ flujo ({n} ev)', r_close: '△ plegar',
    p_name_ph: 'Nombre del programa (ej: PayPal)', p_hdr_ph: 'header requerido (ej: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : dominio1, dominio2, …', p_save: 'Guardar', p_local: 'módulo(s), 100% local',
    ai_p: 'C2FF funciona sin IA: los modos son probes deterministas locales. Esta pasarela solo conecta <b>tu</b> IA (self-hosted o API) para analizar un hallazgo puntual: botón <span style="color:var(--green)">IA »</span> en HALLAZGOS, respuesta en COORDINACIÓN. Ningún dato sale de tu máquina sin esta configuración.',
    ai_off: 'desactivada', ai_on: 'activada',
    ai_st_off: 'IA DESACTIVADA - el framework funciona 100% local sin ella',
    ai_st_ready: 'IA CONECTADA: {p} · {m}', ai_st_inc: 'IA ACTIVADA PERO INCOMPLETA: baseURL y model requeridos',
    ai_url_ph: 'URL base - ej: http://localhost:11434 o https://api.MiIA.tld/v1',
    ai_model_ph: 'model - ej: llama3.1:8b', ai_key_ph: 'clave API (vacío si servidor local)',
    ai_save: 'Guardar', ai_test: 'Probar conexión', ai_testing: 'probando…', ai_ok: 'OK - respuesta: ', ai_fail: 'FALLO: ',
    ai_note: 'config guardada localmente en data/ai.json - nunca se envía a otro sitio que al endpoint que pongas',
    ch_ph: 'root@c2ff:~# mensaje al agente de análisis…', ch_send: 'Enviar',
    ch_empty: 'Canal abierto. Escribe aquí, el monitor me despierta al instante.',
    ft: '100% local - probes deterministas, sin tokens ni dependencias - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ACTIVO: ciclos locales cada 30 min, 0 tokens.',
    to_fl_pa: 'FLOTA EN PAUSA - retómala cuando quieras.',
    to_fl_cy: 'Ciclo inmediato lanzado (presupuesto 60 req).',
    to_launch: '[GO] modo {m} (CWE {c}) sobre {p} - ciclo local lanzado',
    to_ai_ok: 'config guardada', to_ai_no: 'fallo al guardar', to_ai_no_cfg: 'IA no configurada - regla en la pestaña IA',
    to_ai_head: 'ANÁLISIS IA', to_ai_bad: 'ANÁLISIS IA falló',
    w_me: 'OPERATOR', w_claude: 'CLAUDE', w_ia: 'IA', w_launch: '⚡ LANZAMIENTO',
    navt: 'SESIÓN', tm_h2: 'Sesiones de grupo - caza en equipo, con red o sin ella',
    tm_p: 'Abre una sala compartida: tu grupo ve la flota, los hallazgos y puede triar en directo. Chat de sesión dedicado más abajo. Tres niveles de acceso: LOCAL (solo), LAN vía ABRIR A LA RED, y MUNDO vía ABRIR AL MUNDO - un túnel público (cloudflared si está instalado) hace válido el enlace de invitación desde cualquier red, sin exponer directamente tu máquina. Todo pasa por la clave de sala - regenérala para echar a todos de golpe.',
    tm_handle: 'Tu apodo (16 caracteres máx)', tm_save_h: 'Elegir', tm_room_ph: 'nombre de la sala (ej: c2ff-core)',
    tm_save: 'Aplicar', tm_on: 'SALA ABIERTA: {r} - {n} en línea', tm_off: 'MODO EQUIPO DESACTIVADO - sesión local en solitario',
    tm_room: 'Sala', tm_key: 'Clave de sala', tm_regen: 'Regenerar clave', tm_regen_ok: 'nueva clave generada - los enlaces antiguos están muertos',
    tm_invite: 'Enlace de invitación (cópialo a tu equipo)', tm_copy: 'Copiar', tm_copied: 'copiado al portapapeles',
    tm_members: 'Miembros', tm_nobody: 'todavía nadie - envía el enlace a tu equipo', tm_you: '(tú)', tm_here: 'presente',
    tm_saved: 'apodo guardado', tm_no_handle: 'apodo vacío', tm_cfg_ok: 'sala actualizada', tm_cfg_no: 'fallo',
    tm_live: 'ABRIR A LA RED', tm_shore: 'VOLVER A LOCAL', tm_need_on: 'activa primero la sala (ON)',
    tm_bind_lan: 'RED: {a}', tm_bind_lo: 'LOCAL: solo localhost',
    to_team_live: '[GO-LIVE] servidor relanzado con acceso de red - enlace LAN mostrado, reconexión en 2 s', to_team_shore: 'servidor relanzado en local (127.0.0.1)',
    tm_tun_open: 'ABRIR AL MUNDO (túnel)', tm_tun_close: 'CERRAR TÚNEL',
    tm_tun_wait: 'túnel público abriéndose (unos segundos)…',
    tm_tun_on: 'SESIÓN ABIERTA AL MUNDO: {u} - el enlace de invitación funciona desde cualquier red, no necesitas la misma red',
    tm_tun_closed: 'túnel cerrado - de vuelta a LAN/local', tm_chat_empty: 'canal de sesión abierto - los miembros de la sala se leen aquí',
    tm_chat_h2: 'Chat de sesión', tm_msg_ph: 'mensaje a la sesión…',
    tm_admin: 'admin', tm_guest: 'invitado', tm_kick: 'KICK', tm_kick_ok: 'miembro expulsado de la sala (otro clic lo desbloquea)', tm_role_ok: 'rol actualizado',
    tm_mic_on: 'ACTIVAR MICRÓFONO', tm_mic_off: 'SILENCIAR MICRÓFONO',
    tm_mic_denied: 'micrófono denegado o no disponible: se requiere HTTPS (túnel MUNDO o localhost) y conceder el permiso',
  },
  de: {
    snd_on: 'TON: AN', snd_off: 'TON: AUS', snd_ok: 'Oberflächenklänge aktiv - Bibliothek: Klick, Tab, Kopieren, Alarme',
    snd_stop: 'Stummschaltung aktiv: keine C2FF-Klänge mehr',
    amb_on: 'AMBIANCE: AN', amb_off: 'AMBIANCE: AUS', amb_ok: 'lebendige Atmosphäre - der Farbton gleitet sanft zwischen den Familien (Grün, Blau, Gelb...)',
    amb_stop: 'Atmosphäre eingefroren auf dem Original-Grün',
    nt_on: 'NOTIFS: AN', nt_off: 'NOTIFS: AUS', nt_ok: 'Browser-Benachrichtigungen aktiv - Piepen bei P1 und P2',
    nt_denied: 'Benachrichtigungen vom Browser blockiert: in den Seiteneinstellungen erlauben',
    term_denied: 'Terminal verweigert oder nicht verfügbar: localhost nötig, oder offener Raum als Admin',
    term_p: 'echte Bash - Verlauf mit Pfeiltasten, Ctrl+C bricht ab, Ctrl+D schließt', term_restart: 'Zurücksetzen',
    navtrm: 'TERM', term_h2: 'Terminal - Arbeitsshell direkt in der Konsole',
    sub_ttl: 'command & control framework',
    fl_off: 'FLOTTE : GESTOPPT', fl_paused: 'FLOTTE : PAUSE', fl_active: 'FLOTTE : AKTIV ({n} Zyklen)',
    fl_last: 'letzter Zyklus', fl_none: 'noch kein Zyklus', fl_info: 'Intervall {i} Min, Budget {b} Anf/Zyklus',
    navf: 'Flotte', navfd: 'Findings', navp: 'Programme', navai: 'KI', navc: 'Koordination',
    st_runs: 'Runs', st_beacons: 'Aktive Beacons', st_sig: 'Signale',
    h2f: 'Flotte - alle Programme, laufende Agents zuerst',
    h2fd: 'Findings-Basis - persistentes Triage-Marking', h2eng: 'Fleet-Engine - lokale Zyklen ohne Tokens',
    h2prog: 'Programme - Scope, Header, Start', h2new: 'Neues Programm', h2ai: 'KI-Agent - 100% optionale Integration',
    h2c: 'Koordination - privater Kanal',
    fl_start: 'Starten', fl_pause: 'Pause', fl_cycle: 'Jetzt zyklieren',
    f_add: 'Hinzufügen', f_none: 'noch kein Signal', f_ph: 'manueller Finding: Endpoint + Beweis + verteidigbare Stufe…',
    st_sig_off: 'signal', st_sig_an: 'analyse', st_sig_sub: 'eingereicht', st_sig_dup: 'dup', st_sig_ref: 'abgelehnt', st_sig_cl: 'geschlossen',
    r_none: 'kein Run erkannt', r_live: '{n} AKTIV', r_done: 'FERTIG', r_feed: '▽ Feed ({n} ev)', r_close: '△ zuklappen',
    p_name_ph: 'Programmname (z.B. PayPal)', p_hdr_ph: 'erforderlicher Header (z.B. X-Bug-Bounty: xxx)',
    p_scope_ph: 'Scope : Domain1, Domain2, …', p_save: 'Speichern', p_local: 'Modul(e), 100% lokal',
    ai_p: 'C2FF läuft ohne KI: Modi sind deterministische lokale Probes. Dieses Gateway verbindet nur <b>deine</b> KI (self-hosted oder API) zur punktgenauen Analyse eines Findings: Taste <span style="color:var(--green)">IA »</span> in FINDINGS, Antwort in KOORDINATION. Keine Daten verlassen deine Maschine ohne diese Konfiguration.',
    ai_off: 'deaktiviert', ai_on: 'aktiviert',
    ai_st_off: 'KI DEAKTIVIERT - Framework läuft 100% lokal ohne sie',
    ai_st_ready: 'KI VERBUNDEN: {p} · {m}', ai_st_inc: 'KI AKTIVIERT, ABER UNVOLLSTÄNDIG: baseURL und model nötig',
    ai_url_ph: 'Basis-URL - z.B. http://localhost:11434 oder https://api.MeineKI.tld/v1',
    ai_model_ph: 'model - z.B. llama3.1:8b', ai_key_ph: 'API-Schlüssel (leer für lokale Server)',
    ai_save: 'Speichern', ai_test: 'Verbindung testen', ai_testing: 'teste…', ai_ok: 'OK - Antwort: ', ai_fail: 'FEHLER: ',
    ai_note: 'Config lokal in data/ai.json gespeichert - wird nur an den Endpoint gesendet, den du einträgst',
    ch_ph: 'root@c2ff:~# Nachricht an den Analyse-Agent…', ch_send: 'Senden',
    ch_empty: 'Kanal offen. Schreib hier, der Monitor weckt mich sofort.',
    ft: '100% lokal - deterministische Probes, ohne Tokens, ohne externe Abhängigkeiten - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE AKTIV: lokale Zyklen alle 30 Min, 0 Tokens.',
    to_fl_pa: 'FLOTTEN-PAUSE - fortsetzen wann du willst.',
    to_fl_cy: 'Sofort-Zyklus gestartet (Budget 60 Anf).',
    to_launch: '[GO] Modus {m} (CWE {c}) auf {p} - lokaler Zyklus gestartet',
    to_ai_ok: 'Config gespeichert', to_ai_no: 'Speichern fehlgeschlagen', to_ai_no_cfg: 'KI nicht konfiguriert - im KI-Tab einstellen',
    to_ai_head: 'KI-ANALYSE', to_ai_bad: 'KI-ANALYSE fehlgeschlagen',
    w_me: 'OPERATOR', w_claude: 'CLAUDE', w_ia: 'KI', w_launch: '⚡ START',
    navt: 'SESSION', tm_h2: 'Gruppensitzungen - gemeinsam jagen, mit oder ohne Netzwerk',
    tm_p: 'Öffne einen geteilten Raum: Deine Gruppe sieht Flotte und Findings und kann live triagen. Eigener Sitzungs-Chat unten. Drei Zugriffsstufen: LOKAL (Solo), LAN via NETZWERK ÖFFNEN und WELT via WELT ÖFFNEN - ein öffentlicher Tunnel (cloudflared, falls installiert) macht den Einladungslink aus jedem Netz gültig, ohne deine Maschine direkt freizugeben. Alles läuft über den Raum-Schlüssel - neu generieren wirft alle gleichzeitig raus.',
    tm_handle: 'Dein Name (max. 16 Zeichen)', tm_save_h: 'Wählen', tm_room_ph: 'Raumname (z.B. c2ff-core)',
    tm_save: 'Anwenden', tm_on: 'RAUM OFFEN: {r} - {n} online', tm_off: 'TEAM-MODUS AUS - lokale Solositzung',
    tm_room: 'Raum', tm_key: 'Raum-Schlüssel', tm_regen: 'Schlüssel neu generieren', tm_regen_ok: 'neuer Schlüssel erzeugt - alte Links sind tot',
    tm_invite: 'Einladungslink (an dein Team schicken)', tm_copy: 'Kopieren', tm_copied: 'in die Zwischenablage kopiert',
    tm_members: 'Mitglieder', tm_nobody: 'noch niemand - schick den Link an dein Team', tm_you: '(du)', tm_here: 'da',
    tm_saved: 'Name gespeichert', tm_no_handle: 'Name leer', tm_cfg_ok: 'Raum aktualisiert', tm_cfg_no: 'fehlgeschlagen',
    tm_live: 'NETZWERK ÖFFNEN', tm_shore: 'ZURÜCK LOKAL', tm_need_on: 'erst den Raum aktivieren (ON)',
    tm_bind_lan: 'NETZWERK: {a}', tm_bind_lo: 'LOKAL: nur localhost',
    to_team_live: '[GO-LIVE] Server mit Netzwerkzugang neu gestartet - LAN-Link angezeigt, Wiederverbindung in 2 s', to_team_shore: 'Server lokal neu gestartet (127.0.0.1)',
    tm_tun_open: 'WELT ÖFFNEN (Tunnel)', tm_tun_close: 'TUNNEL SCHLIESSEN',
    tm_tun_wait: 'öffentlicher Tunnel wird aufgebaut (einige Sekunden)…',
    tm_tun_on: 'SITZUNG FÜR DIE WELT OFFEN: {u} - der Einladungslink funktioniert aus jedem Netz, kein gemeinsames Netz nötig',
    tm_tun_closed: 'Tunnel geschlossen - zurück zu LAN/lokal', tm_chat_empty: 'Sitzungskanal offen - Raummitglieder sehen sich hier gegenseitig',
    tm_chat_h2: 'Sitzungs-Chat', tm_msg_ph: 'Nachricht an die Sitzung…',
    tm_admin: 'admin', tm_guest: 'Gast', tm_kick: 'KICK', tm_kick_ok: 'Mitglied aus dem Raum entfernt (nochmals klicken hebt es auf)', tm_role_ok: 'Rolle aktualisiert',
    tm_mic_on: 'MIKROFON AKTIVIEREN', tm_mic_off: 'MIKROFON STUMMSCHALTEN',
    tm_mic_denied: 'Mikrofon verweigert oder nicht verfügbar: HTTPS nötig (WELT-Tunnel oder localhost) und Berechtigung erteilen',
  },
  pt: {
    snd_on: 'SOM: ON', snd_off: 'SOM: OFF', snd_ok: 'sons de interface ativos - biblioteca: clique, aba, copiar, alertas',
    snd_stop: 'mudo total ativado: sem mais sons do C2FF',
    amb_on: 'AMBIENTE: ON', amb_off: 'AMBIENTE: OFF', amb_ok: 'ambiente vivo - o tom desliza suavemente entre as famílias (verde, azul, amarelo...)',
    amb_stop: 'ambiente congelado no verde original',
    nt_on: 'NOTIFS: ON', nt_off: 'NOTIFS: OFF', nt_ok: 'notificações do navegador ativas - bip em P1 e P2',
    nt_denied: 'notificações bloqueadas pelo navegador: permita-as nas configurações do site',
    term_denied: 'terminal recusado ou indisponível: localhost necessário, ou sala ABERTA como admin',
    term_p: 'bash real - histórico com setas, Ctrl+C interrompe, Ctrl+D fecha', term_restart: 'Reiniciar',
    navtrm: 'TERM', term_h2: 'Terminal - shell de trabalho, na própria consola',
    sub_ttl: 'command & control framework',
    fl_off: 'ESQUADRÃO : PARADO', fl_paused: 'ESQUADRÃO : EM PAUSA', fl_active: 'ESQUADRÃO : ATIVO ({n} ciclos)',
    fl_last: 'último ciclo', fl_none: 'nenhum ciclo ainda', fl_info: 'intervalo {i} min, orçamento {b} req/ciclo',
    navf: 'Esquadrão', navfd: 'Achados', navp: 'Programas', navai: 'IA', navc: 'Coordenação',
    st_runs: 'Runs', st_beacons: 'Beacons ativos', st_sig: 'Sinais',
    h2f: 'Esquadrão - todos os programas, agentes em curso primeiro',
    h2fd: 'Base de achados - triagem persistente', h2eng: 'Motor - ciclos locais sem tokens',
    h2prog: 'Programas - scope, header exigido, lançamento', h2new: 'Novo programa', h2ai: 'Agente IA - integração 100% opcional',
    h2c: 'Coordenação - canal privado',
    fl_start: 'Iniciar', fl_pause: 'Pausa', fl_cycle: 'Ciclo agora',
    f_add: 'Adicionar', f_none: 'nenhum sinal ainda', f_ph: 'achado manual: endpoint + prova + severidade defensável…',
    st_sig_off: 'sinal', st_sig_an: 'análise', st_sig_sub: 'enviado', st_sig_dup: 'dup', st_sig_ref: 'rejeitado', st_sig_cl: 'fechado',
    r_none: 'nenhum run detectado', r_live: '{n} EM CURSO', r_done: 'FEITO', r_feed: '▽ fluxo ({n} ev)', r_close: '△ recolher',
    p_name_ph: 'Nome do programa (ex: PayPal)', p_hdr_ph: 'header exigido (ex: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : domínio1, domínio2, …', p_save: 'Guardar', p_local: 'módulo(s), 100% local',
    ai_p: 'O C2FF funciona sem IA: os modos são probes deterministas locais. Este portal liga apenas <b>a tua</b> IA (self-hosted ou API) para analisar um achado pontual: botão <span style="color:var(--green)">IA »</span> em ACHADOS, resposta em COORDENAÇÃO. Nenhum dado sai da tua máquina sem esta configuração.',
    ai_off: 'desativada', ai_on: 'ativada',
    ai_st_off: 'IA DESATIVADA - framework funciona 100% local sem ela',
    ai_st_ready: 'IA CONECTADA: {p} · {m}', ai_st_inc: 'IA ATIVADA MAS INCOMPLETA: baseURL e model obrigatórios',
    ai_url_ph: 'URL base - ex: http://localhost:11434 ou https://api.MinhaIA.tld/v1',
    ai_model_ph: 'model - ex: llama3.1:8b', ai_key_ph: 'chave API (vazio se servidor local)',
    ai_save: 'Guardar', ai_test: 'Testar conexão', ai_testing: 'a testar…', ai_ok: 'OK - resposta: ', ai_fail: 'FALHA: ',
    ai_note: 'config guardada localmente em data/ai.json - nunca enviada para outro lado além do endpoint que colocares',
    ch_ph: 'root@c2ff:~# mensagem ao agente de análise…', ch_send: 'Enviar',
    ch_empty: 'Canal aberto. Escreve aqui, o monitor acorda-me na hora.',
    ft: '100% local - probes deterministas, sem tokens nem dependências - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ATIVO: ciclos locais a cada 30 min, 0 tokens.',
    to_fl_pa: 'ESQUADRÃO EM PAUSA - retoma quando quiseres.',
    to_fl_cy: 'Ciclo imediato lançado (orçamento 60 req).',
    to_launch: '[GO] modo {m} (CWE {c}) em {p} - ciclo local lançado',
    to_ai_ok: 'config guardada', to_ai_no: 'falha ao guardar', to_ai_no_cfg: 'IA não configurada - define no separador IA',
    to_ai_head: 'ANÁLISE IA', to_ai_bad: 'ANÁLISE IA falhou',
    w_me: 'OPERATOR', w_claude: 'CLAUDE', w_ia: 'IA', w_launch: '⚡ LANÇAMENTO',
    navt: 'SESSÃO', tm_h2: 'Sessões em grupo - caça em equipa, com rede ou sem',
    tm_p: 'Abre uma sala partilhada: o teu grupo vê a frota, os findings e pode triar em direto. Chat de sessão dedicado em baixo. Três níveis de acesso: LOCAL (a solo), LAN via ABRIR À REDE, e MUNDO via ABRIR AO MUNDO - um túnel público (cloudflared se instalado) torna o link de convite válido de qualquer rede, sem expor diretamente a tua máquina. Tudo passa pela chave da sala - regenera-a para expulsar todos de uma vez.',
    tm_handle: 'O teu pseudónimo (16 caracteres máx)', tm_save_h: 'Escolher', tm_room_ph: 'nome da sala (ex: c2ff-core)',
    tm_save: 'Aplicar', tm_on: 'SALA ABERTA: {r} - {n} online', tm_off: 'MODO EQUIPA DESATIVADO - sessão local a solo',
    tm_room: 'Sala', tm_key: 'Chave da sala', tm_regen: 'Regenerar chave', tm_regen_ok: 'nova chave gerada - os links antigos estão mortos',
    tm_invite: 'Link de convite (copia-o à tua equipa)', tm_copy: 'Copiar', tm_copied: 'copiado para a área de transferência',
    tm_members: 'Membros', tm_nobody: 'ninguém ainda - envia o link à tua equipa', tm_you: '(tu)', tm_here: 'presente',
    tm_saved: 'pseudónimo guardado', tm_no_handle: 'pseudónimo vazio', tm_cfg_ok: 'sala atualizada', tm_cfg_no: 'falhou',
    tm_live: 'ABRIR À REDE', tm_shore: 'VOLTAR LOCAL', tm_need_on: 'ativa primeiro a sala (ON)',
    tm_bind_lan: 'REDE: {a}', tm_bind_lo: 'LOCAL: apenas localhost',
    to_team_live: '[GO-LIVE] servidor relançado com acesso de rede - link LAN mostrado, reconexão em 2 s', to_team_shore: 'servidor relançado em local (127.0.0.1)',
    tm_tun_open: 'ABRIR AO MUNDO (túnel)', tm_tun_close: 'FECHAR TÚNEL',
    tm_tun_wait: 'túnel público a abrir (alguns segundos)…',
    tm_tun_on: 'SESSÃO ABERTA AO MUNDO: {u} - o link de convite funciona de qualquer rede, não precisas da mesma rede',
    tm_tun_closed: 'túnel fechado - de volta a LAN/local', tm_chat_empty: 'canal de sessão aberto - os membros da leem-se aqui',
    tm_chat_h2: 'Chat de sessão', tm_msg_ph: 'mensagem para a sessão…',
    tm_admin: 'admin', tm_guest: 'convidado', tm_kick: 'KICK', tm_kick_ok: 'membro expulso da sala (clicar outra vez desbloqueia)', tm_role_ok: 'papel atualizado',
    tm_mic_on: 'ATIVAR MICROFONE', tm_mic_off: 'SILENCIAR MICROFONE',
    tm_mic_denied: 'microfone recusado ou indisponível: HTTPS obrigatório (túnel MUNDO ou localhost) e conceder a permissão',
  },
  it: {
    snd_on: 'SUONO: ON', snd_off: 'SUONO: OFF', snd_ok: 'suoni interfaccia attivi - libreria: clic, scheda, copia, allarmi',
    snd_stop: 'muto totale attivo: nessun suono C2FF',
    amb_on: 'AMBIENTE: ON', amb_off: 'AMBIENTE: OFF', amb_ok: 'atmosfera viva - la tinta scorre dolcemente tra le famiglie (verde, blu, giallo...)',
    amb_stop: 'atmosfera bloccata sul verde originale',
    nt_on: 'NOTIFS: ON', nt_off: 'NOTIFS: OFF', nt_ok: 'notifiche del browser attive - bip su P1 e P2',
    nt_denied: 'notifiche bloccate dal browser: autorizzale nelle impostazioni del sito',
    term_denied: 'terminale negato o non disponibile: serve localhost, o stanza APERTA come admin',
    term_p: 'bash reale - cronologia con frecce, Ctrl+C interrompe, Ctrl+D chiude', term_restart: 'Reimposta',
    navtrm: 'TERM', term_h2: 'Terminale - shell di lavoro, direttamente nella console',
    sub_ttl: 'command & control framework',
    fl_off: 'FLOTTA : ARRESTATO', fl_paused: 'FLOTTA : IN PAUSA', fl_active: 'FLOTTA : ATTIVO ({n} cicli)',
    fl_last: 'ultimo ciclo', fl_none: 'nessun ciclo ancora', fl_info: 'intervallo {i} min, budget {b} req/ciclo',
    navf: 'Flotta', navfd: 'Risultati', navp: 'Programmi', navai: 'IA', navc: 'Coordinamento',
    st_runs: 'Runs', st_beacons: 'Beacon attivi', st_sig: 'Segnali',
    h2f: 'Flotta - tutti i programmi, agenti in corso prima',
    h2fd: 'Base findings - triaggio persistente', h2eng: 'Motore flotta - cicli locali senza token',
    h2prog: 'Programmi - scope, header richiesto, lancio', h2new: 'Nuovo programma', h2ai: 'Agente IA - integrazione 100% opzionale',
    h2c: 'Coordinamento - canale privato',
    fl_start: 'Avvia', fl_pause: 'Pausa', fl_cycle: 'Ciclo ora',
    f_add: 'Aggiungi', f_none: 'nessun segnale ancora', f_ph: 'finding manuale: endpoint + prova + gravità difendibile…',
    st_sig_off: 'segnale', st_sig_an: 'analisi', st_sig_sub: 'inviato', st_sig_dup: 'dup', st_sig_ref: 'rifiutato', st_sig_cl: 'chiuso',
    r_none: 'nessun run rilevato', r_live: '{n} IN CORSO', r_done: 'FINITO', r_feed: '▽ flusso ({n} ev)', r_close: '△ chiudi',
    p_name_ph: 'Nome programma (es: PayPal)', p_hdr_ph: 'header richiesto (es: X-Bug-Bounty: xxx)',
    p_scope_ph: 'scope : dominio1, dominio2, …', p_save: 'Salva', p_local: 'modulo/i, 100% locale',
    ai_p: 'C2FF funziona senza IA: i modi sono probes deterministici locali. Questo gateway collega solo <b>la tua</b> IA (self-hosted o API) per analizzare un finding puntuale: bottone <span style="color:var(--green)">IA »</span> in FINDINGS, risposta in COORDINAMENTO. Nessun dato lascia la tua macchina senza questa configurazione.',
    ai_off: 'disattivata', ai_on: 'attivata',
    ai_st_off: 'IA DISATTIVATA - il framework gira 100% locale senza di essa',
    ai_st_ready: 'IA CONNESSA: {p} · {m}', ai_st_inc: 'IA ATTIVATA MA INCOMPLETA: baseURL e model richiesti',
    ai_url_ph: 'URL base - es: http://localhost:11434 o https://api.MiaIA.tld/v1',
    ai_model_ph: 'model - es: llama3.1:8b', ai_key_ph: 'chiave API (vuoto se server locale)',
    ai_save: 'Salva', ai_test: 'Testa connessione', ai_testing: 'test in corso…', ai_ok: 'OK - risposta: ', ai_fail: 'FALLITO: ',
    ai_note: 'config salvata localmente in data/ai.json - mai inviata altrove se non all\'endpoint che inserisci',
    ch_ph: 'root@c2ff:~# messaggio all\'agente di analisi…', ch_send: 'Invia',
    ch_empty: 'Canale aperto. Scrivi qui, il monitor mi sveglia subito.',
    ft: '100% locale - probes deterministici, senza token né dipendenze - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE ATTIVO: cicli locali ogni 30 min, 0 token.',
    to_fl_pa: 'FLOTTA IN PAUSA - riprendi quando vuoi.',
    to_fl_cy: 'Ciclo immediato lanciato (budget 60 req).',
    to_launch: '[GO] modo {m} (CWE {c}) su {p} - ciclo locale lanciato',
    to_ai_ok: 'config salvata', to_ai_no: 'salvataggio fallito', to_ai_no_cfg: 'IA non configurata - imposta nel tab IA',
    to_ai_head: 'ANALISI IA', to_ai_bad: 'ANALISI IA fallita',
    w_me: 'OPERATOR', w_claude: 'CLAUDE', w_ia: 'IA', w_launch: '⚡ LANCIO',
    navt: 'SESSIONE', tm_h2: 'Sessioni di gruppo - caccia insieme, con o senza rete',
    tm_p: 'Apri una stanza condivisa: il tuo gruppo vede la flotta, i findings e può fare triage in diretta. Chat di sessione dedicata qui sotto. Tre livelli di accesso: LOCALE (da solo), LAN tramite APRI ALLA RETE, e MONDO tramite APRI AL MONDO - un tunnel pubblico (cloudflared se installato) rende il link di invito valido da qualsiasi rete, senza esporre direttamente la tua macchina. Tutto passa dalla chiave della stanza - rigenerala per cacciare tutti in una volta.',
    tm_handle: 'Il tuo nickname (16 caratteri max)', tm_save_h: 'Scegli', tm_room_ph: 'nome della stanza (es: c2ff-core)',
    tm_save: 'Applica', tm_on: 'STANZA APERTA: {r} - {n} online', tm_off: 'MODALITÀ TEAM DISATTIVATA - sessione locale da soli',
    tm_room: 'Stanza', tm_key: 'Chiave della stanza', tm_regen: 'Rigenera chiave', tm_regen_ok: 'nuova chiave generata - i vecchi link sono morti',
    tm_invite: 'Link di invito (copialo al tuo team)', tm_copy: 'Copia', tm_copied: 'copiato negli appunti',
    tm_members: 'Membri', tm_nobody: 'ancora nessuno - invia il link al tuo team', tm_you: '(tu)', tm_here: 'presente',
    tm_saved: 'nickname salvato', tm_no_handle: 'nickname vuoto', tm_cfg_ok: 'stanza aggiornata', tm_cfg_no: 'fallito',
    tm_live: 'APRI ALLA RETE', tm_shore: 'TORNA LOCALE', tm_need_on: 'attiva prima la stanza (ON)',
    tm_bind_lan: 'RETE: {a}', tm_bind_lo: 'LOCALE: solo localhost',
    to_team_live: '[GO-LIVE] server riavviato con accesso di rete - link LAN mostrato, riconnessione in 2 s', to_team_shore: 'server riavviato in locale (127.0.0.1)',
    tm_tun_open: 'APRI AL MONDO (tunnel)', tm_tun_close: 'CHIUDI TUNNEL',
    tm_tun_wait: 'tunnel pubblico in apertura (pochi secondi)…',
    tm_tun_on: 'SESSIONE APERTA AL MONDO: {u} - il link di invito funziona da qualsiasi rete, non serve la stessa rete',
    tm_tun_closed: 'tunnel chiuso - torna a LAN/locale', tm_chat_empty: 'canale di sessione aperto - i membri della stanza si leggono qui',
    tm_chat_h2: 'Chat della sessione', tm_msg_ph: 'messaggio alla sessione…',
    tm_admin: 'admin', tm_guest: 'ospite', tm_kick: 'KICK', tm_kick_ok: 'membro espulso dalla stanza (clicca di nuovo per sbloccare)', tm_role_ok: 'ruolo aggiornato',
    tm_mic_on: 'ATTIVA MICROFONO', tm_mic_off: 'SILENZIA MICROFONO',
    tm_mic_denied: 'microfono negato o non disponibile: serve HTTPS (tunnel MONDO o localhost) e concedere il permesso',
  },
  ar: {
    snd_on: 'الصوت: تشغيل', snd_off: 'الصوت: إيقاف', snd_ok: 'أصوات الواجهة مفعلة - المكتبة: نقر، تبويب، نسخ، تنبيهات',
    snd_stop: 'الصمت الكامل مفعل: لا أصوات C2FF بعد الآن',
    amb_on: 'الجو: تشغيل', amb_off: 'الجو: إيقاف', amb_ok: 'أجواء حية - اللون ينزلق بهدوء بين العائلات (أخضر، أزرق، أصفر...)',
    amb_stop: 'الجو مثبت على الأخضر الأصلي',
    nt_on: 'الإشعارات: تشغيل', nt_off: 'الإشعارات: إيقاف', nt_ok: 'تم تفعيل إشعارات المتصفح - نغمة على P1 و P2',
    nt_denied: 'الإشعارات محجوبة من المتصفح: اسمح بها من إعدادات الموقع',
    term_denied: 'الطرفية مرفوضة أو غير متاحة: localhost مطلوب، أو غرفة مفتوحة بصلاحية مشرف',
    term_p: 'bash حقيقي - السجل بالأسهم، Ctrl+C يقطع، Ctrl+D يغلق', term_restart: 'إعادة تعيين',
    navtrm: 'طرفية', term_h2: 'الطرفية - قشرة عمل في الكونسول مباشرة',
    sub_ttl: 'command & control framework',
    fl_off: 'الأسطول : متوقف', fl_paused: 'الأسطول : موقوف مؤقتاً', fl_active: 'الأسطول : نشط ({n} دورات)',
    fl_last: 'آخر دورة', fl_none: 'لا دورة بعد', fl_info: 'الفاصل {i} دقيقة، الميزانية {b} طلب/دورة',
    navf: 'الأسطول', navfd: 'النتائج', navp: 'البرامج', navai: 'الذكاء الاصطناعي', navc: 'التنسيق',
    st_runs: 'الجلسات', st_beacons: 'منارات نشطة', st_sig: 'إشارات',
    h2f: 'الأسطول - كل البرامج، الوكلاء الجاريون أولاً',
    h2fd: 'قاعدة النتائج - فرز مستمر', h2eng: 'محرك الأسطول - دورات محلية بدون رموز',
    h2prog: 'البرامج - النطاق، الترويسة المطلوبة، الإطلاق', h2new: 'برنامج جديد', h2ai: 'وكيل الذكاء الاصطناعي - تكامل اختياري 100%',
    h2c: 'التنسيق - قناة خاصة',
    fl_start: 'تشغيل', fl_pause: 'إيقاف مؤقت', fl_cycle: 'دورة الآن',
    f_add: 'إضافة', f_none: 'لا إشارة بعد', f_ph: 'نتيجة يدوية: نقطة نهاية + إثبات + خطورة دفاعية…',
    st_sig_off: 'إشارة', st_sig_an: 'تحليل', st_sig_sub: 'مُرسل', st_sig_dup: 'مكرر', st_sig_ref: 'مرفوض', st_sig_cl: 'مغلق',
    r_none: 'لا جلسة مرصودة', r_live: '{n} جارية', r_done: 'منتهية', r_feed: '▽ التدفق ({n} حدث)', r_close: '△ طي',
    p_name_ph: 'اسم البرنامج (مثال: PayPal)', p_hdr_ph: 'الترويسة المطلوبة (مثال: X-Bug-Bounty: xxx)',
    p_scope_ph: 'النطاق : نطاق1، نطاق2، …', p_save: 'حفظ', p_local: 'وحدة/وحدات، 100% محلي',
    ai_p: 'يعمل C2FF بدون ذكاء اصطناعي: الأوضاع probes محلية حتمية. هذا الربط يوصل <b>ذكاءك الاصطناعي</b> (محلي أو API) فقط لتحليل نتيجة عابرة: زر <span style="color:var(--green)">IA »</span> في النتائج، والإجابة في التنسيق. لا تخرج أي بيانات من جهازك بدون هذا الإعداد.',
    ai_off: 'معطلة', ai_on: 'مفعلة',
    ai_st_off: 'الذكاء الاصطناعي معطل - الإطار يعمل 100% محلياً بدونه',
    ai_st_ready: 'الذكاء الاصطناعي متصل: {p} · {m}', ai_st_inc: 'مفعل لكن غير مكتمل: baseURL و model مطلوبان',
    ai_url_ph: 'URL الأساس - مثال: http://localhost:11434 أو https://api.MyAI.tld/v1',
    ai_model_ph: 'model - مثال: llama3.1:8b', ai_key_ph: 'المفتاح API (فارغ للخوادم المحلية)',
    ai_save: 'حفظ', ai_test: 'اختبار الاتصال', ai_testing: 'جارٍ الاختبار…', ai_ok: 'تم - الرد: ', ai_fail: 'فشل: ',
    ai_note: 'الإعداد محفوظ محلياً في data/ai.json - لا يُرسل أبداً إلا للنقطة التي تحددها',
    ch_ph: 'root@c2ff:~# رسالة إلى وكيل التحليل…', ch_send: 'إرسال',
    ch_empty: 'القناة مفتوحة. اكتب هنا، المراقب يوقظني فوراً.',
    ft: 'محلي 100% - probes حتمية، بدون رموز أو تبعيات - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE نشط: دورات محلية كل 30 دقيقة، 0 رموز.',
    to_fl_pa: 'الأسطول موقوف مؤقتاً - استئنف متى شئت.',
    to_fl_cy: 'دورة فورية أُطلقت (ميزانية 60 طلب).',
    to_launch: '[GO] وضع {m} (CWE {c}) على {p} - دورة محلية أُطلقت',
    to_ai_ok: 'تم حفظ الإعداد', to_ai_no: 'فشل الحفظ', to_ai_no_cfg: 'الذكاء الاصطناعي غير مهيأ - اضبطه في تبويب IA',
    to_ai_head: 'تحليل الذكاء الاصطناعي', to_ai_bad: 'فشل التحليل',
    w_me: 'OPERATOR', w_claude: 'CLAUDE', w_ia: 'IA', w_launch: '⚡ إطلاق',
    navt: 'جلسة', tm_h2: 'جلسات جماعية - الصيد معاً، بنفس الشبكة أو بدونها',
    tm_p: 'افتح غرفة مشتركة: يرى فريقك الأسطول والنتائج ويمكنه الفرز مباشرة. دردشة جلسة مخصصة بالأسفل. ثلاثة مستويات وصول: محلي (فردي)، الشبكة عبر فتح للشبكة، والعالم عبر فتح للعالم - نفق عام (cloudflared إذا كان مثبتاً) يجعل رابط الدعوة صالحاً من أي شبكة دون تعريض جهازك مباشرة. كل شيء يمر بمفتاح الغرفة - أعد توليده لطرد الجميع دفعة واحدة.',
    tm_handle: 'اسمك (16 حرفاً كحد أقصى)', tm_save_h: 'اختيار', tm_room_ph: 'اسم الغرفة (مثال: c2ff-core)',
    tm_save: 'تطبيق', tm_on: 'الغرفة مفتوحة: {r} - {n} متصل', tm_off: 'وضع الفريق متوقف - جلسة محلية فردية',
    tm_room: 'الغرفة', tm_key: 'مفتاح الغرفة', tm_regen: 'إعادة توليد المفتاح', tm_regen_ok: 'تم توليد مفتاح جديد - الروابط القديمة ماتت',
    tm_invite: 'رابط الدعوة (انسخه لفريقك)', tm_copy: 'نسخ', tm_copied: 'تم النسخ إلى الحافظة',
    tm_members: 'الأعضاء', tm_nobody: 'لا أحد بعد - أرسل الرابط لفريقك', tm_you: '(أنت)', tm_here: 'حاضر',
    tm_saved: 'تم حفظ الاسم', tm_no_handle: 'الاسم فارغ', tm_cfg_ok: 'تم تحديث الغرفة', tm_cfg_no: 'فشل',
    tm_live: 'فتح للشبكة', tm_shore: 'عودة محلي', tm_need_on: 'فعّل الغرفة أولاً (ON)',
    tm_bind_lan: 'الشبكة: {a}', tm_bind_lo: 'محلي: localhost فقط',
    to_team_live: '[GO-LIVE] أعد تشغيل الخادم بصلاحية الشبكة - رابط الشبكة ظاهر، إعادة الاتصال خلال 2 ث', to_team_shore: 'أُعيد تشغيل الخادم محلياً (127.0.0.1)',
    tm_tun_open: 'فتح للعالم (نفق)', tm_tun_close: 'إغلاق النفق',
    tm_tun_wait: 'النفق العام يُفتح الآن (بضع ثوانٍ)…',
    tm_tun_on: 'الجلسة مفتوحة للعالم: {u} - رابط الدعوة يعمل من أي شبكة، لا حاجة لنفس الشبكة',
    tm_tun_closed: 'أُغلق النفق - عودة إلى الشبكة/المحلي', tm_chat_empty: 'قناة الجلسة مفتوحة - أعضاء الغرفة يتحدثون هنا',
    tm_chat_h2: 'دردشة الجلسة', tm_msg_ph: 'رسالة إلى الجلسة…',
    tm_admin: 'مشرف', tm_guest: 'ضيف', tm_kick: 'طرد', tm_kick_ok: 'طُرد العضو من الغرفة (اضغط مجدداً للفك)', tm_role_ok: 'تم تحديث الدور',
    tm_mic_on: 'تشغيل الميكروفون', tm_mic_off: 'كتم الميكروفون',
    tm_mic_denied: 'الميكروفون مرفوض أو غير متاح: HTTPS مطلوب (نفق عالم أو localhost) مع منح الإذن',
  },
  zh: {
    snd_on: '音效: 开', snd_off: '音效: 关', snd_ok: '界面音效已开启 - 音效库：点击、切换、复制、警报',
    snd_stop: '已完全静音：不再有 C2FF 音效',
    amb_on: '氛围: 开', amb_off: '氛围: 关', amb_ok: '活氛围 - 色调在色系间缓缓流动 (绿, 蓝, 黄...)',
    amb_stop: '氛围固定在原版绿',
    nt_on: '通知: 开', nt_off: '通知: 关', nt_ok: '浏览器通知已开启 - P1 和 P2 会有提示音',
    nt_denied: '浏览器通知被拦截：请在站点设置中允许',
    term_denied: '终端被拒绝或不可用：需要 localhost，或以管理员身份开启房间',
    term_p: '真实 bash - 方向键调历史, Ctrl+C 中断, Ctrl+D 关闭', term_restart: '重置',
    navtrm: '终端', term_h2: '终端 - 直接在控制台里的工作 shell',
    sub_ttl: 'command & control framework',
    fl_off: '舰队 : 已停止', fl_paused: '舰队 : 已暂停', fl_active: '舰队 : 活跃（{n} 个循环）',
    fl_last: '上次循环', fl_none: '尚无循环', fl_info: '间隔 {i} 分钟，预算 {b} 请求/循环',
    navf: '舰队', navfd: '发现', navp: '项目', navai: 'AI', navc: '协同',
    st_runs: 'Runs', st_beacons: '活跃信标', st_sig: '信号',
    h2f: '舰队 - 全部项目，运行中的代理优先',
    h2fd: '发现库 - 持久分诊标记', h2eng: '舰队引擎 - 本地循环，零令牌',
    h2prog: '项目 - 范围、必需头、启动', h2new: '新建项目', h2ai: 'AI 代理 - 100% 可选集成',
    h2c: '协同 - 私人频道',
    fl_start: '启动', fl_pause: '暂停', fl_cycle: '立即循环',
    f_add: '添加', f_none: '尚无信号', f_ph: '手动发现：端点 + 证据 + 可辩护等级…',
    st_sig_off: 'signal', st_sig_an: 'analyse', st_sig_sub: '已提交', st_sig_dup: 'dup', st_sig_ref: '已拒绝', st_sig_cl: '已关闭',
    r_none: '未检测到运行', r_live: '{n} 运行中', r_done: '已完成', r_feed: '▽ 流 ({n} 条)', r_close: '△ 收起',
    p_name_ph: '项目名（如 PayPal）', p_hdr_ph: '必需的研究头（如 X-Bug-Bounty: xxx）',
    p_scope_ph: '范围：域名1、域名2、…', p_save: '保存', p_local: '个模块，100% 本地',
    ai_p: 'C2FF 无需 AI 即可运行：各模式均为确定性的本地探测器。此网关仅用于接入<b>你自己的</b> AI（自托管或 API）按需分析单条发现：在"发现"页点 <span style="color:var(--green)">IA »</span>，回复呈现在"协同"页。没有此配置，任何数据都不会离开你的机器。',
    ai_off: '已禁用', ai_on: '已启用',
    ai_st_off: 'AI 已禁用 - 框架在无 AI 的情况下 100% 本地运行',
    ai_st_ready: 'AI 已连接：{p} · {m}', ai_st_inc: 'AI 已启用但不完整：需要 baseURL 和 model',
    ai_url_ph: '基础 URL - 如 http://localhost:11434 或 https://api.MyAI.tld/v1',
    ai_model_ph: 'model - 如 llama3.1:8b', ai_key_ph: 'API 密钥（本地服务器留空）',
    ai_save: '保存', ai_test: '测试连接', ai_testing: '测试中…', ai_ok: '成功 - 回复：', ai_fail: '失败：',
    ai_note: '配置存储在本地 data/ai.json - 只发送到你填写的端点',
    ch_ph: 'root@c2ff:~# 发送给分析代理的消息…', ch_send: '发送',
    ch_empty: '频道已开启。在此输入，监视器立刻唤醒我。',
    ft: '100% 本地 - 确定性探测，无令牌无外部依赖 - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE 已激活：每 30 分钟本地循环，0 令牌。',
    to_fl_pa: '舰队已暂停 - 随时恢复。',
    to_fl_cy: '立即循环已启动（预算 60 请求）。',
    to_launch: '[GO] 模式 {m}（CWE {c}）作用于 {p} - 本地循环已启动',
    to_ai_ok: '配置已保存', to_ai_no: '保存失败', to_ai_no_cfg: 'AI 未配置 - 请在 AI 标签页设置',
    to_ai_head: 'AI 分析', to_ai_bad: 'AI 分析失败',
    w_me: 'OPERATOR', w_claude: 'CLAUDE', w_ia: 'AI', w_launch: '⚡ 发射',
    navt: '会话', tm_h2: '团队会话 - 无论是否同一网络都可协同狩猎',
    tm_p: '打开一个共享房间：你的团队可以查看舰队、发现并实时分诊。下方是专用会话聊天。三种访问级别：本地（单人）、局域网（开启网络）和全世界（开启世界通道）- 公共隧道（如已安装 cloudflared）让邀请链接在任何网络都有效，无需直接暴露你的机器。一切通过房间密钥控制 - 重新生成即可一次性踢出所有人。',
    tm_handle: '你的昵称（最多16字符）', tm_save_h: '选择', tm_room_ph: '房间名（如：c2ff-core）',
    tm_save: '应用', tm_on: '房间已开放：{r} - {n} 人在线', tm_off: '团队模式已关闭 - 本地单人会话',
    tm_room: '房间', tm_key: '房间密钥', tm_regen: '重新生成密钥', tm_regen_ok: '新密钥已生成 - 旧链接全部失效',
    tm_invite: '邀请链接（复制给团队）', tm_copy: '复制', tm_copied: '已复制到剪贴板',
    tm_members: '成员', tm_nobody: '还没有人 - 把链接发给你的团队', tm_you: '(你)', tm_here: '在线',
    tm_saved: '昵称已保存', tm_no_handle: '昵称为空', tm_cfg_ok: '房间已更新', tm_cfg_no: '失败',
    tm_live: '开启局域网', tm_shore: '回到本地', tm_need_on: '请先开启房间 (ON)',
    tm_bind_lan: '局域网: {a}', tm_bind_lo: '本地：仅 localhost',
    to_team_live: '[GO-LIVE] 服务器已以网络访问权限重启 - 显示局域网链接，2 秒后重连', to_team_shore: '服务器已以本地模式重启 (127.0.0.1)',
    tm_tun_open: '开启世界通道 (隧道)', tm_tun_close: '关闭隧道',
    tm_tun_wait: '公共隧道正在开启（需要几秒）…',
    tm_tun_on: '会话已向全世界开放：{u} - 邀请链接在任何网络都有效，无需同一网络',
    tm_tun_closed: '隧道已关闭 - 返回局域网/本地', tm_chat_empty: '会话频道已开启 - 房间成员在此互聊',
    tm_chat_h2: '会话聊天', tm_msg_ph: '发送到会话的消息…',
    tm_admin: '管理员', tm_guest: '访客', tm_kick: '踢出', tm_kick_ok: '成员已被移出房间（再次点击可解除）', tm_role_ok: '角色已更新',
    tm_mic_on: '开启麦克风', tm_mic_off: '关闭麦克风',
    tm_mic_denied: '麦克风被拒绝或不可用：需要 HTTPS（世界隧道或 localhost）并授权麦克风',
  },
  ru: {
    snd_on: 'ЗВУК: ВКЛ', snd_off: 'ЗВУК: ВЫКЛ', snd_ok: 'звуки интерфейса включены - библиотека: клик, вкладка, копирование, алерты',
    snd_stop: 'полная тишина включена: звуков C2FF больше нет',
    amb_on: 'АТМОСФЕРА: ВКЛ', amb_off: 'АТМОСФЕРА: ВЫКЛ', amb_ok: 'живая атмосфера - оттенок плавно перетекает между семьями (зелёный, синий, жёлтый...)',
    amb_stop: 'атмосфера заморожена на оригинальном зелёном',
    nt_on: 'NOTIFS: ВКЛ', nt_off: 'NOTIFS: ВЫКЛ', nt_ok: 'уведомления браузера включены - писк на P1 и P2',
    nt_denied: 'уведомления заблокированы браузером: разрешите в настройках сайта',
    term_denied: 'терминал отклонён или недоступен: нужен localhost или открытая комната с ролью админ',
    term_p: 'настоящий bash - история стрелками, Ctrl+C прерывает, Ctrl+D закрывает', term_restart: 'Сброс',
    navtrm: 'ТЕРМИНАЛ', term_h2: 'Терминал - рабочая оболочка прямо в консоли',
    sub_ttl: 'command & control framework',
    fl_off: 'ФЛОТ : ОСТАНОВЛЕН', fl_paused: 'ФЛОТ : НА ПАУЗЕ', fl_active: 'ФЛОТ : АКТИВЕН ({n} цикл.)',
    fl_last: 'последний цикл', fl_none: 'циклов пока нет', fl_info: 'интервал {i} мин, бюджет {b} запр/цикл',
    navf: 'Флот', navfd: 'Находки', navp: 'Программы', navai: 'ИИ', navc: 'Координация',
    st_runs: 'Runs', st_beacons: 'Активные маяки', st_sig: 'Сигналы',
    h2f: 'Флот - все программы, активные агенты первыми',
    h2fd: 'База находок - постоянная триажная разметка', h2eng: 'Движок флота - локальные циклы без токенов',
    h2prog: 'Программы - скоуп, требуемый заголовок, запуск', h2new: 'Новая программа', h2ai: 'ИИ-агент - 100% опциональная интеграция',
    h2c: 'Координация - частный канал',
    fl_start: 'Запустить', fl_pause: 'Пауза', fl_cycle: 'Цикл сейчас',
    f_add: 'Добавить', f_none: 'сигналов пока нет', f_ph: 'ручная находка: эндпоинт + доказательство + защищаемая степень…',
    st_sig_off: 'signal', st_sig_an: 'analyse', st_sig_sub: 'отправлено', st_sig_dup: 'dup', st_sig_ref: 'отклонено', st_sig_cl: 'закрыто',
    r_none: 'запусков не обнаружено', r_live: '{n} В РАБОТЕ', r_done: 'ЗАВЕРШЕНО', r_feed: '▽ поток ({n} соб)', r_close: '△ свернуть',
    p_name_ph: 'Название программы (напр. PayPal)', p_hdr_ph: 'требуемый заголовок (напр. X-Bug-Bounty: xxx)',
    p_scope_ph: 'скоуп : домен1, домен2, …', p_save: 'Сохранить', p_local: 'модуль/модулей, 100% локально',
    ai_p: 'C2FF работает без ИИ: режимы - детерминированные локальные пробы. Этот шлюз только подключает <b>ваш</b> ИИ (self-hosted или API) для точечного анализа находки: кнопка <span style="color:var(--green)">IA »</span> в НАХОДКАХ, ответ в КООРДИНАЦИИ. Никакие данные не покидают вашу машину без этой настройки.',
    ai_off: 'отключен', ai_on: 'включен',
    ai_st_off: 'ИИ ОТКЛЮЧЕН - фреймворк работает 100% локально без него',
    ai_st_ready: 'ИИ ПОДКЛЮЧЕН: {p} · {m}', ai_st_inc: 'ИИ ВКЛЮЧЕН, НО НЕ ПОЛОН: baseURL и model обязательны',
    ai_url_ph: 'базовый URL - напр. http://localhost:11434 или https://api.MyAI.tld/v1',
    ai_model_ph: 'model - напр. llama3.1:8b', ai_key_ph: 'API-ключ (пусто для локальных серверов)',
    ai_save: 'Сохранить', ai_test: 'Проверить связь', ai_testing: 'проверка…', ai_ok: 'OK - ответ: ', ai_fail: 'СБОЙ: ',
    ai_note: 'конфиг хранится локально в data/ai.json - отправляется только на указанный вами эндпоинт',
    ch_ph: 'root@c2ff:~# сообщение агенту анализа…', ch_send: 'Отправить',
    ch_empty: 'Канал открыт. Пишите здесь, монитор будит меня мгновенно.',
    ft: '100% локально - детерминированные пробы, без токенов и внешних зависимостей - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE АКТИВЕН: локальные циклы каждые 30 мин, 0 токенов.',
    to_fl_pa: 'ФЛОТ НА ПАУЗЕ - возобновите когда захотите.',
    to_fl_cy: 'Немедленный цикл запущен (бюджет 60 запр).',
    to_launch: '[GO] режим {m} (CWE {c}) на {p} - локальный цикл запущен',
    to_ai_ok: 'конфиг сохранен', to_ai_no: 'не удалось сохранить', to_ai_no_cfg: 'ИИ не настроен - настройте во вкладке ИИ',
    to_ai_head: 'ИИ-АНАЛИЗ', to_ai_bad: 'ИИ-АНАЛИЗ не удался',
    w_me: 'OPERATOR', w_claude: 'CLAUDE', w_ia: 'IA', w_launch: '⚡ ЗАПУСК',
    navt: 'СЕССИЯ', tm_h2: 'Групповые сессии - совместная охота, с сетью или без',
    tm_p: 'Открой общую комнату: твоя группа видит флот, находки и может сортировать в прямом эфире. Ниже - отдельный чат сессии. Три уровня доступа: ЛОКАЛЬНО (соло), LAN через ОТКРЫТЬ В СЕТЬ, и МИР через ОТКРЫТЬ В МИР - публичный туннель (cloudflared, если установлен) делает ссылку-приглашение действительной из любой сети, не раскрывая твою машину напрямую. Всё работает через ключ комнаты - перегенерируй его, чтобы выкинуть всех сразу.',
    tm_handle: 'Твой ник (макс. 16 символов)', tm_save_h: 'Выбрать', tm_room_ph: 'имя комнаты (напр.: c2ff-core)',
    tm_save: 'Применить', tm_on: 'КОМНАТА ОТКРЫТА: {r} - {n} в сети', tm_off: 'РЕЖИМ КОМАНДЫ ВЫКЛЮЧЕН - локальная соло-сессия',
    tm_room: 'Комната', tm_key: 'Ключ комнаты', tm_regen: 'Перегенерировать ключ', tm_regen_ok: 'новый ключ сгенерирован - старые ссылки мертвы',
    tm_invite: 'Ссылка-приглашение (скопируй команде)', tm_copy: 'Копировать', tm_copied: 'скопировано в буфер обмена',
    tm_members: 'Участники', tm_nobody: 'пока никого - отправь ссылку команде', tm_you: '(ты)', tm_here: 'на месте',
    tm_saved: 'ник сохранён', tm_no_handle: 'пустой ник', tm_cfg_ok: 'комната обновлена', tm_cfg_no: 'сбой',
    tm_live: 'ОТКРЫТЬ В СЕТЬ', tm_shore: 'ВЕРНУТЬ ЛОКАЛЬНО', tm_need_on: 'сначала включи комнату (ON)',
    tm_bind_lan: 'СЕТЬ: {a}', tm_bind_lo: 'ЛОКАЛЬНО: только localhost',
    to_team_live: '[GO-LIVE] сервер перезапущен с сетевым доступом - показана LAN-ссылка, переподключение через 2 с', to_team_shore: 'сервер перезапущен локально (127.0.0.1)',
    tm_tun_open: 'ОТКРЫТЬ В МИР (туннель)', tm_tun_close: 'ЗАКРЫТЬ ТУННЕЛЬ',
    tm_tun_wait: 'публичный туннель открывается (несколько секунд)…',
    tm_tun_on: 'СЕССИЯ ОТКРЫТА В МИР: {u} - ссылка-приглашение работает из любой сети, общая сеть не нужна',
    tm_tun_closed: 'туннель закрыт - возврат к LAN/локально', tm_chat_empty: 'канал сессии открыт - участники комнаты общаются здесь',
    tm_chat_h2: 'Чат сессии', tm_msg_ph: 'сообщение в сессию…',
    tm_admin: 'админ', tm_guest: 'гость', tm_kick: 'КИК', tm_kick_ok: 'участник удалён из комнаты (щёлкни снова, чтобы разблокировать)', tm_role_ok: 'роль обновлена',
    tm_mic_on: 'ВКЛЮЧИТЬ МИКРОФОН', tm_mic_off: 'ВЫКЛЮЧИТЬ МИКРОФОН',
    tm_mic_denied: 'микрофон отклонён или недоступен: требуется HTTPS (мировой туннель или localhost) и разрешение доступа',
  },
  ja: {
    snd_on: 'サウンド: ON', snd_off: 'サウンド: OFF', snd_ok: 'UIサウンド有効 - ライブラリ: クリック、タブ、コピー、アラート',
    snd_stop: '完全ミュート中: C2FFのサウンドは鳴りません',
    amb_on: '雰囲気: ON', amb_off: '雰囲気: OFF', amb_ok: '生きた雰囲気 - 色調がゆっくりと色調間を流れる (緑, 青, 黄...)',
    amb_stop: '雰囲気を元の緑に固定',
    nt_on: '通知: ON', nt_off: '通知: OFF', nt_ok: 'ブラウザ通知を有効化 - P1 と P2 でビープ',
    nt_denied: '通知がブラウザでブロック：サイト設定で許可して',
    term_denied: 'ターミナル拒否か利用不可：localhost か管理者としてルームを開く必要あり',
    term_p: '本物の bash - 履歴は矢印キー、Ctrl+C で中断、Ctrl+D で終了', term_restart: 'リセット',
    navtrm: 'ターミナル', term_h2: 'ターミナル - コンソール内の作業シェル',
    sub_ttl: 'command & control framework',
    fl_off: '艦隊 : 停止', fl_paused: '艦隊 : 一時停止', fl_active: '艦隊 : 稼働中（{n} サイクル）',
    fl_last: '前回のサイクル', fl_none: 'サイクルなし', fl_info: '間隔 {i} 分、予算 {b} リクエスト/サイクル',
    navf: '艦隊', navfd: '発見', navp: 'プログラム', navai: 'AI', navc: '調整',
    st_runs: 'Runs', st_beacons: '稼働ビーコン', st_sig: 'シグナル',
    h2f: '艦隊 - 全プログラム、稼働中エージェント優先',
    h2fd: '発見ベース - 永続トリアージ', h2eng: '艦隊エンジン - トークン不要のローカルサイクル',
    h2prog: 'プログラム - スコープ、必須ヘッダー、起動', h2new: '新規プログラム', h2ai: 'AI エージェント - 100%オプション統合',
    h2c: '調整 - プライベートチャネル',
    fl_start: '開始', fl_pause: '一時停止', fl_cycle: '今すぐサイクル',
    f_add: '追加', f_none: 'シグナルなし', f_ph: '手動発見：エンドポイント + 証拠 + 立証可能な深刻度…',
    st_sig_off: 'signal', st_sig_an: 'analyse', st_sig_sub: '提出済', st_sig_dup: 'dup', st_sig_ref: '却下', st_sig_cl: '完了',
    r_none: 'ラン検出なし', r_live: '{n} 稼働中', r_done: '完了', r_feed: '▽ フィード ({n} 件)', r_close: '△ 閉じる',
    p_name_ph: 'プログラム名（例: PayPal）', p_hdr_ph: '必須ヘッダー（例: X-Bug-Bounty: xxx）',
    p_scope_ph: 'スコープ：ドメイン1、ドメイン2、…', p_save: '保存', p_local: 'モジュール、100% ローカル',
    ai_p: 'C2FF は AI なしで動作します：モードは決定論的なローカル探査。このゲートウェイは<b>あなたの</b> AI（セルフホストまたは API）を接続し、単一の発見を都度分析するだけです：発見ページの <span style="color:var(--green)">IA »</span> ボタン、回答は調整ページへ。この設定がなければ何もあなたのマシンから出ません。',
    ai_off: '無効', ai_on: '有効',
    ai_st_off: 'AI 無効 - フレームワークは AI なしで 100% ローカル稼働',
    ai_st_ready: 'AI 接続済み: {p} · {m}', ai_st_inc: 'AI 有効だが不完全：baseURL と model が必要',
    ai_url_ph: 'ベース URL - 例: http://localhost:11434 または https://api.MyAI.tld/v1',
    ai_model_ph: 'model - 例: llama3.1:8b', ai_key_ph: 'API キー（ローカルなら空欄）',
    ai_save: '保存', ai_test: '接続テスト', ai_testing: 'テスト中…', ai_ok: 'OK - 返信：', ai_fail: '失敗：',
    ai_note: '設定は data/ai.json にローカル保存 - 指定したエンドポイント以外には送信されません',
    ch_ph: 'root@c2ff:~# 解析エージェントへのメッセージ…', ch_send: '送信',
    ch_empty: 'チャネル開放。ここに入力すれば、モニターが即座に俺を起こす。',
    ft: '100% ローカル - 決定論的プローブ、トークンも外部依存もなし - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE 稼働：30分ごとにローカルサイクル、トークン 0。',
    to_fl_pa: '艦隊一時停止 - いつでも再開。',
    to_fl_cy: '即時サイクル起動（予算 60 リクエスト）。',
    to_launch: '[GO] モード {m}（CWE {c}）を {p} に実行 - ローカルサイクル起動',
    to_ai_ok: '設定を保存しました', to_ai_no: '保存に失敗', to_ai_no_cfg: 'AI 未設定 - AI タブで設定してください',
    to_ai_head: 'AI 分析', to_ai_bad: 'AI 分析に失敗',
    w_me: 'OPERATOR', w_claude: 'CLAUDE', w_ia: 'AI', w_launch: '⚡ 発射',
    navt: 'セッション', tm_h2: 'グループセッション - ネットワークに関係なく一緒に狩る',
    tm_p: '共有ルームを開こう：チームはフリートと発見を見て、リアルタイムでトリアージできます。下部に専用セッションチャット。アクセスは3段階：ローカル（ソロ）、LAN（ネットワークへ開く）、ワールド（世界へ開く）- 公開トンネル（cloudflared があれば）で招待リンクがどのネットワークからも有効になり、マシンを直接露出しません。すべてルームキーで保護 - 再生成すれば全員を一括で締め出せます。',
    tm_handle: 'ハンドル名（最大16文字）', tm_save_h: '設定', tm_room_ph: 'ルーム名（例：c2ff-core）',
    tm_save: '適用', tm_on: 'ルーム開放中：{r} - {n} 人オンライン', tm_off: 'チームモード無効 - ローカルのソロセッション',
    tm_room: 'ルーム', tm_key: 'ルームキー', tm_regen: 'キー再生成', tm_regen_ok: '新しいキーを生成 - 古いリンクは無効',
    tm_invite: '招待リンク（チームにコピー）', tm_copy: 'コピー', tm_copied: 'クリップボードにコピーしました',
    tm_members: 'メンバー', tm_nobody: 'まだ誰もいない - チームにリンクを送って', tm_you: '(あなた)', tm_here: '参加中',
    tm_saved: 'ハンドル名を保存しました', tm_no_handle: 'ハンドル名が空です', tm_cfg_ok: 'ルームを更新しました', tm_cfg_no: '失敗',
    tm_live: 'ネットワークへ開く', tm_shore: 'ローカルへ戻す', tm_need_on: '先にルームを ON にして',
    tm_bind_lan: 'ネットワーク: {a}', tm_bind_lo: 'ローカル：localhost のみ',
    to_team_live: '[GO-LIVE] ネットワークアクセス付きでサーバー再起動 - LANリンク表示、2 秒で再接続', to_team_shore: 'ローカル (127.0.0.1) でサーバー再起動',
    tm_tun_open: '世界へ開く（トンネル）', tm_tun_close: 'トンネルを閉じる',
    tm_tun_wait: '公開トンネルを準備中（数秒）…',
    tm_tun_on: 'セッションを世界へ公開中：{u} - 招待リンクはどのネットワークからでも有効、同じネットワークは不要',
    tm_tun_closed: 'トンネルを閉じました - LAN/ローカルに戻る', tm_chat_empty: 'セッションチャンネル開放中 - ルームメンバー同士がここで話せます',
    tm_chat_h2: 'セッションチャット', tm_msg_ph: 'セッションへのメッセージ…',
    tm_admin: '管理者', tm_guest: 'ゲスト', tm_kick: 'キック', tm_kick_ok: 'メンバーを退室させました（もう一度クリックで解除）', tm_role_ok: '役割を更新しました',
    tm_mic_on: 'マイクを有効化', tm_mic_off: 'マイクをミュート',
    tm_mic_denied: 'マイクが拒否か利用不可：HTTPS（ワールドトンネルか localhost）と権限の許可が必要',
  },
  ko: {
    snd_on: '사운드: ON', snd_off: '사운드: OFF', snd_ok: 'UI 사운드 켜짐 - 라이브러리: 클릭, 탭, 복사, 알림음',
    snd_stop: '전체 음소거 켜짐: C2FF 사운드 없음',
    amb_on: '분위기: ON', amb_off: '분위기: OFF', amb_ok: '살아있는 분위기 - 색조가 색상군 사이를 부드럽게 흐름 (녹색, 파랑, 노랑...)',
    amb_stop: '분위기가 원래 녹색에 고정',
    nt_on: '알림: ON', nt_off: '알림: OFF', nt_ok: '브라우저 알림 활성화 - P1과 P2에 삑',
    nt_denied: '알림이 브라우저에서 차단됨: 사이트 설정에서 허용',
    term_denied: '터미널 거부 또는 불가: localhost 또는 관리자로 연 방 필요',
    term_p: '진짜 bash - 화살표로 히스토리, Ctrl+C 중단, Ctrl+D 종료', term_restart: '초기화',
    navtrm: '터미널', term_h2: '터미널 - 콘솔 안의 작업 셸',
    sub_ttl: 'command & control framework',
    fl_off: '함대 : 정지', fl_paused: '함대 : 일시정지', fl_active: '함대 : 활성 ({n} 주기)',
    fl_last: '마지막 주기', fl_none: '아직 주기 없음', fl_info: '간격 {i}분, 예산 {b} 요청/주기',
    navf: '함대', navfd: '발견', navp: '프로그램', navai: 'AI', navc: '조정',
    st_runs: 'Runs', st_beacons: '활성 비컨', st_sig: '신호',
    h2f: '함대 - 전체 프로그램, 실행 중 에이전트 우선',
    h2fd: '발견 기반 - 지속 트리아지 태깅', h2eng: '함대 엔진 - 토큰 없는 로컬 주기',
    h2prog: '프로그램 - 스코프, 필수 헤더, 실행', h2new: '새 프로그램', h2ai: 'AI 에이전트 - 100% 선택적 통합',
    h2c: '조정 - 사설 채널',
    fl_start: '시작', fl_pause: '일시정지', fl_cycle: '지금 주기',
    f_add: '추가', f_none: '아직 신호 없음', f_ph: '수동 발견: 엔드포인트 + 증거 + 방어 가능한 심각도…',
    st_sig_off: 'signal', st_sig_an: 'analyse', st_sig_sub: '제출됨', st_sig_dup: 'dup', st_sig_ref: '거부됨', st_sig_cl: '닫힘',
    r_none: '감지된 런 없음', r_live: '{n} 실행 중', r_done: '완료', r_feed: '▽ 피드 ({n} 건)', r_close: '△ 접기',
    p_name_ph: '프로그램 이름 (예: PayPal)', p_hdr_ph: '필수 헤더 (예: X-Bug-Bounty: xxx)',
    p_scope_ph: '스코프 : 도메인1, 도메인2, …', p_save: '저장', p_local: '모듈, 100% 로컬',
    ai_p: 'C2FF는 AI 없이 작동합니다: 모드는 결정론적 로컬 프로브. 이 게이트웨이는 단일 발견을 즉석 분석하기 위해 <b>당신의</b> AI(자체 호스팅 또는 API)만 연결합니다: 발견 탭의 <span style="color:var(--green)">IA »</span> 버튼, 답변은 조정 탭에. 이 설정이 없으면 어떤 데이터도 당신의 머신을 떠나지 않습니다.',
    ai_off: '비활성', ai_on: '활성',
    ai_st_off: 'AI 비활성 - 프레임워크는 AI 없이 100% 로컬 작동',
    ai_st_ready: 'AI 연결됨: {p} · {m}', ai_st_inc: 'AI 활성화했지만 불완전: baseURL과 model 필요',
    ai_url_ph: '베이스 URL - 예: http://localhost:11434 또는 https://api.MyAI.tld/v1',
    ai_model_ph: 'model - 예: llama3.1:8b', ai_key_ph: 'API 키 (로컬 서버면 비움)',
    ai_save: '저장', ai_test: '연결 테스트', ai_testing: '테스트 중…', ai_ok: 'OK - 응답: ', ai_fail: '실패: ',
    ai_note: '설정은 data/ai.json에 로컬 저장 - 지정한 엔드포인트 외에는 절대 전송 안 됨',
    ch_ph: 'root@c2ff:~# 분석 에이전트에게 메시지…', ch_send: '전송',
    ch_empty: '채널이 열렸다. 여기 쓰면 모니터가 즉시 깨운다.',
    ft: '100% 로컬 - 결정론적 프로브, 토큰·외부 의존성 없음 - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE 활성: 30분마다 로컬 주기, 토큰 0.',
    to_fl_pa: '함대 일시정지 - 원할 때 재개.',
    to_fl_cy: '즉시 주기 실행 (예산 60 요청).',
    to_launch: '[GO] 모드 {m} (CWE {c}) → {p} - 로컬 주기 실행',
    to_ai_ok: '설정 저장됨', to_ai_no: '저장 실패', to_ai_no_cfg: 'AI 미설정 - AI 탭에서 설정하세요',
    to_ai_head: 'AI 분석', to_ai_bad: 'AI 분석 실패',
    w_me: 'OPERATOR', w_claude: 'CLAUDE', w_ia: 'AI', w_launch: '⚡ 발사',
    navt: '세션', tm_h2: '그룹 세션 - 네트워크가 달라도 함께 사냥',
    tm_p: '공유 방을 열어라: 팀이 플릿과 발견 항목을 보고 실시간으로 분류할 수 있다. 아래에 전용 세션 채팅. 접근은 3단계: 로컬(솔로), LAN(네트워크로 열기), 월드(세계로 열기) - 공개 터널(cloudflared 설치 시)이 초대 링크를 어떤 네트워크에서도 유효하게 하며 기계를 직접 노출하지 않는다. 모든 것은 방 키로 통제 - 재생성하면 모두를 한 번에 내보낸다.',
    tm_handle: '닉네임 (최대 16자)', tm_save_h: '선택', tm_room_ph: '방 이름 (예: c2ff-core)',
    tm_save: '적용', tm_on: '방 열림: {r} - {n} 접속 중', tm_off: '팀 모드 꺼짐 - 로컬 솔로 세션',
    tm_room: '방', tm_key: '방 키', tm_regen: '키 재생성', tm_regen_ok: '새 키 생성됨 - 이전 링크는 죽음',
    tm_invite: '초대 링크 (팀에 복사)', tm_copy: '복사', tm_copied: '클립보드에 복사됨',
    tm_members: '멤버', tm_nobody: '아직 아무도 없다 - 팀에 링크를 보내라', tm_you: '(너)', tm_here: '접속 중',
    tm_saved: '닉네임 저장됨', tm_no_handle: '닉네임이 비었다', tm_cfg_ok: '방 갱신됨', tm_cfg_no: '실패',
    tm_live: '네트워크로 열기', tm_shore: '로컬로 복귀', tm_need_on: '먼저 방을 켜라 (ON)',
    tm_bind_lan: '네트워크: {a}', tm_bind_lo: '로컬: localhost 만',
    to_team_live: '[GO-LIVE] 서버가 네트워크 접근으로 재시작됨 - LAN 링크 표시, 2초 후 재접속', to_team_shore: '서버가 로컬 (127.0.0.1) 로 재시작됨',
    tm_tun_open: '세계로 열기 (터널)', tm_tun_close: '터널 닫기',
    tm_tun_wait: '공개 터널 여는 중 (몇 초)…',
    tm_tun_on: '세션이 세계로 열림: {u} - 초대 링크는 어떤 네트워크에서든 유효, 같은 네트워크 불필요',
    tm_tun_closed: '터널 닫힘 - LAN/로컬로 복귀', tm_chat_empty: '세션 채널 열림 - 방 멤버들이 여기서 대화한다',
    tm_chat_h2: '세션 채팅', tm_msg_ph: '세션으로 보낼 메시지…',
    tm_admin: '관리자', tm_guest: '게스트', tm_kick: '강퇴', tm_kick_ok: '멤버가 방에서 내보내짐 (다시 클릭하면 해제)', tm_role_ok: '역할 갱신됨',
    tm_mic_on: '마이크 켜기', tm_mic_off: '마이크 끄기',
    tm_mic_denied: '마이크 거부 또는 불가: HTTPS(월드 터널 또는 localhost)와 권한 허용 필요',
  },
  hi: {
    snd_on: 'साउंड: ON', snd_off: 'साउंड: OFF', snd_ok: 'इंटरफ़ेस साउंड चालू - लाइब्रेरी: क्लिक, टैब, कॉपी, अलर्ट',
    snd_stop: 'पूर्ण म्यूट चालू: अब कोई C2FF साउंड नहीं',
    amb_on: 'माहौल: ON', amb_off: 'माहौल: OFF', amb_ok: 'जीवंत माहौल - रंग शांति से वर्गों के बीच बहता है (हरा, नीला, पीला...)',
    amb_stop: 'माहौल मूल हरे पर स्थिर',
    nt_on: 'सूचनाएं: ON', nt_off: 'सूचनाएं: OFF', nt_ok: 'ब्राउज़र सूचनाएं चालू - P1 और P2 पर बीप',
    nt_denied: 'सूचनाएं ब्राउज़र में ब्लॉक हैं: साइट सेटिंग्स में अनुमति दें',
    term_denied: 'टर्मिनल अस्वीकृत या अनुपलब्ध: localhost या एडमिन के रूप में खुला कमरा चाहिए',
    term_p: 'असली bash - तीर से हिस्ट्री, Ctrl+C रोकें, Ctrl+D बंद करें', term_restart: 'रीसेट',
    navtrm: 'टर्मिनल', term_h2: 'टर्मिनल - कंसोल में ही काम का शेल',
    sub_ttl: 'command & control framework',
    fl_off: 'बेड़ा : बंद', fl_paused: 'बेड़ा : विराम', fl_active: 'बेड़ा : सक्रिय ({n} चक्र)',
    fl_last: 'अंतिम चक्र', fl_none: 'अभी कोई चक्र नहीं', fl_info: 'अंतराल {i} मिनट, बजट {b} अनुरोध/चक्र',
    navf: 'बेड़ा', navfd: 'खोजें', navp: 'प्रोग्राम', navai: 'AI', navc: 'समन्वय',
    st_runs: 'Runs', st_beacons: 'सक्रिय बीकन', st_sig: 'संकेत',
    h2f: 'बेड़ा - सभी प्रोग्राम, चालू एजेंट पहले',
    h2fd: 'फाइंडिंग आधार - स्थायी ट्रायाज', h2eng: 'बेड़ा इंजन - बिना टोकन लोकल चक्र',
    h2prog: 'प्रोग्राम - स्कोप, आवश्यक हेडर, लॉन्च', h2new: 'नया प्रोग्राम', h2ai: 'AI एजेंट - 100% वैकल्पिक',
    h2c: 'समन्वय - निजी चैनल',
    fl_start: 'शुरू', fl_pause: 'विराम', fl_cycle: 'अभी चक्र',
    f_add: 'जोड़ें', f_none: 'अभी कोई संकेत नहीं', f_ph: 'मैन्युअल फाइंडिंग: एंडपॉइंट + प्रमाण + बचाव योग्य गंभीरता…',
    st_sig_off: 'signal', st_sig_an: 'analyse', st_sig_sub: 'सबमिट', st_sig_dup: 'dup', st_sig_ref: 'अस्वीकृत', st_sig_cl: 'बंद',
    r_none: 'कोई रन नहीं मिला', r_live: '{n} चालू', r_done: 'पूर्ण', r_feed: '▽ फ़ीड ({n} घ)', r_close: '△ निचोड़ें',
    p_name_ph: 'प्रोग्राम का नाम (जैसे: PayPal)', p_hdr_ph: 'आवश्यक हेडर (जैसे: X-Bug-Bounty: xxx)',
    p_scope_ph: 'स्कोप : डोमेन1, डोमेन2, …', p_save: 'सहेजें', p_local: 'मॉड्यूल, 100% लोकल',
    ai_p: 'C2FF बिना AI चलता है: मोड नियतात्मक लोकल प्रोब हैं। यह गेटवे केवल <b>आपके</b> AI (सेल्फ-होस्टेड या API) को जोड़ता है ताकि किसी एक फाइंडिंग का तुरंत विश्लेषण हो: फाइंडिंग टैब में <span style="color:var(--green)">IA »</span> बटन, जवाब समन्वय टैब में। इन सेटिंग्स के बिना कोई डेटा आपकी मशीन से बाहर नहीं जाता।',
    ai_off: 'निष्क्रिय', ai_on: 'सक्रिय',
    ai_st_off: 'AI निष्क्रिय - फ्रेमवर्क बिना AI 100% लोकल चलता है',
    ai_st_ready: 'AI कनेक्टेड: {p} · {m}', ai_st_inc: 'AI सक्रिय लेकिन अधूरा: baseURL और model ज़रूरी',
    ai_url_ph: 'बेस URL - जैसे: http://localhost:11434 या https://api.MyAI.tld/v1',
    ai_model_ph: 'model - जैसे: llama3.1:8b', ai_key_ph: 'API कुंजी (लोकल सर्वर के लिए खाली)',
    ai_save: 'सहेजें', ai_test: 'कनेक्शन जाँचें', ai_testing: 'जाँच हो रही है…', ai_ok: 'ठीक - उत्तर: ', ai_fail: 'विफल: ',
    ai_note: 'कॉन्फ़िग data/ai.json में स्थानीय रूप से संग्रहीत - केवल आपके दिए एंडपॉइंट पर भेजी जाती है',
    ch_ph: 'root@c2ff:~# विश्लेषण एजेंट को संदेश…', ch_send: 'भेजें',
    ch_empty: 'चैनल खुला है। यहाँ लिखो, मॉनिटर मुझे तुरंत जगा देता है।',
    ft: '100% लोकल - नियतात्मक प्रोब, बिना टोकन बिना बाहरी निर्भरता - unrestricted · undetected · unstoppable',
    to_fl_on: 'FLEET-MODE सक्रिय: हर 30 मिनट लोकल चक्र, 0 टोकन।',
    to_fl_pa: 'बेड़ा विराम पर - जब चाहो फिर से शुरू।',
    to_fl_cy: 'तुरंत चक्र लॉन्च (बजट 60 अनुरोध)।',
    to_launch: '[GO] मोड {m} (CWE {c}) → {p} - लोकल चक्र लॉन्च',
    to_ai_ok: 'कॉन्फ़िग सहेजी गई', to_ai_no: 'सहेजना विफल', to_ai_no_cfg: 'AI कॉन्फ़िगर नहीं - AI टैब में सेट करें',
    to_ai_head: 'AI विश्लेषण', to_ai_bad: 'AI विश्लेषण विफल',
    w_me: 'OPERATOR', w_claude: 'CLAUDE', w_ia: 'AI', w_launch: '⚡ लॉन्च',
    navt: 'सेशन', tm_h2: 'समूह सेशन - साथ शिकार, नेटवर्क हो या नहीं',
    tm_p: 'एक साझा कमरा खोलो: तुम्हारी टीम फ्लीट और निष्कर्ष देखेगी और लाइव ट्राइएज कर सकेगी। नीचे समर्पित सेशन चैट। तीन स्तर: लोकल (सोलो), LAN (नेटवर्क के लिए खोलें), और वर्ल्ड (दुनिया के लिए खोलें) - सार्वजनिक टनल (cloudflared यदि स्थापित है) निमंत्रण लिंक को किसी भी नेटवर्क से मान्य बनाता है, मशीन को सीधे उजागर किए बिना। सब कुछ रूम की से गुजरता है - इसे दोबारा बनाओ तो सब एक साथ बाहर।',
    tm_handle: 'तुम्हारा नाम (अधिकतम 16 अक्षर)', tm_save_h: 'चुनें', tm_room_ph: 'कमरे का नाम (जैसे: c2ff-core)',
    tm_save: 'लागू करें', tm_on: 'कमरा खुला: {r} - {n} ऑनलाइन', tm_off: 'टीम मोड बंद - लोकल सोलो सेशन',
    tm_room: 'कमरा', tm_key: 'रूम की', tm_regen: 'की दोबारा बनाओ', tm_regen_ok: 'नई की बनी - पुराने लिंक मर गए',
    tm_invite: 'निमंत्रण लिंक (टीम को कॉपी करो)', tm_copy: 'कॉपी', tm_copied: 'क्लिपबोर्ड में कॉपी हो गया',
    tm_members: 'सदस्य', tm_nobody: 'अभी कोई नहीं - टीम को लिंक भेजो', tm_you: '(तुम)', tm_here: 'मौजूद',
    tm_saved: 'नाम सेव हुआ', tm_no_handle: 'नाम खाली है', tm_cfg_ok: 'कमरा अपडेट हुआ', tm_cfg_no: 'विफल',
    tm_live: 'नेटवर्क के लिए खोलें', tm_shore: 'लोकल पर वापस', tm_need_on: 'पहले कमरा चालू करो (ON)',
    tm_bind_lan: 'नेटवर्क: {a}', tm_bind_lo: 'लोकल: केवल localhost',
    to_team_live: '[GO-LIVE] सर्वर नेटवर्क पहुंच के साथ फिर शुरू - LAN लिंक दिखा, 2 सेकंड में पुनःकनेक्ट', to_team_shore: 'सर्वर लोकल (127.0.0.1) पर फिर शुरू',
    tm_tun_open: 'दुनिया के लिए खोलें (टनल)', tm_tun_close: 'टनल बंद करें',
    tm_tun_wait: 'सार्वजनिक टनल खुल रहा है (कुछ सेकंड)…',
    tm_tun_on: 'सेशन दुनिया के लिए खुला: {u} - निमंत्रण लिंक किसी भी नेटवर्क से काम करता है, वही नेटवर्क जरूरी नहीं',
    tm_tun_closed: 'टनल बंद - LAN/लोकल पर वापस', tm_chat_empty: 'सेशन चैनल खुला - कमरे के सदस्य यहाँ बातें करते हैं',
    tm_chat_h2: 'सेशन चैट', tm_msg_ph: 'सेशन को संदेश…',
    tm_admin: 'एडमिन', tm_guest: 'अतिथि', tm_kick: 'निकालो', tm_kick_ok: 'सदस्य कमरे से निकाला गया (दोबारा क्लिक से अनब्लॉक)', tm_role_ok: 'भूमिका अपडेट हुई',
    tm_mic_on: 'माइक चालू करो', tm_mic_off: 'माइक बंद करो',
    tm_mic_denied: 'माइक अस्वीकृत या अनुपलब्ध: HTTPS जरूरी (वर्ल्ड टनल या localhost) और अनुमति देनी होगी',
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

const state = { tab: 'live', chatSeen: 0, fndSeen: 0, firstLoad: true, unread: 0, tick: 0, data: { runs: [], findings: [], programs: [], chat: [], modes: [], team: {} } };
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
function jget(url) { return fetch(url, { headers: KHEAD() }); }
function jpost(url, body) { return fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...KHEAD() }, body: JSON.stringify(body) }); }
const expanded = new Set();
let forceDraw = true; // premier paint integral, puis re-rendu differentiel

const TABS = { live: 'FLOTTE', findings: 'FINDINGS', programs: 'PROGRAMMES', ai: 'IA', team: 'TEAM', chat: 'COORDINATION' };
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
const drawn = { runs: '', fnd: '', prog: '', chat: '', ai: '', team: '' };
function focusInside(sel) {
  const r = $(sel);
  const a = document.activeElement;
  return r && a && a.tagName !== 'BODY' && r.contains(a);
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
  }
  $('fndList').innerHTML = state.data.findings.slice(0, 120).map(f => {
    const sel = FND_STATUS.map(s => '<option value="' + s + '"' + (f.status === s ? ' selected' : '') + '>' + T('st_sig_' + s) + '</option>').join('');
    return '<div class="fnd S-' + esc(f.sev) + '"><div class="fh">' +
      '<span class="sev">' + esc(f.sev) + '</span>' +
      '<span class="pill p-prog">' + esc((f.program || '?').toUpperCase()) + '</span>' +
      '<small style="color:var(--dim)">' + esc(f.id) + ' · ' + esc(f.run) + ' · ' + esc(f.agent) + '</small>' +
      '<small style="color:var(--dim);margin-left:auto">' + new Date(f.t).toLocaleTimeString('fr-FR') + '</small>' +
      '<select data-k="' + esc(f.key) + '" class="fstat">' + sel + '</select>' +
      '<button class="ghost ia-run" data-t="' + esc(f.text.slice(0, 400)) + '">IA »</button></div>' +
      '<div class="txt">' + hl(f.text) + '</div></div>';
  }).join('') || '<div class="fnd">' + T('f_none') + '</div>';
  document.querySelectorAll('.fnd select').forEach(s => s.addEventListener('change', () => {
    jpost('/api/findings', { op: 'patch', key: s.dataset.k, status: s.value, name: HANDLE });
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
  $('progList').innerHTML = state.data.programs.map(p =>
    '<div class="card"><h3>' + esc(p.name) + (p.veille ? ' <small style="color:var(--amber)">(veille)</small>' : '') + '</h3>' +
    '<div class="subtle" style="color:var(--dim);font-size:10.5px">' + esc(p.platform || '') + '</div>' +
    '<div class="scope">' + esc((p.scope || []).join(' · ')) + '</div>' +
    (p.header ? '<div class="hdr">⧉ ' + esc(p.header) + '</div>' : '') +
    (p.regle ? '<div class="hdr">⌦ regle : ' + esc(p.regle) + '</div>' : '') +
    '<div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;align-items:center">' +
    '<select class="mode" data-p="' + esc(p.id) + '">' + modes.map(m => '<option value="' + esc(m.key) + '">' + esc(m.label) + ' · CWE ' + esc(m.cwes) + '</option>').join('') + '</select>' +
    '<button class="go launch" data-p="' + esc(p.id) + '">GO ›</button></div>' +
    '<div class="subtle" style="color:var(--dim);font-size:10.5px" id="mdesc-' + esc(p.id) + '"></div></div>'
  ).join('');
  document.querySelectorAll('.prog .mode').forEach(sel => {
    const upd = () => { const m = modes.find(x => x.key === sel.value); const d = $('mdesc-' + sel.dataset.p); if (d && m) d.textContent = '▸ CWE ' + m.cwes + ' - ' + m.desc + ' (' + m.n + ' module(s), 100% local)'; };
    sel.addEventListener('change', upd); upd();
  });
  document.querySelectorAll('.launch').forEach(b => b.addEventListener('click', () => {
    const p = b.dataset.p;
    const sel = document.querySelector('.mode[data-p="' + p + '"]');
    const m = modes.find(x => x.key === sel.value);
    jpost('/api/fleet', { op: 'run', program: p, mode: sel.value });
    toast(T('w_launch'), TF('to_launch', { m: m ? m.label : sel.value, c: m ? m.cwes : '?', p: p.toUpperCase() }), 'HIT');
    setTimeout(refresh, 500);
  }));
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
    (m.kind === 'queue' ? T('w_launch') + ' ' : '') + esc(m.name || (m.from === 'user' ? T('w_me') : m.from === 'ia' ? T('w_ia') : T('w_claude'))) + ' · ' + new Date(m.t).toLocaleTimeString('fr-FR') + '</div>' +
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

// ---------- mode team : sessions de groupe a distance ----------
function drawTeam() {
  const tm = state.data.team || {};
  const remote = tm.bind === 'lan';
  const tun = typeof tm.tunnel === 'string' ? tm.tunnel : '';
  const amAdmin = (tm.you || 'guest') === 'admin';
  rtcTick();
  const sig = JSON.stringify([tm.enabled, tm.room, tm.members, HANDLE, tm.bind, tm.lan, tun, tm.chat, tm.you, microOn]);
  if (sig === drawn.team && !forceDraw) return;
  drawn.team = sig;
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
  $('tmMembers').innerHTML = (tm.members || []).map(m =>
    '<div class="tm-m"><span class="dot ' + (m.active ? 'run' : '') + '" style="' + (m.active ? 'color:var(--green)' : 'color:var(--faint)') + '"></span>' +
    '<b style="color:' + (m.h === HANDLE ? 'var(--green)' : 'var(--text)') + '">' + esc(m.h) + (m.h === HANDLE ? ' <small style="color:var(--faint)">' + T('tm_you') + '</small>' : '') + '</b>' +
    '<span class="pill ' + (m.role === 'admin' ? 'p-prog' : 'p-done') + '">' + (m.role === 'admin' ? T('tm_admin') : T('tm_guest')) + '</span>' +
    '<span class="pill ' + (m.active ? 'p-live' : 'p-done') + '">' + (m.active ? T('tm_here') : Math.round(m.ms / 60000) + ' min') + '</span>' +
    (amAdmin && m.h !== HANDLE ?
      '<select class="tmrole" data-h="' + esc(m.h) + '"><option value="guest"' + (m.role === 'admin' ? '' : ' selected') + '>' + T('tm_guest') + '</option><option value="admin"' + (m.role === 'admin' ? ' selected' : '') + '>' + T('tm_admin') + '</option></select>' +
      '<button class="ghost tmkick" data-h="' + esc(m.h) + '">' + T('tm_kick') + '</button>' : '') +
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
      '<div class="msg ' + (m.name === HANDLE ? 'user' : 'claude') + '"><div class="who">' +
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
  jpost('/api/team', { op: 'role.set', h: sel.dataset.h, r: sel.value }).then(r => r.json()).then(j => {
    toast('SESSION', j.ok ? T('tm_role_ok') : (j.error || T('tm_cfg_no')), j.ok ? 'HIT' : 'P2');
    setTimeout(refresh, 300);
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
    toast('TEAM', j.ok ? T('tm_cfg_ok') : T('tm_cfg_no'), j.ok ? 'HIT' : 'P2');
    setTimeout(refresh, 300);
  });
});
$('tmRegen').addEventListener('click', () => {
  jpost('/api/team', { op: 'regen' }).then(r => r.json()).then(j => {
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
// traverse la roue chromatique (vert -> bleu -> jaune -> violet -> cyan -> vert),
// toujours par le plus court chemin, easing smoothstep : arrivee posee, jamais de saut.
const AMB = { live: true };
const AMB_STOPS = [112, 232, 48, 300, 170]; // vert, bleu, jaune, violet, cyan
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
  } else h = 112;
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
  const m = { '1': 'live', '2': 'findings', '3': 'programs', '4': 'ai', '5': 'team', '6': 'term', '7': 'chat' }[e.key];
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
    drawRuns(d.runs); drawFindings(); drawPrograms(); drawChat(); drawFleet(); drawAI(); drawTeam();
    // presence team : battement toutes les ~5 s (3 polls)
    if (state.tick % 3 === 0 && HANDLE) {
      jpost('/api/team', { op: 'beat', handle: HANDLE }).then(r => r.json()).then(j => {
        if (j.team) state.data.team = j.team;
        else if (j.error) { toast('SESSION', j.error, 'P2'); HANDLE = ''; try { localStorage.removeItem('c2ff-handle'); } catch (e) {} forceDraw = true; }
      }).catch(() => {});
    }
    forceDraw = false;
    state.firstLoad = false;
  } catch (e) { /* serveur occupe */ }
  inflight = false;
}
setInterval(refresh, 1500);
refresh();