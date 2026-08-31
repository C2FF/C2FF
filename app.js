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
    fl_off: 'FLEET : ARRETE', fl_paused: 'FLEET : EN PAUSE', fl_active: 'FLEET : ACTIF ({n} cycles)',
    fl_last: 'dernier cycle', fl_none: 'aucun cycle encore', fl_info: 'intervalle {i} min, budget {b} req/cycle',
    sub_ttl: 'command & control framework',
    navt: 'Team', tm_h2: 'Mode team - sessions de groupe a distance',
    tm_p: "Ouvre la salle et partage le lien d'invitation : ton equipe voit la flotte, les findings, la coordination et peut trier en direct, depuis n'importe ou. Le serveur reste ta machine : pour un acces a distance relance C2FF avec C2FF_BIND=0.0.0.0 (sinon seul localhost passe). Tout passe par la cle de salle - regenere-la pour virer tout le monde d'un coup.",
    tm_handle: 'Ton pseudo (16 caracteres max)', tm_save_h: 'Choisir', tm_room_ph: 'nom de la salle (ex : c2ff-core)',
    tm_save: 'Appliquer', tm_on: 'SALLE OUVERTE : {r} - {n} en ligne', tm_off: 'MODE TEAM DESACTIVE - session locale solo',
    tm_room: 'Salle', tm_key: 'Cle de salle', tm_regen: 'Regenerer la cle', tm_regen_ok: 'nouvelle cle generee - les anciens liens sont morts',
    tm_invite: 'Lien d invitation (a copier vers ton equipe)', tm_copy: 'Copier', tm_copied: 'copie dans le presse-papiers',
    tm_members: 'Membres', tm_nobody: 'personne encore - envoie le lien a ton equipe', tm_you: '(toi)', tm_here: 'present',
    tm_saved: 'pseudo enregistre', tm_no_handle: 'pseudo vide', tm_cfg_ok: 'salle mise a jour', tm_cfg_no: 'echec',
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
    navt: 'Team', tm_h2: 'Team mode - remote group sessions',
    tm_p: "Open the room and share the invite link: your team sees the fleet, findings, coordination and can triage live, from anywhere. The server stays on your machine: for remote access relaunch C2FF with C2FF_BIND=0.0.0.0 (otherwise only localhost gets through). Everything is gated by the room key - regenerate it to kick everyone at once.",
    tm_handle: 'Your handle (16 chars max)', tm_save_h: 'Set', tm_room_ph: 'room name (ex: c2ff-core)',
    tm_save: 'Apply', tm_on: 'ROOM OPEN: {r} - {n} online', tm_off: 'TEAM MODE OFF - local solo session',
    tm_room: 'Room', tm_key: 'Room key', tm_regen: 'Regenerate key', tm_regen_ok: 'new key generated - old links are dead',
    tm_invite: 'Invite link (copy to your team)', tm_copy: 'Copy', tm_copied: 'copied to clipboard',
    tm_members: 'Members', tm_nobody: 'nobody yet - send the invite link', tm_you: '(you)', tm_here: 'here',
    tm_saved: 'handle saved', tm_no_handle: 'empty handle', tm_cfg_ok: 'room updated', tm_cfg_no: 'failed',
  },
  es: {
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
  },
  de: {
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
  },
  pt: {
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
  },
  it: {
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
  },
  ar: {
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
  },
  zh: {
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
  },
  ru: {
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
  },
  ja: {
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
  },
  ko: {
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
  },
  hi: {
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
  state.tab = t;
  document.querySelectorAll('.navbtn').forEach(b => b.classList.toggle('active', b.dataset.tab === t));
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === 'v-' + t));
  if (t === 'chat') { state.unread = 0; }
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
  const c = state.data.chat;
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
  const sig = JSON.stringify([tm.enabled, tm.room, tm.members, HANDLE]);
  if (sig === drawn.team && !forceDraw) return;
  drawn.team = sig;
  $('tmStatus').textContent = tm.enabled ? TF('tm_on', { r: tm.room || '-', n: tm.online || 0 }) : T('tm_off');
  $('tmStatus').className = 'pill ' + (tm.enabled ? 'p-live' : 'p-done');
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
    '<span class="pill ' + (m.active ? 'p-live' : 'p-done') + '">' + (m.active ? T('tm_here') : Math.round(m.ms / 60000) + ' min') + '</span>' +
    '<small style="color:var(--faint);margin-left:auto">' + m.reqs + ' req</small></div>'
  ).join('') || '<div style="color:var(--faint);font-size:11.5px">' + T('tm_nobody') + '</div>';
  // lien d'invitation : la cle dans l'URL (n'est utile que si C2FF_BIND=0.0.0.0)
  const invite = tm.enabled && (tm.room || tm.enabled)
    ? location.origin + '/?k=' + (TEAMKEY || 'LA_CLE') + '  (handle : ' + (HANDLE || 'choisir un pseudo') + ')'
    : '';
  $('tmInvite').textContent = invite;
}
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
$('tmCopy').addEventListener('click', () => {
  const t = $('tmInvite').textContent;
  if (!t) return;
  const ta = document.createElement('textarea');
  ta.value = t; document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); toast('TEAM', T('tm_copied'), 'HIT'); } catch (e) {}
  ta.remove();
});

// ---------- langue / init i18n ----------
$('langSel').innerHTML = LANGS.map(l => '<option value="' + l[0] + '"' + (l[0] !== 'fr' && !I18N[l[0]] ? ' disabled' : '') + '>' + l[1] + (l[0] !== 'fr' && !I18N[l[0]] ? ' ·' : '') + '</option>').join('');
$('langSel').addEventListener('change', () => setLang($('langSel').value));
const _initEntry = LANGS.find(x => x[0] === LANG);
document.documentElement.dir = (_initEntry && _initEntry[2] === 'rtl') ? 'rtl' : 'ltr';
applyI18n();

// ---------- nav / poll ----------
document.querySelectorAll('.navbtn').forEach(b => b.addEventListener('click', () => setTab(b.dataset.tab)));
document.addEventListener('keydown', e => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') { if (e.key === 'Escape') e.target.blur(); return; }
  const m = { '1': 'live', '2': 'findings', '3': 'programs', '4': 'ai', '5': 'team', '6': 'chat' }[e.key];
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
      toast('COORDINATION', (topChat.from === 'claude' ? T('w_claude') : esc(topChat.name) || T('w_me')) + ' : ' + (topChat.text || ''), '');
    }
    if (!state.firstLoad) {
      d.findings.slice(0, Math.max(0, d.findings.length - prevFnd)).forEach(f => {
        if (['P1', 'P2', 'HIT'].includes(f.sev)) toast('[' + (f.program || '').toUpperCase() + '] ' + f.run + ' · ' + f.agent, f.text, f.sev === 'P1' ? 'P1' : f.sev);
      });
    }
    drawRuns(d.runs); drawFindings(); drawPrograms(); drawChat(); drawFleet(); drawAI(); drawTeam();
    // presence team : battement toutes les ~5 s (3 polls)
    if (state.tick % 3 === 0 && HANDLE) {
      jpost('/api/team', { op: 'beat', handle: HANDLE }).then(r => r.json()).then(j => { if (j.team) state.data.team = j.team; }).catch(() => {});
    }
    forceDraw = false;
    state.firstLoad = false;
  } catch (e) { /* serveur occupe */ }
  inflight = false;
}
setInterval(refresh, 1500);
refresh();