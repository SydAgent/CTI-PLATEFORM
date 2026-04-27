/**
 * ONYX CTI v5.0 SOVEREIGN — Dictionnaire Français Exhaustif
 *
 * Convention :
 *  - Clés hiérarchiques par module : nav.*, header.*, stats.*, etc.
 *  - Les acronymes techniques standards (IOC, APT, CVE, MITRE, TTP, STIX, C2,
 *    OSINT, SSE, YARA, Sigma, SIEM, EDR, XDR) sont conservés en anglais
 *    conformément à la norme ISO/IEC 27032 et au vocabulaire MITRE ATT&CK.
 *  - Aucun terme utilisateur ne reste en anglais.
 */

const fr = {
  // ═══════════════════════════════════════════════════════════════════════════
  // Navigation
  // ═══════════════════════════════════════════════════════════════════════════
  nav: {
    overview: 'Vue d\'ensemble',
    ailab: 'Laboratoire IA',
    iocs: 'Explorateur IOC',
    threats: 'Acteurs de la menace',
    graph: 'Graphe de menaces',
    crawlers: 'Collecteurs',
    reports: 'Rapports',
    attack: 'Matrice ATT&CK',
    recommendations: 'Recommandations',
    system_online: 'Système opérationnel',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // En-tête & Barre de recherche
  // ═══════════════════════════════════════════════════════════════════════════
  header: {
    search_placeholder: 'Rechercher IOC, menaces, TTPs...',
    live: '● EN DIRECT',
    offline: '○ HORS LIGNE',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // Page de chargement
  // ═══════════════════════════════════════════════════════════════════════════
  loading: {
    title: 'ONYX CTI — Initialisation du Centre de Commandement',
    subtitle: 'Chargement de la matrice de renseignement sécurisée...',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // Cartes statistiques (Overview)
  // ═══════════════════════════════════════════════════════════════════════════
  stats: {
    total_iocs: 'IOCs actifs totaux',
    active_threats: 'Acteurs de menace actifs',
    stix_objects: 'Objets STIX',
    engine_confidence: 'Confiance du moteur',
    live_suffix: 'en direct',
    new_suffix: 'nouveaux',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // Distribution de sévérité
  // ═══════════════════════════════════════════════════════════════════════════
  severity: {
    title: 'Distribution de sévérité',
    critical: 'critique',
    high: 'élevée',
    medium: 'moyenne',
    low: 'faible',
    info: 'information',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // Flux d'événements en direct
  // ═══════════════════════════════════════════════════════════════════════════
  feed: {
    title: 'Flux d\'événements en direct',
    events_count: 'événements',
    awaiting: 'En attente de télémétrie en direct...',
    paused: 'EN PAUSE',
    queued: 'en file d\'attente',
    resume: '▶ REPRENDRE',
    pause: '⏸ PAUSE',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // Explorateur IOC
  // ═══════════════════════════════════════════════════════════════════════════
  ioc: {
    title: '⬡ Explorateur IOC — Flux MISP / OTX en direct',
    filter_placeholder: 'Filtrer IOCs, domaines, empreintes...',
    all: 'tous',
    indicators_count: 'indicateurs',
    awaiting: 'En attente de télémétrie en direct...',
    clear_filter: '✕ Effacer le filtre',
    col_type: 'TYPE',
    col_value: 'VALEUR IOC',
    col_source: 'SOURCE',
    col_confidence: 'CONFIANCE',
    col_action: 'ACTION',
    hunt: '→ CHASSER',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // Acteurs de la menace
  // ═══════════════════════════════════════════════════════════════════════════
  threats: {
    title: '☠ Renseignement sur les acteurs de la menace',
    select_adversary: 'Sélectionnez un adversaire',
    awaiting: 'En attente de renseignements sur les menaces...',
    aliases_label: 'Alias :',
    origin_label: 'Origine :',
    target_label: 'Cible :',
    visualize: '◎ VISUALISER L\'INFRASTRUCTURE',
    observed_ttps: 'TTPs MITRE observés',
    active_iocs: 'IOCs actifs',
    hunt_indicators: '⬡ CHASSER LES INDICATEURS ACTIFS',
    no_ttps: 'Aucun TTP enregistré',
    no_telemetry: 'Aucune télémétrie active correspondant à cet acteur.',
    active: '● ACTIF',
    monitored: '○ SURVEILLÉ',
    severity_label: 'Sévérité',
    status_label: 'Statut',
    // Sous-composants ThreatActorIntel
    known_aliases: 'Alias connus',
    no_known_aliases: 'Aucun alias connu',
    targeted_sectors: 'Secteurs ciblés',
    target_regions: 'Régions cibles principales',
    malware_arsenal: 'Arsenal de maliciels et outils',
    identified_count: 'identifiés',
    no_tooling: 'Aucune donnée d\'outillage disponible depuis le pipeline d\'ingestion actif',
    mitre_ttps: 'TTPs MITRE ATT&CK',
    techniques_count: 'techniques',
    click_for_detail: 'Cliquez sur une technique pour afficher l\'analyse détaillée',
    close: '✕ Fermer',
    explanation: 'Explication',
    operational_impact: 'Impact opérationnel',
    concrete_example: 'Exemple concret',
    remediation: 'Remédiation',
    node_types: 'Types de nœuds',
    threat_actor: 'Acteur de menace',
    malware_tool: 'Maliciel / Outil',
    mitre_technique: 'Technique MITRE',
    ioc_indicator: 'Indicateur IOC',
    mitre_heatmap: 'Grille tactique/technique MITRE ATT&CK',
    low_label: 'Faible',
    critical_label: 'Critique',
    no_mitre_activity: 'Aucune activité MITRE détectée',
    kill_chain_timeline: 'Chronologie de la chaîne d\'attaque',
    no_kill_chain: 'Aucun événement de chaîne d\'attaque détecté',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // Collecteurs (Crawlers)
  // ═══════════════════════════════════════════════════════════════════════════
  crawlers: {
    title: '🕸 Centre de commande des collecteurs',
    engine_desc: 'Moteur d\'ingestion temps réel surveillant les forums du Dark Web, les flux OSINT et les sites de fuites de rançongiciels. Les journaux affichent la reconnaissance active à travers les services cachés Tor et les infrastructures C2 connues.',
    active_nodes: 'Nœuds Tor actifs',
    total_harvested: 'IOCs récoltés au total',
    connection_drops: 'Pertes de connexion',
    filter_placeholder: 'Filtrer les journaux par mot-clé...',
    resume_queued: '▶ REPRENDRE',
    queued_suffix: 'EN FILE',
    pause_feed: '⏸ PAUSE DU FLUX',
    clear: '✕ EFFACER',
    autoscroll_on: '▼ DÉFILEMENT AUTO : ACTIVÉ',
    autoscroll_off: '◫ DÉFILEMENT AUTO : DÉSACTIVÉ',
    col_time: 'Heure',
    col_node: 'Nœud',
    col_action: 'Action',
    col_target: 'Cible (IP / Onion)',
    col_latency: 'Lat (ms)',
    awaiting: 'En attente de télémétrie en direct...',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // Rapports
  // ═══════════════════════════════════════════════════════════════════════════
  reports: {
    title: '📋 Rapports de renseignement sur les menaces',
    awaiting: 'En attente de rapports de renseignement entrants...',
    loading: 'Chargement du renseignement...',
    executive_summary: 'Résumé exécutif',
    threat_overview: 'Aperçu des menaces et analyse technique',
    impact_analysis: 'Analyse d\'impact',
    recommended_mitigation: 'Remédiation recommandée',
    extracted_iocs: 'Indicateurs extraits (IOCs)',
    mitre_pivots: 'TTPs MITRE et pivots croisés',
    none_extracted: 'Aucun extrait',
    no_ttps_matched: 'Aucun TTP strict correspondant',
    priority_suffix: 'PRIORITÉ',
    source_label: 'SOURCE',
    id_label: 'ID',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // Laboratoire IA
  // ═══════════════════════════════════════════════════════════════════════════
  ailab: {
    title: '⟁ Laboratoire d\'intelligence artificielle',
    subtitle: 'Moteur NLP SciBERT · Cartographie MITRE ATT&CK · Export STIX 2.1 · Extraction IOC temps réel',
    model_label: 'MODÈLE',
    corpus_label: 'CORPUS',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // Carte des menaces
  // ═══════════════════════════════════════════════════════════════════════════
  map: {
    title: 'MATRICE GÉOPOLITIQUE DES MENACES',
    live: 'EN DIRECT',
    threat_sources: 'sources de menace',
    verified_arcs: 'arcs vérifiés',
    synced_ago: 's depuis sync.',
    webgl_disabled: 'ACCÉLÉRATION MATÉRIELLE WEBGL DÉSACTIVÉE',
    fallback: '[ REPLI : MODE 2D SÉCURISÉ ACTIF ]',
    loading_engine: 'Chargement du moteur GL sécurisé...',
    source_label: 'Source :',
    target_label: 'Cible :',
    verified_vector: '✓ VECTEUR BIDIRECTIONNEL VÉRIFIÉ',
    threat_origin: 'Origine de la menace :',
    ioc_label: 'IOC :',
    confidence_label: 'Confiance :',
    intel_label: 'renseignement',
    live_intel: '⚡ RENSEIGNEMENT EN DIRECT',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // Recommandations
  // ═══════════════════════════════════════════════════════════════════════════
  recommendations: {
    title: '🛡 Recommandations actionnables',
    no_recommendations: 'Aucune recommandation disponible pour le moment.',
    action_label: 'Action',
    command_label: 'Commande',
    equipment_label: 'Équipement',
    justification_label: 'Justification',
    priority: {
      critical: 'CRITIQUE',
      high: 'HAUTE',
      medium: 'MOYENNE',
      low: 'FAIBLE',
    },
    copy_command: 'Copier la commande',
    copied: 'Copié !',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // Termes communs
  // ═══════════════════════════════════════════════════════════════════════════
  common: {
    loading: 'Chargement...',
    error: 'Erreur',
    retry: 'Réessayer',
    export: 'Exporter',
    download: 'Télécharger',
    cancel: 'Annuler',
    confirm: 'Confirmer',
    close: 'Fermer',
    save: 'Enregistrer',
    delete: 'Supprimer',
    search: 'Rechercher',
    filter: 'Filtrer',
    all: 'Tous',
    none: 'Aucun',
    yes: 'Oui',
    no: 'Non',
    unknown: 'Inconnu',
    not_available: 'N/D',
    date: 'Date',
    time: 'Heure',
    type: 'Type',
    value: 'Valeur',
    source: 'Source',
    status: 'Statut',
    online: 'En ligne',
    offline: 'Hors ligne',
    running: 'en cours',
    idle: 'inactif',
    error_status: 'erreur',
    version: 'Version',
    platform_name: 'ONYX CTI v5.0 SOVEREIGN',
    codename: 'SOVEREIGN',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // Métadonnées SEO (layout)
  // ═══════════════════════════════════════════════════════════════════════════
  meta: {
    title: 'ONYX CTI — Centre de Commandement',
    description: 'Plateforme souveraine de renseignement sur les cybermenaces — Suivi IOC temps réel, surveillance du Dark Web et cartographie ATT&CK.',
  },
} as const;

/** Type utilitaire pour l'autocomplétion des clés imbriquées. */
export type TranslationKey = FlattenKeys<typeof fr>;

/**
 * Aplatissement récursif des clés d'un objet pour obtenir
 * les chemins pointés (ex: "nav.overview", "stats.total_iocs").
 */
type FlattenKeys<T, Prefix extends string = ''> = T extends Record<string, unknown>
  ? {
      [K in keyof T & string]: T[K] extends Record<string, unknown>
        ? FlattenKeys<T[K], `${Prefix}${K}.`>
        : `${Prefix}${K}`;
    }[keyof T & string]
  : never;

export default fr;
