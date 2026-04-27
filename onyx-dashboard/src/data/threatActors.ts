export interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  country: string;
  countryCode: string;
  flag: string;
  attribution: string;
  type: 'etatique' | 'criminel' | 'hacktiviste';
  dangerScore: number;
  dangerJustification: string;
  sectors: string[];
  ttps: { id: string; name: string; description: string }[];
  tools: string[];
  malwares: string[];
  campaigns: { name: string; year: string; description: string }[];
  recentActivity: boolean;
  activityTrend: 'hausse' | 'stable' | 'baisse';
  sophistication: number;
  stealth: number;
  persistence: number;
  impact: number;
  activityScore: number;
}

export const THREAT_ACTORS: ThreatActor[] = [
  {
    id: 'apt28',
    name: 'APT28',
    aliases: ['Fancy Bear', 'Sofacy', 'Sednit', 'STRONTIUM', 'Pawn Storm'],
    country: 'Russie',
    countryCode: 'RU',
    flag: 'RU',
    attribution: 'GRU — Direction Principale du Renseignement (Unité 26165)',
    type: 'etatique',
    dangerScore: 9.2,
    dangerJustification: 'Capacités offensives de niveau étatique, accès à des zero-days, persistance longue durée',
    sectors: ['Gouvernement', 'Défense', 'Partis politiques', 'Médias', 'ONG'],
    ttps: [
      { id: 'T1566', name: 'Phishing', description: 'Spearphishing ciblé sur profils politiques et militaires' },
      { id: 'T1078', name: 'Comptes valides', description: 'Utilisation de credentials volés pour accès persistant' },
      { id: 'T1059', name: 'Interpréteur de commandes', description: 'PowerShell et scripts bash pour post-exploitation' },
      { id: 'T1071', name: 'Protocoles applicatifs', description: 'C2 via HTTP/HTTPS pour éviter la détection' },
      { id: 'T1027', name: 'Obfuscation', description: 'Chiffrement et encodage des payloads' }
    ],
    tools: ['Mimikatz', 'X-Agent', 'Sofacy', 'Komplex', 'Zebrocy', 'CHOPSTICK'],
    malwares: ['X-Agent', 'Sofacy', 'Zebrocy', 'Cannon', 'LoJax (premier UEFI rootkit documenté)'],
    campaigns: [
      { name: 'Operation Pawn Storm', year: '2014-2024', description: 'Campagne continue ciblant OTAN, gouvernements et journalistes' },
      { name: 'DNC Hack', year: '2016', description: 'Intrusion dans le Comité National Démocrate américain' },
      { name: 'Bundestag Hack', year: '2015', description: 'Compromission du parlement allemand, 16 Go de données exfiltrées' },
      { name: 'Olympic Destroyer', year: '2018', description: 'Sabotage des Jeux Olympiques de PyeongChang' }
    ],
    recentActivity: true,
    activityTrend: 'hausse',
    sophistication: 9.2, stealth: 8.5, persistence: 9.0, impact: 8.8, activityScore: 9.1
  },
  {
    id: 'apt29',
    name: 'APT29',
    aliases: ['Cozy Bear', 'The Dukes', 'NOBELIUM', 'Midnight Blizzard', 'UNC2452'],
    country: 'Russie',
    countryCode: 'RU',
    flag: 'RU',
    attribution: 'SVR — Service du Renseignement Extérieur de la Fédération de Russie',
    type: 'etatique',
    dangerScore: 9.5,
    dangerJustification: 'Niveau de sophistication exceptionnel, capacité de présence non détectée sur 9+ mois, ciblage des chaînes d\'approvisionnement logicielles',
    sectors: ['Gouvernement', 'Think tanks', 'Industrie pharmaceutique', 'Technologie', 'Agences de renseignement alliées'],
    ttps: [
      { id: 'T1195.002', name: 'Supply Chain Compromise', description: 'Compromission du pipeline de build SolarWinds Orion' },
      { id: 'T1566.001', name: 'Spearphishing avec pièce jointe', description: 'Documents Office weaponisés à destination de cibles diplomatiques' },
      { id: 'T1059.001', name: 'PowerShell', description: 'Exécution de payloads en mémoire sans écriture sur disque' },
      { id: 'T1071', name: 'Protocoles C2', description: 'Beaconing via HTTPS avec intervalles aléatoires pour éviter détection' },
      { id: 'T1550.001', name: 'Tokens d\'application', description: 'Abus de tokens OAuth pour persistance dans environnements cloud' }
    ],
    tools: ['Cobalt Strike', 'WellMess', 'WellMail', 'MiniDuke', 'CosmicDuke', 'SUNBURST', 'Sliver'],
    malwares: ['SUNBURST', 'TEARDROP', 'RAINDROP', 'GoldMax', 'Sibot', 'GoldFinder'],
    campaigns: [
      { name: 'SolarWinds / SUNBURST', year: '2020', description: 'Compromission de 18 000 organisations via mise à jour SolarWinds Orion, 18 agences US touchées' },
      { name: 'Democratic Party Intrusion', year: '2015-2016', description: 'Accès non détecté pendant un an dans les systèmes du Parti Démocrate' },
      { name: 'COVID-19 Vaccine Research', year: '2020', description: 'Ciblage de laboratoires développant des vaccins contre le COVID-19' },
      { name: 'Microsoft Midnight Blizzard', year: '2024', description: 'Compromission de comptes email de dirigeants Microsoft via password spray' }
    ],
    recentActivity: true,
    activityTrend: 'hausse',
    sophistication: 9.8, stealth: 9.5, persistence: 9.7, impact: 9.3, activityScore: 9.2
  },
  {
    id: 'lazarus',
    name: 'Lazarus Group',
    aliases: ['Hidden Cobra', 'Guardians of Peace', 'ZINC', 'Labyrinth Chollima', 'APT38'],
    country: 'Corée du Nord',
    countryCode: 'KP',
    flag: 'KP',
    attribution: 'RGB — Bureau Général de Reconnaissance, Unité 180',
    type: 'etatique',
    dangerScore: 9.4,
    dangerJustification: 'Double mission espionnage et financement d\'État via cryptomonnaies, responsable de plus de 3 milliards USD de vols crypto',
    sectors: ['Finance', 'Cryptomonnaies', 'Défense', 'Médias', 'Infrastructures critiques'],
    ttps: [
      { id: 'T1486', name: 'Chiffrement de données', description: 'Ransomware déployé après exfiltration pour maximiser impact' },
      { id: 'T1055', name: 'Injection de processus', description: 'Injection dans processus légitimes Windows pour contourner EDR' },
      { id: 'T1027', name: 'Obfuscation', description: 'Malwares hautement obfusqués avec anti-analyse avancée' },
      { id: 'T1190', name: 'Exploitation service public', description: 'Exploitation de vulnérabilités dans VPNs et serveurs exposés' },
      { id: 'T1588.002', name: 'Outils achetés', description: 'Utilisation de Cobalt Strike licencié et outils commerciaux' }
    ],
    tools: ['WannaCry', 'Destover', 'BLINDINGCAN', 'ELECTRICFISH', 'HOPLIGHT', 'Cobalt Strike'],
    malwares: ['WannaCry', 'Maui Ransomware', 'TraderTraitor', 'AppleJeus', 'BLINDINGCAN'],
    campaigns: [
      { name: 'Sony Pictures Hack', year: '2014', description: 'Destruction de données et fuite massive suite au film "The Interview"' },
      { name: 'Bangladesh Bank Heist', year: '2016', description: 'Vol de 81 millions USD via le système SWIFT interbancaire' },
      { name: 'WannaCry Global', year: '2017', description: 'Ransomware ayant touché 150 pays et 200 000 systèmes en 72h' },
      { name: 'Ronin Bridge', year: '2022', description: 'Vol de 625 millions USD en cryptomonnaies sur le bridge Axie Infinity' },
      { name: 'TraderTraitor', year: '2023-2024', description: 'Ciblage d\'employés d\'échanges crypto via faux recrutements LinkedIn' }
    ],
    recentActivity: true,
    activityTrend: 'hausse',
    sophistication: 9.0, stealth: 8.7, persistence: 8.9, impact: 9.5, activityScore: 9.3
  },
  {
    id: 'sandworm',
    name: 'Sandworm',
    aliases: ['Voodoo Bear', 'IRIDIUM', 'Seashell Blizzard', 'TeleBots', 'BlackEnergy Group'],
    country: 'Russie',
    countryCode: 'RU',
    flag: 'RU',
    attribution: 'GRU — Unité 74455, Centre Principal des Technologies Spéciales',
    type: 'etatique',
    dangerScore: 9.8,
    dangerJustification: 'Seul groupe documenté ayant causé des coupures de courant réelles via cyberattaques, capacité de destruction physique d\'infrastructures',
    sectors: ['Énergie', 'Infrastructures critiques', 'Gouvernement', 'Médias', 'Transport'],
    ttps: [
      { id: 'T1561', name: 'Effacement de disque', description: 'Wipers destructeurs déployés sur infrastructures critiques ukrainiennes' },
      { id: 'T1485', name: 'Destruction de données', description: 'Destruction irréversible de données opérationnelles et sauvegardes' },
      { id: 'T1078', name: 'Comptes valides', description: 'Utilisation de credentials légitimes pour accès aux systèmes ICS/SCADA' },
      { id: 'T1059', name: 'Scripts malveillants', description: 'Scripts PowerShell et VBScript pour déploiement de wipers' },
      { id: 'T1499', name: 'Déni de service', description: 'Attaques DDoS massives en coordination avec opérations destructrices' }
    ],
    tools: ['BlackEnergy', 'NotPetya', 'Industroyer', 'Industroyer2', 'CaddyWiper', 'HermeticWiper'],
    malwares: ['BlackEnergy 3', 'Industroyer', 'NotPetya', 'Olympic Destroyer', 'CaddyWiper', 'Industroyer2'],
    campaigns: [
      { name: 'Ukraine Power Grid', year: '2015-2016', description: 'Premières coupures de courant causées par cyberattaque, 225 000 foyers affectés' },
      { name: 'NotPetya', year: '2017', description: 'Wiper déguisé en ransomware, 10 milliards USD de dommages mondiaux' },
      { name: 'Olympic Destroyer', year: '2018', description: 'Sabotage de la cérémonie d\'ouverture des JO de PyeongChang' },
      { name: 'Industroyer2', year: '2022', description: 'Tentative de destruction du réseau électrique ukrainien, déjouée in extremis' }
    ],
    recentActivity: true,
    activityTrend: 'hausse',
    sophistication: 9.8, stealth: 8.2, persistence: 9.0, impact: 10.0, activityScore: 9.5
  },
  {
    id: 'volt-typhoon',
    name: 'Volt Typhoon',
    aliases: ['Bronze Silhouette', 'Vanguard Panda', 'DEV-0391', 'UNC3236'],
    country: 'Chine',
    countryCode: 'CN',
    flag: 'CN',
    attribution: 'PLA — Armée Populaire de Libération, probablement Unité 61398 ou affilié MSS',
    type: 'etatique',
    dangerScore: 8.9,
    dangerJustification: 'Spécialisation dans le pré-positionnement discret sur infrastructures critiques occidentales, objectif sabotage en cas de conflit',
    sectors: ['Infrastructures critiques', 'Énergie', 'Transport', 'Communications', 'Eau', 'Défense'],
    ttps: [
      { id: 'T1133', name: 'Services distants externes', description: 'Exploitation de VPNs et routeurs exposés comme vecteur initial' },
      { id: 'T1190', name: 'Exploitation applicative', description: 'Exploitation CVEs dans Fortinet, Ivanti, Cisco pour accès initial' },
      { id: 'T1036', name: 'Masquerading', description: 'Activités malveillantes dissimulées dans trafic réseau légitime (LOTL)' },
      { id: 'T1572', name: 'Tunneling de protocole', description: 'Usage de Fast Reverse Proxy pour tunneliser C2 via protocoles légitimes' },
      { id: 'T1078', name: 'Living off the Land', description: 'Utilisation exclusive d\'outils système légitimes pour éviter détection' }
    ],
    tools: ['Fast Reverse Proxy (FRP)', 'Impacket', 'WinRAR', 'netsh', 'PowerShell natif'],
    malwares: ['Aucun malware personnalisé documenté — stratégie LOTL exclusive'],
    campaigns: [
      { name: 'US Critical Infrastructure Pre-positioning', year: '2023-2024', description: 'CISA et NSA confirment présence dans infrastructures critiques US pour pré-positionnement' },
      { name: 'Guam Military Infrastructure', year: '2023', description: 'Ciblage spécifique des infrastructures militaires US à Guam (hub stratégique Pacifique)' }
    ],
    recentActivity: true,
    activityTrend: 'hausse',
    sophistication: 9.1, stealth: 9.8, persistence: 9.5, impact: 8.5, activityScore: 8.9
  },
  {
    id: 'charming-kitten',
    name: 'Charming Kitten',
    aliases: ['APT35', 'Phosphorus', 'Mint Sandstorm', 'TA453', 'ITG18'],
    country: 'Iran',
    countryCode: 'IR',
    flag: 'IR',
    attribution: 'MOIS — Ministère du Renseignement iranien / IRGC — Corps des Gardiens de la Révolution islamique',
    type: 'etatique',
    dangerScore: 8.7,
    dangerJustification: 'Sophistication croissante, ciblage de dissidents iraniens et chercheurs occidentaux, capacités de phishing social avancées',
    sectors: ['Gouvernement', 'Recherche académique', 'Think tanks', 'Journalisme', 'ONG', 'Secteur nucléaire'],
    ttps: [
      { id: 'T1566', name: 'Phishing', description: 'Campagnes de phishing très personnalisées avec profils LinkedIn et email falsifiés' },
      { id: 'T1598', name: 'Phishing pour informations', description: 'Collecte de credentials via fausses pages de connexion Google et Microsoft' },
      { id: 'T1539', name: 'Vol de cookies', description: 'Exfiltration de cookies de session pour contournement MFA' },
      { id: 'T1534', name: 'Hameçonnage interne', description: 'Utilisation de comptes compromis pour cibler les contacts de la victime' },
      { id: 'T1114', name: 'Collecte d\'emails', description: 'Exfiltration systématique des boîtes mail des cibles compromises' }
    ],
    tools: ['HYPERSCRAPE', 'PowerShell RAT', 'Sponsor Backdoor', 'BellaCiao', 'MischiefTut'],
    malwares: ['HYPERSCRAPE', 'BellaCiao', 'Sponsor', 'CharmPower', 'PowerLess Backdoor'],
    campaigns: [
      { name: 'Operation SpoofedScholars', year: '2021', description: 'Usurpation d\'identité de chercheurs universitaires pour cibler experts géopolitique' },
      { name: 'Nuclear Negotiators Targeting', year: '2021-2022', description: 'Ciblage de négociateurs occidentaux des accords nucléaires iraniens' },
      { name: 'Academia and Media Targeting', year: '2022-2024', description: 'Campagne continue contre journalistes, universitaires et think tanks' }
    ],
    recentActivity: true,
    activityTrend: 'stable',
    sophistication: 8.3, stealth: 8.7, persistence: 8.5, impact: 7.8, activityScore: 8.6
  },
  {
    id: 'lockbit',
    name: 'LockBit 3.0',
    aliases: ['LockBit Black', 'ABCD Group', 'LockBit ransomware group'],
    country: 'Russie',
    countryCode: 'RU',
    flag: 'RU',
    attribution: 'Groupe cybercriminel russophone, modèle RaaS (Ransomware-as-a-Service)',
    type: 'criminel',
    dangerScore: 8.5,
    dangerJustification: 'Groupe ransomware le plus prolifique de 2022-2023, modèle RaaS avec 100+ affiliés actifs, double extorsion systématique',
    sectors: ['Tous secteurs', 'Santé', 'Éducation', 'Gouvernement', 'Finance', 'Industrie'],
    ttps: [
      { id: 'T1486', name: 'Chiffrement', description: 'Chiffrement ultra-rapide via algorithme AES-256 + RSA-2048' },
      { id: 'T1490', name: 'Inhibition de récupération', description: 'Suppression des shadow copies et sauvegardes Windows avant chiffrement' },
      { id: 'T1489', name: 'Arrêt de services', description: 'Arrêt des services de sécurité et bases de données avant déploiement' },
      { id: 'T1083', name: 'Découverte de fichiers', description: 'Reconnaissance complète du réseau avant exfiltration ciblée' },
      { id: 'T1567', name: 'Exfiltration web', description: 'Exfiltration vers StealBit avant chiffrement pour double extorsion' }
    ],
    tools: ['LockBit 3.0 ransomware', 'StealBit', 'Cobalt Strike', 'Mimikatz', 'AnyDesk'],
    malwares: ['LockBit Black (v3.0)', 'StealBit exfiltration tool'],
    campaigns: [
      { name: 'Boeing Attack', year: '2023', description: 'Exfiltration de 43 Go de données Boeing, publication après refus de paiement' },
      { name: 'ICBC Ransomware', year: '2023', description: 'Paralysie de la plus grande banque mondiale (Industrial and Commercial Bank of China)' },
      { name: 'Royal Mail UK', year: '2023', description: 'Perturbation majeure des services postaux britanniques pendant plusieurs semaines' },
      { name: 'Operation Cronos', year: '2024', description: 'Démantèlement partiel par Europol et FBI, arrestations et reprise d\'activité sous LockBit 4.0' }
    ],
    recentActivity: true,
    activityTrend: 'hausse',
    sophistication: 8.0, stealth: 7.5, persistence: 8.2, impact: 9.0, activityScore: 8.8
  },
  {
    id: 'fin7',
    name: 'FIN7',
    aliases: ['Carbanak Group', 'Sangria Tornado'],
    country: 'Russie',
    countryCode: 'RU',
    flag: 'RU',
    attribution: 'Cybercriminel organisé',
    type: 'criminel',
    dangerScore: 9.0,
    dangerJustification: 'Groupe cybercriminel très structuré, spécialisé dans le vol de données bancaires et ransomware, ciblant massivement les points de vente (PoS).',
    sectors: ['Hôtellerie', 'Restauration', 'Finance', 'Commerce de détail'],
    ttps: [
      { id: 'T1195', name: 'Supply Chain Compromise', description: 'Compromission via des tiers' },
      { id: 'T1566', name: 'Phishing', description: 'Spearphishing ciblé sur le personnel' },
      { id: 'T1059', name: 'Command and Scripting Interpreter', description: 'Scripts malveillants' }
    ],
    tools: ['Carbanak', 'Griffon', 'Tirion', 'Cobalt Strike'],
    malwares: ['Tirion', 'Carbanak', 'Griffon'],
    campaigns: [
      { name: 'Carbanak Heists', year: '2014-2015', description: 'Vol de plus d\'un milliard de dollars dans les banques' },
      { name: 'Restaurant Chains', year: '2020', description: 'Vol massif de cartes de crédit' }
    ],
    recentActivity: true,
    activityTrend: 'hausse',
    sophistication: 8.9, stealth: 8.5, persistence: 8.0, impact: 9.2, activityScore: 8.8
  },
  {
    id: 'kimsuky',
    name: 'Kimsuky',
    aliases: ['Thallium', 'Velvet Chollima', 'APT43'],
    country: 'Corée du Nord',
    countryCode: 'KP',
    flag: 'KP',
    attribution: 'RGB (Reconnaissance General Bureau)',
    type: 'etatique',
    dangerScore: 8.8,
    dangerJustification: 'Acteur majeur nord-coréen ciblant les experts géopolitiques et le renseignement étranger avec des campagnes massives de spearphishing.',
    sectors: ['Gouvernement', 'Think Tanks', 'Académique', 'Défense'],
    ttps: [
      { id: 'T1566.001', name: 'Spearphishing Attachment', description: 'Documents Word/Excel malveillants' },
      { id: 'T1059.003', name: 'Windows Command Shell', description: 'Exécution de commandes natives' },
      { id: 'T1123', name: 'Audio Capture', description: 'Espionnage via micro' }
    ],
    tools: ['BabyShark', 'AppleSeed', 'GoldDragon'],
    malwares: ['BabyShark', 'AppleSeed'],
    campaigns: [
      { name: 'Operation Kabar Cobra', year: '2019', description: 'Ciblage de responsables sud-coréens' },
      { name: 'Global Intelligence Gathering', year: '2022-2023', description: 'Ciblage d\'experts de la péninsule coréenne' }
    ],
    recentActivity: true,
    activityTrend: 'stable',
    sophistication: 8.2, stealth: 8.0, persistence: 8.5, impact: 8.1, activityScore: 8.4
  },
  {
    id: 'blackcat',
    name: 'BlackCat',
    aliases: ['ALPHV', 'Noberus'],
    country: 'Russie',
    countryCode: 'RU',
    flag: 'RU',
    attribution: 'Cybercriminel (RaaS)',
    type: 'criminel',
    dangerScore: 9.5,
    dangerJustification: 'L\'un des groupes ransomware RaaS les plus sophistiqués, utilisant Rust pour viser Windows et Linux.',
    sectors: ['Santé', 'Divertissement', 'Industrie', 'Gouvernement'],
    ttps: [
      { id: 'T1486', name: 'Data Encrypted for Impact', description: 'Chiffrement via algorithme avancé en Rust' },
      { id: 'T1078', name: 'Valid Accounts', description: 'Accès initial via comptes compromis' },
      { id: 'T1562.001', name: 'Disable or Modify Tools', description: 'Désactivation des antivirus et EDR' }
    ],
    tools: ['BlackCat Ransomware', 'Exmatter', 'Cobalt Strike'],
    malwares: ['BlackCat Ransomware', 'Exmatter'],
    campaigns: [
      { name: 'MGM Resorts', year: '2023', description: 'Paralysie des opérations hôtelières et casinos' },
      { name: 'Change Healthcare', year: '2024', description: 'Attaque majeure du système de santé américain' }
    ],
    recentActivity: true,
    activityTrend: 'hausse',
    sophistication: 9.1, stealth: 8.3, persistence: 8.7, impact: 9.8, activityScore: 9.4
  },
  {
    id: 'muddywater',
    name: 'MuddyWater',
    aliases: ['Earth Vetala', 'MERCURY', 'Seedworm'],
    country: 'Iran',
    countryCode: 'IR',
    flag: 'IR',
    attribution: 'MOIS — Ministère du Renseignement',
    type: 'etatique',
    dangerScore: 8.4,
    dangerJustification: 'Acteur prolifique agissant pour le MOIS iranien, ciblant le Moyen-Orient et l\'Asie avec un fort usage de scripts.',
    sectors: ['Gouvernement', 'Télécommunications', 'Énergie'],
    ttps: [
      { id: 'T1566', name: 'Phishing', description: 'Distribution de documents leurres' },
      { id: 'T1059', name: 'Command and Scripting', description: 'Fort usage de PowerShell et scripts' },
      { id: 'T1071', name: 'Application Layer Protocol', description: 'C2 via protocoles web légitimes' }
    ],
    tools: ['Atera', 'ScreenConnect', 'MuddyC3'],
    malwares: ['MuddyC3', 'POWERSTATS'],
    campaigns: [
      { name: 'Middle East Telecoms', year: '2021', description: 'Ciblage des opérateurs télécoms' },
      { name: 'Operation Quicksand', year: '2022', description: 'Ciblage des gouvernements asiatiques' }
    ],
    recentActivity: true,
    activityTrend: 'stable',
    sophistication: 7.9, stealth: 7.5, persistence: 8.0, impact: 7.8, activityScore: 8.1
  },
  {
    id: 'scattered-spider',
    name: 'Scattered Spider',
    aliases: ['UNC3944', '0ktapus', 'Star Fraud'],
    country: 'États-Unis',
    countryCode: 'US',
    flag: 'US',
    attribution: 'Criminels occidentaux, affiliés RaaS',
    type: 'criminel',
    dangerScore: 9.3,
    dangerJustification: 'Maitrise exceptionnelle de l\'ingénierie sociale (vishing, SIM swapping) couplée aux tactiques de ransomware.',
    sectors: ['Télécommunications', 'IT', 'Finance', 'Cryptomonnaies'],
    ttps: [
      { id: 'T1566.002', name: 'Spearphishing Link', description: 'Phishing via SMS et appels (vishing)' },
      { id: 'T1552', name: 'Unsecured Credentials', description: 'Recherche de mots de passe internes' },
      { id: 'T1078', name: 'Valid Accounts', description: 'Abus de portails SSO et contournement MFA' }
    ],
    tools: ['Ngrok', 'AnyDesk', 'Mimikatz', 'FleetDeck'],
    malwares: ['BlackCat Ransomware', 'ALPHV (affiliés)'],
    campaigns: [
      { name: '0ktapus Campaign', year: '2022', description: 'Compromission de 130+ organisations via Okta' },
      { name: 'Las Vegas Casinos', year: '2023', description: 'Attaques conjointes sur MGM et Caesars' }
    ],
    recentActivity: true,
    activityTrend: 'hausse',
    sophistication: 8.7, stealth: 8.9, persistence: 8.1, impact: 9.5, activityScore: 9.0
  }
];
