const puppeteer = require('puppeteer');
const fs = require('fs');

async function generatePDF() {
    console.log("Lancement de Puppeteer...");
    const browser = await puppeteer.launch({ headless: 'new' });
    const page = await browser.newPage();
    
    // Contenu HTML de l'architecture
    const htmlContent = `
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>ONYX CTI — Architecture Technique Complète</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Georgia&family=Helvetica:wght@400;700&display=swap');
            
            :root {
                --primary: #0a192f;
                --accent: #00e5ff;
                --text: #333333;
                --bg: #ffffff;
                --code-bg: #F5F5F5;
            }

            body {
                font-family: 'Georgia', serif;
                font-size: 11pt;
                line-height: 1.4;
                color: var(--text);
                margin: 0;
                padding: 0;
            }

            h1, h2, h3, h4, h5, h6 {
                font-family: 'Helvetica', sans-serif;
                font-weight: bold;
                color: var(--primary);
                page-break-after: avoid;
            }

            h1 { font-size: 18pt; text-transform: uppercase; border-bottom: 2px solid var(--accent); padding-bottom: 5px; margin-top: 30px; }
            h2 { font-size: 14pt; margin-top: 25px; }
            h3 { font-size: 12pt; margin-top: 20px; }

            .page-break { page-break-before: always; }
            
            /* Cover Page */
            .cover-page {
                height: 100vh;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                text-align: center;
                page-break-after: always;
            }
            .cover-title { font-size: 32pt; font-weight: bold; margin-bottom: 10px; color: var(--primary); }
            .cover-subtitle { font-size: 18pt; color: #555; margin-bottom: 50px; }
            .cover-meta { font-size: 12pt; font-family: 'Helvetica', sans-serif; color: #777; margin-top: auto; padding-bottom: 50px;}
            .confidential { color: #d32f2f; font-weight: bold; border: 2px solid #d32f2f; padding: 10px 20px; display: inline-block; border-radius: 5px; margin-bottom: 40px;}

            /* Table of Contents */
            .toc { margin-bottom: 30px; }
            .toc ul { list-style-type: none; padding-left: 0; }
            .toc li { margin-bottom: 8px; }
            .toc a { text-decoration: none; color: var(--primary); font-family: 'Helvetica', sans-serif; font-weight: bold; }
            .toc ul ul { padding-left: 20px; font-weight: normal; }
            .toc ul ul a { font-weight: normal; color: #555; }

            /* Blocks */
            pre {
                font-family: 'Courier New', monospace;
                font-size: 9pt;
                background-color: var(--code-bg);
                border-left: 4px solid var(--accent);
                padding: 10px;
                overflow-x: auto;
                page-break-inside: avoid;
            }
            code {
                font-family: 'Courier New', monospace;
                background-color: var(--code-bg);
                padding: 2px 4px;
                border-radius: 3px;
                font-size: 0.9em;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
                page-break-inside: avoid;
            }
            th, td {
                border: 1px solid #ddd;
                padding: 12px;
                text-align: left;
            }
            th {
                background-color: var(--primary);
                color: white;
                font-family: 'Helvetica', sans-serif;
            }
            tr:nth-child(even) { background-color: #f9f9f9; }

            .ascii-art {
                font-family: 'Courier New', monospace;
                font-size: 8pt;
                white-space: pre;
                background-color: var(--primary);
                color: var(--accent);
                padding: 15px;
                border-radius: 5px;
                page-break-inside: avoid;
                line-height: 1.1;
                overflow-x: auto;
            }
            .ascii-title {
                font-family: 'Helvetica', sans-serif;
                font-weight: bold;
                font-size: 10pt;
                color: var(--primary);
                margin-bottom: 5px;
                text-transform: uppercase;
            }
            p {
                text-align: justify;
            }
            
            ul { margin-top: 5px; margin-bottom: 15px; }
            li { margin-bottom: 5px; text-align: justify; }

        </style>
    </head>
    <body>

    <!-- PAGE DE COUVERTURE -->
    <div class="cover-page">
        <div style="font-family: Courier New; font-size: 10pt; color: #00e5ff; background: #0a192f; padding: 20px; border-radius: 10px; margin-bottom: 40px; display:inline-block;">
             ██████╗ ███╗   ██╗██╗   ██╗██╗  ██╗<br>
            ██╔═══██╗████╗  ██║╚██╗ ██╔╝╚██╗██╔╝<br>
            ██║   ██║██╔██╗ ██║ ╚████╔╝  ╚███╔╝ <br>
            ██║   ██║██║╚██╗██║  ╚██╔╝   ██╔██╗ <br>
            ╚██████╔╝██║ ╚████║   ██║   ██╔╝ ██╗<br>
             ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝
        </div>
        <div class="cover-title">ONYX CTI</div>
        <div class="cover-subtitle">Architecture Technique Complète<br>Plateforme de Cyber Threat Intelligence</div>
        <div class="confidential">CONFIDENTIEL — USAGE INTERNE STRICT</div>
        <div class="cover-meta">
            Version : v4.2 Sovereign<br>
            Généré le : ${new Date().toLocaleDateString('fr-FR', { day: '2-digit', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit' })}<br>
            Auteur : Architecte Système Senior
        </div>
    </div>

    <!-- TABLE DES MATIÈRES -->
    <div class="page-break"></div>
    <h1>Table des Matières</h1>
    <div class="toc">
        <ul>
            <li><a href="#section-1">1. VISION STRATÉGIQUE ET OBJECTIFS DU SYSTÈME</a></li>
            <li><a href="#section-2">2. VUE GLOBALE DE L'ARCHITECTURE</a></li>
            <li><a href="#section-3">3. ARCHITECTURE FRONTEND</a>
                <ul>
                    <li><a href="#section-3-1">3.1 Stack technologique frontend</a></li>
                    <li><a href="#section-3-2">3.2 Structure des composants</a></li>
                    <li><a href="#section-3-3">3.3 Design system</a></li>
                    <li><a href="#section-3-4">3.4 Modules fonctionnels</a></li>
                    <li><a href="#section-3-5">3.5 Gestion d'état et flux de données</a></li>
                </ul>
            </li>
            <li><a href="#section-4">4. ARCHITECTURE BACKEND</a>
                <ul>
                    <li><a href="#section-4-1">4.1 Stack technologique backend</a></li>
                    <li><a href="#section-4-2">4.2 API REST — endpoints documentés</a></li>
                    <li><a href="#section-4-3">4.3 Module d'analyse sémantique SciBERT</a></li>
                    <li><a href="#section-4-4">4.4 Pipeline d'ingestion CTI</a></li>
                    <li><a href="#section-4-5">4.5 Gestion des WebSockets et temps réel</a></li>
                </ul>
            </li>
            <li><a href="#section-5">5. ARCHITECTURE DE LA BASE DE DONNÉES</a></li>
            <li><a href="#section-6">6. INTÉGRATIONS ET SOURCES DE DONNÉES</a></li>
            <li><a href="#section-7">7. SÉCURITÉ ET CONFORMITÉ</a></li>
            <li><a href="#section-8">8. INFRASTRUCTURE ET DÉPLOIEMENT</a></li>
            <li><a href="#section-9">9. PLAN D'IMPLÉMENTATION PAR PHASES</a></li>
            <li><a href="#section-10">10. BONNES PRATIQUES ET RECOMMANDATIONS</a></li>
            <li><a href="#section-11">11. GLOSSAIRE ET RÉFÉRENCES</a></li>
        </ul>
    </div>

    <!-- SECTION 1 -->
    <div class="page-break"></div>
    <h1 id="section-1">1. VISION STRATÉGIQUE ET OBJECTIFS DU SYSTÈME</h1>
    <p>
        La plateforme ONYX CTI (Cyber Threat Intelligence) est conçue comme un système d'information souverain, analytique et prédictif, visant à répondre à la complexité croissante des menaces cybernétiques. Face à l'hyper-fragmentation des sources d'intelligence (open-source, commerciale, dark web) et au volume massif de données hétérogènes (IoCs, rapports stratégiques, télémétrie), ONYX apporte une solution d'unification et de corrélation sémantique propulsée par l'intelligence artificielle. Le problème fondamental qu'elle résout réside dans le délai cognitif imposé aux analystes : transformer une donnée brute en connaissance exploitable. ONYX automatise l'ingestion, normalise selon le standard STIX 2.1, et expose l'intelligence via des interfaces immersives et hautement réactives.
    </p>
    <p>
        Ce système s'adresse à une pluralité d'acteurs de la cybersécurité opérant à différents niveaux décisionnels. Pour les analystes SOC (Security Operations Center) et les équipes de Detection Engineering, ONYX fournit un flux temps réel d'IoCs qualifiés et de signatures de menaces directement injectables dans les SIEM/EDR. Pour les chercheurs en sécurité et les équipes de Threat Hunting, la plateforme offre un Laboratoire IA et un Graphe de Menaces permettant des investigations approfondies sur les TTPs (Tactics, Techniques, and Procedures) des acteurs étatiques (APT). Enfin, pour les RSSI (Responsables de la Sécurité des Systèmes d'Information) et les décideurs exécutifs, ONYX génère des rapports de synthèse automatisés, des matrices géopolitiques et des indicateurs de risque macroscopiques (BLUF - Bottom Line Up Front).
    </p>
    <p>
        Les objectifs opérationnels mesurables de la plateforme s'articulent autour de l'efficacité et de la précision. Le système vise une réduction de 60% du temps de qualification d'une alerte grâce à l'enrichissement contextuel automatique, un TTR (Time to Respond) amélioré par l'intégration d'un pipeline MLOps (Machine Learning Operations) basé sur SciBERT pour l'analyse de texte, et une couverture de 99.9% de disponibilité (High Availability) sur ses modules d'ingestion. La plateforme garantit une latence d'ingestion et de propagation des alertes critiques inférieure à 500 millisecondes de bout en bout.
    </p>
    <p>
        Positionnée comme une alternative souveraine, ONYX se distingue par son approche "Zero-Fluff" et "Privacy-First", s'opposant aux solutions boîte noire du marché. Là où des acteurs établis proposent des flux propriétaires opaques, ONYX privilégie l'explicabilité de son IA et le contrôle total des données par l'organisation hébergeuse.
    </p>
    
    <div class="ascii-title">Tableau Comparatif de Positionnement</div>
    <table>
        <thead>
            <tr>
                <th>Dimension</th>
                <th>ONYX CTI (Sovereign)</th>
                <th>Recorded Future</th>
                <th>Mandiant Advantage</th>
                <th>CrowdStrike Falcon</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><strong>Couverture des sources</strong></td>
                <td>Hybride (OSINT + Custom + Private)</td>
                <td>Massive (Scraping global)</td>
                <td>Focalisée Incident Response</td>
                <td>Focalisée Endpoint (EDR)</td>
            </tr>
            <tr>
                <td><strong>Temps Réel & Latence</strong></td>
                <td>Ultra-basse (&lt;500ms, WebSockets)</td>
                <td>Faible (APIs polling)</td>
                <td>Faible (Intégration SIEM)</td>
                <td>Basse (Agent direct)</td>
            </tr>
            <tr>
                <td><strong>Explicabilité IA (XAI)</strong></td>
                <td>Totale (Whitebox NLP, SciBERT)</td>
                <td>Boîte noire (Scores de risque)</td>
                <td>Hybride (Analyst-driven)</td>
                <td>Boîte noire (ML opaque)</td>
            </tr>
            <tr>
                <td><strong>Personnalisation / Graphe</strong></td>
                <td>Extrême (Neo4j, Cytoscape interactif)</td>
                <td>Modérée (Vues standardisées)</td>
                <td>Limitée (Vues rapports)</td>
                <td>Modérée (Graphe de processus)</td>
            </tr>
            <tr>
                <td><strong>Coût et Souveraineté</strong></td>
                <td>On-Premise / Déploiement Souverain</td>
                <td>SaaS très coûteux</td>
                <td>SaaS Premium</td>
                <td>SaaS / EDR lié</td>
            </tr>
        </tbody>
    </table>

    <!-- SECTION 2 -->
    <div class="page-break"></div>
    <h1 id="section-2">2. VUE GLOBALE DE L'ARCHITECTURE</h1>
    <p>L'architecture de la plateforme ONYX CTI s'articule autour d'un modèle "Monolithe Modulaire" fortement couplé à une architecture événementielle. Ce choix garantit la simplicité de déploiement d'un monolithe tout en préservant l'isolation logique des domaines métiers (Actors, Threats, NLP), facilitant une éventuelle transition future vers des microservices purs si la charge le justifie.</p>

    <div class="ascii-title">Schéma d'Architecture Logique (ASCII Art)</div>
    <div class="ascii-art">
  [CLIENT LAYER]
  +-------------------------------------------------------------------------+
  |  Web Browser (React / Next.js 14)                                       |
  |  +---------------+  +---------------+  +---------------+  +----------+  |
  |  | Zustand Store |  | React Query   |  | Cytoscape.js  |  | UI Utils |  |
  |  +---------------+  +---------------+  +---------------+  +----------+  |
  +-----------------------|----------------------^--------------------------+
                          | HTTPS / REST         | WebSockets (WSS)
                          v                      v
  [API GATEWAY & EDGE]
  +-------------------------------------------------------------------------+
  |  Nginx / Kubernetes Ingress / Rate Limiting / SSL Termination           |
  +-----------------------|----------------------^--------------------------+
                          |                      |
  [APPLICATION LAYER (Node.js & Python)]         |
  +-------------------------------------------------------------------------+
  |  +--------------------+  +--------------------+  +--------------------+ |
  |  | Auth & Gateway API |  | Realtime Event Bus |  | CTI Data Services  | |
  |  | (Express/Fastify)  |  | (Socket.io/Redis)  |  | (CRUD, Export STIX)| |
  |  +--------------------+  +--------------------+  +--------------------+ |
  |            |                       |                       |            |
  |  +------------------------------------------------------------------+   |
  |  |  +------------------+   +-------------------+   +-------------+  |   |
  |  |  | SciBERT NLP (Py) |   | Ingestion Workers |   | Report Gen. |  |   |
  |  |  | (FastAPI + Hugg) |   | (Celery / Node)   |   | (Puppeteer) |  |   |
  |  |  +------------------+   +-------------------+   +-------------+  |   |
  |  +------------------------------------------------------------------+   |
  +-------------------|-------------------|--------------------|------------+
                      |                   |                    |
  [DATA LAYER]        v                   v                    v
  +-------------------------------------------------------------------------+
  |  +----------------+  +-----------------+  +--------------+ +----------+ |
  |  | PostgreSQL     |  | Neo4j (Graph)   |  | ElasticSearch| | Redis    | |
  |  | (Relational)   |  | (Threat Models) |  | (Full-text)  | | (Cache)  | |
  |  +----------------+  +-----------------+  +--------------+ +----------+ |
  +-------------------------------------------------------------------------+
    </div>

    <p>
        <strong>Couche de Présentation (Client Layer) :</strong> Développée en Next.js 14, elle centralise l'interface utilisateur. Elle communique via des appels REST (sécurisés par JWT) pour les requêtes transactionnelles, et maintient une connexion WebSocket persistante pour la réception d'événements en temps réel (alertes, mises à jour de nœuds du graphe).
    </p>
    <p>
        <strong>Couche Applicative et Logique Métier (Application Layer) :</strong> Le cœur du système implémente une architecture hexagonale (Ports & Adapters). Le domaine métier (CTI, STIX) est isolé des technologies sous-jacentes. L'API Node.js gère la logique transactionnelle, la sécurité et l'orchestration. Un sous-système Python (FastAPI) est dédié exclusivement aux tâches de Machine Learning intensives (SciBERT), justifiant l'approche polyglotte pour optimiser les performances d'inférence GPU/CPU.
    </p>
    <p>
        <strong>Couche de Données (Data Layer) :</strong> L'architecture adopte une persistance polyglotte. PostgreSQL agit comme source de vérité (Source of Truth) pour les entités relationnelles. Neo4j est utilisé pour la projection en graphe et la résolution de relations complexes (Threat Actor -> Tool -> Vulnerability). Redis assure le caching et la distribution des messages (Pub/Sub).
    </p>
    <p>
        <strong>Flux de données de bout en bout :</strong> Les Workers d'ingestion (CRON) tirent les données brutes (ex: CISA KEV JSON). Les données sont normalisées, enrichies (via SciBERT si texte non structuré), et stockées dans PostgreSQL. L'événement <code>OnNewThreat</code> est publié sur Redis Pub/Sub. Le serveur WebSocket Node.js intercepte l'événement et le diffuse aux clients React. L'état global Zustand du client se met à jour, forçant le re-rendu du composant React Query et l'animation instantanée sur le Cytoscape Threat Graph.
    </p>

    <!-- SECTION 3 -->
    <div class="page-break"></div>
    <h1 id="section-3">3. ARCHITECTURE FRONTEND</h1>
    
    <h2 id="section-3-1">3.1 Stack technologique frontend</h2>
    <p>
        L'application frontend repose sur <strong>Next.js 14 (App Router)</strong>, justifié par son rendu côté serveur (SSR) performant et son architecture de routage par dossiers qui favorise la modularité. <strong>TypeScript strict</strong> est imposé (noImplicitAny, strictNullChecks) pour éliminer les erreurs d'exécution relatives aux structures complexes de données CTI (STIX). <strong>Tailwind CSS</strong> couplé à <strong>Radix UI</strong> (headless components) permet de forger un design system sur-mesure, dense et militaire, sans les surcharges des bibliothèques de composants monolithiques. <strong>React Query (TanStack Query)</strong> gère l'état asynchrone (cache serveur, réinvalidation automatique), tandis que <strong>Zustand</strong> orchestre l'état client éphémère (sélections de nœuds, filtres actifs) avec une empreinte mémoire minimale par rapport à Redux.
    </p>

    <h2 id="section-3-2">3.2 Structure des composants</h2>
    <p>L'arborescence est conçue selon le pattern "Feature-Sliced Design" (FSD) adapté :</p>
<pre><code>src/
├── app/                  # Routes Next.js (/, /actors, /reports, /graph, etc.)
│   ├── layout.tsx        # Shell global, Navigation persistante
│   └── page.tsx          # Dashboard Exécutif
├── components/           # Composants UI agnostiques et réutilisables
│   ├── ui/               # Atomes (Button, Badge, Card, Modal, Tooltip)
│   └── layout/           # Molécules de mise en page (Sidebar, Header, Grids)
├── modules/              # Logique métier isolée par domaine
│   ├── scibert/          # Pipeline NLP, Visualisation d'embeddings
│   ├── threat-graph/     # Wrapper Cytoscape, logique de layout
│   ├── kill-chain/       # Matrice MITRE interactif
│   └── detection/        # Générateur de règles YARA/Sigma
├── hooks/                # Custom React Hooks (useWebSocket, useDebounce)
├── stores/               # Zustand global state (useAppStore, useGraphStore)
├── types/                # Interfaces TS globales (STIX2.1, API Responses)
├── utils/                # Fonctions pures (formatters, data parsers)
├── data/                 # Datasets statiques ou fallbacks (threatActors.ts)
└── styles/               # Design system, variables CSS globales</code></pre>

    <h2 id="section-3-3">3.3 Design system</h2>
    <p>
        L'esthétique de la plateforme est délibérément "Dark Mode Native", évoquant un environnement analytique militaire et premium. Les variables CSS globales définissent une palette chromatique précise : fond principal <code>#0A0E17</code> (Obsidian Blue), panneaux <code>#111827</code> (Slate Dark), texte primaire <code>#E2E8F0</code> (Ice White). Les couleurs d'accentuation portent une sémantique stricte : <code>#EF4444</code> (Critical Alert), <code>#F59E0B</code> (Warning), <code>#3B82F6</code> (Info), <code>#10B981</code> (Secure), et <code>#00E5FF</code> (Cyber Cyan pour les interactions actives).
    </p>
    <p>
        La typographie utilise <em>Inter</em> pour l'interface globale (lisibilité optimale) et <em>JetBrains Mono</em> ou <em>Fira Code</em> pour les métadonnées, les règles de détection (YARA) et les identifiants techniques (Hashes, IPs). Le système d'espacement (spacing) repose sur un module de base de 4px, garantissant un alignement strict. Les animations sont limitées à des micro-interactions de 150ms (courbe ease-in-out) pour maintenir une perception de réactivité instantanée, essentielle dans un contexte SOC.
    </p>

    <h2 id="section-3-4">3.4 Modules fonctionnels</h2>
    <p>L'application est divisée en modules hautement cohésifs :</p>
    <ul>
        <li><strong>SciBERT :</strong> Interface d'analyse sémantique textuelle. Gère la soumission de texte brut, l'affichage des entités nommées (NER) extraites en surbrillance, et la visualisation des scores de similarité cosinus avec les profils d'acteurs connus.</li>
        <li><strong>Graphe de Menaces (Threat Graph) :</strong> Implémentation avancée de Cytoscape.js supportant le rendu WebGL de milliers de nœuds. Gère le clustering par algorithme Force-Directed (Cola/Dagre), la sélection multiple, et le filtrage contextuel (Isoler le sous-graphe d'une campagne).</li>
        <li><strong>Matrice Géopolitique :</strong> Cartographie SVG interactive mondiale liant les zones de conflit aux activités des APT (Advanced Persistent Threats), avec gestion de filtres par région et type de ciblage.</li>
        <li><strong>Laboratoire IA :</strong> Environnement de simulation (sandbox) avec mode "Jury Presentation". Inclut des scénarios pré-chargés (ex: SolarWinds SUNBURST) pour des démonstrations déterministes des capacités analytiques.</li>
        <li><strong>Rapports et Export :</strong> Module de génération asynchrone. Interface de configuration de rapports exécutifs PDF et exportation technique au format JSON STIX 2.1 validé.</li>
    </ul>

    <h2 id="section-3-5">3.5 Gestion d'état et flux de données frontend</h2>
    <p>
        La gestion d'état est strictement scindée. <strong>React Query</strong> est responsable du "Server State" : <code>staleTime</code> est défini à 1 minute pour les données volatiles (incidents) et à 24 heures pour les données statiques (référentiel acteurs). <strong>Zustand</strong> gère le "Client State" : <code>useGraphStore</code> maintient la liste des nœuds sélectionnés et les niveaux de zoom. La synchronisation temps réel s'effectue via un hook <code>useWebSocket</code> qui écoute les événements Socket.io et utilise <code>queryClient.setQueryData()</code> pour mettre à jour le cache React Query en local de manière optimiste, garantissant une UI sans rechargement.
    </p>

    <!-- SECTION 4 -->
    <div class="page-break"></div>
    <h1 id="section-4">4. ARCHITECTURE BACKEND</h1>

    <h2 id="section-4-1">4.1 Stack technologique backend</h2>
    <p>
        L'architecture backend est hybride, reflétant la diversité des charges de travail. L'API principale est construite sur <strong>Node.js avec Express (ou Fastify) et TypeScript</strong>. Node.js excelle dans la gestion des I/O asynchrones, idéal pour router des requêtes, interagir avec la base de données et maintenir des milliers de connexions WebSocket ouvertes. Parallèlement, un microservice <strong>Python avec FastAPI</strong> est dédié au module d'analyse sémantique SciBERT. Python est incontournable pour l'écosystème ML (PyTorch, Transformers). La coexistence est justifiée : Node.js orchestre et sert l'UI à haute fréquence, tandis que FastAPI expose une interface interne synchrone et intensive en calcul.
    </p>

    <h2 id="section-4-2">4.2 API REST — endpoints documentés</h2>
    <p>L'API suit les principes RESTful avec une stricte validation des payloads (zod/joi).</p>
    <table>
        <thead>
            <tr>
                <th>Méthode</th>
                <th>Endpoint</th>
                <th>Rôle et Paramètres</th>
                <th>Code / Réponse</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>POST</td>
                <td><code>/api/auth/login</code></td>
                <td>Authentification. Body: <code>{ email, password }</code></td>
                <td>200 OK - <code>{ token, refreshToken }</code></td>
            </tr>
            <tr>
                <td>GET</td>
                <td><code>/api/actors</code></td>
                <td>Liste les menaces. Query: <code>?region=europe&amp;type=apt</code></td>
                <td>200 OK - Array of ThreatActor objects</td>
            </tr>
            <tr>
                <td>GET</td>
                <td><code>/api/actors/:id/iocs</code></td>
                <td>Récupère les IoCs liés à un acteur spécifique.</td>
                <td>200 OK - Array of STIX Indicators</td>
            </tr>
            <tr>
                <td>POST</td>
                <td><code>/api/nlp/analyze</code></td>
                <td>Soumission texte pour SciBERT. Body: <code>{ text }</code></td>
                <td>200 OK - <code>{ entities, matches, confidence }</code></td>
            </tr>
            <tr>
                <td>GET</td>
                <td><code>/api/reports</code></td>
                <td>Liste les rapports générés.</td>
                <td>200 OK - Array of Report Metadata</td>
            </tr>
            <tr>
                <td>POST</td>
                <td><code>/api/reports/generate</code></td>
                <td>Déclenche la génération PDF. Body: <code>{ type, filter }</code></td>
                <td>202 Accepted - <code>{ jobId }</code></td>
            </tr>
            <tr>
                <td>GET</td>
                <td><code>/api/reports/:id/pdf</code></td>
                <td>Téléchargement du fichier binaire PDF.</td>
                <td>200 OK - <code>application/pdf</code> stream</td>
            </tr>
            <tr>
                <td>POST</td>
                <td><code>/api/export/stix</code></td>
                <td>Génère un bundle STIX. Body: <code>{ actorIds[] }</code></td>
                <td>200 OK - STIX 2.1 Bundle JSON</td>
            </tr>
        </tbody>
    </table>

    <h2 id="section-4-3">4.3 Module d'analyse sémantique SciBERT</h2>
    <p>
        Le pipeline NLP est hébergé sur le service Python. Il utilise le modèle <code>allenai/scibert_scivocab_uncased</code> via la librairie HuggingFace Transformers. SciBERT, pré-entraîné sur des corpus scientifiques, se révèle exceptionnellement performant pour comprendre la sémantique technique des rapports de cybersécurité (noms de malware, TTPs, CVEs).
    </p>
    <div class="ascii-title">Pipeline NLP SciBERT (ASCII Art)</div>
    <div class="ascii-art">
[RAW TEXT INPUT] -> (Node.js API) -> (FastAPI Service)
       |
       v
[PREPROCESSING] (Regex cleanup, sentence tokenization)
       |
       v
[SCIBERT TOKENIZER] (Subword tokenization, [CLS] & [SEP] padding)
       |
       v
[SCIBERT MODEL] (PyTorch Inference / GPU Accelerated)
       |
       v
[POOLING LAYER] (Mean pooling of hidden states -> 768d Vector)
       |
       v
[COSINE SIMILARITY] (Match vector against pre-computed Threat Actor Vectors)
       |
       v
[POST-PROCESSING] (Threshold filtering > 0.85, JSON formatting) -> [OUTPUT]
    </div>

    <h2 id="section-4-4">4.4 Pipeline d'ingestion CTI</h2>
    <p>
        Le moteur d'ingestion s'appuie sur un planificateur (node-cron ou agenda.js). Des workers spécialisés interrogent les sources externes (CISA KEV, Abuse.ch, AlienVault OTX) à des fréquences variables (ex: toutes les 5 minutes pour les IPs malicieuses, toutes les 24h pour les CVEs).
        Chaque flux de données entrant subit une série de transformations :
        1. <strong>Extraction :</strong> Parsing du format source (CSV, JSON, TAXII).
        2. <strong>Normalisation :</strong> Mapping des champs vers le modèle de données interne ONYX (inspiré de STIX).
        3. <strong>Déduplication :</strong> Calcul d'un hash cryptographique (SHA-256) sur les champs clés de l'IoC (ex: valeur de l'IP + type). Si le hash existe, mise à jour de la date de "last_seen" et du compteur d'occurrences.
        4. <strong>Scoring :</strong> Attribution dynamique d'un score de sévérité basé sur la réputation de la source et la présence dans d'autres feeds (corrélation).
    </p>

    <h2 id="section-4-5">4.5 Gestion des WebSockets et temps réel</h2>
    <p>
        L'architecture temps réel utilise <strong>Socket.io</strong> couplé à un adaptateur <strong>Redis</strong> pour le scaling horizontal. Le serveur WebSocket organise les clients en "rooms" logiques (ex: <code>room:threat_graph</code>, <code>room:alerts_critical</code>). Lorsqu'un worker d'ingestion détecte un nouvel incident critique de sévérité haute, l'API Node.js publie un événement via Redis Pub/Sub. Le serveur Socket.io capte cet événement et le "broadcast" instantanément à tous les clients connectés à la room appropriée. Une stratégie de "heartbeat" (ping/pong) maintient la connexion active, avec reconnexion automatique exponentielle (exponential backoff) côté client en cas de perte réseau.
    </p>

    <!-- SECTION 5 -->
    <div class="page-break"></div>
    <h1 id="section-5">5. ARCHITECTURE DE LA BASE DE DONNÉES</h1>

    <h2 id="section-5-1">5.1 Stratégie multi-bases (Polyglot Persistence)</h2>
    <p>
        L'exigence de performance et de requêtage complexe de la CTI interdit l'usage d'une base unique. 
        <strong>PostgreSQL</strong> (ACID) est le stockage primaire (Source of Truth) pour la gestion des utilisateurs, les méta-données des acteurs et les journaux d'audit.
        <strong>Elasticsearch</strong> est déployé pour indexer des millions d'IoCs (hashes, IPs, domaines) et de textes libres (rapports externes), permettant des recherches full-text quasi instantanées et des agrégations complexes.
        <strong>Neo4j</strong> est indispensable pour le moteur de Graphe. Les requêtes relationnelles classiques (SQL) deviennent exponentiellement lentes (JOINs multiples) pour déterminer si l'Acteur A utilise le Malware B qui exploite la Vulnérabilité C hébergée sur l'IP D. Neo4j résout cela nativement via le parcours de graphe.
        <strong>Redis</strong> agit comme un cache en mémoire ultrarapide pour alléger PostgreSQL sur les requêtes fréquentes (top 10 menaces).
    </p>

    <h2 id="section-5-2">5.2 Schéma de base de données PostgreSQL</h2>
    <p>Le schéma relationnel garantit l'intégrité des entités structurées.</p>
<pre><code class="language-sql">-- Extrait du schéma DDL
CREATE TABLE threat_actors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    aliases TEXT[],
    origin_country VARCHAR(100),
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE iocs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    value VARCHAR(512) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'ipv4-addr', 'file:hashes.md5', 'domain-name'
    severity_score INTEGER CHECK (severity_score >= 0 AND severity_score &lt;= 100),
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    source_feed VARCHAR(100),
    UNIQUE(value, type)
);

CREATE TABLE campaigns (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    actor_id UUID REFERENCES threat_actors(id) ON DELETE CASCADE,
    objective TEXT,
    start_date DATE
);

-- Index pour optimiser les requêtes fréquentes
CREATE INDEX idx_iocs_value_type ON iocs(value, type);
CREATE INDEX idx_campaigns_actor ON campaigns(actor_id);
</code></pre>

    <h2 id="section-5-3">5.3 Modèle de graphe (Neo4j)</h2>
    <p>
        L'ontologie du graphe mappe directement la spécification STIX 2.1.
        <strong>Nœuds :</strong> <code>(:ThreatActor)</code>, <code>(:Malware)</code>, <code>(:Vulnerability {cve_id})</code>, <code>(:Infrastructure {ip})</code>, <code>(:Campaign)</code>, <code>(:Identity {sector})</code>.
        <strong>Relations (Edges) :</strong> <code>-[:USES]-&gt;</code>, <code>-[:TARGETS]-&gt;</code>, <code>-[:EXPLOITS]-&gt;</code>, <code>-[:ATTRIBUTED_TO]-&gt;</code>.
    </p>
    <p>Requête Cypher de référence pour analyser la chaîne d'attaque d'un acteur :</p>
<pre><code class="language-cypher">MATCH path = (a:ThreatActor {name: "APT29"})-[:USES]-&gt;(m:Malware)-[:EXPLOITS]-&gt;(v:Vulnerability)
RETURN path
LIMIT 50;
</code></pre>

    <h2 id="section-5-4">5.4 Stratégie de cache Redis</h2>
    <p>
        Le pattern <em>Cache-Aside</em> est implémenté. L'API interroge d'abord Redis. En cas de <em>Cache Miss</em>, elle interroge PostgreSQL, renvoie la réponse au client et stocke asynchronement le résultat dans Redis.
        Configurations de TTL (Time-To-Live) : 
        - Sessions Utilisateurs JWT : 24h
        - Méta-données Géopolitiques : 6h (faible volatilité)
        - Flux CTI (Top menaces) : 3h
        - Résultats Inférence SciBERT : 1h (optimisation des requêtes répétées sur le même texte).
    </p>

    <h2 id="section-5-5">5.5 Migrations et versionning du schéma</h2>
    <p>
        <strong>Prisma Migrate</strong> est sélectionné pour son intégration native avec TypeScript. Les fichiers de migration (fichiers <code>.sql</code>) sont versionnés dans le dossier <code>prisma/migrations/</code> (ex: <code>202604241030_init_schema.sql</code>). Lors du pipeline CI/CD de déploiement, la commande <code>npx prisma migrate deploy</code> est exécutée de manière transactionnelle. En cas d'échec d'une migration en production, la stratégie implique une restauration du snapshot de base de données (Point-in-Time Recovery - PITR) et un rollback du déploiement applicatif.
    </p>

    <!-- SECTION 6 -->
    <div class="page-break"></div>
    <h1 id="section-6">6. INTÉGRATIONS ET SOURCES DE DONNÉES</h1>

    <h2 id="section-6-1">6.1 APIs externes intégrées</h2>
    <p>La valeur de la plateforme ONYX réside dans la corrélation d'une multitude de sources externes qualifiées :</p>
    <ul>
        <li><strong>CISA KEV (Known Exploited Vulnerabilities) :</strong> Endpoint JSON public. Polling quotidien. Les CVEs signalées sont transformées en nœuds <code>(:Vulnerability {exploited: true})</code> dans Neo4j. Volume estimé : ~1000 entrées.</li>
        <li><strong>Abuse.ch URLhaus / Feodo Tracker :</strong> API REST POST publique et flux CSV. Polling toutes les 5 minutes pour la réactivité sur les serveurs de commande et contrôle (C2) et la distribution de malwares. Données stockées en index Elasticsearch et PostgreSQL. Volume estimé : ~100k actifs/jour.</li>
        <li><strong>AlienVault OTX (Open Threat Exchange) :</strong> API REST avec clé d'authentification. Ingère les "Pulses" (rapports communautaires) via polling horaire. Extraction des IoCs associés.</li>
        <li><strong>MITRE ATT&CK :</strong> Flux JSON via protocole TAXII. Polling hebdomadaire. Alimente statiquement la matrice Kill Chain et les descriptions de TTPs.</li>
        <li><strong>NVD NIST CVE :</strong> API REST publique 2.0. Base de référence pour enrichir les descriptions techniques et les scores CVSS des vulnérabilités ingérées depuis d'autres sources.</li>
    </ul>

    <h2 id="section-6-2">6.2 Stratégie de fallback et résilience</h2>
    <p>
        Les APIs externes sont par nature instables (Rate limiting, pannes). Le pattern <strong>Circuit Breaker</strong> (via la bibliothèque <code>opossum</code> en Node.js) est implémenté. Si une source échoue (ex: NVD renvoie 503) plus de 5 fois en 1 minute, le circuit s'ouvre : les appels suivants sont bloqués immédiatement pour éviter la surcharge. Pendant l'ouverture du circuit, le système bascule sur un <strong>Fallback Dataset</strong> de référence local en lecture seule, garantissant la continuité de service pour l'interface utilisateur. Des alertes Grafana sont déclenchées si un circuit reste ouvert plus de 15 minutes.
    </p>

    <h2 id="section-6-3">6.3 Format STIX 2.1 — implémentation</h2>
    <p>
        STIX (Structured Threat Information Expression) 2.1 est le cœur du modèle de données pivot. L'exportation de données depuis ONYX génère des <em>STIX Bundles</em> conformes à la norme OASIS.
        Le mapping de notre graphe Neo4j vers STIX est direct :
        - Un nœud <code>(:ThreatActor)</code> génère un objet STIX <code>threat-actor</code>.
        - Un nœud <code>(:Malware)</code> génère un objet STIX <code>malware</code>.
        - La relation <code>-[:USES]-&gt;</code> génère un objet STIX <code>relationship</code> avec <code>relationship_type: "uses"</code>.
        La validité du bundle JSON est systématiquement vérifiée par un schéma JSON de validation avant la génération finale, assurant une ingestion sans friction par des plateformes tierces comme MISP, OpenCTI, ou l'intégration native dans Splunk Enterprise Security.
    </p>

    <!-- SECTION 7 -->
    <div class="page-break"></div>
    <h1 id="section-7">7. SÉCURITÉ ET CONFORMITÉ</h1>

    <h2 id="section-7-1">7.1 Authentification et autorisation</h2>
    <p>
        L'authentification repose sur des <strong>JSON Web Tokens (JWT)</strong> asymétriques (algorithme RS256). Pour limiter l'impact d'un vol de token, la durée de vie du <em>Access Token</em> est de 15 minutes. Une stratégie de <em>Refresh Token Rotation</em> est en place : un token de rafraîchissement (stocké en base de données et dans un cookie HTTP-Only, Secure) est utilisé pour obtenir un nouvel Access Token, le Refresh Token précédent étant alors invalidé. 
        Le contrôle d'accès est basé sur les rôles (RBAC) :
        - <em>Administrateur</em> : Accès total, configuration système, gestion des utilisateurs.
        - <em>Analyste Senior</em> : Modification des graphes, déclenchement d'actions (export, génération de rapports).
        - <em>Analyste Junior</em> : Consultation, enrichissement manuel d'IoCs.
        - <em>Lecteur</em> : Consultation en lecture seule (tableaux de bord exécutifs).
        L'authentification multifacteur (MFA) via TOTP (Time-Based One-Time Password) est obligatoire pour les rôles Analyste Senior et Administrateur.
    </p>

    <h2 id="section-7-2">7.2 Sécurité applicative</h2>
    <p>
        Toutes les entrées API sont strictement validées et typées au moment de l'exécution à l'aide de la librairie <strong>Zod</strong>. Toute requête contenant des propriétés non définies dans le schéma est rejetée (Status 400).
        Les en-têtes de sécurité HTTP sont appliqués via Helmet.js : Content-Security-Policy (CSP) stricte bloquant les scripts inline, HSTS (Strict-Transport-Security) forçant l'usage de TLS, et X-Frame-Options réglé sur DENY pour prévenir le Clickjacking.
        Les attaques par Injection SQL sont prévenues architecturalement par l'utilisation exclusive d'un ORM (Prisma) qui paramètre les requêtes de bas niveau.
        Un middleware de <strong>Rate Limiting</strong> (Redis) plafonne les requêtes à 100 requêtes/minute par adresse IP, et 20 requêtes/minute pour l'endpoint d'authentification afin de contrer le brute-force.
    </p>

    <h2 id="section-7-3">7.3 Sécurité des données</h2>
    <p>
        La sécurité des données au repos (Data at Rest) dans la base PostgreSQL est assurée au niveau du disque par l'infrastructure cloud ou on-premise (chiffrement de volume AES-256). Pour les données applicatives hautement sensibles (ex: notes d'investigation internes d'un analyste), un chiffrement applicatif en AES-256-GCM est appliqué avant l'insertion en base, la clé de chiffrement étant gérée par un KMS (Key Management Service).
        Les données en transit (Data in Transit) imposent le protocole <strong>TLS 1.3</strong> de bout en bout, de l'Ingress Controller jusqu'aux pods applicatifs dans le cluster. Les journaux d'application (logs) sont nettoyés (sanitization) pour s'assurer de ne jamais consigner de mots de passe, tokens ou données PII (Personally Identifiable Information).
    </p>

    <h2 id="section-7-4">7.4 Conformité</h2>
    <p>
        L'architecture supporte nativement le <strong>TLP (Traffic Light Protocol)</strong> (TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:RED) standard dans le milieu du renseignement. Chaque indicateur, rapport ou entité graphe possède un attribut TLP. L'API filtre automatiquement les données retournées selon les habilitations de l'utilisateur et le TLP de la donnée.
        Pour la conformité RGPD, bien que traitant majoritairement des données techniques (IPs, Hashes), les données utilisateurs sont minimisées. Une procédure de purge automatisée (Droit à l'oubli) permet de supprimer ou d'anonymiser irréversiblement les traces d'un analyste (audit logs liés à un UUID au lieu du nom). La plateforme s'aligne sur les recommandations du guide d'hygiène informatique de l'ANSSI pour le déploiement.
    </p>

    <!-- SECTION 8 -->
    <div class="page-break"></div>
    <h1 id="section-8">8. INFRASTRUCTURE ET DÉPLOIEMENT</h1>

    <h2 id="section-8-1">8. Architecture de déploiement</h2>
    <p>
        L'infrastructure est conçue pour être "Cloud-Native" et agnostique vis-à-vis du fournisseur, permettant un déploiement "On-Premise" strict (Air-Gapped) ou Cloud public (AWS/Azure). Chaque composant applicatif est conteneurisé via des images <strong>Docker</strong> optimisées et minimalistes (distroless ou Alpine) pour réduire la surface d'attaque.
        Pour le développement local, un fichier <code>docker-compose.yml</code> orchestre les bases de données (PostgreSQL, Redis, Neo4j, Elasticsearch) et les services Node.js/Python, offrant un environnement "Production-like" reproductible d'une simple commande.
        En production, <strong>Kubernetes (K8s)</strong> assure l'orchestration. Les composants Stateless (API Node.js, Service SciBERT Python, UI Next.js) sont gérés par des <em>Deployments</em> Kubernetes couplés à des <em>Horizontal Pod Autoscalers (HPA)</em> réagissant à la charge CPU. Les composants Stateful (Bases de données) utilisent des <em>StatefulSets</em> avec des volumes persistants (PVC). L'exposition externe passe par un <em>Ingress Controller</em> (NGINX ou Traefik) qui gère la terminaison TLS.
    </p>

    <h2 id="section-8-2">8.2 Pipeline CI/CD</h2>
    <p>
        L'intégration et le déploiement continus s'appuient sur <strong>GitHub Actions</strong> (ou GitLab CI pour un contexte souverain local). Le workflow est exécuté à chaque Pull Request :
        1. <strong>Qualité et Sécurité :</strong> Exécution de <code>npm run lint</code> (ESLint), <code>npm run typecheck</code> (TypeScript compiler), et scan de vulnérabilités des dépendances (<code>npm audit</code>, Trivy).
        2. <strong>Tests automatisés :</strong> Exécution de la suite de tests unitaires (Vitest) et d'intégration (Supertest avec base de test éphémère). Une PR ne peut être mergée si la couverture de code descend sous la barre des 80%.
        3. <strong>Build et Publication :</strong> Au merge sur la branche <code>main</code>, l'image Docker applicative est construite, taggée avec le hash du commit (ex: <code>onyx-api:1.0.4-a1b2c3d</code>) et poussée vers un registre privé.
        4. <strong>Déploiement :</strong> Le déploiement sur l'environnement de "Staging" est automatique. Le déploiement en "Production" nécessite une approbation manuelle dans l'interface CI, déclenchant l'application des manifests Kubernetes (via ArgoCD en mode GitOps ou Helm).
    </p>

    <h2 id="section-8-3">8.3 Monitoring et observabilité</h2>
    <p>
        L'observabilité est critique pour une plateforme CTI devant traiter des flux temps réel. La stack de monitoring est basée sur <strong>Prometheus et Grafana</strong>. L'API Node.js expose un endpoint <code>/metrics</code> (format Prometheus) rapportant le nombre de requêtes par seconde, la latence moyenne, le nombre d'IoCs ingérés par minute, et l'utilisation de la mémoire.
        Des alertes automatisées (via Alertmanager vers Slack ou PagerDuty) sont configurées pour :
        - Un temps de réponse API (p99) supérieur à 500ms sur une fenêtre de 5 minutes.
        - Un taux d'erreur HTTP 5xx supérieur à 1%.
        - Une indisponibilité d'un feed CTI majeur (ex: KEV) pendant plus de 2 heures.
        Les logs applicatifs sont consolidés et indexés par <strong>Grafana Loki</strong>, permettant une corrélation directe entre les métriques de performance et les journaux d'erreurs textuels, sans la complexité d'une stack ELK lourde.
    </p>

    <h2 id="section-8-4">8.4 Environnements et Gestion des Secrets</h2>
    <p>
        La stratégie multi-environnements distingue trois contextes :
        - <strong>Local / Dev</strong> : Services mockés, bases locales, secrets injectés via fichiers <code>.env</code>.
        - <strong>Staging / Pre-Prod</strong> : Réplique exacte de la production en termes de topologie réseau et Kubernetes, avec données anonymisées ou restreintes. Permet la validation métier finale.
        - <strong>Production</strong> : Cluster sécurisé, accès restreint.
        La gestion des secrets (clés d'API OTX, mots de passe de base de données, clés JWT) en production proscrit l'utilisation de variables d'environnement en clair. La solution préconisée est <strong>HashiCorp Vault</strong> (ou AWS Secrets Manager/Azure Key Vault), qui injecte les secrets directement dans les pods Kubernetes au démarrage via un provider CSI, assurant la rotation des secrets et la traçabilité des accès.
    </p>

    <!-- SECTION 9 -->
    <div class="page-break"></div>
    <h1 id="section-9">9. PLAN D'IMPLÉMENTATION PAR PHASES</h1>

    <p>Le développement et la mise en production de la plateforme ONYX suivent une méthodologie agile itérative sur un cycle de 12 semaines, divisé en 5 phases critiques.</p>

    <h2 id="section-9-0">Phase 0 — Fondations (Semaines 1-2)</h2>
    <p>
        <strong>Objectifs :</strong> Établir l'infrastructure de développement et l'architecture de base (le "Squelette").<br>
        <strong>Livrables :</strong> Monorepo configuré (Turborepo) avec linting/Prettier stricts. Mise en place du pipeline CI (GitHub Actions). Déploiement de la base de données PostgreSQL initiale et du serveur d'authentification (JWT/RBAC). Initialisation du frontend Next.js avec le Design System atomique de base (Couleurs, Typographie, Composants génériques).<br>
        <strong>Risques :</strong> Retard dans la définition du modèle de données de base. <em>Mitigation :</em> Adopter le standard STIX 2.1 comme source de vérité structurelle immédiate.
    </p>

    <h2 id="section-9-1">Phase 1 — Modules de Données (Semaines 3-4)</h2>
    <p>
        <strong>Objectifs :</strong> Mettre en œuvre la mécanique d'ingestion et de peuplement du système.<br>
        <strong>Livrables :</strong> Développement des Workers d'ingestion asynchrones. Intégration des flux publics (CISA KEV, Abuse.ch). Implémentation de la déduplication et du scoring de sévérité. Déploiement du microservice Python avec le modèle SciBERT basique opérationnel via API FastAPI. Interface frontend de la "Matrice Géopolitique" connectée à des données d'acteurs de référence statiques.<br>
        <strong>Risques :</strong> Variabilité des formats des feeds externes. <em>Mitigation :</em> Créer une couche "Adapter" stricte validant le schéma avant l'ingestion interne.
    </p>

    <h2 id="section-9-2">Phase 2 — Modules Analytiques (Semaines 5-6)</h2>
    <p>
        <strong>Objectifs :</strong> Rendre la donnée ingérée visuellement exploitable pour l'analyste.<br>
        <strong>Livrables :</strong> Déploiement de la base orientée graphe (Neo4j). Développement du composant "Graphe de Menaces" frontend en Cytoscape.js supportant le rendu WebGL et les layouts Force-Directed. Interface de modélisation "Kill Chain" (MITRE ATT&CK) interactive. Création des vues "Fiches Complètes" pour les Threat Actors avec enrichissement des TTPs.<br>
        <strong>Risques :</strong> Performances de rendu du graphe dans le navigateur avec des milliers de nœuds. <em>Mitigation :</em> Implémenter un clustering dynamique (Regroupement) et de la pagination de graphe au niveau API.
    </p>

    <h2 id="section-9-3">Phase 3 — Intelligence Avancée et Temps Réel (Semaines 7-8)</h2>
    <p>
        <strong>Objectifs :</strong> Transformer le tableau de bord statique en une plateforme réactive et intelligente.<br>
        <strong>Livrables :</strong> Mise en place du serveur WebSocket et de l'infrastructure Redis Pub/Sub. Intégration de la remontée d'alertes en temps réel sur l'UI (Toasts, mise à jour du Graphe sans rechargement). Finalisation du "Laboratoire IA" avec le scénario déterministe complet (SolarWinds SUNBURST) prêt pour présentation. Fonctionnalité d'export asynchrone des bundles STIX 2.1 validés.<br>
        <strong>Risques :</strong> Surcharge du serveur WebSocket en cas d'afflux massif de nouveaux IoCs. <em>Mitigation :</em> Implémentation du "Throttling" et du "Debouncing" des événements côté serveur.
    </p>

    <h2 id="section-9-4">Phase 4 &amp; 5 — Premium, Optimisation, Déploiement (Semaines 9-12)</h2>
    <p>
        <strong>Objectifs :</strong> Polissage final "Executive-Grade", sécurisation et lancement.<br>
        <strong>Livrables :</strong> (S9-10) Création du Tableau de Bord Exécutif (BLUF, métriques macroscopiques). Générateur de rapports dynamiques PDF exécutés via Puppeteer en backend. Campagne d'optimisation des performances (Core Web Vitals cibles atteints, Lazy Loading). (S11-12) Déploiement complet en production via manifests Kubernetes. Configuration des dashboards de monitoring Grafana. Documentation opérationnelle finalisée et remise. Formation de la première cohorte d'utilisateurs SOC.<br>
        <strong>Risques :</strong> Régressions de performance sur l'environnement de production sous charge réelle. <em>Mitigation :</em> Campagne de tests de charge massifs (K6/JMeter) sur l'environnement de Staging durant la semaine 10.
    </p>

    <!-- SECTION 10 -->
    <div class="page-break"></div>
    <h1 id="section-10">10. BONNES PRATIQUES ET RECOMMANDATIONS</h1>

    <h2 id="section-10-1">Conventions de Code et Qualité</h2>
    <p>
        Le maintien d'un code de niveau militaire exige une rigueur absolue. L'utilisation d'<strong>ESLint</strong> avec la configuration recommandée de TypeScript et <strong>Prettier</strong> est imposée de force via des hooks <code>pre-commit</code> (Husky). Le code non conforme n'entre pas dans le dépôt.
        Les conventions de nommage TypeScript suivent le standard de l'industrie : <code>PascalCase</code> pour les Interfaces, Types et Composants React ; <code>camelCase</code> pour les fonctions, variables et instances ; <code>UPPER_SNAKE_CASE</code> pour les constantes globales. Aucun type <code>any</code> n'est toléré (<code>eslint: @typescript-eslint/no-explicit-any</code> réglé sur "error").
    </p>

    <h2 id="section-10-2">Stratégie de Tests</h2>
    <p>
        La pyramide de tests vise une couverture de code de 80% des chemins critiques :
        - <strong>Tests Unitaires (Vitest) :</strong> Valident la logique métier isolée, les fonctions pures (utils), et le reducer Zustand. Exécution rapide en CI.
        - <strong>Tests d'Intégration (Supertest + Base éphémère) :</strong> Valident les contrats API (Endpoints REST), les insertions en base et l'interaction entre les couches Controller/Service/Repository.
        - <strong>Tests E2E (Playwright) :</strong> Simulent les flux utilisateurs critiques depuis un navigateur headless (Login, création de rapport, navigation dans le graphe). Limités en nombre pour éviter la fragilité des tests et la lenteur d'exécution CI.
    </p>

    <h2 id="section-10-3">Documentation Systémique</h2>
    <p>
        Le code doit être auto-documenté autant que possible par un nommage explicite, cependant des blocs <strong>JSDoc</strong> sont obligatoires pour toutes les fonctions publiques, utilitaires complexes et interfaces. Chaque module principal dans l'arborescence (ex: <code>src/modules/scibert</code>) doit contenir un fichier <code>README.md</code> expliquant son architecture interne et son comportement. L'API backend expose une documentation interactive vivante générée automatiquement via <strong>OpenAPI 3.0 / Swagger</strong>, accessible sur l'endpoint <code>/api-docs</code> en environnement de développement.
    </p>

    <h2 id="section-10-4">Gestion des Erreurs et Résilience</h2>
    <p>
        L'utilisation de blocs <code>try/catch</code> génériques est proscrite au profit de <strong>classes d'erreurs typées</strong> (ex: <code>NotFoundError</code>, <code>ValidationException</code>, <code>ExternalAPIError</code>). Toutes les erreurs techniques sont interceptées par un middleware central Node.js. Le logger structuré (Pino ou Winston) consigne l'erreur avec la stack trace complète (niveau ERROR). L'API renvoie au client un message d'erreur standardisé, édulcoré (sans exposer l'architecture sous-jacente) et localisé en français.
    </p>

    <h2 id="section-10-5">Performance Frontend</h2>
    <p>
        L'interface doit rester fluide même lors de la manipulation de datasets volumineux. Le <strong>Code Splitting</strong> et le <strong>Lazy Loading</strong> sont configurés via <code>next/dynamic</code> : le moteur lourd Cytoscape.js n'est chargé que lorsque l'utilisateur accède à la route "Graphe". Les images et assets statiques utilisent le composant natif Next.js <code>&lt;Image&gt;</code> pour l'optimisation des formats (WebP/AVIF). Les métriques "Core Web Vitals" cibles sont strictes : un LCP (Largest Contentful Paint) inférieur à 2.5 secondes et un CLS (Cumulative Layout Shift) proche de 0, garanti par des dimensions explicites sur tous les conteneurs d'interface dynamiques.
    </p>

    <!-- SECTION 11 -->
    <div class="page-break"></div>
    <h1 id="section-11">11. GLOSSAIRE ET RÉFÉRENCES</h1>

    <h2 id="section-11-1">Glossaire CTI</h2>
    <ul>
        <li><strong>APT (Advanced Persistent Threat) :</strong> Acteur malveillant souvent étatique, menant des campagnes d'espionnage ou de sabotage ciblées et prolongées.</li>
        <li><strong>TTP (Tactics, Techniques, and Procedures) :</strong> Description comportementale de la façon dont un adversaire opère. Les TTPs sont le niveau le plus précieux de l'intelligence selon la "Pyramide de la Douleur" de David Bianco.</li>
        <li><strong>IoC (Indicator of Compromise) :</strong> Empreinte technique laissée par une attaque (adresse IP de C2, hash de fichier malveillant, domaine frauduleux).</li>
        <li><strong>STIX (Structured Threat Information Expression) :</strong> Langage standardisé (JSON) pour représenter et échanger des informations sur les menaces cybernétiques.</li>
        <li><strong>TAXII (Trusted Automated Exchange of Intelligence Information) :</strong> Protocole de transport conçu spécifiquement pour l'échange de données STIX sur HTTPS.</li>
        <li><strong>Kill Chain (Cyber Kill Chain) :</strong> Modèle développé par Lockheed Martin décrivant les phases d'une cyberattaque (Reconnaissance, Weaponization, Delivery, Exploitation, Installation, C2, Actions on Objectives).</li>
        <li><strong>MITRE ATT&CK :</strong> Base de connaissances globale de tactiques et techniques adversaires, utilisée massivement comme framework de référence pour modéliser les menaces.</li>
        <li><strong>CVSS (Common Vulnerability Scoring System) :</strong> Standard ouvert pour évaluer la gravité des vulnérabilités logicielles.</li>
        <li><strong>YARA / Sigma :</strong> Langages de création de règles de détection. YARA pour identifier des patterns dans les fichiers (malwares), Sigma pour les événements de logs (SIEM).</li>
        <li><strong>C2 / C&C (Command and Control) :</strong> Serveur contrôlé par un attaquant servant à envoyer des commandes aux systèmes compromis et exfiltrer des données.</li>
    </ul>

    <h2 id="section-11-2">Références Architecturales et Standards</h2>
    <ul>
        <li>OASIS Cyber Threat Intelligence (CTI) Technical Committee - <em>STIX Version 2.1 Specification</em>.</li>
        <li>MITRE Corporation - <em>ATT&CK® Design and Philosophy</em>.</li>
        <li>Google Research - <em>SciBERT: A Pretrained Language Model for Scientific Text</em> (Beltagy et al., 2019).</li>
        <li>Neo4j Graph Database - <em>Graph Modeling Guidelines for Cyber Security</em>.</li>
        <li>Next.js Documentation - <em>App Router &amp; React Server Components Architecture</em>.</li>
        <li>Agence Nationale de la Sécurité des Systèmes d'Information (ANSSI) - <em>Guide d'hygiène informatique (2024)</em>.</li>
    </ul>

    </body>
    </html>
    `; // END OF HTML

    // Écrire le contenu HTML temporairement pour debug ou vérification
    fs.writeFileSync('architecture_document.html', htmlContent);
    console.log("Fichier HTML généré temporairement.");

    // Configurer le contenu sur Puppeteer
    await page.setContent(htmlContent, { waitUntil: 'networkidle0' });

    // Générer le PDF avec les options spécifiées par l'utilisateur
    console.log("Génération du document PDF en cours...");
    await page.pdf({
        path: '../onyx-dashboard/public/ONYX_CTI_Architecture_Complete.pdf',
        format: 'A4',
        printBackground: true,
        margin: {
            top: '30px',
            right: '2cm',
            bottom: '80px',
            left: '2cm'
        },
        displayHeaderFooter: true,
        headerTemplate: `
            <div style="font-size: 8pt; font-family: 'Helvetica', sans-serif; width: 100%; display: flex; justify-content: space-between; padding: 0 2cm; color: #555; align-items: center;">
                <div>ONYX CTI</div>
                <div style="font-weight: bold; color: #0a192f; text-transform: uppercase;">Architecture Technique Complète</div>
                <div><img src="data:image/svg+xml;utf8,<svg width='20' height='20' viewBox='0 0 24 24' fill='none' stroke='%230a192f' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><polygon points='12 2 2 7 12 12 22 7 12 2'></polygon><polyline points='2 17 12 22 22 17'></polyline><polyline points='2 12 12 17 22 12'></polyline></svg>" width="16" height="16"/></div>
            </div>
        `,
        footerTemplate: `
            <div style="font-size: 8pt; font-family: 'Helvetica', sans-serif; width: 100%; display: flex; justify-content: space-between; padding: 0 2cm; color: #555; align-items: center;">
                <div>CONFIDENTIEL — ONYX CTI v4.2</div>
                <div>Page <span class="pageNumber"></span> sur <span class="totalPages"></span></div>
                <div class="date"></span></div>
            </div>
        `
    });

    console.log("Document PDF généré avec succès : ONYX_CTI_Architecture_Complete.pdf (sauvegardé dans public/)");
    await browser.close();
}

generatePDF().catch(console.error);
