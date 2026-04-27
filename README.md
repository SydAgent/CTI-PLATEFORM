# 🛡️ ONYX CTI v3.0 Genesis

**Plateforme de Cyber Threat Intelligence (CTI) en temps réel**, conçue pour l'analyse opérationnelle et stratégique des menaces cyber, l'agrégation OSINT multi-sources, et la corrélation acteurs / campagnes / IOCs / vulnérabilités.

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Next.js](https://img.shields.io/badge/Next.js-14-black)
![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 🎯 Vue d'ensemble

ONYX CTI agrège en temps réel **15+ sources OSINT gratuites** (URLhaus, ThreatFox, AlienVault OTX, MITRE ATT&CK, GDELT, CISA KEV, etc.) pour offrir :

- 📊 **Tableau de bord stratégique** avec score de risque global, alertes prioritaires, top acteurs
- 🌍 **Matrice géopolitique interactive** (deck.gl) avec arcs de manœuvre entre pays
- 🕸️ **Graphe de menaces** dynamique (Cytoscape.js) avec relations acteurs/malwares/CVEs/IOCs
- 🔍 **Explorateur IOC** avec filtres avancés
- 🎭 **Analyse d'acteurs de la menace** (MITRE ATT&CK + corrélations OTX)
- 🧠 **Moteur sémantique SciBERT** pour l'analyse de contenu
- 📄 **Export STIX 2.1** conforme OASIS
- 🛡️ **Plans de remédiation contextuels**

---

## 🏗️ Stack technique

| Couche | Technologies |
|---|---|
| Framework | Next.js 14 (App Router) |
| Langage | TypeScript strict |
| Backend | FastAPI (Python 3.11+) |
| Cartographie | MapLibre GL + deck.gl |
| Graphes | Cytoscape.js (dagre, cose-bilkent, breadthfirst) |
| Charts | Recharts |
| State | useSyncExternalStore (React 18) |
| Style | Tailwind CSS + tokens CSS variables (light/dark) |
| NLP | SciBERT (allenai/scibert_scivocab_uncased) |
| AI/RAG | Gemini 2.5 Flash + Qdrant Vector Store |
| Infrastructure | Docker Compose, Elasticsearch, MongoDB, Redis |

---

## 🌐 Sources OSINT intégrées

### Sans clé API (immédiatement opérationnelles)
- **CISA KEV** — Vulnérabilités activement exploitées
- **GDELT DOC + GEO 2.0** — Événements géopolitiques mondiaux
- **MITRE ATT&CK** — Référentiel acteurs / TTPs
- **OpenPhish** — URLs de phishing
- **Tor Exit Nodes** — IPs suspectes
- **NVD** — Base nationale CVE (rate limité)
- **CIRCL OSINT** — Feeds MISP communautaires
- **ReliefWeb (ONU)** — Crises humanitaires

### Avec clé API gratuite
- **URLhaus / ThreatFox / MalwareBazaar** (abuse.ch — clé unifiée)
- **AlienVault OTX** — Pulses & adversaires
- **AbuseIPDB** — Réputation IP
- **VirusTotal** — Analyse de fichiers (limites strictes en gratuit)

---

## 🚀 Installation

### Prérequis
- Node.js ≥ 18.17
- npm ≥ 9 (ou yarn/pnpm)
- Python 3.11+ (pour le backend)
- Docker & Docker Compose (pour l'infrastructure)

### Étapes

```bash
# 1. Cloner le dépôt
git clone https://github.com/Amalkaraoud/CTI-Platform-.git
cd CTI-Platform-

# 2. Configurer les variables d'environnement
cp .env.example .env
# Éditer .env et renseigner les clés API obtenues

# 3. Lancer l'infrastructure (Elasticsearch, MongoDB, Redis, Tor)
docker-compose up -d

# 4. Installer et lancer le dashboard
cd onyx-dashboard
npm install
npm run dev

# 5. Installer et lancer le backend API
cd ../onyx-api
pip install -e ../onyx-core
pip install -e .
uvicorn onyx_api.main:app --reload --port 8000
```

La plateforme est accessible sur `http://localhost:3000`.

---

## 🔑 Obtention des clés API gratuites

| Source | URL d'inscription | Délai |
|---|---|---|
| abuse.ch (URLhaus, ThreatFox, MB) | https://auth.abuse.ch/ | 5 min |
| AlienVault OTX | https://otx.alienvault.com/ | 5 min |
| AbuseIPDB | https://www.abuseipdb.com/register | 5 min |
| VirusTotal | https://www.virustotal.com/gui/join-us | 10 min |
| NVD (optionnel) | https://nvd.nist.gov/developers/request-an-api-key | Instantané |

---

## 📂 Architecture du projet

```
├── onyx-dashboard/              # Frontend Next.js 14
│   ├── src/
│   │   ├── app/                 # Routes (App Router)
│   │   │   └── api/proxy/       # Proxy CORS unifié
│   │   ├── components/          # Composants React
│   │   │   ├── ExecutiveDashboard.tsx
│   │   │   ├── ThreatMap3D.tsx  # Matrice géopolitique deck.gl
│   │   │   ├── ThreatGraph.tsx  # Graphe Cytoscape.js
│   │   │   ├── ActeursMenace.tsx
│   │   │   ├── IoCTable.tsx
│   │   │   └── ...
│   │   ├── lib/
│   │   │   ├── connectors/      # 15+ connecteurs OSINT
│   │   │   ├── stix/            # Export STIX 2.1
│   │   │   ├── RealTimeDataService.ts
│   │   │   └── store.ts
│   │   └── styles/
│   │       └── globals.css      # Thème light/dark via tokens CSS
│   └── tailwind.config.js
│
├── onyx-api/                    # Backend FastAPI
│   └── onyx_api/
│       ├── routers/             # Endpoints REST
│       ├── services/            # Logique métier (OSINT, RAG, NLP)
│       └── workers/             # Tâches asynchrones (Celery)
│
├── onyx-core/                   # Modèles & services partagés
│   └── onyx_core/
│       ├── models/              # STIX, IoC, Threat Actor
│       └── services/            # ES, MongoDB, Redis, Scoring
│
├── onyx-nlp/                    # Pipeline NLP (SciBERT, spaCy)
├── onyx-crawlers/               # Crawlers darkweb / clearweb
├── onyx-connectors/             # Connecteurs externes
├── onyx-analyzers/              # Analyseurs de menaces
├── infra/                       # Config Docker (ES, Mongo, Tor)
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## 🛡️ Sécurité

- ✅ Clés API stockées exclusivement en variables d'environnement (jamais dans le code)
- ✅ Toutes les requêtes externes passent par un proxy serveur (`/api/proxy/[source]`) → pas de clés exposées côté client
- ✅ Validation des entrées et sanitization sur les composants critiques
- ✅ Guardrails AI activés (input/output length limits, content filtering)
- ✅ `.env` et `.env.local` exclus du repo via `.gitignore`
- ✅ Tor proxy intégré pour les crawlers darkweb avec circuit rotation

---

## 📊 Conformité & Standards

- **STIX 2.1** : export conforme OASIS pour interopérabilité avec MISP, OpenCTI, etc.
- **MITRE ATT&CK** : référentiel acteurs / techniques / tactiques
- **WCAG AA** : contraste validé sur les modes clair et sombre

---

## 📝 Licence

MIT — voir [LICENSE](LICENSE)

---

## 👤 Auteur

**Amal Karaoud**
GitHub: [@Amalkaraoud](https://github.com/Amalkaraoud)

---

*Plateforme développée dans le cadre d'un projet de cybersécurité, intégrant les meilleures pratiques de l'industrie pour la threat intelligence opérationnelle.*
