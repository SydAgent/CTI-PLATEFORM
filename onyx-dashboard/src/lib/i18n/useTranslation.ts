/**
 * ONYX CTI v5.0 SOVEREIGN — Hook de Traduction (Zero Overhead)
 *
 * Architecture :
 *  - Le dictionnaire est aplati en une Map<string, string> au chargement du module.
 *  - Le lookup est O(1) — aucune traversée d'objet à chaque appel de `t()`.
 *  - Aucun Context Provider requis — import direct.
 *  - Aucun re-render déclenché — la Map est immuable et externe au cycle React.
 *
 * Usage :
 *   import { useT, t } from '@/lib/i18n/useTranslation';
 *
 *   // Dans un composant React :
 *   const t = useT();
 *   return <h1>{t('nav.overview')}</h1>;
 *
 *   // Hors composant (utilitaires, workers) :
 *   import { t } from '@/lib/i18n/useTranslation';
 *   console.log(t('common.loading'));
 */

import { useCallback } from 'react';
import fr, { type TranslationKey } from './fr';

// ─── Aplatissement du dictionnaire au chargement du module ──────────────────
// Construit une fois, jamais recalculé, jamais garbage-collected.

const flatMap = new Map<string, string>();

function flattenDict(obj: Record<string, unknown>, prefix = ''): void {
  for (const key of Object.keys(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    const value = obj[key];
    if (typeof value === 'string') {
      flatMap.set(fullKey, value);
    } else if (typeof value === 'object' && value !== null) {
      flattenDict(value as Record<string, unknown>, fullKey);
    }
  }
}

flattenDict(fr as unknown as Record<string, unknown>);

// ─── Fonction de traduction pure (utilisable hors React) ────────────────────

/**
 * Traduction par clé pointée. Retourne la valeur localisée ou la clé elle-même
 * en cas de clé manquante (facilite le debugging sans crash).
 *
 * @param key - Clé pointée (ex: "nav.overview", "stats.total_iocs")
 * @param fallback - Valeur de repli optionnelle si la clé n'existe pas
 * @returns Chaîne localisée
 */
export function t(key: TranslationKey | string, fallback?: string): string {
  return flatMap.get(key) ?? fallback ?? key;
}

// ─── Hook React (pour usage dans les composants) ────────────────────────────

/**
 * Hook React retournant la fonction `t()` mémorisée.
 * Zero re-render : la référence de fonction est stable (useCallback avec []).
 *
 * @returns Fonction de traduction `t(key, fallback?)`
 */
export function useT(): (key: TranslationKey | string, fallback?: string) => string {
  return useCallback(
    (key: TranslationKey | string, fallback?: string) => t(key, fallback),
    []
  );
}

/**
 * Accès direct à une section du dictionnaire (pour les boucles).
 * Retourne l'objet de section ou un objet vide.
 *
 * @param section - Nom de section de premier niveau (ex: "nav", "stats")
 */
export function getSection<K extends keyof typeof fr>(section: K): typeof fr[K] {
  return fr[section];
}

export default useT;
