import { v4 as uuidv4 } from 'uuid';

export type Entity = {
  id: string;
  type: 'actor' | 'malware' | 'vulnerability' | 'indicator' | 'campaign' | 'infrastructure' | string;
  name: string;
  description?: string;
  attributes: Record<string, any>;
  relations: Array<{
    direction: 'incoming' | 'outgoing';
    sourceId?: string;
    targetId?: string;
    sourceName?: string;
    targetName?: string;
    relationshipType: string;
  }>;
};

export function entityToStixBundle(entity: Entity, neighborEntities: Entity[] = []) {
  const now = new Date().toISOString();
  const bundleId = `bundle--${uuidv4()}`;

  const stixObjects: any[] = [];

  // Conversion de l'entité principale en SDO STIX 2.1
  const mainSdo = entityToStixSdo(entity, now);
  stixObjects.push(mainSdo);

  // Conversion des entités voisines
  const neighborSdos = neighborEntities.map(n => entityToStixSdo(n, now));
  stixObjects.push(...neighborSdos);

  // Helper findStixId
  const findStixId = (originalId: string | undefined, objects: any[]) => {
     if (!originalId) return mainSdo.id;
     // Note: In this simplified mock, we might not always find the exact mapping,
     // so we fallback to a generated ID or the original ID
     const found = objects.find(o => o.name === originalId || o.id.includes(originalId));
     return found ? found.id : originalId;
  };

  // Conversion des relations en SRO STIX 2.1
  for (const rel of entity.relations) {
    stixObjects.push({
      type: 'relationship',
      spec_version: '2.1',
      id: `relationship--${uuidv4()}`,
      created: now,
      modified: now,
      relationship_type: rel.relationshipType,
      source_ref: rel.direction === 'outgoing' ? mainSdo.id : findStixId(rel.sourceId, stixObjects),
      target_ref: rel.direction === 'outgoing' ? findStixId(rel.targetId, stixObjects) : mainSdo.id,
    });
  }

  return {
    type: 'bundle',
    id: bundleId,
    spec_version: '2.1',
    objects: stixObjects,
  };
}

function entityToStixSdo(entity: Entity, timestamp: string) {
  const baseFields = {
    spec_version: '2.1',
    id: `${stixTypeFor(entity.type)}--${uuidv4()}`,
    created: timestamp,
    modified: timestamp,
    name: entity.name,
    description: entity.description ?? '',
  };

  switch (entity.type) {
    case 'actor':
      return { ...baseFields, type: 'intrusion-set', aliases: entity.attributes.aliases ?? [] };
    case 'malware':
    case 'tool':
      return { ...baseFields, type: 'malware', is_family: entity.attributes.is_family ?? false, malware_types: entity.attributes.types ?? ['unknown'] };
    case 'vulnerability':
      return {
        ...baseFields,
        type: 'vulnerability',
        external_references: [{ source_name: 'cve', external_id: entity.attributes.cveID ?? entity.name }],
      };
    case 'indicator':
    case 'ioc':
      return {
        ...baseFields,
        type: 'indicator',
        pattern: entity.attributes.stixPattern ?? `[${entity.attributes.iocType || 'file'}:value = '${entity.attributes.value}']`,
        pattern_type: 'stix',
        valid_from: timestamp,
      };
    case 'campaign':
      return { ...baseFields, type: 'campaign' };
    case 'infrastructure':
      return { ...baseFields, type: 'infrastructure', infrastructure_types: entity.attributes.types ?? ['unknown'] };
    default:
      return { ...baseFields, type: 'custom-object' };
  }
}

function stixTypeFor(type: string): string {
  const map: Record<string, string> = {
    actor: 'intrusion-set',
    malware: 'malware',
    tool: 'malware',
    vulnerability: 'vulnerability',
    indicator: 'indicator',
    ioc: 'indicator',
    campaign: 'campaign',
    infrastructure: 'infrastructure',
  };
  return map[type] || 'custom-object';
}
