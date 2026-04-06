// ============================================================================
// ONYX CTI — MongoDB Initialization Script
// Creates the STIX 2.1 database schema with collections, indexes, and
// validation rules. Runs once on first container startup.
// ============================================================================

// Switch to the ONYX database
db = db.getSiblingDB('onyx_cti');

print('[ONYX] ==========================================');
print('[ONYX] MongoDB Schema Initialization — ONYX CTI v3.0');
print('[ONYX] ==========================================');

// --------------------------------------------------------------------------
// STIX Domain Objects (SDO) — Primary intelligence store
// --------------------------------------------------------------------------
db.createCollection('stix_objects', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['id', 'type', 'created', 'modified', 'spec_version'],
      properties: {
        id: {
          bsonType: 'string',
          pattern: '^[a-z][a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
          description: 'STIX 2.1 identifier: type--uuid4'
        },
        type: {
          bsonType: 'string',
          enum: [
            'threat-actor', 'malware', 'campaign', 'intrusion-set',
            'tool', 'attack-pattern', 'indicator', 'observed-data',
            'infrastructure', 'malware-analysis', 'vulnerability',
            'report', 'note', 'opinion', 'grouping', 'identity',
            'location', 'course-of-action'
          ],
          description: 'STIX Domain Object type'
        },
        spec_version: {
          bsonType: 'string',
          enum: ['2.1'],
          description: 'STIX specification version'
        },
        created: { bsonType: 'date' },
        modified: { bsonType: 'date' },
        created_by_ref: { bsonType: 'string' },
        confidence: { bsonType: 'int', minimum: 0, maximum: 100 },
        lang: { bsonType: 'string' },
        revoked: { bsonType: 'bool' },
        object_marking_refs: {
          bsonType: 'array',
          items: { bsonType: 'string' }
        },
        external_references: {
          bsonType: 'array',
          items: {
            bsonType: 'object',
            properties: {
              source_name: { bsonType: 'string' },
              url: { bsonType: 'string' },
              external_id: { bsonType: 'string' }
            }
          }
        }
      }
    }
  },
  validationLevel: 'moderate',
  validationAction: 'warn'
});

// Primary indexes for STIX objects
db.stix_objects.createIndex({ 'id': 1 }, { unique: true, name: 'idx_stix_id' });
db.stix_objects.createIndex({ 'type': 1, 'modified': -1 }, { name: 'idx_type_modified' });
db.stix_objects.createIndex({ 'type': 1, 'created': -1 }, { name: 'idx_type_created' });
db.stix_objects.createIndex({ 'name': 'text', 'description': 'text' }, { name: 'idx_text_search', default_language: 'english' });
db.stix_objects.createIndex({ 'created_by_ref': 1 }, { name: 'idx_created_by', sparse: true });
db.stix_objects.createIndex({ 'object_marking_refs': 1 }, { name: 'idx_markings' });
db.stix_objects.createIndex({ 'external_references.source_name': 1 }, { name: 'idx_ext_ref_source', sparse: true });
db.stix_objects.createIndex({ 'confidence': -1 }, { name: 'idx_confidence' });
db.stix_objects.createIndex({ 'revoked': 1 }, { name: 'idx_revoked' });

print('[ONYX] ✓ Collection: stix_objects (with validation + 9 indexes)');

// --------------------------------------------------------------------------
// STIX Relationships (SRO) — Entity link graph
// --------------------------------------------------------------------------
db.createCollection('stix_relationships');

db.stix_relationships.createIndex({ 'id': 1 }, { unique: true, name: 'idx_rel_id' });
db.stix_relationships.createIndex({ 'source_ref': 1, 'relationship_type': 1 }, { name: 'idx_source_type' });
db.stix_relationships.createIndex({ 'target_ref': 1, 'relationship_type': 1 }, { name: 'idx_target_type' });
db.stix_relationships.createIndex({ 'source_ref': 1, 'target_ref': 1 }, { name: 'idx_source_target' });
db.stix_relationships.createIndex({ 'relationship_type': 1 }, { name: 'idx_rel_type' });
db.stix_relationships.createIndex({ 'created': -1 }, { name: 'idx_rel_created' });
db.stix_relationships.createIndex({ 'confidence': -1 }, { name: 'idx_rel_confidence' });

print('[ONYX] ✓ Collection: stix_relationships (7 indexes)');

// --------------------------------------------------------------------------
// STIX Sightings — Evidence of threat observation
// --------------------------------------------------------------------------
db.createCollection('stix_sightings');

db.stix_sightings.createIndex({ 'id': 1 }, { unique: true, name: 'idx_sight_id' });
db.stix_sightings.createIndex({ 'sighting_of_ref': 1 }, { name: 'idx_sight_of' });
db.stix_sightings.createIndex({ 'where_sighted_refs': 1 }, { name: 'idx_sight_where' });
db.stix_sightings.createIndex({ 'first_seen': -1 }, { name: 'idx_sight_first' });
db.stix_sightings.createIndex({ 'last_seen': -1 }, { name: 'idx_sight_last' });

print('[ONYX] ✓ Collection: stix_sightings (5 indexes)');

// --------------------------------------------------------------------------
// Marking Definitions — TLP + custom markings
// --------------------------------------------------------------------------
db.createCollection('marking_definitions');

db.marking_definitions.createIndex({ 'id': 1 }, { unique: true, name: 'idx_marking_id' });
db.marking_definitions.createIndex({ 'definition_type': 1 }, { name: 'idx_marking_type' });

// Seed TLP markings (STIX 2.1 standard)
const tlpMarkings = [
  {
    id: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
    type: 'marking-definition',
    spec_version: '2.1',
    name: 'TLP:CLEAR',
    created: new Date('2017-01-20T00:00:00.000Z'),
    definition_type: 'tlp',
    definition: { tlp: 'clear' }
  },
  {
    id: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
    type: 'marking-definition',
    spec_version: '2.1',
    name: 'TLP:GREEN',
    created: new Date('2017-01-20T00:00:00.000Z'),
    definition_type: 'tlp',
    definition: { tlp: 'green' }
  },
  {
    id: 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
    type: 'marking-definition',
    spec_version: '2.1',
    name: 'TLP:AMBER',
    created: new Date('2017-01-20T00:00:00.000Z'),
    definition_type: 'tlp',
    definition: { tlp: 'amber' }
  },
  {
    id: 'marking-definition--826578e1-40a3-4b46-a8d5-5765f42690ce',
    type: 'marking-definition',
    spec_version: '2.1',
    name: 'TLP:AMBER+STRICT',
    created: new Date('2017-01-20T00:00:00.000Z'),
    definition_type: 'tlp',
    definition: { tlp: 'amber+strict' }
  },
  {
    id: 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
    type: 'marking-definition',
    spec_version: '2.1',
    name: 'TLP:RED',
    created: new Date('2017-01-20T00:00:00.000Z'),
    definition_type: 'tlp',
    definition: { tlp: 'red' }
  }
];

tlpMarkings.forEach(m => {
  db.marking_definitions.updateOne({ id: m.id }, { $set: m }, { upsert: true });
});

print('[ONYX] ✓ Collection: marking_definitions (seeded 5 TLP markings)');

// --------------------------------------------------------------------------
// Crawler State — Track crawler jobs, schedules, and results
// --------------------------------------------------------------------------
db.createCollection('crawler_state');

db.crawler_state.createIndex({ 'crawler_id': 1 }, { unique: true, name: 'idx_crawler_id' });
db.crawler_state.createIndex({ 'status': 1, 'last_run': -1 }, { name: 'idx_status_lastrun' });
db.crawler_state.createIndex({ 'crawler_type': 1 }, { name: 'idx_crawler_type' });
db.crawler_state.createIndex({ 'next_run': 1 }, { name: 'idx_next_run' });

print('[ONYX] ✓ Collection: crawler_state (4 indexes)');

// --------------------------------------------------------------------------
// Feed Configurations — External feed source definitions
// --------------------------------------------------------------------------
db.createCollection('feed_configs');

db.feed_configs.createIndex({ 'feed_id': 1 }, { unique: true, name: 'idx_feed_id' });
db.feed_configs.createIndex({ 'enabled': 1, 'next_poll': 1 }, { name: 'idx_feed_poll' });

print('[ONYX] ✓ Collection: feed_configs (2 indexes)');

// --------------------------------------------------------------------------
// Playbooks — Automated analysis chain definitions
// --------------------------------------------------------------------------
db.createCollection('playbooks');

db.playbooks.createIndex({ 'playbook_id': 1 }, { unique: true, name: 'idx_playbook_id' });
db.playbooks.createIndex({ 'enabled': 1 }, { name: 'idx_playbook_enabled' });
db.playbooks.createIndex({ 'trigger_type': 1 }, { name: 'idx_playbook_trigger' });

print('[ONYX] ✓ Collection: playbooks (3 indexes)');

// --------------------------------------------------------------------------
// Users — Platform users and RBAC
// --------------------------------------------------------------------------
db.createCollection('users');

db.users.createIndex({ 'username': 1 }, { unique: true, name: 'idx_username' });
db.users.createIndex({ 'email': 1 }, { unique: true, name: 'idx_email' });
db.users.createIndex({ 'api_key_hash': 1 }, { unique: true, sparse: true, name: 'idx_api_key' });
db.users.createIndex({ 'role': 1 }, { name: 'idx_role' });

// Seed default admin user (password: must be changed on first login)
db.users.updateOne(
  { username: 'admin' },
  {
    $setOnInsert: {
      username: 'admin',
      email: 'admin@onyx.local',
      // bcrypt hash of 'onyx_admin_2026' — MUST be changed on first login
      password_hash: '$2b$12$LJ3m4ys5LMDhq7T5RfZOd.7VqZ7XFb9G5Rr8FhYqXvE9l5VQoJKGy',
      role: 'admin',
      is_active: true,
      force_password_change: true,
      created_at: new Date(),
      last_login: null,
      preferences: {
        theme: 'dark',
        language: 'en',
        dashboard_layout: 'default',
        timezone: 'UTC'
      }
    }
  },
  { upsert: true }
);

print('[ONYX] ✓ Collection: users (seeded admin user)');

// --------------------------------------------------------------------------
// Audit Log — Immutable event log for compliance
// --------------------------------------------------------------------------
db.createCollection('audit_log', {
  capped: false
});

db.audit_log.createIndex({ 'timestamp': -1 }, { name: 'idx_audit_time' });
db.audit_log.createIndex({ 'user_id': 1, 'timestamp': -1 }, { name: 'idx_audit_user' });
db.audit_log.createIndex({ 'action': 1 }, { name: 'idx_audit_action' });
db.audit_log.createIndex({ 'resource_type': 1, 'resource_id': 1 }, { name: 'idx_audit_resource' });
// TTL index: auto-delete audit logs after 365 days
db.audit_log.createIndex({ 'timestamp': 1 }, { expireAfterSeconds: 31536000, name: 'idx_audit_ttl' });

print('[ONYX] ✓ Collection: audit_log (5 indexes, 365d TTL)');

// --------------------------------------------------------------------------
// Summary
// --------------------------------------------------------------------------
print('[ONYX] ==========================================');
print('[ONYX] MongoDB initialization complete!');
print('[ONYX] Collections: 8');
print('[ONYX] Total indexes: 40');
print('[ONYX] Seed data: TLP markings + admin user');
print('[ONYX] ==========================================');
