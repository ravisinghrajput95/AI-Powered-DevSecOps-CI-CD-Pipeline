#!/usr/bin/env python3
"""
The canonical ExecutiveReport JSON Schema, as an importable Python module
rather than a separately-committed file at a path that has to be gotten
exactly right. Both run_security_analysis.py and render_report.py import
SCHEMA directly from here — there is no --schema CLI argument anymore,
and no file path for either script to get wrong.

WHY A MODULE, NOT A JSON FILE (revisited): the original design used a
standalone .json file specifically for cross-language consumption
(Backstage/REST/future dashboards, per the design review). That goal is
still real, but nothing non-Python actually consumes this schema today —
the only two real consumers are the two Python scripts in this same repo,
and a separately-committed file at a separately-remembered path turned
into a repeated, real source of friction (twice: once for the path
itself, once because loading it had no error handling). If/when a real
non-Python consumer shows up, export this SCHEMA dict to JSON with a
one-line script (json.dump(SCHEMA, ...)) — generating a JSON file FROM
this module, rather than maintaining a hand-written JSON file as the
primary source of truth that this module would otherwise have to stay in
sync with by hand.

This is the exact same dict that was at schemas/executive_report.schema.json
— moved, not changed. Delete that file/directory; this module replaces it.
"""

SCHEMA = {'$schema': 'https://json-schema.org/draft/2020-12/schema',
 '$id': 'https://ai-powered-devsecops-pipeline/schemas/executive_report.schema.json',
 'title': 'ExecutiveReport',
 'description': 'The canonical AI reasoning contract — sits between '
                'final_release_context.json and any renderer '
                '(HTML/Markdown/PDF/Backstage/REST). Contains AI reasoning only: no '
                'deterministic computation, no presentation markup, no '
                'provider-specific artifacts. '
                'report_id/generated_at/release_context_ref are populated by Python, '
                'not the model — the model only ever produces the fields under '
                'ai_output (see run_security_analysis.py).',
 'type': 'object',
 'required': ['schema_version',
              'report_id',
              'generated_at',
              'release_context_ref',
              'executive_summary',
              'cross_domain_correlations',
              'top_risks',
              'priority_actions',
              'release_readiness',
              'assumptions_and_unknowns'],
 'additionalProperties': False,
 'properties': {'schema_version': {'type': 'string', 'const': '1.0.0'},
                'report_id': {'type': 'string',
                              'description': 'Deterministic, Python-computed — '
                                             'sha256(release_context_ref.version + '
                                             'generated_at)[:16].'},
                'generated_at': {'type': 'string', 'format': 'date-time'},
                'release_context_ref': {'type': 'object',
                                        'required': ['repository',
                                                     'version',
                                                     'generated_at'],
                                        'additionalProperties': False,
                                        'properties': {'repository': {'type': 'string'},
                                                       'version': {'type': 'string'},
                                                       'generated_at': {'type': 'string',
                                                                        'format': 'date-time'}}},
                'executive_summary': {'type': 'object',
                                      'required': ['overall_health',
                                                   'deployment_confidence',
                                                   'dominant_risk_themes',
                                                   'narrative'],
                                      'additionalProperties': False,
                                      'properties': {'overall_health': {'type': 'string',
                                                                        'enum': ['CRITICAL',
                                                                                 'HIGH',
                                                                                 'MEDIUM',
                                                                                 'LOW']},
                                                     'deployment_confidence': {'type': 'string',
                                                                               'enum': ['HIGH',
                                                                                        'MEDIUM',
                                                                                        'LOW']},
                                                     'dominant_risk_themes': {'type': 'array',
                                                                              'items': {'type': 'string'},
                                                                              'minItems': 1,
                                                                              'maxItems': 6},
                                                     'narrative': {'type': 'string'}}},
                'cross_domain_correlations': {'type': 'array',
                                              'items': {'type': 'object',
                                                        'required': ['correlation_id',
                                                                     'title',
                                                                     'description',
                                                                     'business_impact',
                                                                     'confidence',
                                                                     'affected_domains',
                                                                     'supporting_evidence',
                                                                     'recommended_action'],
                                                        'additionalProperties': False,
                                                        'properties': {'correlation_id': {'type': 'string'},
                                                                       'title': {'type': 'string',
                                                                                 'maxLength': 200},
                                                                       'description': {'type': 'string'},
                                                                       'business_impact': {'type': 'string'},
                                                                       'confidence': {'type': 'string',
                                                                                      'enum': ['HIGH',
                                                                                               'MEDIUM',
                                                                                               'LOW']},
                                                                       'affected_domains': {'type': 'array',
                                                                                            'items': {'type': 'string',
                                                                                                      'enum': ['application_security',
                                                                                                               'infrastructure_security',
                                                                                                               'runtime_security',
                                                                                                               'container_security',
                                                                                                               'supply_chain']},
                                                                                            'minItems': 1},
                                                                       'supporting_evidence': {'type': 'array',
                                                                                               'items': {'type': 'string',
                                                                                                         'pattern': '^[a-f0-9]{12}$'},
                                                                                               'minItems': 1},
                                                                       'recommended_action': {'type': 'string'}}}},
                'top_risks': {'type': 'array',
                              'items': {'type': 'object',
                                        'required': ['risk_id',
                                                     'title',
                                                     'impact',
                                                     'why_it_matters',
                                                     'confidence',
                                                     'supporting_evidence',
                                                     'recommended_action'],
                                        'additionalProperties': False,
                                        'properties': {'risk_id': {'type': 'string'},
                                                       'title': {'type': 'string',
                                                                 'maxLength': 200},
                                                       'impact': {'type': 'string'},
                                                       'why_it_matters': {'type': 'string'},
                                                       'confidence': {'type': 'string',
                                                                      'enum': ['HIGH',
                                                                               'MEDIUM',
                                                                               'LOW']},
                                                       'supporting_evidence': {'type': 'array',
                                                                               'items': {'type': 'string',
                                                                                         'pattern': '^[a-f0-9]{12}$'},
                                                                               'minItems': 1},
                                                       'recommended_action': {'type': 'string'}}}},
                'priority_actions': {'type': 'array',
                                     'items': {'type': 'object',
                                               'required': ['action_id',
                                                            'title',
                                                            'rationale',
                                                            'expected_risk_reduction',
                                                            'dependencies',
                                                            'estimated_complexity',
                                                            'supporting_evidence'],
                                               'additionalProperties': False,
                                               'properties': {'action_id': {'type': 'string'},
                                                              'title': {'type': 'string',
                                                                        'maxLength': 200},
                                                              'rationale': {'type': 'string'},
                                                              'expected_risk_reduction': {'type': 'string'},
                                                              'dependencies': {'type': 'array',
                                                                               'items': {'type': 'string'}},
                                                              'estimated_complexity': {'type': 'string',
                                                                                       'enum': ['LOW',
                                                                                                'MEDIUM',
                                                                                                'HIGH',
                                                                                                'UNKNOWN']},
                                                              'supporting_evidence': {'type': 'array',
                                                                                      'items': {'type': 'string',
                                                                                                'pattern': '^[a-f0-9]{12}$'}}}}},
                'release_readiness': {'type': 'object',
                                      'required': ['recommendation',
                                                   'confidence',
                                                   'rationale',
                                                   'blocking_evidence',
                                                   'conditions'],
                                      'additionalProperties': False,
                                      'properties': {'recommendation': {'type': 'string',
                                                                        'enum': ['APPROVE',
                                                                                 'APPROVE_WITH_CONDITIONS',
                                                                                 'MANUAL_REVIEW_REQUIRED',
                                                                                 'DO_NOT_APPROVE']},
                                                     'confidence': {'type': 'string',
                                                                    'enum': ['HIGH',
                                                                             'MEDIUM',
                                                                             'LOW']},
                                                     'rationale': {'type': 'string'},
                                                     'blocking_evidence': {'type': 'array',
                                                                           'items': {'type': 'string',
                                                                                     'pattern': '^[a-f0-9]{12}$'}},
                                                     'conditions': {'type': ['array',
                                                                             'null'],
                                                                    'items': {'type': 'string'},
                                                                    'description': 'What '
                                                                                   'would '
                                                                                   'need '
                                                                                   'to '
                                                                                   'change '
                                                                                   'to '
                                                                                   'move '
                                                                                   'toward '
                                                                                   'a '
                                                                                   'more '
                                                                                   'favorable '
                                                                                   'recommendation. '
                                                                                   'NOT '
                                                                                   'restricted '
                                                                                   'to '
                                                                                   'APPROVE_WITH_CONDITIONS '
                                                                                   '— '
                                                                                   'confirmed '
                                                                                   'via '
                                                                                   'a '
                                                                                   'real '
                                                                                   'run '
                                                                                   'that '
                                                                                   'this '
                                                                                   'is '
                                                                                   'genuinely '
                                                                                   'useful '
                                                                                   'for '
                                                                                   'DO_NOT_APPROVE '
                                                                                   'too '
                                                                                   '("what '
                                                                                   'would '
                                                                                   'need '
                                                                                   'to '
                                                                                   'be '
                                                                                   'true '
                                                                                   'for '
                                                                                   'this '
                                                                                   'to '
                                                                                   'become '
                                                                                   'approvable"), '
                                                                                   'which '
                                                                                   'is '
                                                                                   'a '
                                                                                   'better '
                                                                                   'interpretation '
                                                                                   'than '
                                                                                   'the '
                                                                                   'original '
                                                                                   'narrower '
                                                                                   'intent. '
                                                                                   'null '
                                                                                   'only '
                                                                                   'when '
                                                                                   'there '
                                                                                   'is '
                                                                                   'truly '
                                                                                   'nothing '
                                                                                   'actionable '
                                                                                   'to '
                                                                                   'list.'}}},
                'assumptions_and_unknowns': {'type': 'array',
                                             'items': {'type': 'object',
                                                       'required': ['related_to',
                                                                    'impact_on_assessment'],
                                                       'additionalProperties': False,
                                                       'properties': {'related_to': {'type': 'string',
                                                                                     'description': 'A '
                                                                                                    'pointer '
                                                                                                    'into '
                                                                                                    'final_release_context.json, '
                                                                                                    'e.g. '
                                                                                                    "'scan_status.backend.codeql' "
                                                                                                    'or '
                                                                                                    "'provenance.infrastructure_security' "
                                                                                                    '— '
                                                                                                    'NOT '
                                                                                                    'a '
                                                                                                    'restatement '
                                                                                                    'of '
                                                                                                    'the '
                                                                                                    'value. '
                                                                                                    'The '
                                                                                                    'renderer '
                                                                                                    'resolves '
                                                                                                    'the '
                                                                                                    'pointer; '
                                                                                                    'the '
                                                                                                    'AI '
                                                                                                    'only '
                                                                                                    'states '
                                                                                                    'the '
                                                                                                    'impact.'},
                                                                      'impact_on_assessment': {'type': 'string'}}}}}}