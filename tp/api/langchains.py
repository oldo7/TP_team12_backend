import json
import re

from django.conf import settings
from langchain_deepseek import ChatDeepSeek
from pydantic import ValidationError

from .langchain_tools import (
    ANALYSIS_TOOL_MAP,
    ASSISTANT_TOOLS,
    PROPOSAL_TOOL_MAP,
)


class AssistantConfigurationError(Exception):
    pass


class AssistantProviderError(Exception):
    pass


VALID_PROPOSAL_TYPES = {
    'technology',
    'component',
    'damageScenario',
    'attackStep',
    'threatScenario',
    'control',
}

PROPOSAL_TYPE_LABELS = {
    'technology': 'Technology',
    'component': 'Component',
    'damageScenario': 'Damage scenario',
    'attackStep': 'Attack step',
    'threatScenario': 'Threat scenario',
    'control': 'Control',
}


def _ids(queryset):
    return list(queryset.values_list('id', flat=True))


def _component_coverage(component):
    missing = []
    if not component.mapped_damage_scenarios.exists():
        missing.append('damageScenarios')
    if not component.attack_steps.exists():
        missing.append('attackSteps')
    if not component.controls.exists():
        missing.append('controls')

    return {
        'component_id': component.id,
        'component_name': component.name,
        'technology_ids': _ids(component.technology.all()),
        'communicates_with_ids': _ids(component.communicates_with.all()),
        'attack_step_ids': _ids(component.attack_steps.all()),
        'threat_scenario_ids': _ids(component.threat_scenarios.all()),
        'damage_scenario_ids': _ids(component.mapped_damage_scenarios),
        'control_ids': _ids(component.controls.all()),
        'missing': missing,
    }


def _named_ids(queryset):
    return [
        {
            'id': item.id,
            'name': item.name,
        }
        for item in queryset
    ]


def _damage_scenario_components(scenario):
    components_by_id = {}
    for threat_scenario in scenario.threat_scenarios.all():
        for component in threat_scenario.components.all():
            components_by_id[component.id] = component

    return [
        {
            'id': component.id,
            'name': component.name,
        }
        for component in components_by_id.values()
    ]


def _entity_overview(
    *,
    components,
    technologies,
    damage_scenarios,
    attack_steps,
    threat_scenarios,
    controls,
):
    return {
        'counts': {
            'technologies': len(technologies),
            'components': len(components),
            'damageScenarios': len(damage_scenarios),
            'attackSteps': len(attack_steps),
            'threatScenarios': len(threat_scenarios),
            'controls': len(controls),
        },
        'components': [
            {
                'id': component.id,
                'name': component.name,
                'usesTechnologies': _named_ids(component.technology.all()),
                'communicatesWith': _named_ids(component.communicates_with.all()),
                'attackSteps': _named_ids(component.attack_steps.all()),
                'threatScenarios': _named_ids(component.threat_scenarios.all()),
                'damageScenarios': _named_ids(component.mapped_damage_scenarios),
                'controls': _named_ids(component.controls.all()),
                'missing': _component_coverage(component)['missing'],
            }
            for component in components
        ],
        'technologies': [
            {
                'id': technology.id,
                'name': technology.name,
                'components': _named_ids(technology.component_set.all()),
            }
            for technology in technologies
        ],
        'attackSteps': [
            {
                'id': step.id,
                'name': step.name,
                'component': (
                    {'id': step.component_id, 'name': step.component.name}
                    if step.component_id and step.component
                    else None
                ),
                'previousSteps': _named_ids(step.previous_steps.all()),
                'nextSteps': _named_ids(step.next_steps.all()),
                'threatScenarios': _named_ids(step.threat_scenarios.all()),
                'damageScenarios': _named_ids(step.mapped_damage_scenarios),
                'controls': _named_ids(step.controls.all()),
            }
            for step in attack_steps
        ],
        'damageScenarios': [
            {
                'id': scenario.id,
                'name': scenario.name,
                'components': _damage_scenario_components(scenario),
                'attackSteps': _named_ids(scenario.mapped_attack_steps),
                'threatScenarios': _named_ids(scenario.threat_scenarios.all()),
            }
            for scenario in damage_scenarios
        ],
        'threatScenarios': [
            {
                'id': scenario.id,
                'name': scenario.name,
                'components': _named_ids(scenario.components.all()),
                'attackSteps': _named_ids(scenario.attack_steps.all()),
                'damageScenarios': _named_ids(scenario.damage_scenarios.all()),
                'controls': _named_ids(scenario.controls.all()),
                'isCompletePath': (
                    scenario.components.exists()
                    and scenario.attack_steps.exists()
                    and scenario.damage_scenarios.exists()
                ),
            }
            for scenario in threat_scenarios
        ],
        'controls': [
            {
                'id': control.id,
                'name': control.name,
                'component': (
                    {'id': control.component_id, 'name': control.component.name}
                    if control.component_id and control.component
                    else None
                ),
                'attackSteps': _named_ids(control.attack_steps.all()),
                'threatScenarios': _named_ids(control.threat_scenarios.all()),
            }
            for control in controls
        ],
    }


def _project_context(project):
    components = list(project.components.all().order_by('name'))
    technologies = list(project.technologies.all().order_by('name'))
    damage_scenarios = list(project.damage_scenarios.all().order_by('name'))
    attack_steps = list(project.attack_steps.all().order_by('name'))
    threat_scenarios = list(project.threat_scenarios.all().order_by('name'))
    controls = list(project.controls.all().order_by('name'))

    return {
        'project': {
            'id': project.id,
            'name': project.name,
            'description': project.description,
        },
        'entityOverview': _entity_overview(
            components=components,
            technologies=technologies,
            damage_scenarios=damage_scenarios,
            attack_steps=attack_steps,
            threat_scenarios=threat_scenarios,
            controls=controls,
        ),
        'components': [
            {
                'id': component.id,
                'name': component.name,
                'description': component.description,
                'technology_ids': _ids(component.technology.all()),
                'communicates_with_ids': _ids(component.communicates_with.all()),
                'attack_step_ids': _ids(component.attack_steps.all()),
                'threat_scenario_ids': _ids(component.threat_scenarios.all()),
                'damage_scenario_ids': _ids(component.mapped_damage_scenarios),
                'control_ids': _ids(component.controls.all()),
            }
            for component in components
        ],
        'technologies': [
            {
                'id': technology.id,
                'name': technology.name,
                'description': technology.description,
                'component_ids': _ids(technology.component_set.filter(project=project)),
            }
            for technology in technologies
        ],
        'damageScenarios': [
            {
                'id': scenario.id,
                'name': scenario.name,
                'description': scenario.description,
                'affected_CIA_parts': scenario.affected_CIA_parts,
                'safety_impact': scenario.safety_impact,
                'finantial_impact': scenario.finantial_impact,
                'operational_impact': scenario.operational_impact,
                'privacy_impact': scenario.privacy_impact,
                'threat_scenario_ids': _ids(scenario.threat_scenarios.all()),
                'attack_step_ids': _ids(scenario.mapped_attack_steps),
                'component_ids': _ids(
                    project.components.filter(threat_scenarios__damage_scenarios=scenario).distinct()
                ),
                'concerns': [
                    {
                        'component_id': concern.component_id,
                        'affected_CIA_parts': concern.affected_CIA_parts,
                    }
                    for concern in scenario.concerns.all()
                ],
            }
            for scenario in damage_scenarios
        ],
        'attackSteps': [
            {
                'id': step.id,
                'name': step.name,
                'description': step.description,
                'component_id': step.component_id,
                'required_access': step.required_access,
                'fr_et': step.fr_et,
                'fr_se': step.fr_se,
                'fr_koC': step.fr_koC,
                'fr_WoO': step.fr_WoO,
                'fr_eq': step.fr_eq,
                'previous_step_ids': _ids(step.previous_steps.all()),
                'next_step_ids': _ids(step.next_steps.all()),
                'control_ids': _ids(step.controls.all()),
                'threat_scenario_ids': _ids(step.threat_scenarios.all()),
                'damage_scenario_ids': _ids(step.mapped_damage_scenarios),
            }
            for step in attack_steps
        ],
        'threatScenarios': [
            {
                'id': scenario.id,
                'name': scenario.name,
                'description': scenario.description,
                'component_ids': list(scenario.components.values_list('id', flat=True)),
                'attack_step_ids': list(scenario.attack_steps.values_list('id', flat=True)),
                'damage_scenario_ids': list(scenario.damage_scenarios.values_list('id', flat=True)),
                'control_ids': _ids(scenario.controls.all()),
            }
            for scenario in threat_scenarios
        ],
        'controls': [
            {
                'id': control.id,
                'name': control.name,
                'description': control.description,
                'component_id': control.component_id,
                'fr_et': control.fr_et,
                'fr_se': control.fr_se,
                'fr_koC': control.fr_koC,
                'fr_WoO': control.fr_WoO,
                'fr_eq': control.fr_eq,
                'attack_step_ids': list(control.attack_steps.values_list('id', flat=True)),
                'threat_scenario_ids': _ids(control.threat_scenarios.all()),
            }
            for control in controls
        ],
        'relationshipMap': {
            'componentCoverage': [_component_coverage(component) for component in components],
            'threatScenarioLinks': [
                {
                    'threat_scenario_id': scenario.id,
                    'threat_scenario_name': scenario.name,
                    'component_ids': _ids(scenario.components.all()),
                    'attack_step_ids': _ids(scenario.attack_steps.all()),
                    'damage_scenario_ids': _ids(scenario.damage_scenarios.all()),
                    'control_ids': _ids(scenario.controls.all()),
                    'is_complete_path': (
                        scenario.components.exists()
                        and scenario.attack_steps.exists()
                        and scenario.damage_scenarios.exists()
                    ),
                }
                for scenario in threat_scenarios
            ],
            'attackStepLinks': [
                {
                    'attack_step_id': step.id,
                    'attack_step_name': step.name,
                    'component_id': step.component_id,
                    'previous_step_ids': _ids(step.previous_steps.all()),
                    'next_step_ids': _ids(step.next_steps.all()),
                    'threat_scenario_ids': _ids(step.threat_scenarios.all()),
                    'damage_scenario_ids': _ids(step.mapped_damage_scenarios),
                    'control_ids': _ids(step.controls.all()),
                }
                for step in attack_steps
            ],
        },
    }


def _system_prompt():
    return '''
You are a conversational cybersecurity TARA assistant for an existing web app.
Answer normal questions directly in concise plain text.
Use the prompt, conversation history, context, currentAnalysis, and proposalMemory to decide whether to answer directly, call analyze_current_state, or call proposal tools.
When the user asks to analyze, inspect, review, summarize, or understand the current model, call analyze_current_state.
When the user asks to create, implement, draft, generate, add, continue, or propose TARA model objects, call proposal tools for every object needed to address the request and relevant currentAnalysis gaps.
Treat follow-ups like "implement these", "create those", "go on", or "do it" after an analysis as proposal requests.
Do not narrate multi-step plans when calling tools. Do not claim that proposals were saved; tools only prepare reviewable drafts.
Every proposal tool call must include a concise user-facing rationale explaining why the proposal belongs in the model. Do not include private chain-of-thought.
Before proposing, inspect proposalMemory. Avoid duplicating pending, accepted, rejected, or failed proposals unless the user explicitly asks to revise them.
Treat accepted proposalMemory items with createdId as already implemented. When the user says "go on" or similar, propose the remaining useful gaps not already covered by proposalMemory.
Treat rejected proposalMemory items as not desired unless the user asks for alternatives.
Before proposing new objects, carefully map the user's request and currentAnalysis gaps against context.entityOverview first, then context.components, context.technologies, context.damageScenarios, context.attackSteps, context.threatScenarios, context.controls, and context.relationshipMap for exact IDs.
Prefer joining to existing objects over proposing duplicates. If an existing entity represents the same concept or endpoint, reuse its database ID in the proposal payload.
When creating a new attack step for an existing component, set payload.component to that component ID.
When asked for attack steps for a component, also ensure the proposed attack steps are connected into a usable path: reuse or propose a threat scenario, reuse or propose relevant damage scenarios, and link them through payload.attack_steps and payload.damage_scenarios.
If a relevant threat scenario or damage scenario already exists, reuse its existing ID in the new proposal payload instead of creating a duplicate. If neither exists, propose the missing damage scenario and threat scenario in the same response.
When creating a threat scenario, include all relevant existing component IDs, attack step IDs, and damage scenario IDs in payload.components, payload.attack_steps, and payload.damage_scenarios.
When creating a control for an existing component or attack step, set payload.component and payload.attack_steps to the matching existing IDs.
When creating a component that uses existing technologies, put those technology IDs in payload.technology.
Use references only for objects proposed in the same response. Use real IDs for existing objects already present in context.
Each rationale should mention whether the proposal fills a missing relationship, links to existing IDs, or creates a genuinely missing entity.

Use these API payload rules:
- technology: name, description.
- component: name, description, communicates_with array, technology array of existing technology IDs.
- damageScenario: name, description, affected_CIA_parts, safety_impact, finantial_impact, operational_impact, privacy_impact.
- attackStep: name, description, required_access, fr_et, fr_se, fr_koC, fr_WoO, fr_eq, optional component, previous_steps array, controls array.
- threatScenario: name, description, threat_class null, components array, attack_steps array, damage_scenarios array, compromises array.
- control: name, description, fr_et, fr_se, fr_koC, fr_WoO, fr_eq, optional component, attack_steps array.

Use tool references instead of invented database IDs for objects proposed in the same response.
Only use existing IDs from project context. Never include or invent project IDs.
Rating values:
- CIA bitmask: C=4, I=2, A=1, all=7.
- impact values: 0 Negligible, 1 Moderate, 2 Major, 3 Severe.
- fr_et: 0, 1, 4, 10, 17, 19, 99.
- fr_se: 0, 3, 6, 8.
- fr_koC: 0, 3, 7, 11.
- fr_WoO: 0, 1, 4, 10, 99.
- fr_eq: 0, 4, 7, 9.
'''.strip()


def _normalize_history(history):
    if not isinstance(history, list):
        return []

    normalized = []
    for item in history[-12:]:
        if not isinstance(item, dict):
            continue

        role = str(item.get('role', '')).strip()
        content = str(item.get('content', '')).strip()
        if role not in {'user', 'assistant'} or not content:
            continue

        normalized.append(('human' if role == 'user' else 'ai', content))

    return normalized


def _safe_list(value):
    return value if isinstance(value, list) else []


def _safe_dict(value):
    return value if isinstance(value, dict) else {}


def _normalize_proposal_memory(proposal_memory):
    if not isinstance(proposal_memory, list):
        return []

    normalized = []
    allowed_statuses = {'pending', 'accepted', 'rejected', 'failed', 'saving'}

    for item in proposal_memory[-60:]:
        if not isinstance(item, dict):
            continue

        proposal_type = str(item.get('type', '')).strip()
        status = str(item.get('status', '')).strip()
        temp_id = str(item.get('tempId', '')).strip()
        title = str(item.get('title', '')).strip()

        if proposal_type not in VALID_PROPOSAL_TYPES or status not in allowed_statuses:
            continue

        if not temp_id or not title:
            continue

        memory_item = {
            'tempId': temp_id,
            'type': proposal_type,
            'title': title,
            'description': str(item.get('description', '')).strip(),
            'rationale': str(item.get('rationale', '')).strip(),
            'status': status,
            'payload': _safe_dict(item.get('payload')),
            'references': _safe_list(item.get('references')),
        }

        created_id = item.get('createdId')
        if isinstance(created_id, int):
            memory_item['createdId'] = created_id

        error = str(item.get('error', '')).strip()
        if error:
            memory_item['error'] = error

        normalized.append(memory_item)

    return normalized


def _messages(project, prompt, history=None, proposal_memory=None):
    return [
        ('system', _system_prompt()),
        *_normalize_history(history),
        (
            'human',
            json.dumps(
                {
                    'prompt': prompt,
                    'context': _project_context(project),
                    'currentAnalysis': _build_state_analysis(project, {}),
                    'proposalMemory': _normalize_proposal_memory(proposal_memory),
                },
                ensure_ascii=False,
            ),
        ),
    ]


def _normalize_reference(reference):
    if not isinstance(reference, dict):
        raise AssistantProviderError('Proposal references must be objects.')

    field = str(reference.get('field', '')).strip()
    temp_id = str(reference.get('tempId', '')).strip()
    mode = str(reference.get('mode', '')).strip()
    label = str(reference.get('label', '')).strip()

    if not field or not temp_id or mode not in {'one', 'many'}:
        raise AssistantProviderError('Proposal reference is missing field, tempId, or valid mode.')

    return {
        'field': field,
        'tempId': temp_id,
        'mode': mode,
        'label': label,
    }


def _normalize_proposal(proposal):
    if not isinstance(proposal, dict):
        raise AssistantProviderError('Each proposal must be an object.')

    temp_id = str(proposal.get('tempId', '')).strip()
    proposal_type = str(proposal.get('type', '')).strip()
    title = str(proposal.get('title', '')).strip()
    description = str(proposal.get('description', '')).strip()
    rationale = str(proposal.get('rationale', '')).strip()
    payload = proposal.get('payload')
    references = proposal.get('references', [])

    if not temp_id or not title:
        raise AssistantProviderError('Proposal is missing tempId or title.')

    if proposal_type not in VALID_PROPOSAL_TYPES:
        raise AssistantProviderError(f'Unsupported proposal type: {proposal_type}')

    if not isinstance(payload, dict):
        raise AssistantProviderError('Proposal payload must be an object.')

    if references is None:
        references = []

    if not isinstance(references, list):
        raise AssistantProviderError('Proposal references must be a list.')

    return {
        'tempId': temp_id,
        'type': proposal_type,
        'title': title,
        'description': description,
        'rationale': rationale,
        'payload': payload,
        'references': [_normalize_reference(reference) for reference in references],
        'status': 'pending',
    }


def _assistant_base_url():
    return re.sub(r'/chat/completions/?$', '', settings.ASSISTANT_API_URL.rstrip('/'))


def _tool_call_name(tool_call):
    if isinstance(tool_call, dict):
        return tool_call.get('name')
    return getattr(tool_call, 'name', None)


def _tool_call_args(tool_call):
    if isinstance(tool_call, dict):
        return tool_call.get('args', {})
    return getattr(tool_call, 'args', {})


def _assistant_content(response):
    content = getattr(response, 'content', '')
    if isinstance(content, str):
        return content.strip()

    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get('text'), str):
                parts.append(item['text'])
        return '\n'.join(part.strip() for part in parts if part.strip())

    return ''


def _gap(severity, title, description):
    return {
        'severity': severity,
        'title': title,
        'description': description,
    }


def _build_state_analysis(project, args):
    focus = str(args.get('focus', '')).strip()
    include_gaps = args.get('include_gaps', True)
    include_recommendations = args.get('include_recommendations', True)

    components = list(project.components.all().order_by('name'))
    technologies = list(project.technologies.all())
    damage_scenarios = list(project.damage_scenarios.all())
    attack_steps = list(project.attack_steps.all())
    threat_scenarios = list(project.threat_scenarios.all())
    controls = list(project.controls.all())

    counts = {
        'technologies': len(technologies),
        'components': len(components),
        'damageScenarios': len(damage_scenarios),
        'attackSteps': len(attack_steps),
        'threatScenarios': len(threat_scenarios),
        'controls': len(controls),
    }
    gaps = []

    if not components:
        gaps.append(_gap('high', 'No components modeled', 'Start by modeling the primary system components and interfaces.'))

    for component in components:
        if not component.mapped_damage_scenarios.exists():
            gaps.append(_gap('medium', f'{component.name} has no damage scenarios', 'Add impact-focused damage scenarios for this component.'))
        if not component.attack_steps.exists():
            gaps.append(_gap('medium', f'{component.name} has no attack steps', 'Add attack path steps tied to this component.'))
        if not component.controls.exists():
            gaps.append(_gap('low', f'{component.name} has no controls', 'Add or link controls after attack steps are modeled.'))

    for scenario in threat_scenarios:
        if not scenario.attack_steps.exists() or not scenario.damage_scenarios.exists():
            gaps.append(_gap('medium', f'{scenario.name} is weakly linked', 'Threat scenarios should connect at least one attack step to at least one damage scenario.'))

    for step in attack_steps:
        if not step.threat_scenarios.exists():
            gaps.append(_gap('low', f'{step.name} is not linked to a threat scenario', 'Link the attack step into a threat scenario so it contributes to an end-to-end path.'))

    recommendations = []
    if include_recommendations:
        if counts['technologies'] and counts['components']:
            recommendations.append('Check that each component is linked to the technologies it actually uses.')
        if counts['damageScenarios'] and counts['attackSteps'] and not counts['threatScenarios']:
            recommendations.append('Create threat scenarios to connect attack steps to damage scenarios.')
        if gaps:
            recommendations.append('Prioritize medium and high gaps before adding lower-value controls.')
        if not recommendations:
            recommendations.append('The model has a coherent starting structure; refine ratings and relationships next.')

    if focus:
        recommendations.insert(0, f'Focus requested: {focus}')

    summary = (
        f"{project.name} currently has {counts['components']} component(s), "
        f"{counts['damageScenarios']} damage scenario(s), {counts['attackSteps']} attack step(s), "
        f"{counts['threatScenarios']} threat scenario(s), and {counts['controls']} control(s)."
    )

    return {
        'title': 'Current state analysis',
        'summary': summary,
        'counts': counts,
        'gaps': gaps if include_gaps else [],
        'recommendations': recommendations,
    }


def _normalize_tool_calls(project, response):
    tool_calls = getattr(response, 'tool_calls', None)
    proposals = []
    analyses = []

    if not tool_calls:
        return proposals, analyses

    for tool_call in tool_calls:
        name = _tool_call_name(tool_call)
        args = _tool_call_args(tool_call)

        if not isinstance(name, str) or (
            name not in PROPOSAL_TOOL_MAP and name not in ANALYSIS_TOOL_MAP
        ):
            raise AssistantProviderError(f'Unsupported assistant tool call: {name}')

        if not isinstance(args, dict):
            raise AssistantProviderError(f'Arguments for {name} must be an object.')

        if name in ANALYSIS_TOOL_MAP:
            try:
                validated_args = ANALYSIS_TOOL_MAP[name].invoke(args)
            except ValidationError as exc:
                raise AssistantProviderError(f'Invalid arguments for {name}: {exc}') from exc
            except Exception as exc:
                raise AssistantProviderError(f'Failed to process {name}: {exc}') from exc

            analyses.append(_build_state_analysis(project, validated_args))
            continue

        try:
            proposal = PROPOSAL_TOOL_MAP[name].invoke(args)
        except ValidationError as exc:
            raise AssistantProviderError(f'Invalid arguments for {name}: {exc}') from exc
        except Exception as exc:
            raise AssistantProviderError(f'Failed to process {name}: {exc}') from exc

        proposals.append(_normalize_proposal(proposal))

    return proposals, analyses


def _call_assistant(project, prompt, history=None, proposal_memory=None):
    if not settings.ASSISTANT_API:
        raise AssistantConfigurationError('ASSISTANT_API is not configured.')

    if not settings.ASSISTANT_API_URL:
        raise AssistantConfigurationError('ASSISTANT_API_URL is not configured.')

    chat_model = ChatDeepSeek(
        model=settings.ASSISTANT_MODEL,
        api_key=settings.ASSISTANT_API,
        base_url=_assistant_base_url(),
        temperature=0.2,
        timeout=60,
    )
    chat_model_with_tools = chat_model.bind_tools(ASSISTANT_TOOLS, tool_choice='auto')

    try:
        response = chat_model_with_tools.invoke(
            _messages(project, prompt, history, proposal_memory)
        )
    except Exception as exc:
        raise AssistantProviderError(f'Assistant API request failed: {exc}') from exc

    return response


def _fallback_message(proposals, analyses):
    if analyses:
        return 'I analyzed the current model state.'

    if proposals:
        return _proposal_summary(proposals)

    return ''


def _proposal_title(proposal):
    title = str(proposal.get('title') or proposal.get('payload', {}).get('name') or '').strip()
    return title or str(proposal.get('tempId', 'Untitled proposal')).strip()


def _proposal_reason(proposal):
    rationale = str(proposal.get('rationale', '')).strip()
    if rationale:
        return rationale

    description = str(proposal.get('description', '')).strip()
    if description:
        return description

    return 'The assistant marked this as useful for the requested model changes.'


def _proposal_summary(proposals):
    proposal_word = 'proposal' if len(proposals) == 1 else 'proposals'
    lines = [
        f"I prepared {len(proposals)} {proposal_word} for review:",
        '',
    ]

    for proposal in proposals:
        proposal_type = PROPOSAL_TYPE_LABELS.get(proposal['type'], proposal['type'])
        lines.append(
            f"- {proposal_type}: {_proposal_title(proposal)} - {_proposal_reason(proposal)}"
        )

    return '\n'.join(lines)


def prepare_langchain_response(project, prompt, history=None, proposal_memory=None):
    response = _call_assistant(project, prompt, history, proposal_memory)
    proposals, analyses = _normalize_tool_calls(project, response)
    message = _fallback_message(proposals, analyses) or _assistant_content(response)

    if not message and not proposals and not analyses:
        raise AssistantProviderError('Assistant response did not include text or tool calls.')

    return {
        'prompt': prompt,
        'provider': 'assistant',
        'mode': 'conversation',
        'assistantApiConfigured': True,
        'apiUrlConfigured': True,
        'model': settings.ASSISTANT_MODEL,
        'message': message,
        'analysis': analyses[0] if analyses else None,
        'proposals': proposals,
    }
