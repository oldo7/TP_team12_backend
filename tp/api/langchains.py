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


def _project_context(project):
    return {
        'project': {
            'id': project.id,
            'name': project.name,
            'description': project.description,
        },
        'components': [
            {
                'id': component.id,
                'name': component.name,
                'description': component.description,
            }
            for component in project.components.all().order_by('name')
        ],
        'technologies': [
            {
                'id': technology.id,
                'name': technology.name,
                'description': technology.description,
            }
            for technology in project.technologies.all().order_by('name')
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
                'concerns': [
                    {
                        'component_id': concern.component_id,
                        'affected_CIA_parts': concern.affected_CIA_parts,
                    }
                    for concern in scenario.concerns.all()
                ],
            }
            for scenario in project.damage_scenarios.prefetch_related('concerns').all().order_by('name')
        ],
        'attackSteps': [
            {
                'id': step.id,
                'name': step.name,
                'description': step.description,
                'component_id': step.component_id,
                'required_access': step.required_access,
            }
            for step in project.attack_steps.all().order_by('name')
        ],
        'threatScenarios': [
            {
                'id': scenario.id,
                'name': scenario.name,
                'description': scenario.description,
                'component_ids': list(scenario.components.values_list('id', flat=True)),
                'attack_step_ids': list(scenario.attack_steps.values_list('id', flat=True)),
                'damage_scenario_ids': list(scenario.damage_scenarios.values_list('id', flat=True)),
            }
            for scenario in project.threat_scenarios.all().order_by('name')
        ],
        'controls': [
            {
                'id': control.id,
                'name': control.name,
                'description': control.description,
                'component_id': control.component_id,
                'attack_step_ids': list(control.attack_steps.values_list('id', flat=True)),
            }
            for control in project.controls.all().order_by('name')
        ],
    }


def _system_prompt():
    return '''
You are a conversational cybersecurity TARA assistant for an existing web app.
Answer normal questions directly in concise plain text.
When the user asks to inspect, review, audit, summarize, or analyze the current model, call analyze_current_state.
When the user asks to prepare, draft, create, suggest, or add TARA model objects, call the proposal tools for every object.
Do not claim that proposals were saved; tools only prepare reviewable drafts.

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


def _messages(project, prompt, history=None):
    return [
        ('system', _system_prompt()),
        *_normalize_history(history),
        (
            'human',
            json.dumps(
                {
                    'prompt': prompt,
                    'context': _project_context(project),
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


def _call_assistant(project, prompt, history=None):
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
        response = chat_model_with_tools.invoke(_messages(project, prompt, history))
    except Exception as exc:
        raise AssistantProviderError(f'Assistant API request failed: {exc}') from exc

    return response


def _fallback_message(proposals, analyses):
    parts = []
    if analyses:
        parts.append('I analyzed the current model state.')
    if proposals:
        parts.append(f"I prepared {len(proposals)} proposal{'s' if len(proposals) != 1 else ''} for review.")
    return ' '.join(parts)


def prepare_langchain_response(project, prompt, history=None):
    response = _call_assistant(project, prompt, history)
    proposals, analyses = _normalize_tool_calls(project, response)
    message = _assistant_content(response) or _fallback_message(proposals, analyses)

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
