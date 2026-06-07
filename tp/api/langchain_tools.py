from typing import Any, Literal

from langchain_core.tools import tool
from pydantic import BaseModel, Field


class ProposalReference(BaseModel):
    field: str = Field(description='API payload field that will receive the referenced object ID.')
    tempId: str = Field(description='Temporary proposal ID being referenced.')
    mode: Literal['one', 'many'] = Field(description='Whether the field expects one ID or many IDs.')
    label: str = Field(default='', description='Human-readable label for the referenced proposal.')


class ProposalArgs(BaseModel):
    temp_id: str = Field(description='Stable kebab-case local proposal ID.')
    title: str = Field(description='Short UI title.')
    description: str = Field(default='', description='Short UI summary.')
    rationale: str = Field(
        default='',
        description='Concise user-facing reason this proposal should be included.',
    )
    references: list[ProposalReference] | None = Field(
        default=None,
        description='Deferred relationships to proposals that may not exist in the database yet.',
    )


class TechnologyArgs(ProposalArgs):
    name: str


class ComponentArgs(ProposalArgs):
    name: str
    communicates_with: list[int] | None = None
    technology: list[int] | None = None


class DamageScenarioArgs(ProposalArgs):
    name: str
    affected_CIA_parts: int = Field(ge=0, le=7)
    safety_impact: int = Field(ge=0, le=3)
    finantial_impact: int = Field(ge=0, le=3)
    operational_impact: int = Field(ge=0, le=3)
    privacy_impact: int = Field(ge=0, le=3)


class AttackStepArgs(ProposalArgs):
    name: str
    required_access: str = ''
    fr_et: Literal[0, 1, 4, 10, 17, 19, 99]
    fr_se: Literal[0, 3, 6, 8]
    fr_koC: Literal[0, 3, 7, 11]
    fr_WoO: Literal[0, 1, 4, 10, 99]
    fr_eq: Literal[0, 4, 7, 9]
    component: int | None = None
    previous_steps: list[int] | None = None
    controls: list[int] | None = None


class CompromiseReference(BaseModel):
    component_id: int | None = None
    compromised_part_cia: int = Field(ge=0, le=7)


class ThreatScenarioArgs(ProposalArgs):
    name: str
    threat_class: int | None = None
    components: list[int] | None = None
    attack_steps: list[int] | None = None
    damage_scenarios: list[int] | None = None
    compromises: list[CompromiseReference] | None = None


class ControlArgs(ProposalArgs):
    name: str
    fr_et: Literal[0, 1, 4, 10, 17, 19, 99]
    fr_se: Literal[0, 3, 6, 8]
    fr_koC: Literal[0, 3, 7, 11]
    fr_WoO: Literal[0, 1, 4, 10, 99]
    fr_eq: Literal[0, 4, 7, 9]
    component: int | None = None
    attack_steps: list[int] | None = None


class AnalyzeCurrentStateArgs(BaseModel):
    focus: str = Field(
        default='',
        description='Optional user-specified area to emphasize in the current project analysis.',
    )
    include_gaps: bool = Field(default=True)
    include_recommendations: bool = Field(default=True)


def _references(references: list[ProposalReference] | None) -> list[dict[str, Any]]:
    return [reference.model_dump() for reference in references or []]


def _proposal(
    *,
    temp_id: str,
    proposal_type: str,
    title: str,
    description: str,
    rationale: str,
    payload: dict[str, Any],
    references: list[ProposalReference] | None,
) -> dict[str, Any]:
    return {
        'tempId': temp_id,
        'type': proposal_type,
        'title': title,
        'description': description,
        'rationale': rationale,
        'payload': payload,
        'references': _references(references),
        'status': 'pending',
    }


@tool(args_schema=TechnologyArgs)
def propose_technology(
    temp_id: str,
    title: str,
    description: str,
    name: str,
    rationale: str = '',
    references: list[ProposalReference] | None = None,
) -> dict[str, Any]:
    """Prepare a technology proposal for the current project."""
    return _proposal(
        temp_id=temp_id,
        proposal_type='technology',
        title=title,
        description=description,
        rationale=rationale,
        payload={
            'name': name,
            'description': description,
        },
        references=references,
    )


@tool(args_schema=ComponentArgs)
def propose_component(
    temp_id: str,
    title: str,
    description: str,
    name: str,
    communicates_with: list[int] | None = None,
    technology: list[int] | None = None,
    rationale: str = '',
    references: list[ProposalReference] | None = None,
) -> dict[str, Any]:
    """Prepare a component proposal. Use references for not-yet-created related proposals."""
    return _proposal(
        temp_id=temp_id,
        proposal_type='component',
        title=title,
        description=description,
        rationale=rationale,
        payload={
            'name': name,
            'description': description,
            'communicates_with': communicates_with or [],
            'technology': technology or [],
        },
        references=references,
    )


@tool(args_schema=DamageScenarioArgs)
def propose_damage_scenario(
    temp_id: str,
    title: str,
    description: str,
    name: str,
    affected_CIA_parts: int,
    safety_impact: int,
    finantial_impact: int,
    operational_impact: int,
    privacy_impact: int,
    rationale: str = '',
    references: list[ProposalReference] | None = None,
) -> dict[str, Any]:
    """Prepare a damage scenario proposal using CIA and impact integer ratings."""
    payload = {
        'name': name,
        'description': description,
        'affected_CIA_parts': affected_CIA_parts,
        'safety_impact': safety_impact,
        'finantial_impact': finantial_impact,
        'operational_impact': operational_impact,
        'privacy_impact': privacy_impact,
    }
    return _proposal(
        temp_id=temp_id,
        proposal_type='damageScenario',
        title=title,
        description=description,
        rationale=rationale,
        payload=payload,
        references=references,
    )


@tool(args_schema=AttackStepArgs)
def propose_attack_step(
    temp_id: str,
    title: str,
    description: str,
    name: str,
    fr_et: int,
    fr_se: int,
    fr_koC: int,
    fr_WoO: int,
    fr_eq: int,
    required_access: str = '',
    component: int | None = None,
    previous_steps: list[int] | None = None,
    controls: list[int] | None = None,
    rationale: str = '',
    references: list[ProposalReference] | None = None,
) -> dict[str, Any]:
    """Prepare an attack step proposal using ISO/SAE attack-potential factor scores."""
    payload = {
        'name': name,
        'description': description,
        'required_access': required_access,
        'fr_et': fr_et,
        'fr_se': fr_se,
        'fr_koC': fr_koC,
        'fr_WoO': fr_WoO,
        'fr_eq': fr_eq,
        'previous_steps': previous_steps or [],
        'controls': controls or [],
    }
    if component is not None:
        payload['component'] = component
    return _proposal(
        temp_id=temp_id,
        proposal_type='attackStep',
        title=title,
        description=description,
        rationale=rationale,
        payload=payload,
        references=references,
    )


@tool(args_schema=ThreatScenarioArgs)
def propose_threat_scenario(
    temp_id: str,
    title: str,
    description: str,
    name: str,
    threat_class: int | None = None,
    components: list[int] | None = None,
    attack_steps: list[int] | None = None,
    damage_scenarios: list[int] | None = None,
    compromises: list[CompromiseReference] | None = None,
    rationale: str = '',
    references: list[ProposalReference] | None = None,
) -> dict[str, Any]:
    """Prepare a threat scenario proposal linking attack steps, damage scenarios, and compromises."""
    return _proposal(
        temp_id=temp_id,
        proposal_type='threatScenario',
        title=title,
        description=description,
        rationale=rationale,
        payload={
            'name': name,
            'description': description,
            'threat_class': threat_class,
            'components': components or [],
            'attack_steps': attack_steps or [],
            'damage_scenarios': damage_scenarios or [],
            'compromises': [
                compromise.model_dump() for compromise in compromises or []
            ],
        },
        references=references,
    )


@tool(args_schema=ControlArgs)
def propose_control(
    temp_id: str,
    title: str,
    description: str,
    name: str,
    fr_et: int,
    fr_se: int,
    fr_koC: int,
    fr_WoO: int,
    fr_eq: int,
    component: int | None = None,
    attack_steps: list[int] | None = None,
    rationale: str = '',
    references: list[ProposalReference] | None = None,
) -> dict[str, Any]:
    """Prepare a control proposal using ISO/SAE attack-potential factor scores."""
    payload = {
        'name': name,
        'description': description,
        'fr_et': fr_et,
        'fr_se': fr_se,
        'fr_koC': fr_koC,
        'fr_WoO': fr_WoO,
        'fr_eq': fr_eq,
        'attack_steps': attack_steps or [],
    }
    if component is not None:
        payload['component'] = component
    return _proposal(
        temp_id=temp_id,
        proposal_type='control',
        title=title,
        description=description,
        rationale=rationale,
        payload=payload,
        references=references,
    )


@tool(args_schema=AnalyzeCurrentStateArgs)
def analyze_current_state(
    focus: str = '',
    include_gaps: bool = True,
    include_recommendations: bool = True,
) -> dict[str, Any]:
    """Analyze the current project model state before proposing or changing anything."""
    return {
        'focus': focus,
        'include_gaps': include_gaps,
        'include_recommendations': include_recommendations,
    }


PROPOSAL_TOOLS = [
    propose_technology,
    propose_component,
    propose_damage_scenario,
    propose_attack_step,
    propose_threat_scenario,
    propose_control,
]

ANALYSIS_TOOLS = [analyze_current_state]

ASSISTANT_TOOLS = [*PROPOSAL_TOOLS, *ANALYSIS_TOOLS]

PROPOSAL_TOOL_MAP = {proposal_tool.name: proposal_tool for proposal_tool in PROPOSAL_TOOLS}

ANALYSIS_TOOL_MAP = {analysis_tool.name: analysis_tool for analysis_tool in ANALYSIS_TOOLS}
