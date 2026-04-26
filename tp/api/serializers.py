from rest_framework import serializers
from .models import *
from .calculations import calculate_attack_feasibility, calculate_impact_level, impact_level_label
from django.contrib.auth.models import User


LEGACY_IMPACT_ALIASES = {
    'low': ImpactRating.NEGLIGIBLE,
    'negligible': ImpactRating.NEGLIGIBLE,
    'medium': ImpactRating.MODERATE,
    'moderate': ImpactRating.MODERATE,
    'high': ImpactRating.MAJOR,
    'major': ImpactRating.MAJOR,
    'critical': ImpactRating.SEVERE,
    'severe': ImpactRating.SEVERE,
}

LEGACY_CIA_ALIASES = {
    '': CIABitmask.NONE,
    '0': CIABitmask.NONE,
    '000': CIABitmask.NONE,
    'none': CIABitmask.NONE,
    'availability': CIABitmask.AVAILABILITY,
    'a': CIABitmask.AVAILABILITY,
    '1': CIABitmask.AVAILABILITY,
    '001': CIABitmask.AVAILABILITY,
    'integrity': CIABitmask.INTEGRITY,
    'i': CIABitmask.INTEGRITY,
    '2': CIABitmask.INTEGRITY,
    '010': CIABitmask.INTEGRITY,
    'confidentiality': CIABitmask.CONFIDENTIALITY,
    'c': CIABitmask.CONFIDENTIALITY,
    '4': CIABitmask.CONFIDENTIALITY,
    '100': CIABitmask.CONFIDENTIALITY,
    'ia': CIABitmask.INTEGRITY | CIABitmask.AVAILABILITY,
    '011': CIABitmask.INTEGRITY | CIABitmask.AVAILABILITY,
    'ca': CIABitmask.CONFIDENTIALITY | CIABitmask.AVAILABILITY,
    '101': CIABitmask.CONFIDENTIALITY | CIABitmask.AVAILABILITY,
    'ci': CIABitmask.CONFIDENTIALITY | CIABitmask.INTEGRITY,
    '110': CIABitmask.CONFIDENTIALITY | CIABitmask.INTEGRITY,
    'cia': CIABitmask.CONFIDENTIALITY | CIABitmask.INTEGRITY | CIABitmask.AVAILABILITY,
    'all': CIABitmask.CONFIDENTIALITY | CIABitmask.INTEGRITY | CIABitmask.AVAILABILITY,
    '111': CIABitmask.CONFIDENTIALITY | CIABitmask.INTEGRITY | CIABitmask.AVAILABILITY,
}

LEGACY_ET_ALIASES = {
    'low': ElapsedTimeScore.LEQ_1_DAY,
    'medium': ElapsedTimeScore.LEQ_1_MONTH,
    'high': ElapsedTimeScore.LEQ_3_MONTHS,
    'critical': ElapsedTimeScore.GT_6_MONTHS,
}

LEGACY_SE_ALIASES = {
    'low': SpecialistExpertiseScore.LAYMAN,
    'medium': SpecialistExpertiseScore.PROFICIENT,
    'high': SpecialistExpertiseScore.EXPERT,
    'critical': SpecialistExpertiseScore.MULTIPLE_EXPERTS,
}

LEGACY_KOC_ALIASES = {
    'low': KnowledgeScore.PUBLIC,
    'medium': KnowledgeScore.RESTRICTED,
    'high': KnowledgeScore.SENSITIVE,
    'critical': KnowledgeScore.CRITICAL,
}

LEGACY_WOO_ALIASES = {
    'low': WindowOfOpportunityScore.UNNECESSARY_UNLIMITED,
    'medium': WindowOfOpportunityScore.MODERATE,
    'high': WindowOfOpportunityScore.DIFFICULT,
}

LEGACY_EQ_ALIASES = {
    'low': EquipmentScore.STANDARD,
    'medium': EquipmentScore.SPECIALIZED,
    'high': EquipmentScore.BESPOKE,
    'critical': EquipmentScore.MULTIPLE_BESPOKE,
}


class FlexibleChoiceField(serializers.ChoiceField):
    def __init__(self, *args, aliases=None, **kwargs):
        self.aliases = {
            str(key).strip().lower(): value
            for key, value in (aliases or {}).items()
        }
        super().__init__(*args, **kwargs)

    def to_internal_value(self, data):
        if isinstance(data, str):
            normalized = data.strip().lower()
            if normalized in self.aliases:
                data = self.aliases[normalized]
            else:
                for value, label in self.choices.items():
                    if normalized == str(value).lower() or normalized == str(label).lower():
                        data = value
                        break
        return super().to_internal_value(data)


class CIABitmaskField(serializers.IntegerField):
    default_error_messages = {
        'invalid': 'Use a CIA bitmask between 0 and 7, for example 7/111 for CIA or 4/100 for C.',
    }

    def to_internal_value(self, data):
        if isinstance(data, str):
            normalized = data.strip().lower().replace(',', '').replace(' ', '')
            if normalized in LEGACY_CIA_ALIASES:
                data = LEGACY_CIA_ALIASES[normalized]
            elif len(normalized) == 3 and set(normalized) <= {'0', '1'}:
                data = int(normalized, 2)
        value = super().to_internal_value(data)
        if value < 0 or value > 7:
            self.fail('invalid')
        return value

    def to_representation(self, value):
        if value in (None, ''):
            return 0
        return int(value)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']

class ProjectSerializer(serializers.ModelSerializer):
    owner = UserSerializer(read_only=True)
    
    class Meta:
        model = Project
        fields = ['id', 'name', 'description', 'owner', 'created_at']

class TechnologySerializer(serializers.ModelSerializer):
    project_id = serializers.PrimaryKeyRelatedField(
        source='project',
        queryset=Project.objects.all(),
        required=True,
        write_only=True
    )
    
    class Meta:
        model = Technology
        fields = ["id", "name", "description", "project", "project_id"]
        extra_kwargs = {
            'name': {'max_length': 100},
            'description': {'max_length': 500},
            'project': {'read_only': True}
        }

class DataEntitySerializer(serializers.ModelSerializer):
    project_id = serializers.PrimaryKeyRelatedField(
        source='project',
        queryset=Project.objects.all(),
        required=True,
        write_only=True
    )
    
    class Meta:
        model = DataEntity
        fields = ["id", "name", "description", "component", "technology", "project", "project_id"]
        extra_kwargs = {
            'name': {'max_length': 100},
            'description': {'max_length': 500},
            'project': {'read_only': True}
        }

class ControlSimpleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Control
        fields = ["id", "name"]

class ComponentSimpleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Component
        fields = ["id", "name"]

class AttackStepSimpleSerializer(serializers.ModelSerializer):
    class Meta:
        model = AttackStep
        fields = ["id", "name"]

class DamageScenarioSimpleSerializer(serializers.ModelSerializer):
    il = serializers.SerializerMethodField()
    il_label = serializers.SerializerMethodField()

    class Meta:
        model = DamageScenario
        fields = ["id", "name", "description", "affected_CIA_parts", "impact_scale", "safety_impact",
                  "finantial_impact", "operational_impact", "privacy_impact", "il", "il_label"]

    def get_il(self, obj):
        return calculate_impact_level(obj)

    def get_il_label(self, obj):
        return impact_level_label(calculate_impact_level(obj))

class ThreatScenarioSimpleSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatScenario
        fields = ["id", "name"]

class DamageScenarioConcernSerializer(serializers.ModelSerializer):
    affected_CIA_parts = CIABitmaskField()
    affected_cia_binary = serializers.CharField(read_only=True)

    class Meta:
        model = DamageScenarioConcern
        fields = ["id", "component", "affected_CIA_parts", "affected_cia_binary"]
        extra_kwargs = {
            'id': {'read_only': False, 'required': False},
        }

class DamageScenarioSerializer(serializers.ModelSerializer):
    affected_CIA_parts = CIABitmaskField()
    impact_scale = FlexibleChoiceField(
        choices=ImpactRating.choices, aliases=LEGACY_IMPACT_ALIASES)
    safety_impact = FlexibleChoiceField(
        choices=ImpactRating.choices, aliases=LEGACY_IMPACT_ALIASES)
    finantial_impact = FlexibleChoiceField(
        choices=ImpactRating.choices, aliases=LEGACY_IMPACT_ALIASES)
    operational_impact = FlexibleChoiceField(
        choices=ImpactRating.choices, aliases=LEGACY_IMPACT_ALIASES)
    privacy_impact = FlexibleChoiceField(
        choices=ImpactRating.choices, aliases=LEGACY_IMPACT_ALIASES)
    threat_scenarios = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=ThreatScenario.objects.all(),
        required=False
    )
    project_id = serializers.PrimaryKeyRelatedField(
        source='project',
        queryset=Project.objects.all(),
        required=True,
        write_only=True
    )
    concerns = DamageScenarioConcernSerializer(many=True, required=False)
    il = serializers.SerializerMethodField()
    il_label = serializers.SerializerMethodField()
    
    class Meta:
        model = DamageScenario
        fields = [
            "id", "name", "description", "affected_CIA_parts", "impact_scale",
            "safety_impact", "finantial_impact", "operational_impact",
            "privacy_impact", "threat_scenarios", "concerns", "il", "il_label",
            "project", "project_id"
        ]
        extra_kwargs = {
            'name': {'max_length': 100},
            'project': {'read_only': True}
        }

    def create(self, validated_data):
        validated_data.pop('concerns', None)
        return super().create(validated_data)

    def update(self, instance, validated_data):
        validated_data.pop('concerns', None)
        return super().update(instance, validated_data)

    def get_il(self, obj):
        return calculate_impact_level(obj)

    def get_il_label(self, obj):
        return impact_level_label(calculate_impact_level(obj))


class DamageScenarioDetailSerializer(serializers.ModelSerializer):
    affected_cia_binary = serializers.CharField(read_only=True)
    threat_scenarios = ThreatScenarioSimpleSerializer(many=True, read_only=True)
    attack_steps = AttackStepSimpleSerializer(
        many=True, read_only=True, source='mapped_attack_steps')
    concerns = DamageScenarioConcernSerializer(many=True, read_only=True)
    il = serializers.SerializerMethodField()
    il_label = serializers.SerializerMethodField()

    class Meta:
        model = DamageScenario
        fields = [
            "id", "name", "description", "affected_CIA_parts", "impact_scale",
            "safety_impact", "finantial_impact", "operational_impact",
            "privacy_impact", "affected_cia_binary",
            "threat_scenarios", "attack_steps", "concerns", "il", "il_label", "project"
        ]

    def get_il(self, obj):
        return calculate_impact_level(obj)

    def get_il_label(self, obj):
        return impact_level_label(calculate_impact_level(obj))

class ControlSerializer(serializers.ModelSerializer):
    fr_et = FlexibleChoiceField(
        choices=ElapsedTimeScore.choices, aliases=LEGACY_ET_ALIASES)
    fr_se = FlexibleChoiceField(
        choices=SpecialistExpertiseScore.choices, aliases=LEGACY_SE_ALIASES)
    fr_koC = FlexibleChoiceField(
        choices=KnowledgeScore.choices, aliases=LEGACY_KOC_ALIASES)
    fr_WoO = FlexibleChoiceField(
        choices=WindowOfOpportunityScore.choices, aliases=LEGACY_WOO_ALIASES)
    fr_eq = FlexibleChoiceField(
        choices=EquipmentScore.choices, aliases=LEGACY_EQ_ALIASES)
    attack_steps = serializers.PrimaryKeyRelatedField(
        many=True, 
        queryset=AttackStep.objects.all(), 
        required=False
    )
    project_id = serializers.PrimaryKeyRelatedField(
        source='project',
        queryset=Project.objects.all(),
        required=True,
        write_only=True
    )
    attack_potential_points = serializers.SerializerMethodField()
    attack_potential = serializers.SerializerMethodField()
    afl = serializers.SerializerMethodField()
    afl_value = serializers.SerializerMethodField()
    
    class Meta:
        model = Control
        fields = [
            "id", "name", "description", "fr_et", "fr_se", "fr_koC", "fr_WoO", "fr_eq",
            "component", "attack_steps", "attack_potential_points", "attack_potential",
            "afl", "afl_value", "project", "project_id"
        ]
        extra_kwargs = {
            'name': {'max_length': 100},
            'project': {'read_only': True}
        }

    def get_attack_potential_points(self, obj):
        return calculate_attack_feasibility(obj)['attack_potential_points']

    def get_attack_potential(self, obj):
        return calculate_attack_feasibility(obj)['attack_potential']

    def get_afl(self, obj):
        return calculate_attack_feasibility(obj)['afl']

    def get_afl_value(self, obj):
        return calculate_attack_feasibility(obj)['afl_value']

class ControlDetailSerializer(serializers.ModelSerializer):
    attack_steps = AttackStepSimpleSerializer(many=True, read_only=True)
    attack_potential_points = serializers.SerializerMethodField()
    attack_potential = serializers.SerializerMethodField()
    afl = serializers.SerializerMethodField()
    afl_value = serializers.SerializerMethodField()
    
    class Meta:
        model = Control
        fields = [
            "id", "name", "description", "fr_et", "fr_se", "fr_koC", "fr_WoO", "fr_eq",
            "component", "attack_steps", "attack_potential_points", "attack_potential",
            "afl", "afl_value", "project"
        ]

    def get_attack_potential_points(self, obj):
        return calculate_attack_feasibility(obj)['attack_potential_points']

    def get_attack_potential(self, obj):
        return calculate_attack_feasibility(obj)['attack_potential']

    def get_afl(self, obj):
        return calculate_attack_feasibility(obj)['afl']

    def get_afl_value(self, obj):
        return calculate_attack_feasibility(obj)['afl_value']

class ThreatClassSerializer(serializers.ModelSerializer):
    project_id = serializers.PrimaryKeyRelatedField(
        source='project',
        queryset=Project.objects.all(),
        required=True,
        write_only=True
    )
    
    class Meta:
        model = ThreatClass
        fields = ["id", "name", "description", "project", "project_id"]
        extra_kwargs = {
            'name': {'max_length': 100},
            'description': {'max_length': 500},
            'project': {'read_only': True}
        }

class AttackStepSerializer(serializers.ModelSerializer):
    fr_et = FlexibleChoiceField(
        choices=ElapsedTimeScore.choices, aliases=LEGACY_ET_ALIASES)
    fr_se = FlexibleChoiceField(
        choices=SpecialistExpertiseScore.choices, aliases=LEGACY_SE_ALIASES)
    fr_koC = FlexibleChoiceField(
        choices=KnowledgeScore.choices, aliases=LEGACY_KOC_ALIASES)
    fr_WoO = FlexibleChoiceField(
        choices=WindowOfOpportunityScore.choices, aliases=LEGACY_WOO_ALIASES)
    fr_eq = FlexibleChoiceField(
        choices=EquipmentScore.choices, aliases=LEGACY_EQ_ALIASES)
    previous_steps = serializers.PrimaryKeyRelatedField(
        many=True, 
        queryset=AttackStep.objects.all(), 
        required=False
    )
    threat_scenarios = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=ThreatScenario.objects.all(),
        required=False
    )
    controls = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Control.objects.all(),
        required=False
    )
    project_id = serializers.PrimaryKeyRelatedField(
        source='project',
        queryset=Project.objects.all(),
        required=True,
        write_only=True
    )
    attack_potential_points = serializers.SerializerMethodField()
    attack_potential = serializers.SerializerMethodField()
    afl = serializers.SerializerMethodField()
    afl_value = serializers.SerializerMethodField()
    
    class Meta:
        model = AttackStep
        fields = [
            "id", "name", "description", "required_access", "fr_et", "fr_se", "fr_koC", "fr_WoO", "fr_eq",
            "component", "previous_steps", "threat_class", "threat_scenarios", "controls",
            "attack_potential_points", "attack_potential", "afl", "afl_value",
            "project", "project_id"
        ]
        extra_kwargs = {
            'name': {'max_length': 100},
            'project': {'read_only': True}
        }

    def get_attack_potential_points(self, obj):
        return calculate_attack_feasibility(obj)['attack_potential_points']

    def get_attack_potential(self, obj):
        return calculate_attack_feasibility(obj)['attack_potential']

    def get_afl(self, obj):
        return calculate_attack_feasibility(obj)['afl']

    def get_afl_value(self, obj):
        return calculate_attack_feasibility(obj)['afl_value']

class AttackStepDetailSerializer(serializers.ModelSerializer):
    previous_steps = AttackStepSimpleSerializer(many=True, read_only=True)
    next_steps = AttackStepSimpleSerializer(many=True, read_only=True)
    threat_scenarios = ThreatScenarioSimpleSerializer(many=True, read_only=True)
    controls = ControlSimpleSerializer(many=True, read_only=True)
    threat_class = ThreatClassSerializer(read_only=True)
    damage_scenarios = DamageScenarioSimpleSerializer(
        many=True, read_only=True, source='mapped_damage_scenarios')
    attack_potential_points = serializers.SerializerMethodField()
    attack_potential = serializers.SerializerMethodField()
    afl = serializers.SerializerMethodField()
    afl_value = serializers.SerializerMethodField()
    
    class Meta:
        model = AttackStep
        fields = [
            "id", "name", "description", "required_access", "fr_et", "fr_se", "fr_koC", "fr_WoO", "fr_eq",
            "component", "previous_steps", "next_steps", "threat_class", "threat_scenarios",
            "damage_scenarios", "controls", "attack_potential_points", "attack_potential",
            "afl", "afl_value", "project"
        ]

    def get_attack_potential_points(self, obj):
        return calculate_attack_feasibility(obj)['attack_potential_points']

    def get_attack_potential(self, obj):
        return calculate_attack_feasibility(obj)['attack_potential']

    def get_afl(self, obj):
        return calculate_attack_feasibility(obj)['afl']

    def get_afl_value(self, obj):
        return calculate_attack_feasibility(obj)['afl_value']

class ThreatScenarioSerializer(serializers.ModelSerializer):
    components = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Component.objects.all(),
        required=False
    )
    attack_steps = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=AttackStep.objects.all(),
        required=False
    )
    damage_scenarios = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=DamageScenario.objects.all(),
        required=False
    )
    compromises = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Comporomises.objects.all(),
        required=False
    )
    project_id = serializers.PrimaryKeyRelatedField(
        source='project',
        queryset=Project.objects.all(),
        required=True,
        write_only=True
    )
    
    class Meta:
        model = ThreatScenario
        fields = [
            "id", "name", "description", "components", "attack_steps", "damage_scenarios",
            "threat_class", "compromises", "project", "project_id"
        ]
        extra_kwargs = {
            'name': {'max_length': 100},
            'project': {'read_only': True}
        }

class ThreatScenarioDetailSerializer(serializers.ModelSerializer):
    components = ComponentSimpleSerializer(many=True, read_only=True)
    attack_steps = AttackStepSimpleSerializer(many=True, read_only=True)
    damage_scenarios = DamageScenarioSimpleSerializer(many=True, read_only=True)
    threat_class = ThreatClassSerializer(read_only=True)
    compromises = serializers.SerializerMethodField()
    
    class Meta:
        model = ThreatScenario
        fields = [
            "id", "name", "description", "components", "attack_steps", "damage_scenarios",
            "threat_class", "compromises", "project"
        ]
    
    def get_compromises(self, obj):
        return [{
            "component_id": c.component_id,
            "compromised_part_cia": c.compromised_CIA_part,
            "compromised_part_cia_binary": c.compromised_cia_binary,
        }
                for c in obj.compromise_items.all()]

class ComponentSerializer(serializers.ModelSerializer):
    communicates_with = serializers.PrimaryKeyRelatedField(
        many=True, 
        queryset=Component.objects.all(), 
        required=False
    )
    technology = serializers.PrimaryKeyRelatedField(
        many=True, 
        queryset=Technology.objects.all(), 
        required=False
    )
    data_entity = DataEntitySerializer(many=True, read_only=True)
    project_id = serializers.PrimaryKeyRelatedField(
        source='project',
        queryset=Project.objects.all(),
        required=True,
        write_only=True
    )
    
    class Meta:
        model = Component
        fields = ["id", "name", "description", "communicates_with", "technology", "data_entity", "project", "project_id"]
        extra_kwargs = {
            'name': {'max_length': 100},
            'description': {'max_length': 500},
            'project': {'read_only': True}
        }

class ComponentDetailSerializer(serializers.ModelSerializer):
    data_entity = DataEntitySerializer(many=True, read_only=True)
    technology = TechnologySerializer(many=True, read_only=True)
    damage_scenario = DamageScenarioSerializer(many=True, read_only=True, source='mapped_damage_scenarios')
    control = ControlDetailSerializer(many=True, read_only=True, source='controls')
    threat_scenarios = ThreatScenarioSimpleSerializer(
        many=True, read_only=True, source='mapped_threat_scenarios')
    attack_steps = AttackStepSimpleSerializer(many=True, read_only=True)
    
    class Meta:
        model = Component
        fields = ["id", "name", "description", "data_entity", "technology", "damage_scenario", 
                  "control", "threat_scenarios", "attack_steps", "project"]

class ComporomisesSerializer(serializers.ModelSerializer):
    compromised_CIA_part = CIABitmaskField()
    compromised_cia_binary = serializers.CharField(read_only=True)
    project_id = serializers.PrimaryKeyRelatedField(
        source='project',
        queryset=Project.objects.all(),
        required=True,
        write_only=True
    )
    
    class Meta:
        model = Comporomises
        fields = ["id", "compromised_CIA_part", "compromised_cia_binary", "threat_scenario", "component", "project", "project_id"]
        extra_kwargs = {
            'project': {'read_only': True}
        }
