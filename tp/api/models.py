from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MaxValueValidator, MinValueValidator


# ISO/SAE 21434 impact ratings stored as ordered integers:
# 0 = Negligible, 1 = Moderate, 2 = Major, 3 = Severe
class ImpactRating(models.IntegerChoices):
    NEGLIGIBLE = 0, 'Negligible'
    MODERATE = 1, 'Moderate'
    MAJOR = 2, 'Major'
    SEVERE = 3, 'Severe'


# ISO/SAE 21434 attack-potential factor scores stored as the standard point values:
# ET: 0 = <=1 day, 1 = <=1 week, 4 = <=1 month, 10 = <=3 months, 17 = <=6 months, 19 = >6 months, 99 = not practical
# SE: 0 = Layman, 3 = Proficient, 6 = Expert, 8 = Multiple experts
# KoC: 0 = Public, 3 = Restricted, 7 = Sensitive, 11 = Critical
# WoO: 0 = Unnecessary/unlimited, 1 = Easy, 4 = Moderate, 10 = Difficult, 99 = None
# Eq: 0 = Standard, 4 = Specialized, 7 = Bespoke, 9 = Multiple bespoke
class ElapsedTimeScore(models.IntegerChoices):
    LEQ_1_DAY = 0, '<=1 day'
    LEQ_1_WEEK = 1, '<=1 week'
    LEQ_1_MONTH = 4, '<=1 month'
    LEQ_3_MONTHS = 10, '<=3 months'
    LEQ_6_MONTHS = 17, '<=6 months'
    GT_6_MONTHS = 19, '>6 months'
    NOT_PRACTICAL = 99, 'Not practical'


class SpecialistExpertiseScore(models.IntegerChoices):
    LAYMAN = 0, 'Layman'
    PROFICIENT = 3, 'Proficient'
    EXPERT = 6, 'Expert'
    MULTIPLE_EXPERTS = 8, 'Multiple experts'


class KnowledgeScore(models.IntegerChoices):
    PUBLIC = 0, 'Public'
    RESTRICTED = 3, 'Restricted'
    SENSITIVE = 7, 'Sensitive'
    CRITICAL = 11, 'Critical'


class WindowOfOpportunityScore(models.IntegerChoices):
    UNNECESSARY_UNLIMITED = 0, 'Unnecessary/unlimited'
    EASY = 1, 'Easy'
    MODERATE = 4, 'Moderate'
    DIFFICULT = 10, 'Difficult'
    NONE = 99, 'None'


class EquipmentScore(models.IntegerChoices):
    STANDARD = 0, 'Standard'
    SPECIALIZED = 4, 'Specialized'
    BESPOKE = 7, 'Bespoke'
    MULTIPLE_BESPOKE = 9, 'Multiple bespoke'


# CIA bitmask stored as a 3-bit integer in CIA order:
# 0b100 (4) = Confidentiality, 0b010 (2) = Integrity, 0b001 (1) = Availability
# Combinations are additive, so 0b111 (7) means all three are affected.
class CIABitmask:
    NONE = 0
    CONFIDENTIALITY = 4
    INTEGRITY = 2
    AVAILABILITY = 1


class Technology(models.Model):
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=500)
    project = models.ForeignKey(
        'Project', on_delete=models.CASCADE, related_name='technologies', null=True, blank=True)

    def __str__(self):
        return self.name


class Project(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    owner = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='projects')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class Component(models.Model):
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=500)
    communicates_with = models.ManyToManyField(
        'self', symmetrical=True, blank=True)
    technology = models.ManyToManyField(Technology, blank=True)
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name='components')

    def __str__(self):
        return self.name

    @property
    def mapped_threat_scenarios(self):
        return ThreatScenario.objects.filter(
            components=self
        ).distinct()

    @property
    def mapped_damage_scenarios(self):
        return DamageScenario.objects.filter(
            threat_scenarios__components=self
        ).distinct()


class DataEntity(models.Model):
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=500)
    component = models.ForeignKey(
        Component, null=True, blank=True, on_delete=models.SET_NULL, related_name='data_entities')
    technology = models.ManyToManyField(Technology, blank=True)
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name='data_entities', null=True, blank=True)

    def __str__(self):
        return self.name


class ControlClass(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    fr_et = models.PositiveSmallIntegerField(choices=ElapsedTimeScore.choices, default=ElapsedTimeScore.LEQ_1_DAY)
    fr_se = models.PositiveSmallIntegerField(choices=SpecialistExpertiseScore.choices, default=SpecialistExpertiseScore.LAYMAN)
    fr_koC = models.PositiveSmallIntegerField(choices=KnowledgeScore.choices, default=KnowledgeScore.PUBLIC)
    fr_WoO = models.PositiveSmallIntegerField(choices=WindowOfOpportunityScore.choices, default=WindowOfOpportunityScore.UNNECESSARY_UNLIMITED)
    fr_eq = models.PositiveSmallIntegerField(choices=EquipmentScore.choices, default=EquipmentScore.STANDARD)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['name']


class Control(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    control_class = models.ForeignKey(
        ControlClass, null=True, blank=True, on_delete=models.SET_NULL, related_name='controls')
    fr_et = models.PositiveSmallIntegerField(choices=ElapsedTimeScore.choices)
    fr_se = models.PositiveSmallIntegerField(choices=SpecialistExpertiseScore.choices)
    fr_koC = models.PositiveSmallIntegerField(choices=KnowledgeScore.choices)
    fr_WoO = models.PositiveSmallIntegerField(choices=WindowOfOpportunityScore.choices)
    fr_eq = models.PositiveSmallIntegerField(choices=EquipmentScore.choices)
    component = models.ForeignKey(
        Component, null=True, blank=True, on_delete=models.SET_NULL, related_name='controls')
    attack_steps = models.ManyToManyField('AttackStep', blank=True, related_name='controls')
    threat_scenarios = models.ManyToManyField('ThreatScenario', blank=True, related_name='controls')
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name='controls', null=True, blank=True)

    def __str__(self):
        return self.name


class ThreatClass(models.Model):
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=500)
    project = models.ForeignKey(Project, on_delete=models.CASCADE,
                                related_name='threat_classes', null=True, blank=True)

    def __str__(self):
        return self.name


class AttackStep(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    required_access = models.CharField(max_length=200, blank=True)
    fr_et = models.PositiveSmallIntegerField(choices=ElapsedTimeScore.choices)
    fr_se = models.PositiveSmallIntegerField(choices=SpecialistExpertiseScore.choices)
    fr_koC = models.PositiveSmallIntegerField(choices=KnowledgeScore.choices)
    fr_WoO = models.PositiveSmallIntegerField(choices=WindowOfOpportunityScore.choices)
    fr_eq = models.PositiveSmallIntegerField(choices=EquipmentScore.choices)
    component = models.ForeignKey(
        Component, null=True, blank=True, on_delete=models.SET_NULL, related_name='attack_steps')
    previous_steps = models.ManyToManyField(
        'self',
        symmetrical=False,
        blank=True,
        related_name='next_steps',
    )
    threat_class = models.ForeignKey(
        ThreatClass, null=True, blank=True, on_delete=models.SET_NULL)
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name='attack_steps', null=True, blank=True)

    def __str__(self):
        return self.name

    @property
    def mapped_damage_scenarios(self):
        return DamageScenario.objects.filter(
            threat_scenarios__attack_steps=self
        ).distinct()


class ThreatScenario(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    components = models.ManyToManyField(
        Component, blank=True, related_name='threat_scenarios')
    attack_steps = models.ManyToManyField(
        AttackStep, blank=True, related_name='threat_scenarios')
    threat_class = models.ForeignKey(
        ThreatClass, null=True, blank=True, on_delete=models.SET_NULL)
    damage_scenarios = models.ManyToManyField(
        'DamageScenario', blank=True, related_name='threat_scenarios')
    project = models.ForeignKey(Project, on_delete=models.CASCADE,
                                related_name='threat_scenarios', null=True, blank=True)

    def __str__(self):
        return self.name


class DamageScenario(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    affected_CIA_parts = models.PositiveSmallIntegerField(
        default=CIABitmask.NONE,
        validators=[MinValueValidator(0), MaxValueValidator(7)],
    )
    impact_scale = models.PositiveSmallIntegerField(choices=ImpactRating.choices)
    safety_impact = models.PositiveSmallIntegerField(choices=ImpactRating.choices)
    finantial_impact = models.PositiveSmallIntegerField(choices=ImpactRating.choices)
    operational_impact = models.PositiveSmallIntegerField(choices=ImpactRating.choices)
    privacy_impact = models.PositiveSmallIntegerField(choices=ImpactRating.choices)
    project = models.ForeignKey(Project, on_delete=models.CASCADE,
                                related_name='damage_scenarios', null=True, blank=True)

    def __str__(self):
        return self.name

    @property
    def mapped_attack_steps(self):
        return AttackStep.objects.filter(
            threat_scenarios__damage_scenarios=self
        ).distinct()

    def save(self, *args, **kwargs):
        self.impact_scale = max(
            self.safety_impact,
            self.finantial_impact,
            self.operational_impact,
            self.privacy_impact,
        )
        super().save(*args, **kwargs)

    @property
    def affected_cia_binary(self):
        return format(self.affected_CIA_parts, '03b')


class DamageScenarioConcern(models.Model):
    damage_scenario = models.ForeignKey(
        DamageScenario,
        on_delete=models.CASCADE,
        related_name='concerns',
    )
    component = models.ForeignKey(
        Component,
        on_delete=models.CASCADE,
        related_name='damage_scenario_concerns',
    )
    affected_CIA_parts = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(7)],
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['damage_scenario', 'component'],
                name='unique_damage_scenario_component_concern',
            )
        ]

    def __str__(self):
        return f"{self.damage_scenario} - {self.component} - {self.affected_CIA_parts}"

    @property
    def affected_cia_binary(self):
        return format(self.affected_CIA_parts, '03b')


class RiskTreatmentDecision(models.TextChoices):
    AVOID = 'avoid', 'Avoid'
    REDUCE = 'reduce', 'Reduce'
    SHARE = 'share', 'Share'
    ACCEPT = 'accept', 'Accept'


class RiskTreatment(models.Model):
    threat_scenario = models.ForeignKey(
        ThreatScenario, on_delete=models.CASCADE, related_name='risk_treatments')
    damage_scenario = models.ForeignKey(
        DamageScenario, on_delete=models.CASCADE, related_name='risk_treatments')
    decision = models.CharField(max_length=10, choices=RiskTreatmentDecision.choices)
    rationale = models.TextField(blank=True)
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name='risk_treatments')

    class Meta:
        unique_together = [['threat_scenario', 'damage_scenario']]
        ordering = ['threat_scenario', 'damage_scenario']

    def __str__(self):
        return f"{self.threat_scenario} / {self.damage_scenario}: {self.decision}"


class ControlGroup(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name='control_groups')
    controls = models.ManyToManyField(
        'Control', blank=True, related_name='control_groups')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['name']


class CybersecurityGoal(models.Model):
    CAL_CHOICES = [(1, 'CAL 1'), (2, 'CAL 2'), (3, 'CAL 3'), (4, 'CAL 4')]

    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    cal = models.PositiveSmallIntegerField(choices=CAL_CHOICES, null=True, blank=True)
    damage_scenarios = models.ManyToManyField(
        DamageScenario, blank=True, related_name='cybersecurity_goals')
    controls = models.ManyToManyField(
        'Control', blank=True, related_name='cybersecurity_goals')
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name='cybersecurity_goals')

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class Comporomises(models.Model):
    compromised_CIA_part = models.PositiveSmallIntegerField(
        default=CIABitmask.NONE,
        validators=[MinValueValidator(0), MaxValueValidator(7)],
    )
    threat_scenario = models.ForeignKey(
        ThreatScenario, null=True, blank=True, on_delete=models.SET_NULL, related_name='compromise_items')
    component = models.ForeignKey(
        Component, null=True, blank=True, on_delete=models.SET_NULL, related_name='compromises')
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name='compromises', null=True, blank=True)

    def __str__(self):
        return f"{self.component} - {self.compromised_CIA_part}"

    @property
    def compromised_cia_binary(self):
        return format(self.compromised_CIA_part, '03b')
