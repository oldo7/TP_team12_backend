from django.contrib.auth.models import User
from rest_framework.test import APITestCase

from .models import (
    AttackStep,
    CIABitmask,
    Component,
    Comporomises,
    DamageScenario,
    DamageScenarioConcern,
    ElapsedTimeScore,
    EquipmentScore,
    ImpactRating,
    KnowledgeScore,
    Project,
    SpecialistExpertiseScore,
    ThreatScenario,
    WindowOfOpportunityScore,
)


class TaraMappingTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='tester', password='secret')
        self.client.force_authenticate(user=self.user)

        self.project = Project.objects.create(
            name='Test Project',
            description='TARA mapping test',
            owner=self.user,
        )
        self.component = Component.objects.create(
            name='Gateway ECU',
            description='Gateway component',
            project=self.project,
        )
        self.attack_step = AttackStep.objects.create(
            name='Inject malicious CAN frame',
            fr_et=ElapsedTimeScore.LEQ_1_DAY,
            fr_se=SpecialistExpertiseScore.LAYMAN,
            fr_koC=KnowledgeScore.PUBLIC,
            fr_WoO=WindowOfOpportunityScore.UNNECESSARY_UNLIMITED,
            fr_eq=EquipmentScore.STANDARD,
            component=self.component,
            project=self.project,
        )
        self.damage_scenario = DamageScenario.objects.create(
            name='Loss of braking availability',
            affected_CIA_parts=CIABitmask.AVAILABILITY,
            impact_scale=ImpactRating.MAJOR,
            safety_impact=ImpactRating.MAJOR,
            finantial_impact=ImpactRating.MODERATE,
            operational_impact=ImpactRating.MAJOR,
            privacy_impact=ImpactRating.NEGLIGIBLE,
            project=self.project,
        )
        self.threat_scenario = ThreatScenario.objects.create(
            name='Compromise brake command path',
            project=self.project,
        )
        self.threat_scenario.attack_steps.add(self.attack_step)
        self.threat_scenario.damage_scenarios.add(self.damage_scenario)
        self.threat_scenario.components.add(self.component)

    def test_attack_step_detail_lists_mapped_damage_scenarios(self):
        response = self.client.get(
            f'/api/attack_step/{self.attack_step.id}/',
            {'project_id': self.project.id},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [scenario['id'] for scenario in response.data['damage_scenarios']],
            [self.damage_scenario.id],
        )
        self.assertEqual(
            [scenario['id'] for scenario in response.data['threat_scenarios']],
            [self.threat_scenario.id],
        )
        self.assertEqual(response.data['attack_potential_points'], 0)
        self.assertEqual(response.data['attack_potential'], 'Basic')
        self.assertEqual(response.data['afl'], 'High')
        self.assertEqual(response.data['afl_value'], 5)

    def test_damage_scenario_detail_lists_mapped_attack_steps(self):
        response = self.client.get(
            f'/api/damage_scenario/{self.damage_scenario.id}/',
            {'project_id': self.project.id},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [step['id'] for step in response.data['attack_steps']],
            [self.attack_step.id],
        )
        self.assertEqual(response.data['affected_CIA_parts'], CIABitmask.AVAILABILITY)
        self.assertEqual(response.data['affected_cia_binary'], '001')
        self.assertEqual(response.data['il'], ImpactRating.MAJOR)
        self.assertEqual(response.data['il_label'], 'Major')
        self.assertEqual(
            [scenario['id'] for scenario in response.data['threat_scenarios']],
            [self.threat_scenario.id],
        )

    def test_attack_step_create_can_auto_attach_threat_scenario_by_name(self):
        response = self.client.post(
            '/api/attack_step/',
            {
                'name': 'Replay authenticated message',
                'fr_et': 'Medium',
                'fr_se': 'Low',
                'fr_koC': 'Low',
                'fr_WoO': 'Low',
                'fr_eq': 'Low',
                'component': self.component.id,
                'project_id': self.project.id,
                'threat_scenario_name': 'Spoof valid braking message',
            },
            format='json',
        )

        self.assertEqual(response.status_code, 201)
        attack_step = AttackStep.objects.get(id=response.data['id'])
        damage_scenario = DamageScenario.objects.get(
            name='Damage scenario for Replay authenticated message',
        )
        self.assertEqual(
            list(attack_step.threat_scenarios.values_list('name', flat=True)),
            ['Spoof valid braking message'],
        )
        self.assertEqual(list(attack_step.threat_scenarios.get().components.all()), [self.component])
        self.assertEqual(
            list(damage_scenario.threat_scenarios.values_list('name', flat=True)),
            ['Spoof valid braking message'],
        )

    def test_attack_step_create_creates_joined_damage_scenario(self):
        response = self.client.post(
            '/api/attack_step/',
            {
                'name': 'Exploit diagnostic session',
                'description': 'Unlock restricted diagnostics',
                'fr_et': ElapsedTimeScore.LEQ_1_WEEK,
                'fr_se': SpecialistExpertiseScore.PROFICIENT,
                'fr_koC': KnowledgeScore.RESTRICTED,
                'fr_WoO': WindowOfOpportunityScore.EASY,
                'fr_eq': EquipmentScore.SPECIALIZED,
                'component': self.component.id,
                'project_id': self.project.id,
            },
            format='json',
        )

        self.assertEqual(response.status_code, 201)
        attack_step = AttackStep.objects.get(id=response.data['id'])
        damage_scenario = DamageScenario.objects.get(
            name='Damage scenario for Exploit diagnostic session',
        )

        self.assertEqual(damage_scenario.project, self.project)
        self.assertEqual(damage_scenario.affected_CIA_parts, CIABitmask.NONE)
        self.assertEqual(damage_scenario.impact_scale, ImpactRating.NEGLIGIBLE)
        self.assertEqual(attack_step.mapped_damage_scenarios.get(), damage_scenario)
        self.assertEqual(damage_scenario.mapped_attack_steps.get(), attack_step)
        self.assertEqual(
            list(attack_step.threat_scenarios.values_list('name', flat=True)),
            ['Threat scenario for Exploit diagnostic session'],
        )
        self.assertEqual(list(attack_step.threat_scenarios.get().components.all()), [self.component])

    def test_damage_scenario_create_can_reuse_existing_threat_scenario_by_name(self):
        response = self.client.post(
            '/api/damage_scenario/',
            {
                'name': 'Unexpected braking command',
                'affected_CIA_parts': '010',
                'impact_scale': 'Major',
                'safety_impact': 'Major',
                'finantial_impact': 'Moderate',
                'operational_impact': 'Major',
                'privacy_impact': 'Negligible',
                'project_id': self.project.id,
                'threat_scenario_name': self.threat_scenario.name,
            },
            format='json',
        )

        self.assertEqual(response.status_code, 201)
        damage_scenario = DamageScenario.objects.get(id=response.data['id'])
        self.assertEqual(damage_scenario.threat_scenarios.count(), 1)
        self.assertEqual(damage_scenario.affected_CIA_parts, CIABitmask.INTEGRITY)
        self.assertEqual(
            damage_scenario.threat_scenarios.first().id,
            self.threat_scenario.id,
        )

    def test_damage_scenario_concerns_are_limited_to_linked_threat_scenario_components(self):
        second_component = Component.objects.create(
            name='Brake ECU',
            description='Brake controller',
            project=self.project,
        )
        self.threat_scenario.components.add(second_component)

        response = self.client.patch(
            f'/api/damage_scenario/{self.damage_scenario.id}/',
            {
                'project_id': self.project.id,
                'threat_scenarios': [self.threat_scenario.id],
                'concerns': [
                    {
                        'component': self.component.id,
                        'affected_CIA_parts': '100',
                    },
                    {
                        'component': second_component.id,
                        'affected_CIA_parts': '101',
                    },
                ],
            },
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        self.damage_scenario.refresh_from_db()
        self.assertEqual(
            self.damage_scenario.affected_CIA_parts,
            CIABitmask.CONFIDENTIALITY | CIABitmask.AVAILABILITY,
        )
        self.assertEqual(
            list(
                self.damage_scenario.concerns.order_by('component_id').values_list(
                    'component_id', 'affected_CIA_parts'
                )
            ),
            [
                (self.component.id, CIABitmask.CONFIDENTIALITY),
                (
                    second_component.id,
                    CIABitmask.CONFIDENTIALITY | CIABitmask.AVAILABILITY,
                ),
            ],
        )
        self.assertEqual(len(response.data['concerns']), 2)

    def test_damage_scenario_rejects_concern_for_unlinked_component(self):
        other_component = Component.objects.create(
            name='Infotainment ECU',
            description='Out of scope component',
            project=self.project,
        )

        response = self.client.patch(
            f'/api/damage_scenario/{self.damage_scenario.id}/',
            {
                'project_id': self.project.id,
                'threat_scenarios': [self.threat_scenario.id],
                'concerns': [
                    {
                        'component': other_component.id,
                        'affected_CIA_parts': '001',
                    },
                ],
            },
            format='json',
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(DamageScenarioConcern.objects.count(), 0)

    def test_threat_scenario_component_sync_prunes_invalid_damage_concerns(self):
        transient_component = Component.objects.create(
            name='Transient ECU',
            description='Initially in threat scenario',
            project=self.project,
        )
        self.threat_scenario.components.add(transient_component)
        DamageScenarioConcern.objects.create(
            damage_scenario=self.damage_scenario,
            component=transient_component,
            affected_CIA_parts=CIABitmask.CONFIDENTIALITY,
        )
        self.damage_scenario.affected_CIA_parts = CIABitmask.CONFIDENTIALITY
        self.damage_scenario.save(update_fields=['affected_CIA_parts'])

        response = self.client.patch(
            f'/api/threat_scenario/{self.threat_scenario.id}/',
            {
                'project_id': self.project.id,
                'components': [self.component.id],
            },
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(
            DamageScenarioConcern.objects.filter(component=transient_component).exists()
        )
        self.damage_scenario.refresh_from_db()
        self.assertEqual(self.damage_scenario.affected_CIA_parts, CIABitmask.NONE)

    def test_risk_endpoint_generates_rows_from_damage_concerns(self):
        DamageScenarioConcern.objects.create(
            damage_scenario=self.damage_scenario,
            component=self.component,
            affected_CIA_parts=CIABitmask.CONFIDENTIALITY | CIABitmask.AVAILABILITY,
        )

        response = self.client.get('/api/risk/', {'project_id': self.project.id})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)
        risk = response.data[0]
        self.assertEqual(risk['threat_scenario'], self.threat_scenario.id)
        self.assertEqual(risk['damage_scenario'], self.damage_scenario.id)
        self.assertEqual(risk['component'], self.component.id)
        self.assertEqual(
            risk['affected_CIA_parts'],
            CIABitmask.CONFIDENTIALITY | CIABitmask.AVAILABILITY,
        )
        self.assertEqual(risk['attack_potential_points'], 0)
        self.assertEqual(risk['afl'], 'High')
        self.assertEqual(risk['afl_value'], 5)
        self.assertEqual(risk['il'], ImpactRating.MAJOR)
        self.assertEqual(risk['il_label'], 'Major')
        self.assertEqual(risk['rl'], 4)

    def test_threat_scenario_compromise_accepts_cia_bitmask(self):
        response = self.client.post(
            '/api/threat_scenario/',
            {
                'name': 'Read and tamper calibration values',
                'project_id': self.project.id,
                'compromises': [
                    {
                        'component_id': self.component.id,
                        'compromised_part_cia': '110',
                    }
                ],
            },
            format='json',
        )

        self.assertEqual(response.status_code, 201)
        compromise = Comporomises.objects.get(threat_scenario_id=response.data['id'])
        threat_scenario = ThreatScenario.objects.get(id=response.data['id'])
        self.assertEqual(
            compromise.compromised_CIA_part,
            CIABitmask.CONFIDENTIALITY | CIABitmask.INTEGRITY,
        )
        self.assertEqual(list(threat_scenario.components.all()), [self.component])

    def test_threat_scenario_component_endpoint_filters_by_involved_components(self):
        Comporomises.objects.create(
            compromised_CIA_part=CIABitmask.CONFIDENTIALITY,
            threat_scenario=self.threat_scenario,
            component=self.component,
            project=self.project,
        )

        response = self.client.get(
            f'/api/threat_scenario/component/{self.component.id}/',
            {'project_id': self.project.id},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [scenario['id'] for scenario in response.data],
            [self.threat_scenario.id],
        )

    def test_attack_step_previous_steps_are_persisted_and_next_steps_are_derived(self):
        response = self.client.post(
            '/api/attack_step/',
            {
                'name': 'Bypass gateway filtering',
                'description': 'Second chain step',
                'required_access': 'Vehicle network access',
                'fr_et': ElapsedTimeScore.LEQ_1_WEEK,
                'fr_se': SpecialistExpertiseScore.PROFICIENT,
                'fr_koC': KnowledgeScore.RESTRICTED,
                'fr_WoO': WindowOfOpportunityScore.EASY,
                'fr_eq': EquipmentScore.SPECIALIZED,
                'component': self.component.id,
                'project_id': self.project.id,
                'previous_steps': [self.attack_step.id],
            },
            format='json',
        )

        self.assertEqual(response.status_code, 201)

        chained_step = AttackStep.objects.get(id=response.data['id'])
        self.assertEqual(
            list(chained_step.previous_steps.values_list('id', flat=True)),
            [self.attack_step.id],
        )

        detail_response = self.client.get(
            f'/api/attack_step/{self.attack_step.id}/',
            {'project_id': self.project.id},
        )

        self.assertEqual(detail_response.status_code, 200)
        self.assertEqual(
            [step['id'] for step in detail_response.data['next_steps']],
            [chained_step.id],
        )
