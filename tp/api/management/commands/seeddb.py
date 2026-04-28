from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from api.models import (
    Project, Technology, Component, DataEntity, ThreatClass,
    Control, ControlClass, AttackStep, ThreatScenario, DamageScenario,
    DamageScenarioConcern, Comporomises,
)


class Command(BaseCommand):
    help = 'Seed the database with the initial project state.'

    def handle(self, *args, **kwargs):
        self.stdout.write('Seeding database...')

        # ── Users ────────────────────────────────────────────────────────────
        john    = User.objects.create_user('john_doe',  'john@example.com',    'pass1234')
        oliver  = User.objects.create_user('oliver',    'oliver@example.com',  'pass1234')
        richard = User.objects.create_user('richard',   'richard@example.com', 'pass1234')

        # ── Projects ─────────────────────────────────────────────────────────
        proj_oliver  = Project.objects.create(name='Demo Project',   description='Oliver\'s demo project',   owner=oliver)
        proj_richard = Project.objects.create(name='CAN Bus TARA',   description='TARA for a CAN bus system', owner=richard)

        # ── Technologies (Richard's project) ─────────────────────────────────
        t_can    = Technology.objects.create(name='CAN Bus',       description='Controller Area Network protocol',         project=proj_richard)
        t_aes    = Technology.objects.create(name='AES-128',       description='Symmetric encryption standard',            project=proj_richard)
        t_secoc  = Technology.objects.create(name='AUTOSAR SecOC', description='Secure Onboard Communication',             project=proj_richard)
        t_rtos   = Technology.objects.create(name='FreeRTOS',      description='Real-time operating system for embedded',  project=proj_richard)

        # ── Components (Richard's project) ───────────────────────────────────
        c_ecu_main = Component.objects.create(
            name='ECU Main',
            description='Main Engine Control Unit responsible for core vehicle functions',
            project=proj_richard,
        )
        c_gateway = Component.objects.create(
            name='Gateway ECU',
            description='Central gateway routing messages between CAN buses',
            project=proj_richard,
        )
        c_tcu = Component.objects.create(
            name='TCU',
            description='Telematics Control Unit with external connectivity',
            project=proj_richard,
        )

        c_ecu_main.communicates_with.add(c_gateway)
        c_gateway.communicates_with.add(c_tcu)
        c_ecu_main.technology.add(t_can, t_rtos)
        c_gateway.technology.add(t_can, t_secoc)
        c_tcu.technology.add(t_can, t_aes)

        # ── Threat Class ─────────────────────────────────────────────────────
        tc_spoofing = ThreatClass.objects.create(
            name='Spoofing',
            description='Attacker impersonates a legitimate sender on the bus',
            project=proj_richard,
        )

        # ── Attack Step ──────────────────────────────────────────────────────
        as_mitm = AttackStep.objects.create(
            name='CAN Bus Man-in-the-Middle',
            description='Attacker intercepts and replays CAN frames between ECU Main and Gateway',
            required_access='Physical access to OBD port or CAN bus wiring',
            fr_et=10,   # <=3 months
            fr_se=6,    # Expert
            fr_koC=0,   # Public (CAN frames are unencrypted by default)
            fr_WoO=0,   # Unnecessary/unlimited
            fr_eq=7,    # Bespoke hardware (CAN analyser + injector)
            component=c_ecu_main,
            threat_class=tc_spoofing,
            project=proj_richard,
        )

        # ── Controls ─────────────────────────────────────────────────────────
        cls_secoc = ControlClass.objects.get(name='CAN Bus Message Authentication (SecOC)')
        cls_enc   = ControlClass.objects.get(name='Symmetric Encryption')

        ctrl_secoc = Control.objects.create(
            name='SecOC Message Authentication',
            description='AUTOSAR SecOC authenticates every CAN frame with a truncated MAC, preventing replay and injection',
            control_class=cls_secoc,
            fr_et=19,   # >6 months
            fr_se=6,    # Expert
            fr_koC=7,   # Sensitive (session key required)
            fr_WoO=0,   # Unnecessary/unlimited
            fr_eq=4,    # Specialized
            component=c_gateway,
            project=proj_richard,
        )
        ctrl_secoc.attack_steps.add(as_mitm)

        ctrl_enc = Control.objects.create(
            name='AES-128 Payload Encryption',
            description='Sensitive CAN payloads are encrypted with AES-128; attacker cannot read or forge valid ciphertext without the key',
            control_class=cls_enc,
            fr_et=19,   # >6 months
            fr_se=8,    # Multiple experts
            fr_koC=11,  # Critical (encryption key)
            fr_WoO=0,   # Unnecessary/unlimited
            fr_eq=9,    # Multiple bespoke
            component=c_ecu_main,
            project=proj_richard,
        )
        ctrl_enc.attack_steps.add(as_mitm)

        # ── Damage Scenario ───────────────────────────────────────────────────
        ds = DamageScenario.objects.create(
            name='Unauthorized Vehicle Control via CAN Injection',
            description='Attacker injects spoofed CAN frames causing unintended actuation of vehicle functions',
            affected_CIA_parts=6,   # Integrity + Confidentiality (0b110)
            impact_scale=3,         # Severe
            safety_impact=3,        # Severe
            finantial_impact=2,     # Major
            operational_impact=3,   # Severe
            privacy_impact=1,       # Moderate
            project=proj_richard,
        )

        DamageScenarioConcern.objects.create(
            damage_scenario=ds,
            component=c_ecu_main,
            affected_CIA_parts=2,   # Integrity
        )
        DamageScenarioConcern.objects.create(
            damage_scenario=ds,
            component=c_gateway,
            affected_CIA_parts=6,   # Integrity + Confidentiality
        )

        # ── Threat Scenario ───────────────────────────────────────────────────
        ts = ThreatScenario.objects.create(
            name='CAN Bus Injection via OBD Port',
            description='Attacker with physical access injects spoofed CAN frames through the OBD-II port to manipulate ECU behaviour',
            threat_class=tc_spoofing,
            project=proj_richard,
        )
        ts.components.add(c_ecu_main, c_gateway)
        ts.attack_steps.add(as_mitm)
        ts.damage_scenarios.add(ds)

        # Link controls to threat scenario for traceability
        ctrl_secoc.threat_scenarios.add(ts)
        ctrl_enc.threat_scenarios.add(ts)

        # ── Oliver's demo project (minimal) ──────────────────────────────────
        c_demo = Component.objects.create(
            name='Demo Component',
            description='Placeholder component for the demo project',
            project=proj_oliver,
        )

        self.stdout.write(self.style.SUCCESS(
            '\nDone. Users and passwords:\n'
            '  john_doe  / pass1234\n'
            '  oliver    / pass1234\n'
            '  richard   / pass1234\n'
        ))
