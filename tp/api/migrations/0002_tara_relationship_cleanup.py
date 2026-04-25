from django.db import migrations, models


def merge_tara_relationships(apps, schema_editor):
    AttackStep = apps.get_model('api', 'AttackStep')
    DamageScenario = apps.get_model('api', 'DamageScenario')

    for attack_step in AttackStep.objects.all():
        for threat_scenario in attack_step.threat_scenario.all():
            threat_scenario.attack_steps.add(attack_step)

    for damage_scenario in DamageScenario.objects.exclude(threat_scenario=None):
        damage_scenario.threat_scenario.damage_scenarios.add(damage_scenario)


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='threatscenario',
            old_name='attack_step',
            new_name='attack_steps',
        ),
        migrations.RenameField(
            model_name='threatscenario',
            old_name='damage_scenario',
            new_name='damage_scenarios',
        ),
        migrations.RunPython(merge_tara_relationships, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name='attackstep',
            name='threat_scenario',
        ),
        migrations.RemoveField(
            model_name='damagescenario',
            name='threat_scenario',
        ),
        migrations.AlterField(
            model_name='threatscenario',
            name='attack_steps',
            field=models.ManyToManyField(blank=True, related_name='threat_scenarios', to='api.attackstep'),
        ),
        migrations.AlterField(
            model_name='threatscenario',
            name='damage_scenarios',
            field=models.ManyToManyField(blank=True, related_name='threat_scenarios', to='api.damagescenario'),
        ),
    ]
