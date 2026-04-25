from django.db import migrations, models


def migrate_involved_components(apps, schema_editor):
    ThreatScenario = apps.get_model('api', 'ThreatScenario')
    Comporomises = apps.get_model('api', 'Comporomises')

    for threat_scenario in ThreatScenario.objects.all():
        component_ids = set(
            threat_scenario.attack_steps.exclude(component_id=None).values_list(
                'component_id', flat=True
            )
        )
        component_ids.update(
            threat_scenario.damage_scenarios.exclude(component_id=None).values_list(
                'component_id', flat=True
            )
        )
        component_ids.update(
            Comporomises.objects.filter(
                threat_scenario_id=threat_scenario.id
            )
            .exclude(component_id=None)
            .values_list('component_id', flat=True)
        )

        if component_ids:
            threat_scenario.components.add(*component_ids)


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0007_remove_attackstep_prepared_by_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='threatscenario',
            name='components',
            field=models.ManyToManyField(
                blank=True,
                related_name='threat_scenarios',
                to='api.component',
            ),
        ),
        migrations.RunPython(migrate_involved_components, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name='damagescenario',
            name='component',
        ),
    ]
