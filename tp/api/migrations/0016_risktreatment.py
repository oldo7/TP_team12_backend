from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0015_control_group'),
    ]

    operations = [
        migrations.CreateModel(
            name='RiskTreatment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('decision', models.CharField(
                    choices=[('avoid', 'Avoid'), ('reduce', 'Reduce'), ('share', 'Share'), ('accept', 'Accept')],
                    max_length=10,
                )),
                ('rationale', models.TextField(blank=True)),
                ('threat_scenario', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='risk_treatments',
                    to='api.threatscenario',
                )),
                ('damage_scenario', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='risk_treatments',
                    to='api.damagescenario',
                )),
                ('project', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='risk_treatments',
                    to='api.project',
                )),
            ],
            options={
                'ordering': ['threat_scenario', 'damage_scenario'],
                'unique_together': {('threat_scenario', 'damage_scenario')},
            },
        ),
    ]
