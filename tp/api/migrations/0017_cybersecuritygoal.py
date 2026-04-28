from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0016_risktreatment'),
    ]

    operations = [
        migrations.CreateModel(
            name='CybersecurityGoal',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField(blank=True)),
                ('cal', models.PositiveSmallIntegerField(
                    choices=[(1, 'CAL 1'), (2, 'CAL 2'), (3, 'CAL 3'), (4, 'CAL 4')],
                    null=True,
                    blank=True,
                )),
                ('damage_scenarios', models.ManyToManyField(
                    blank=True,
                    related_name='cybersecurity_goals',
                    to='api.damagescenario',
                )),
                ('controls', models.ManyToManyField(
                    blank=True,
                    related_name='cybersecurity_goals',
                    to='api.control',
                )),
                ('project', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='cybersecurity_goals',
                    to='api.project',
                )),
            ],
            options={
                'ordering': ['name'],
            },
        ),
    ]
