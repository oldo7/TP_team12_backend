from django.db import migrations


def merge_attack_step_controls(apps, schema_editor):
    """
    Copy rows from api_attackstep_controls (AttackStep.controls M2M)
    into api_control_attack_steps (Control.attack_steps M2M), skipping duplicates.
    After this migration the schema migration can safely drop api_attackstep_controls.
    """
    db = schema_editor.connection
    db.cursor().execute("""
        INSERT OR IGNORE INTO api_control_attack_steps (control_id, attackstep_id)
        SELECT control_id, attackstep_id FROM api_attackstep_controls
    """)


def reverse_merge(apps, schema_editor):
    pass  # Data loss on reverse is acceptable; the table being restored is the one we're dropping


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0012_seed_control_classes'),
    ]

    operations = [
        migrations.RunPython(merge_attack_step_controls, reverse_merge),
    ]
