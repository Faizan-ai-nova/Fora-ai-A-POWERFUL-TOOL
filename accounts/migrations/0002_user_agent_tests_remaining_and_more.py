from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='agent_tests_remaining',
            field=models.PositiveIntegerField(default=10),
        ),
        migrations.AddField(
            model_name='user',
            name='total_agent_tests_used',
            field=models.PositiveIntegerField(default=0),
        ),
    ]
