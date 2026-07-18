from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='is_public_badge',
            field=models.BooleanField(default=False),
        ),
    ]
