from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agentlab', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='agenttest',
            name='provider',
            field=models.CharField(
                choices=[
                    ('groq', 'Groq'),
                    ('openai', 'OpenAI'),
                    ('gemini', 'Google Gemini'),
                    ('claude', 'Anthropic Claude'),
                    ('custom', 'Custom / Other'),
                ],
                default='groq',
                max_length=10,
            ),
        ),
    ]
