release: python manage.py migrate --noinput && python manage.py seed_plans && python manage.py seed_blog
web: gunicorn freebug_ai.wsgi:application --log-file -
