from django.db import models
from django.urls import reverse
from django.utils import timezone


class Category(models.Model):
    name = models.CharField(max_length=80)
    slug = models.SlugField(unique=True)

    class Meta:
        verbose_name_plural = 'Categories'
        ordering = ['name']

    def __str__(self):
        return self.name


class Post(models.Model):
    """
    A single blog article. Body is stored as pre-formatted HTML (written directly
    by whoever authors the post) so templates can render it without pulling in a
    markdown dependency - keeps the stack minimal for the MVP.
    """

    title = models.CharField(max_length=200)
    slug = models.SlugField(unique=True, max_length=220)
    author_name = models.CharField(max_length=100, default='Fora AI Team')

    excerpt = models.CharField(
        max_length=280,
        help_text='One or two sentences shown on the blog listing and used as the meta description if none is set.'
    )
    cover_emoji = models.CharField(max_length=8, default='🛡️', help_text='Small visual mark shown on the listing card')
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True, related_name='posts')
    reading_time_minutes = models.PositiveSmallIntegerField(default=5)

    body_html = models.TextField(help_text='Full article content as HTML')

    meta_title = models.CharField(max_length=200, blank=True, help_text='Overrides <title> tag if set')
    meta_description = models.CharField(max_length=300, blank=True, help_text='Overrides excerpt for SEO if set')

    is_published = models.BooleanField(default=True)
    published_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-published_at']

    def __str__(self):
        return self.title

    def get_absolute_url(self):
        return reverse('blog:detail', kwargs={'slug': self.slug})

    @property
    def seo_title(self):
        return self.meta_title or f'{self.title} — Fora AI Blog'

    @property
    def seo_description(self):
        return self.meta_description or self.excerpt
