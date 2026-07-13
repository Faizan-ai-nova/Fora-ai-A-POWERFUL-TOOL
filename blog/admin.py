from django.contrib import admin
from .models import Post, Category


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug')
    prepopulated_fields = {'slug': ('name',)}


@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display = ('title', 'category', 'is_published', 'published_at', 'reading_time_minutes')
    list_filter = ('is_published', 'category')
    search_fields = ('title', 'excerpt', 'body_html')
    prepopulated_fields = {'slug': ('title',)}
    date_hierarchy = 'published_at'
    fieldsets = (
        (None, {'fields': ('title', 'slug', 'author_name', 'category', 'cover_emoji', 'reading_time_minutes')}),
        ('Content', {'fields': ('excerpt', 'body_html')}),
        ('SEO', {'fields': ('meta_title', 'meta_description')}),
        ('Publishing', {'fields': ('is_published', 'published_at')}),
    )
