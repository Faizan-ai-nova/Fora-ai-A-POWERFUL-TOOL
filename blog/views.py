from django.core.paginator import Paginator
from django.shortcuts import render, get_object_or_404

from .models import Post, Category


def post_list_view(request):
    posts = Post.objects.filter(is_published=True)

    category_slug = request.GET.get('category')
    active_category = None
    if category_slug:
        active_category = get_object_or_404(Category, slug=category_slug)
        posts = posts.filter(category=active_category)

    paginator = Paginator(posts, 9)
    page_obj = paginator.get_page(request.GET.get('page'))

    return render(request, 'blog/list.html', {
        'page_obj': page_obj,
        'categories': Category.objects.all(),
        'active_category': active_category,
    })


def post_detail_view(request, slug):
    post = get_object_or_404(Post, slug=slug, is_published=True)
    related_posts = Post.objects.filter(
        is_published=True, category=post.category
    ).exclude(pk=post.pk)[:3]

    return render(request, 'blog/detail.html', {
        'post': post,
        'related_posts': related_posts,
    })
