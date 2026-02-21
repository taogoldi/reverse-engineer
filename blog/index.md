---
layout: default
title: Blog
permalink: /blog/
---

# Blog

{% for post in site.posts %}
## [{{ post.title }}]({{ post.url | relative_url }})
{{ post.date | date: "%Y-%m-%d" }}

{% endfor %}
