---
layout: default
title: Reverse Engineer
---

# Reverse Engineer

Public reverse engineering write-ups, malware unpacking notes, and workflow artifacts.

## Latest Posts

{% for post in site.posts %}
- [{{ post.title }}]({{ post.url | relative_url }})
  - {{ post.date | date: "%B %d, %Y" }}
{% endfor %}

---

Direct post URL:
- [Chrysalis Offline Unpacking]({{ "/blog/chrysalis-offline-unpacking/" | relative_url }})
