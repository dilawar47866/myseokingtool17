# ==========================================
# ALL API ENDPOINTS FOR SEO TOOLS
# ==========================================

# Keyword Research API
@app.route('/api/research-keywords', methods=['POST'])
@login_required
def api_research_keywords():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Monthly limit reached'}), 403
    
    if not client:
        return jsonify({'error': 'OpenAI not configured'}), 500
    
    try:
        data = request.get_json()
        seed = data.get('seed', '').strip()
        
        if not seed:
            return jsonify({'error': 'Seed keyword required'}), 400
        
        prompt = f"""Generate 15 long-tail keywords for: "{seed}"

Return ONLY valid JSON array:
[
  {{"keyword": "example keyword", "intent": "Informational", "difficulty": 45, "content_idea": "Blog Title"}}
]

Use intent: Informational, Commercial, or Transactional
Difficulty: 1-100
No markdown, just JSON."""
        
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "Return only JSON arrays"},
                {"role": "user", "content": prompt}
            ],
            timeout=30
        )
        
        raw = res.choices[0].message.content.replace('```json', '').replace('```', '').strip()
        keywords_data = json.loads(raw)
        
        current_user.ai_requests_this_month += 1
        db.session.commit()
        
        return jsonify({'success': True, 'keywords': keywords_data})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Generate Content API
@app.route('/api/generate-content', methods=['POST'])
@login_required
def api_generate_content():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    
    if not client:
        return jsonify({'error': 'OpenAI not configured'}), 500
    
    try:
        keyword = request.get_json().get('keyword')
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "SEO Writer"}, {"role": "user", "content": f"Write SEO blog about: {keyword}"}]
        )
        current_user.ai_requests_this_month += 1
        db.session.commit()
        content = res.choices[0].message.content
        return jsonify({'success': True, 'content': content, 'html_content': markdown.markdown(content)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Article Wizard API
@app.route('/api/article-wizard', methods=['POST'])
@login_required
def api_article_wizard():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    
    if not client:
        return jsonify({'error': 'OpenAI not configured'}), 500
    
    try:
        topic = request.get_json().get('topic')
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "Blog Writer"}, {"role": "user", "content": f"Write comprehensive blog about: {topic}"}]
        )
        current_user.ai_requests_this_month += 1
        db.session.commit()
        content = res.choices[0].message.content
        return jsonify({'success': True, 'content': content, 'html': markdown.markdown(content)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Bulk Writer Single Article API
@app.route('/api/bulk-write-single', methods=['POST'])
@login_required
def api_bulk_write_single():
    if current_user.tier == 'free':
        return jsonify({'error': 'Pro feature'}), 403
    
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    
    if not client:
        return jsonify({'error': 'OpenAI not configured'}), 500
    
    try:
        data = request.get_json()
        keyword = data.get('keyword', '').strip()
        tone = data.get('tone', 'Professional')
        word_count = data.get('word_count', 800)
        
        prompt = f"""Write SEO blog post about: "{keyword}"
Tone: {tone}
Word count: ~{word_count}
Use markdown formatting with H2/H3 headings."""
        
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "SEO Writer"}, {"role": "user", "content": prompt}],
            max_tokens=2000
        )
        
        content = res.choices[0].message.content
        current_user.ai_requests_this_month += 1
        db.session.commit()
        
        return jsonify({
            'success': True,
            'keyword': keyword,
            'content': content,
            'html': markdown.markdown(content),
            'word_count': len(content.split())
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Sitemap Generator API
@app.route('/api/generate-sitemap', methods=['POST'])
@login_required
def api_generate_sitemap():
    try:
        data = request.get_json()
        base_url = data.get('url', '').rstrip('/')
        
        if not base_url.startswith('http'):
            base_url = 'https://' + base_url
        
        urls = data.get('urls', [])
        changefreq = data.get('changefreq', 'weekly')
        priority = data.get('priority', '0.8')
        
        if not urls:
            urls = [base_url]
        
        today = datetime.now().strftime('%Y-%m-%d')
        xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
        
        for url in urls:
            if url.strip():
                xml_lines.append('  <url>')
                xml_lines.append(f'    <loc>{url.strip()}</loc>')
                xml_lines.append(f'    <lastmod>{today}</lastmod>')
                xml_lines.append(f'    <changefreq>{changefreq}</changefreq>')
                xml_lines.append(f'    <priority>{priority}</priority>')
                xml_lines.append('  </url>')
        
        xml_lines.append('</urlset>')
        return jsonify({'success': True, 'sitemap': '\n'.join(xml_lines), 'url_count': len(urls)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Robots.txt Generator API
@app.route('/api/generate-robots', methods=['POST'])
@login_required
def api_generate_robots():
    try:
        data = request.get_json()
        base_url = data.get('url', '').rstrip('/')
        if not base_url.startswith('http'):
            base_url = 'https://' + base_url
        
        disallow = data.get('disallow', ['/admin', '/dashboard'])
        sitemap = data.get('sitemap', f'{base_url}/sitemap.xml')
        
        lines = ['User-agent: *']
        for path in disallow:
            if path.strip():
                lines.append(f'Disallow: {path.strip()}')
        lines.append(f'Sitemap: {sitemap}')
        
        return jsonify({'success': True, 'robots': '\n'.join(lines)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Public Site Audit API
@app.route('/api/public-audit', methods=['POST'])
def api_public_audit():
    try:
        url = request.get_json().get('url')
        if not url.startswith('http'):
            url = 'https://' + url
        
        r = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
        soup = BeautifulSoup(r.content, 'html.parser')
        
        score = 100
        issues = []
        
        if not soup.title:
            score -= 20
            issues.append("Missing Title")
        if not soup.find('meta', attrs={'name': 'description'}):
            score -= 20
            issues.append("Missing Meta Description")
        if not soup.find('h1'):
            score -= 20
            issues.append("Missing H1")
        
        return jsonify({'success': True, 'score': max(0, score), 'issues': issues})
    except:
        return jsonify({'success': True, 'score': 45, 'issues': ['Connection timeout']})

# Pro Site Audit API
@app.route('/api/audit-site', methods=['POST'])
@login_required
def api_audit_site():
    try:
        url = request.get_json().get('url')
        if not url.startswith('http'):
            url = 'https://' + url
        
        r = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=15)
        soup = BeautifulSoup(r.content, 'html.parser')
        
        score = 100
        issues = []
        passed = []
        
        if soup.title:
            passed.append("Title exists")
        else:
            score -= 20
            issues.append({"type": "critical", "msg": "Missing Title"})
        
        if soup.find('meta', attrs={'name': 'description'}):
            passed.append("Meta description found")
        else:
            score -= 20
            issues.append({"type": "critical", "msg": "Missing Meta Description"})
        
        if soup.find('h1'):
            passed.append("H1 found")
        else:
            score -= 20
            issues.append({"type": "critical", "msg": "Missing H1"})
        
        return jsonify({
            'success': True,
            'score': max(0, score),
            'meta': {
                'url': url,
                'title': soup.title.string if soup.title else "None",
                'word_count': len(soup.get_text().split())
            },
            'issues': issues,
            'passed': passed
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# YouTube to Blog API
@app.route('/api/youtube-to-blog', methods=['POST'])
@login_required
def api_youtube_to_blog():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    
    if not client:
        return jsonify({'error': 'OpenAI not configured'}), 500
    
    try:
        video_url = request.get_json().get('url')
        vid = video_url.split("v=")[1].split("&")[0] if "v=" in video_url else video_url.split("youtu.be/")[1].split("?")[0]
        
        # Get transcript
        transcript_list = YouTubeTranscriptApi.get_transcript(vid)
        full_text = " ".join([t['text'] for t in transcript_list])
        
        # Generate blog
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "Convert transcripts to blogs"}, {"role": "user", "content": f"Convert to blog:\n\n{full_text[:10000]}"}]
        )
        
        current_user.ai_requests_this_month += 1
        db.session.commit()
        
        content = res.choices[0].message.content
        return jsonify({'success': True, 'content': content, 'html': markdown.markdown(content)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Humanize Text API
@app.route('/api/humanize-text', methods=['POST'])
@login_required
def api_humanize_text():
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    
    if not client:
        return jsonify({'error': 'OpenAI not configured'}), 500
    
    try:
        text = request.get_json().get('content')
        res = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "system", "content": "Humanize AI text"}, {"role": "user", "content": f"Humanize:\n{text}"}]
        )
        current_user.ai_requests_this_month += 1
        db.session.commit()
        return jsonify({'success': True, 'content': res.choices[0].message.content})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Image Generator API
@app.route('/api/generate-image', methods=['POST'])
@login_required
def api_generate_image():
    if current_user.tier == 'free':
        return jsonify({'error': 'Pro feature'}), 403
    
    if current_user.ai_requests_this_month >= current_user.get_limits()['ai_requests_per_month']:
        return jsonify({'error': 'Limit reached'}), 403
    
    if not client:
        return jsonify({'error': 'OpenAI not configured'}), 500
    
    try:
        prompt = request.get_json().get('prompt')
        res = client.images.generate(model="dall-e-3", prompt=prompt, size="1024x1024", n=1)
        current_user.ai_requests_this_month += 5
        db.session.commit()
        return jsonify({'success': True, 'image_url': res.data[0].url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Readability Checker API
@app.route('/api/check-readability', methods=['POST'])
@login_required
def api_readability():
    try:
        text = request.get_json().get('content', '')
        words = text.split()
        sentences = text.replace('!', '.').replace('?', '.').split('.')
        
        total_words = len(words)
        total_sentences = max(len([s for s in sentences if s.strip()]), 1)
        
        score = 206.835 - (1.015 * (total_words / total_sentences))
        score = max(0, min(100, score))
        
        if score >= 80:
            grade = "6th Grade"
            difficulty = "Easy"
        elif score >= 60:
            grade = "8th Grade"
            difficulty = "Standard"
        else:
            grade = "College"
            difficulty = "Difficult"
        
        return jsonify({
            'success': True,
            'stats': {
                'score': round(score, 1),
                'grade': grade,
                'difficulty': difficulty,
                'words': total_words,
                'sentences': total_sentences,
                'reading_time': f"{max(1, round(total_words / 200))} min"
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Schema Generator API
@app.route('/api/generate-schema', methods=['POST'])
@login_required
def api_schema():
    try:
        data = request.get_json()
        schema_type = data.get('type')
        result = {}
        
        if schema_type == 'faq':
            result = {
                "@context": "https://schema.org",
                "@type": "FAQPage",
                "mainEntity": []
            }
            for qa in data.get('questions', []):
                if qa.get('q') and qa.get('a'):
                    result["mainEntity"].append({
                        "@type": "Question",
                        "name": qa['q'],
                        "acceptedAnswer": {"@type": "Answer", "text": qa['a']}
                    })
        elif schema_type == 'article':
            result = {
                "@context": "https://schema.org",
                "@type": "Article",
                "headline": data.get('headline', ''),
                "author": {"@type": "Person", "name": data.get('author', '')}
            }
        
        return jsonify({'success': True, 'json': json.dumps(result, indent=4)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# WordPress Publish API
@app.route('/api/publish-wordpress', methods=['POST'])
@login_required
def api_publish_wordpress():
    try:
        d = request.get_json()
        wp = d.get('url').rstrip('/')
        creds = f"{d.get('username')}:{d.get('password')}"
        token = base64.b64encode(creds.encode()).decode('utf-8')
        
        r = requests.post(
            f"{wp}/wp-json/wp/v2/posts",
            headers={'Authorization': f'Basic {token}', 'Content-Type': 'application/json'},
            json={'title': d.get('title'), 'content': d.get('content'), 'status': 'draft'}
        )
        return jsonify({'success': True, 'link': r.json().get('link')})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
