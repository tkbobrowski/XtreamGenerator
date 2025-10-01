from __future__ import annotations



def extract_tvg_ids_by_stream_id(m3u_text):
    import re
    tvg_map = {}
    current_tvg = None
    current_name = None
    for line in m3u_text.splitlines():
        line = line.strip()
        if line.startswith("#EXTINF"):
            idm = re.search(r'tvg-id="([^"]*)"', line)
            namem = re.search(r'tvg-name="([^"]*)"', line)
            current_tvg = (idm.group(1).strip() if idm else "") or ""
            current_name = (namem.group(1).strip() if namem else "")
        elif line and not line.startswith("#") and (current_tvg is not None or current_name is not None):
            m = re.search(r'/(\d+)(?:\.[A-Za-z0-9]+)?(?:\?.*)?$', line)
            if m:
                sid = int(m.group(1))
                if not current_tvg:
                    nm = current_name or ""
                    nm = re.sub(r'^\s*[A-Z0-9]{1,3}\s*\|\s*', '', nm)
                    nm = re.sub(r'[\[(].*?[\])]', '', nm)
                    nm = re.sub(r'\b(FHD|UHD|HD|SD|4K|HEVC|H265|H\.265|VIP|BACKUP|TEST|24/7\w*|[0-9]{3,4}p)\b', '', nm, flags=re.I)
                    nm = re.sub(r'\s+', ' ', nm).strip()
                    current_tvg = nm
                if current_tvg:
                    tvg_map[sid] = current_tvg
            current_tvg = None
            current_name = None
    return tvg_map

def sanitize_channel_name(name):
    import re
    if not name:
        return ""
    s = str(name)
    s = re.sub(r'^\s*[A-Z0-9]{1,3}\s*\|\s*', '', s)
    s = re.sub(r'[\[(].*?[\])]', '', s)
    s = re.sub(r'\b(FHD|UHD|HD|SD|4K|HEVC|H265|H\.265|VIP|BACKUP|TEST|24/7\w*|[0-9]{3,4}p)\b', '', s, flags=re.I)
    s = re.sub(r'\s+', ' ', s).strip()
    return s




import re

def extract_tvg_ids_from_m3u(m3u_text):
    tvg_map = {}
    for line in m3u_text.splitlines():
        if line.startswith("#EXTINF"):
            m = re.search(r'tvg-id="([^"]*)".*?,(.*)$', line)
            if m:
                tvg_id, chname = m.groups()
                if tvg_id and chname:
                    tvg_map[chname.strip()] = tvg_id.strip()
    return tvg_map

import os, re, json, hashlib, unicodedata
from urllib.request import urlopen
from urllib.parse import urlsplit

ETC    = '/etc/enigma2'
EPGDIR = '/etc/epgimport'

def _clean_raw(s):
    s = str(s or '')
    s = s.replace('\n',' ').replace('\r',' ').replace('\t',' ')
    s = s.replace('&#10;',' ').replace('&#13;',' ')
    s = re.sub(r'\s+', ' ', s).strip()
    return s

def _xml_escape(s):
    return (s or '').replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('\"','&quot;').replace("'",'&apos;')

def _sanitize_tag(s):
    s = _clean_raw(s).replace('.', '_')
    s = unicodedata.normalize('NFKD', s).encode('ascii', 'ignore').decode('ascii')
    s = re.sub(r'[^A-Za-z0-9_-]+', '_', s)
    s = re.sub(r'_+', '_', s).strip('_')
    return s or 'IPTV'

class GeneratorConfig(object):
    def __init__(self, base_url, port, username, password, prefix,
                 add_port=False, omit_live_seg=True,
                 include_live=True, include_vod=True, include_series=True,
                 st_live=5002, st_vod=4097, st_series=4097,
                 bouquet_top=False, series_mode='off',
                 write_epg=True, epg_source_name='XtreamGenerator EPG',
                 epg_url=''):
        self.base_url = (base_url or '').rstrip('/')
        self.port = int(port)
        self.username = username
        self.password = password
        self.prefix = prefix
        self.add_port = bool(add_port)
        self.omit_live_seg = bool(omit_live_seg)
        self.include_live = bool(include_live)
        self.include_vod = bool(include_vod)
        self.include_series = bool(include_series)
        self.st_live = int(st_live)
        self.st_vod = int(st_vod)
        self.st_series = int(st_series)
        self.bouquet_top = bool(bouquet_top)
        self.series_mode = series_mode
        self.write_epg = bool(write_epg)
        self.epg_source_name = epg_source_name
        self.epg_url = epg_url

class XtreamGenerator(object):
    def __init__(self, cfg: GeneratorConfig):
        self.cfg = cfg
        # LIVE EPG entries: (epg_id, tsid, onid, seq, name)
        self._epg_entries = []

    # URL helpers
    def _ensure_port_kind(self, url, kind):
        p = urlsplit(url)
        need_port = (kind in ('vod', 'series')) or self.cfg.add_port
        if ':' not in p.netloc and need_port:
            url = '%s://%s:%d%s' % (p.scheme, p.hostname, self.cfg.port, p.path or '/')
        return url

    def _build_stream_url(self, item_id, kind, ext=None):
        b = self.cfg.base_url.rstrip('/')
        if not b.startswith(('http://','https://')): b = 'http://' + b
        prefix = '' if kind == 'live' else ('/movie' if kind == 'vod' else '/series')
        url = '%s%s/%s/%s/%s' % (b, prefix, self.cfg.username, self.cfg.password, item_id)
        url = self._ensure_port_kind(url, kind)
        if self.cfg.omit_live_seg and kind == 'live': url = url.replace('/live/', '/')
        if kind == 'live':
            url = re.sub(r'\.(ts|m3u8)$', '', url, flags=re.I)
        else:
            if ext:
                ext = ext.lstrip('.')
                if not re.search(r'\.(ts|m3u8|mp4|mkv|avi|mov|flv|wmv)$', url, re.I):
                    url = url + '.' + ext
        return url

    def _encode_service_url(self, url):
        if url.lower().startswith('http://'):  return 'http%3A//'  + url[7:].replace(':', '%3A', 1)
        if url.lower().startswith('https://'): return 'https%3A//' + url[8:].replace(':', '%3A', 1)
        return 'http%3A//' + url.replace(':', '%3A', 1)

    # TSID/ONID helpers
    def _triplets_from_seed(self, seed):
        try: n = int(re.sub(r'[^0-9]', '', str(seed)))
        except: n = int(hashlib.sha1(str(seed).encode('utf-8')).hexdigest(), 16)
        tsid = (n * 257) & 0xFFFF or 1
        onid = (n * 641) & 0xFFFF or 1
        return (tsid, onid)

    def _hx(self, x): return format(int(x), 'x')

    def _svc_live(self, stype, seq, enc_url, tsid, onid):
        return '#SERVICE %d:0:1:%s:%s:%s:0:0:0:0:%s:' % (
            stype, self._hx(seq), self._hx(tsid), self._hx(onid), enc_url)

    def _svc_vodseries(self, stype, seq, enc_url, title):
        title = _clean_raw(title)
        return '#SERVICE %d:0:1:%s:0:0:0:0:0:0:%s:%s' % (
            stype, self._hx(seq), enc_url, title)

    def _write_atomic(self, path, text):
        tmp = path + '.tmpwrite'
        with open(tmp, 'wb') as w: w.write(text.encode('utf-8'))
        os.replace(tmp, path)

    # API
    def _api(self, action):
        u = '%s/player_api.php?username=%s&password=%s&action=%s' % (
            self.cfg.base_url.rstrip('/'), self.cfg.username, self.cfg.password, action)
        data = urlopen(u, timeout=12).read().decode('utf-8', 'ignore')
        try:    return json.loads(data)
        except: return {}

    def _cats(self, kind):
        action = {'live':'get_live_categories','vod':'get_vod_categories','series':'get_series_categories'}[kind]
        r = self._api(action)
        return r if isinstance(r, list) else []

    def _items(self, kind, cat_id):
        action = {'live':'get_live_streams','vod':'get_vod_streams','series':'get_series'}[kind]
        r = self._api('%s&category_id=%s' % (action, cat_id))
        return r if isinstance(r, list) else []

    def _series_info(self, series_id):
        r = self._api('get_series_info&series_id=%s' % series_id)
        return r if isinstance(r, dict) else {}

    def _iter_episodes(self, info):
        eps = info.get('episodes') if isinstance(info, dict) else None
        if not eps: return
        if isinstance(eps, dict):
            def kkey(k):
                try: return int(re.sub(r'[^0-9]','',str(k)) or 0)
                except: return 0
            for season in sorted(eps.keys(), key=kkey):
                arr = eps.get(season) or []
                if isinstance(arr, list):
                    for ep in arr:
                        if isinstance(ep, dict): yield season, ep
        elif isinstance(eps, list):
            for ep in eps:
                if isinstance(ep, dict):
                    season = ep.get('season') or 1
                    yield season, ep

    def _sanitize(self, s):
        s = _clean_raw(s).lower()
        s = unicodedata.normalize('NFKD', s).encode('ascii','ignore').decode('ascii')
        s = re.sub(r'[^a-z0-9]+','_',s)
        s = re.sub(r'_+','_',s).strip('_')
        return s[:120]

    # bouquet writer
    def _write_bq(self, kind, cid, cname, stype, mode=None):
        cname_clean = _clean_raw(cname)
        fname = 'userbouquet.%s_%s_%s.tv' % (self.cfg.prefix, kind, self._sanitize(cname_clean))
        path  = os.path.join(ETC, fname)
        lines = ['#NAME %s %s %s' % (self.cfg.prefix.upper(), kind.upper(), cname_clean)]
        seq = 1

        tsid, onid = self._triplets_from_seed(cid or cname_clean)

        if kind in ('live','vod'):
            items = self._items(kind, cid)
            for it in items:
                if not isinstance(it, dict): continue
                sid = str(it.get('stream_id','')).strip()
                if not sid: continue
                nm = _clean_raw(it.get('name') or ('CH %s' % sid))
                ext = (it.get('container_extension') or '').strip() if kind=='vod' else None
                url = self._build_stream_url(sid, kind, ext=ext)
                enc = self._encode_service_url(url)
                if kind == 'live':
                    lines.append(self._svc_live(self.cfg.st_live, seq, enc, tsid, onid))
                    epgid = _clean_raw(it.get('epg_channel_id') or '')
                    if not epgid:
                        sid = int(it.get('stream_id', 0) or 0)
                        if sid and hasattr(self, '_tvg_map') and sid in self._tvg_map:
                            epgid = self._tvg_map[sid]
                    if not epgid:
                        epgid = sanitize_channel_name(nm)
                    self._epg_entries.append((epgid, tsid, onid, seq, nm))
                    sid = int(it.get('stream_id', 0) or 0)
                    tvg_from_map = ''
                    try:
                        tvg_from_map = self._tvg_map.get(sid, '') if hasattr(self, '_tvg_map') else ''
                    except Exception:
                        tvg_from_map = ''
                    if tvg_from_map:
                        epgid = tvg_from_map
                    elif epgid and '|' not in epgid:
                        pass
                    else:
                        epgid = sanitize_channel_name(nm)
                    self._epg_entries.append((epgid, tsid, onid, seq, nm))
                    if epgid:
                        # store seq so channels.xml uses SAME seq as bouquet
                        self._epg_entries.append((epgid, tsid, onid, seq, nm))
                else:
                    lines.append(self._svc_vodseries(self.cfg.st_vod if kind=='vod' else self.cfg.st_series, seq, enc, nm))
                lines.append('#DESCRIPTION %s' % nm)
                seq += 1

        else:
            if mode == 'markers':
                for sr in self._items('series', cid):
                    if not isinstance(sr, dict): continue
                    sname = _clean_raw(sr.get('name') or 'Series')
                    lines.append('#DESCRIPTION %s' % sname)
            elif mode == 'episodes':
                for sr in self._items('series', cid):
                    if not isinstance(sr, dict): continue
                    sid = str(sr.get('series_id','')).strip()
                    sname = _clean_raw(sr.get('name') or ('Series %s' % sid))
                    info = self._series_info(sid)
                    for season, ep in (self._iter_episodes(info) or []):
                        eid = str(ep.get('id') or ep.get('episode_id') or ep.get('stream_id') or '').strip()
                        if not eid: continue
                        title = _clean_raw(ep.get('title') or ('%s S%sE%s' % (sname, season, ep.get('episode_num',''))))
                        ext = (ep.get('container_extension') or '').strip() or None
                        url = self._build_stream_url(eid, 'series', ext=ext)
                        enc = self._encode_service_url(url)
                        lines.append(self._svc_vodseries(self.cfg.st_series, seq, enc, title))
                        lines.append('#DESCRIPTION %s' % title)
                        seq += 1

        self._write_atomic(path, '\n'.join(lines) + '\n')
        return fname

    def _build_index_line(self, fname):
        return '#SERVICE 1:7:1:0:0:0:0:0:0:0:FROM BOUQUET "%s" ORDER BY bouquet' % fname

    def _save_bouquet_index_entries(self, new_files):
        bpath = os.path.join(ETC, 'bouquets.tv')
        if os.path.exists(bpath):
            lines = open(bpath, 'rb').read().decode('utf-8','ignore').splitlines()
        else:
            lines = []
        header = lines[0] if lines and lines[0].startswith('#NAME') else '#NAME User - bouquets (TV)'
        existing = lines[1:] if lines and lines[0].startswith('#NAME') else lines

        kept = []
        existing_fns = set()
        rx = re.compile(r'FROM BOUQUET ["\\\']([^"\\\']+)["\\\']', re.I)
        for ln in existing:
            m = rx.search(ln)
            if m:
                fn = (m.group(1) or '').strip()
                if not fn.startswith('userbouquet.%s_' % self.cfg.prefix):
                    kept.append(ln); existing_fns.add(fn)
            else:
                kept.append(ln)

        new_lines = [self._build_index_line(f) for f in new_files if f not in existing_fns]
        if not new_lines: return False
        final = [header]; final.extend(kept); final.extend(new_lines)

        if os.path.exists(bpath):
            with open(bpath,'rb') as r: orig = r.read()
            open(bpath+'.bak','wb').write(orig)

        self._write_atomic(bpath, '\n'.join(final) + '\n')
        return True

    # EPG output using SAME seq as bouquet (player type=1, service=1) and dynamic filenames
    def _make_epg_sref(self, seq, tsid, onid):
        hx = lambda x: format(int(x),'x')
        return '1:0:1:%s:%s:%s:0:0:0:0:http%%3a//example.m3u8' % (hx(seq), hx(tsid), hx(onid))

    def _write_epg_importer_files(self):
        if not self.cfg.write_epg:
            return
        try:
            os.makedirs(EPGDIR, exist_ok=True)

            # Dynamic filenames based on bouquets_prefix (dots -> underscores)
            tag = _sanitize_tag(self.cfg.prefix)
            channels_path = os.path.join(EPGDIR, 'xtreamgenerator_%s_channels.xml' % tag)
            sources_path  = os.path.join(EPGDIR, 'xtreamgenerator_%s.sources.xml'  % tag)

            # channels.xml (ONLY provider epg_channel_id)
            ch_lines = ['<?xml version="1.0" encoding="utf-8"?>', '<channels>']
            seen = set()
            for epgid, tsid, onid, seq, name in self._epg_entries:
                if epgid in seen:  # one mapping per EPG id
                    continue
                seen.add(epgid)
                sref = self._make_epg_sref(seq, tsid, onid)
                ch_lines.append('    <channel id="%s">%s</channel><!-- %s -->' % (_xml_escape(epgid), sref, _xml_escape(name)))
            ch_lines.append('</channels>')
            with open(channels_path, 'wb') as f:
                f.write(('\n'.join(ch_lines) + '\n').encode('utf-8'))

            # sources.xml
            # If user provided EPG URL, use it as-is; otherwise compute host-only default.
            if (self.cfg.epg_url or '').strip():
                xmltv_url = self.cfg.epg_url.strip()
            else:
                base = self.cfg.base_url.rstrip('/')
                if not base.startswith(('http://','https://')):
                    base = 'http://' + base
                p = urlsplit(base)
                host = p.hostname or (p.netloc.split(':',1)[0] if p.netloc else base.replace('http://','').replace('https://',''))
                xmltv_url = '%s://%s/xmltv.php?username=%s&password=%s' % (p.scheme, host, self.cfg.username, self.cfg.password)

            # <description> uses EXACT Bouquets prefix
            desc_txt = self.cfg.prefix

            src_lines = [
                '<sources>',
                '    <sourcecat sourcecatname="%s">' % _xml_escape(self.cfg.epg_source_name),
                '        <source type="gen_xmltv" nocheck="1" channels="%s">' % _xml_escape(channels_path),
                '            <description>%s</description>' % _xml_escape(desc_txt),
                '            <url><![CDATA[%s]]></url>' % xmltv_url,  # CDATA
                '        </source>',
                '    </sourcecat>',
                '</sources>'
            ]
            with open(sources_path, 'wb') as f:
                f.write(('\n'.join(src_lines) + '\n').encode('utf-8'))

        except Exception:
            pass

    def run(self):
        os.makedirs(ETC, exist_ok=True)
        refs = []

        if self.cfg.include_live:
            for c in self._cats('live'):
                if not isinstance(c, dict): continue
                cid = str(c.get('category_id','')).strip()
                cn  = _clean_raw(c.get('category_name') or 'Live')
                if cid: refs.append(self._write_bq('live', cid, cn, self.cfg.st_live))

        if self.cfg.include_vod:
            for c in self._cats('vod'):
                if not isinstance(c, dict): continue
                cid = str(c.get('category_id','')).strip()
                cn  = _clean_raw(c.get('category_name') or 'VOD')
                if cid: refs.append(self._write_bq('vod', cid, cn, self.cfg.st_vod))

        if self.cfg.include_series:
            if self.cfg.series_mode == 'markers':
                for c in self._cats('series'):
                    if not isinstance(c, dict): continue
                    cid = str(c.get('category_id','')).strip()
                    cn  = _clean_raw(c.get('category_name') or 'Series')
                    if cid: refs.append(self._write_bq('series', cid, cn, self.cfg.st_series, mode='markers'))
            elif self.cfg.series_mode == 'episodes':
                for c in self._cats('series'):
                    if not isinstance(c, dict): continue
                    cid = str(c.get('category_id','')).strip()
                    cn  = _clean_raw(c.get('category_name') or 'Series')
                    if cid: refs.append(self._write_bq('series', cid, cn, self.cfg.st_series, mode='episodes'))

        changed = self._save_bouquet_index_entries(refs)
        self._write_epg_importer_files()
        if changed:
            try:
                from enigma import eDVBDB
                eDVBDB.getInstance().reloadBouquets()
            except Exception:
                pass
        return len(refs)
