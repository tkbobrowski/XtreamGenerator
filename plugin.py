from Plugins.Plugin import PluginDescriptor
from Screens.Screen import Screen
from Screens.MessageBox import MessageBox
from Components.ActionMap import ActionMap
from Components.ConfigList import ConfigListScreen
from Components.config import getConfigListEntry, ConfigText, ConfigSelection, ConfigInteger, ConfigYesNo, ConfigSubsection
from Components.Label import Label
from .generator import XtreamGenerator, GeneratorConfig

conf = ConfigSubsection()
conf.base_url        = ConfigText(default='http://line.livemagiciptv.xyz', fixed_size=False)
conf.port            = ConfigInteger(default=80, limits=(1,65535))
conf.username        = ConfigText(default='b10dca2c24', fixed_size=False)
conf.password        = ConfigText(default='2g98idu016', fixed_size=False)
conf.bouquets_prefix = ConfigText(default='xtream_iptv', fixed_size=False)
conf.include_live    = ConfigYesNo(default=True)
conf.include_vod     = ConfigYesNo(default=True)
conf.include_series  = ConfigYesNo(default=True)
conf.streamtype_tv   = ConfigSelection(default='5002', choices=[('4097','4097 (GStreamer)'),('5002','5002 (ExtePlayer3)')])
conf.streamtype_vod  = ConfigSelection(default='4097', choices=[('4097','4097 (GStreamer)'),('5002','5002 (ExtePlayer3)')])
conf.streamtype_ser  = ConfigSelection(default='4097', choices=[('4097','4097 (GStreamer)'),('5002','5002 (ExtePlayer3)')])
conf.omit_live_seg   = ConfigYesNo(default=True)
conf.add_port        = ConfigYesNo(default=True)
conf.bouquet_top     = ConfigYesNo(default=False)
conf.series_mode     = ConfigSelection(default='off', choices=[('off','Off (skip series)'),('markers','Markers only (FAST)'),('episodes','All episodes (SLOW)')])
conf.write_epg       = ConfigYesNo(default=True)
conf.epg_source_name = ConfigText(default='XtreamGenerator EPG', fixed_size=False)
conf.epg_url         = ConfigText(default='', fixed_size=False)

class XtreamGenScreen(Screen, ConfigListScreen):
    skin = '<screen name="XtreamGenerator" position="center,center" size="900,720" title="Xtream Generator"><eLabel text="Xtream Generator" position="20,15" size="860,34" font="Regular;24"/><widget name="lab" position="20,55" size="860,32" font="Regular;20"/><widget name="config" position="20,95" size="860,560" scrollbarMode="showOnDemand"/><eLabel text="OK = Generate   |   MENU = Save   |   EXIT = Close" position="20,665" size="860,34" font="Regular;20"/></screen>'
    def __init__(self, session):
        Screen.__init__(self, session)
        self['lab'] = Label('v1.6.7 — sources.xml <description> = Bouquets prefix (single-ID EPG mapping)')
        entries = [
            getConfigListEntry('Base URL', conf.base_url),
            getConfigListEntry('Port', conf.port),
            getConfigListEntry('Username', conf.username),
            getConfigListEntry('Password', conf.password),
            getConfigListEntry('Bouquets prefix', conf.bouquets_prefix),
            getConfigListEntry('Include Live', conf.include_live),
            getConfigListEntry('Include VOD', conf.include_vod),
            getConfigListEntry('Include Series', conf.include_series),
            getConfigListEntry('Series mode', conf.series_mode),
            getConfigListEntry('StreamType (Live)', conf.streamtype_tv),
            getConfigListEntry('StreamType (VOD)', conf.streamtype_vod),
            getConfigListEntry('StreamType (Series)', conf.streamtype_ser),
            getConfigListEntry("Remove '/live' in URL (Live)", conf.omit_live_seg),
            getConfigListEntry('Add :80 if missing (streams)', conf.add_port),
            getConfigListEntry('Place IPTV bouquets at top', conf.bouquet_top),
            getConfigListEntry('Write EPG Importer files', conf.write_epg),
            getConfigListEntry('EPG source name', conf.epg_source_name),
            getConfigListEntry('EPG URL (CDATA, leave blank = auto)', conf.epg_url),
        ]
        ConfigListScreen.__init__(self, entries, session=session)
        self['actions'] = ActionMap(['OkCancelActions','MenuActions'],
            {'ok': self.generate, 'cancel': self.close, 'menu': self.save_only}, -1)

    def save_only(self):
        for x in self['config'].list: x[1].save()
        self.session.open(MessageBox, 'Settings saved.', MessageBox.TYPE_INFO, timeout=3)

    def generate(self):
        for x in self['config'].list: x[1].save()
        cfg = GeneratorConfig(
            base_url = conf.base_url.value.strip(),
            port     = int(conf.port.value),
            username = conf.username.value.strip(),
            password = conf.password.value.strip(),
            prefix   = (conf.bouquets_prefix.value.strip() or 'xtream_iptv'),
            add_port = conf.add_port.value,
            omit_live_seg = conf.omit_live_seg.value,
            include_live  = conf.include_live.value,
            include_vod   = conf.include_vod.value,
            include_series= conf.include_series.value,
            st_live   = int(conf.streamtype_tv.value),
            st_vod    = int(conf.streamtype_vod.value),
            st_series = int(conf.streamtype_ser.value),
            bouquet_top = conf.bouquet_top.value,
            series_mode = conf.series_mode.value,
            write_epg = conf.write_epg.value,
            epg_source_name = conf.epg_source_name.value.strip() or 'XtreamGenerator EPG',
            epg_url = conf.epg_url.value.strip()
        )
        try:
            cnt = XtreamGenerator(cfg).run()
            self.session.open(MessageBox, 'Generated %d bouquets. Reloading…' % cnt, MessageBox.TYPE_INFO, timeout=6)
        except Exception as e:
            self.session.open(MessageBox, 'Generation failed: %s' % e, MessageBox.TYPE_ERROR, timeout=10)

def main(session, **kwargs):
    session.open(XtreamGenScreen)

def Plugins(**kwargs):
    return [
        PluginDescriptor(name='Xtream Generator', description='Generate bouquets (Live/VOD/Series)', where=PluginDescriptor.WHERE_PLUGINMENU, fnc=main),
        PluginDescriptor(name='Xtream Generator', where=PluginDescriptor.WHERE_EXTENSIONSMENU, fnc=main),
    ]
