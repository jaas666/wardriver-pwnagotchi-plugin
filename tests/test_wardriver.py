"""
Tests for wardriver.py pwnagotchi plugin.

pwnagotchi and other device-specific imports are stubbed out before the
module is imported, so the tests run on any standard Python 3 install
with only pytest and requests available.
"""
import base64
import hashlib
import hmac
import json
import sqlite3
import sys
import threading
import time
import types
from unittest.mock import MagicMock, patch
import pytest

# ---------------------------------------------------------------------------
# Stub out device-specific and optional dependencies before importing wardriver
# ---------------------------------------------------------------------------

class _MockPlugin:
    """Minimal Plugin base so Wardriver can be instantiated in tests."""
    options = {}
    def __init__(self):
        pass

_plugins_mod = types.ModuleType('pwnagotchi.plugins')
_plugins_mod.Plugin = _MockPlugin

_pwnagotchi_mod = types.ModuleType('pwnagotchi')
_pwnagotchi_mod.plugins = _plugins_mod

_ui_mod       = types.ModuleType('pwnagotchi.ui')
_components   = types.ModuleType('pwnagotchi.ui.components')
_components.LabeledValue = MagicMock()
_components.Widget = object          # WardriverIcon inherits from this

_view_mod     = types.ModuleType('pwnagotchi.ui.view')
_view_mod.BLACK = 0

_fonts_mod    = types.ModuleType('pwnagotchi.ui.fonts')
_fonts_mod.Small = MagicMock()

_flask_mod    = types.ModuleType('flask')
_flask_mod.abort = MagicMock()
_flask_mod.render_template_string = MagicMock(return_value='<html/>')

sys.modules.update({
    'pwnagotchi':               _pwnagotchi_mod,
    'pwnagotchi.plugins':       _plugins_mod,
    'pwnagotchi.ui':            _ui_mod,
    'pwnagotchi.ui.components': _components,
    'pwnagotchi.ui.view':       _view_mod,
    'pwnagotchi.ui.fonts':      _fonts_mod,
    'PIL':                      MagicMock(),
    'PIL.Image':                MagicMock(),
    'PIL.ImageOps':             MagicMock(),
    'flask':                    _flask_mod,
    'toml':                     MagicMock(),
    'websockets':               MagicMock(),
    'asyncio':                  MagicMock(),
})

import wardriver  # noqa: E402  (must follow stub setup)
from wardriver import Database, CSVGenerator, GpsdClient, Wardriver, _sign_payload  # noqa: E402

# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------

FAKE_KEY = 'a' * 64

MOCK_UPLOAD_RESPONSE = {
    'job_id': 'job_abc123',
    'state': 'queued',
    'imported': 1,
    'duplicates': 0,
}


def _add_network(db, session_id, mac='AA:BB:CC:DD:EE:FF', ssid='TestNet',
                 auth='[WPA2][CCMP][PSK]', lat='51.5', lon='-0.12',
                 alt='15.0', accuracy=50, channel=6, rssi=-70):
    db.add_wardrived_network(session_id, mac, ssid, auth, lat, lon, alt,
                             accuracy, channel, rssi)


def _make_plugin(tmp_path, wigle_enabled=False, wdgwars_enabled=True,
                 soulcage_enabled=True):
    """
    Return (Wardriver, Database, current_session_id) with enough state
    wired up to exercise upload and webhook logic without running on_loaded.
    """
    w   = Wardriver()
    db  = Database(str(tmp_path / 'test.db'))
    sid = db.new_wardriving_session()
    _add_network(db, sid)   # keep the session alive (non-empty)

    w._Wardriver__db                = db
    w._Wardriver__csv_generator     = CSVGenerator()
    w._Wardriver__lock              = threading.Lock()
    w._Wardriver__session_id        = sid
    w._Wardriver__agent_mode        = 'auto'
    w._Wardriver__session_reported  = []
    w._Wardriver__last_gps          = {'latitude': '-', 'longitude': '-', 'altitude': '-'}
    w._Wardriver__last_ap_refresh   = None
    w._Wardriver__last_ap_reported  = []
    w._Wardriver__path              = str(tmp_path)
    w._Wardriver__ui_enabled        = False
    w._Wardriver__whitelist         = []
    w._Wardriver__gps_config        = {'method': 'bettercap'}
    w._Wardriver__downloaded_assets = True
    w._Wardriver__wigle_enabled     = wigle_enabled
    w._Wardriver__wigle_api_key     = FAKE_KEY if wigle_enabled else None
    w._Wardriver__wigle_donate      = False
    w._Wardriver__wdgwars_enabled   = wdgwars_enabled
    w._Wardriver__wdgwars_api_key   = FAKE_KEY
    w._Wardriver__soulcage_enabled  = soulcage_enabled
    w._Wardriver__soulcage_api_key  = FAKE_KEY
    w.ready = True
    return w, db, sid


def _mock_get(method='GET'):
    req = MagicMock()
    req.method = method
    return req


# ===========================================================================
# _sign_payload
# ===========================================================================

class TestSignPayload:

    def test_output_is_valid_json_with_required_keys(self):
        result = _sign_payload(FAKE_KEY, {'networks': []})
        parsed = json.loads(result)
        assert set(parsed.keys()) == {'data', 'nonce', 'sig'}

    def test_nonce_is_16_hex_characters(self):
        parsed = json.loads(_sign_payload(FAKE_KEY, {}))
        assert len(parsed['nonce']) == 16
        int(parsed['nonce'], 16)   # raises ValueError if not valid hex

    def test_data_field_decodes_to_original_payload(self):
        payload = {'networks': [{'ssid': 'Home', 'bssid': 'AA:BB:CC:DD:EE:FF'}]}
        parsed = json.loads(_sign_payload(FAKE_KEY, payload))
        assert json.loads(base64.b64decode(parsed['data'])) == payload

    def test_signature_is_correct_hmac_sha256(self):
        key = 'b' * 64
        parsed = json.loads(_sign_payload(key, {'x': 1}))
        expected = hmac.new(
            key.encode(),
            (parsed['nonce'] + parsed['data']).encode(),
            hashlib.sha256,
        ).hexdigest()
        assert parsed['sig'] == expected

    def test_payload_encoded_with_compact_separators(self):
        parsed = json.loads(_sign_payload(FAKE_KEY, {'a': 1, 'b': 2}))
        raw = base64.b64decode(parsed['data']).decode()
        assert ' ' not in raw

    def test_each_call_produces_a_unique_nonce(self):
        nonces = {json.loads(_sign_payload(FAKE_KEY, {}))['nonce'] for _ in range(30)}
        assert len(nonces) > 1


# ===========================================================================
# Database
# ===========================================================================

@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / 'test.db'))


class TestDatabase:

    def test_new_session_returns_positive_integer(self, db):
        sid = db.new_wardriving_session()
        _add_network(db, sid)
        assert isinstance(sid, int) and sid > 0

    def test_multiple_sessions_have_distinct_ids(self, db):
        s1 = db.new_wardriving_session()
        _add_network(db, s1, mac='11:22:33:44:55:61')
        s2 = db.new_wardriving_session()
        _add_network(db, s2, mac='11:22:33:44:55:62')
        assert s1 != s2

    def test_add_network_increments_count(self, db):
        sid = db.new_wardriving_session()
        _add_network(db, sid)
        assert db.session_networks_count(sid) == 1

    def test_session_networks_returns_correct_fields(self, db):
        sid = db.new_wardriving_session()
        db.add_wardrived_network(sid, 'AA:BB:CC:DD:EE:FF', 'MyNet',
                                 '[WPA2][CCMP]', '51.5', '-0.1', '20.0',
                                 50, 11, -60)
        nets = db.session_networks(sid)
        assert len(nets) == 1
        n = nets[0]
        assert n['mac']       == 'AA:BB:CC:DD:EE:FF'
        assert n['ssid']      == 'MyNet'
        assert n['auth_mode'] == '[WPA2][CCMP]'
        assert float(n['latitude'])  == pytest.approx(51.5)
        assert int(n['channel'])     == 11
        assert int(n['rssi'])        == -60

    def test_session_without_networks_is_pruned_on_reopen(self, tmp_path):
        # remove_empty_sessions runs in __init__, so pruning happens on the
        # next open, not immediately after the empty session is created.
        path = str(tmp_path / 'prune.db')
        db1 = Database(path)
        db1.new_wardriving_session()   # no networks — should be pruned
        db1.disconnect()

        db2 = Database(path)           # re-open triggers pruning
        assert db2.general_stats()['total_sessions'] == 0
        db2.disconnect()

    def test_session_uploaded_to_wigle_sets_flag(self, db):
        sid = db.new_wardriving_session()
        _add_network(db, sid)
        db.session_uploaded_to_wigle(sid)
        s = next(x for x in db.sessions() if x['id'] == sid)
        assert s['wigle_uploaded']    is True
        assert s['wdgwars_uploaded']  is False
        assert s['soulcage_uploaded'] is False

    def test_session_uploaded_to_wdgwars_sets_flag(self, db):
        sid = db.new_wardriving_session()
        _add_network(db, sid)
        db.session_uploaded_to_wdgwars(sid)
        s = next(x for x in db.sessions() if x['id'] == sid)
        assert s['wdgwars_uploaded']  is True
        assert s['wigle_uploaded']    is False
        assert s['soulcage_uploaded'] is False

    def test_session_uploaded_to_soulcage_sets_flag(self, db):
        sid = db.new_wardriving_session()
        _add_network(db, sid)
        db.session_uploaded_to_soulcage(sid)
        s = next(x for x in db.sessions() if x['id'] == sid)
        assert s['soulcage_uploaded'] is True
        assert s['wigle_uploaded']    is False
        assert s['wdgwars_uploaded']  is False

    def _setup_three_sessions(self, db):
        """Return (uploaded_sid, pending_sid, current_sid)."""
        s_uploaded = db.new_wardriving_session()
        _add_network(db, s_uploaded, mac='11:22:33:44:55:61')
        s_pending = db.new_wardriving_session()
        _add_network(db, s_pending,  mac='11:22:33:44:55:62')
        s_current = db.new_wardriving_session()
        _add_network(db, s_current,  mac='11:22:33:44:55:63')
        return s_uploaded, s_pending, s_current

    def test_wigle_sessions_not_uploaded_filters_correctly(self, db):
        s_up, s_pend, s_cur = self._setup_three_sessions(db)
        db.session_uploaded_to_wigle(s_up)
        pending = db.wigle_sessions_not_uploaded(s_cur)
        assert s_up   not in pending
        assert s_pend in     pending
        assert s_cur  not in pending

    def test_wdgwars_sessions_not_uploaded_filters_correctly(self, db):
        s_up, s_pend, s_cur = self._setup_three_sessions(db)
        db.session_uploaded_to_wdgwars(s_up)
        pending = db.wdgwars_sessions_not_uploaded(s_cur)
        assert s_up   not in pending
        assert s_pend in     pending
        assert s_cur  not in pending

    def test_soulcage_sessions_not_uploaded_filters_correctly(self, db):
        s_up, s_pend, s_cur = self._setup_three_sessions(db)
        db.session_uploaded_to_soulcage(s_up)
        pending = db.soulcage_sessions_not_uploaded(s_cur)
        assert s_up   not in pending
        assert s_pend in     pending
        assert s_cur  not in pending

    def test_general_stats_counts_each_service_separately(self, db):
        s1 = db.new_wardriving_session()
        _add_network(db, s1, mac='11:22:33:44:55:61', ssid='A')
        s2 = db.new_wardriving_session()
        _add_network(db, s2, mac='11:22:33:44:55:62', ssid='B')
        db.session_uploaded_to_wigle(s1)
        db.session_uploaded_to_wdgwars(s2)
        db.session_uploaded_to_soulcage(s1)
        stats = db.general_stats()
        assert stats['total_sessions']            == 2
        assert stats['total_networks']            == 2
        assert stats['sessions_uploaded']         == 1
        assert stats['sessions_wdgwars_uploaded'] == 1
        assert stats['sessions_soulcage_uploaded']== 1

    def test_sessions_rows_include_all_upload_flags(self, db):
        sid = db.new_wardriving_session()
        _add_network(db, sid)
        row = db.sessions()[0]
        assert row['wigle_uploaded']    is False
        assert row['wdgwars_uploaded']  is False
        assert row['soulcage_uploaded'] is False
        assert row['networks']          == 1

    def test_current_session_stats(self, db):
        sid = db.new_wardriving_session()
        _add_network(db, sid)
        stats = db.current_session_stats(sid)
        assert stats['id']         == sid
        assert stats['networks']   == 1
        assert stats['created_at'] is not None

    def test_map_networks_returns_floats(self, db):
        sid = db.new_wardriving_session()
        _add_network(db, sid, lat='51.5', lon='-0.12')
        nets = db.map_networks()
        assert nets[0]['latitude']  == pytest.approx(51.5)
        assert nets[0]['longitude'] == pytest.approx(-0.12)

    def test_migration_adds_new_columns_to_existing_database(self, tmp_path):
        """
        A database created without wdgwars_uploaded/soulcage_uploaded columns
        should have them added automatically on first open.
        """
        db_path = str(tmp_path / 'old.db')
        conn = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE sessions (
                "id" INTEGER,
                "created_at" TEXT DEFAULT CURRENT_TIMESTAMP,
                "wigle_uploaded" INTEGER DEFAULT 0,
                PRIMARY KEY("id")
            );
            CREATE TABLE networks (
                "id" INTEGER, "mac" TEXT NOT NULL, "ssid" TEXT,
                PRIMARY KEY ("id")
            );
            CREATE TABLE wardrive (
                "id" INTEGER,
                "session_id" INTEGER NOT NULL,
                "network_id" INTEGER NOT NULL,
                "auth_mode" TEXT NOT NULL,
                "latitude" TEXT NOT NULL,
                "longitude" TEXT NOT NULL,
                "altitude" TEXT NOT NULL,
                "accuracy" INTEGER NOT NULL,
                "channel" INTEGER NOT NULL,
                "rssi" INTEGER NOT NULL,
                "seen_timestamp" TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY("id")
            );
        """)
        conn.commit()
        conn.close()

        migrated = Database(db_path)
        conn2 = sqlite3.connect(db_path)
        cols = {row[1] for row in conn2.execute('PRAGMA table_info(sessions)')}
        conn2.close()
        migrated.disconnect()

        assert 'wdgwars_uploaded'  in cols
        assert 'soulcage_uploaded' in cols


# ===========================================================================
# Wardriver.__map_auth_mode
# ===========================================================================

_map = Wardriver._Wardriver__map_auth_mode   # unwrap name mangling


class TestMapAuthMode:

    def test_wpa3(self):
        assert _map('[WPA3][SAE]') == 'WPA3'

    def test_wpa2(self):
        assert _map('[WPA2]') == 'WPA2'

    def test_wpa2_compound_capabilities(self):
        assert _map('[WPA2][CCMP][PSK]') == 'WPA2'

    def test_wpa_without_version_number(self):
        assert _map('[WPA][TKIP][PSK]') == 'WPA'

    def test_wep(self):
        assert _map('[WEP]') == 'WEP'

    def test_open_network_empty_string(self):
        assert _map('') == 'OPEN'


# ===========================================================================
# CSVGenerator
# ===========================================================================

@pytest.fixture
def csv_gen():
    return CSVGenerator()


@pytest.fixture
def sample_network():
    return {
        'mac':            'AA:BB:CC:DD:EE:FF',
        'ssid':           'MyNetwork',
        'auth_mode':      '[WPA2][CCMP][PSK]',
        'seen_timestamp': '2026-06-21 12:00:00',
        'channel':        6,
        'rssi':           -65,
        'latitude':       '51.5',
        'longitude':      '-0.12',
        'altitude':       '15.0',
        'accuracy':       50,
    }


class TestCSVGenerator:

    def test_header_row_has_correct_columns(self, csv_gen, sample_network):
        header = csv_gen.networks_to_csv([sample_network]).splitlines()[0]
        assert header == ('MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,'
                          'CurrentLatitude,CurrentLongitude,'
                          'AltitudeMeters,AccuracyMeters,Type')

    def test_network_row_contains_expected_values(self, csv_gen, sample_network):
        row = csv_gen.networks_to_csv([sample_network]).splitlines()[1]
        assert 'AA:BB:CC:DD:EE:FF' in row
        assert 'MyNetwork'          in row
        assert 'WIFI'               in row

    def test_wigle_csv_includes_preheader(self, csv_gen, sample_network):
        lines = csv_gen.networks_to_wigle_csv([sample_network]).splitlines()
        assert 'WigleWifi' in lines[0]
        assert lines[1].startswith('MAC,SSID')


# ===========================================================================
# GpsdClient
# ===========================================================================

class TestGpsdClient:

    @patch('socket.socket')
    @patch('time.sleep')
    def test_get_coordinates_returns_lat_lon_alt(self, _sleep, mock_sock_class):
        mock_sock   = MagicMock()
        mock_stream = MagicMock()
        mock_sock_class.return_value  = mock_sock
        mock_sock.makefile.return_value = mock_stream
        mock_stream.readline.side_effect = [
            '{"class": "VERSION", "release": "3.23"}\n',
            '{"class": "POLL", "tpv": [{"lat": 51.5, "lon": -0.12, "alt": 15.0}]}\n',
        ]

        client = GpsdClient('127.0.0.1', 2947)
        client.connect()
        coords = client.get_coordinates()

        assert coords['Latitude']  == 51.5
        assert coords['Longitude'] == -0.12
        assert coords['Altitude']  == 15.0

    @patch('socket.socket')
    @patch('time.sleep')
    def test_get_coordinates_returns_none_on_empty_tpv(self, _sleep, mock_sock_class):
        mock_sock   = MagicMock()
        mock_stream = MagicMock()
        mock_sock_class.return_value    = mock_sock
        mock_sock.makefile.return_value = mock_stream
        empty_poll  = '{"class": "POLL", "tpv": []}\n'
        mock_stream.readline.side_effect = [
            '{"class": "VERSION", "release": "3.23"}\n',
        ] + [empty_poll] * GpsdClient.MAX_RETRIES

        client = GpsdClient('127.0.0.1', 2947)
        client.connect()
        assert client.get_coordinates() is None

    def test_get_coordinates_returns_none_when_not_connected(self):
        """Calling get_coordinates before connect should not raise."""
        client = GpsdClient('127.0.0.1', 2947)
        # __gpsd_stream is None; the except block catches AttributeError
        with patch('time.sleep'), patch.object(client, 'connect',
                                               side_effect=Exception('no server')):
            result = client.get_coordinates()
        assert result is None


# ===========================================================================
# Upload methods — fixtures
# ===========================================================================

@pytest.fixture
def plugin(tmp_path):
    return _make_plugin(tmp_path)


@pytest.fixture
def plugin_with_prev(tmp_path):
    """Plugin plus a second completed (non-current) session."""
    w, db, sid = _make_plugin(tmp_path)
    prev = db.new_wardriving_session()
    _add_network(db, prev, mac='BB:BB:CC:DD:EE:FF', ssid='PrevNet')
    return w, db, sid, prev


def _mock_ok_response():
    resp = MagicMock()
    resp.json.return_value = MOCK_UPLOAD_RESPONSE
    return resp


# ===========================================================================
# __upload_session_to_wigle
# ===========================================================================

class TestUploadToWigle:

    @patch('wardriver.requests.post')
    def test_success_marks_session_and_returns_true(self, mock_post, plugin_with_prev):
        w, db, sid, prev = plugin_with_prev
        mock_post.return_value = _mock_ok_response()
        w._Wardriver__wigle_api_key = FAKE_KEY

        assert w._Wardriver__upload_session_to_wigle(prev) is True
        assert next(s for s in db.sessions() if s['id'] == prev)['wigle_uploaded'] is True

    @patch('wardriver.requests.post')
    def test_failure_returns_false_and_leaves_flag_unset(self, mock_post, plugin_with_prev):
        w, db, sid, prev = plugin_with_prev
        mock_post.side_effect = Exception('HTTP 500')
        w._Wardriver__wigle_api_key = FAKE_KEY

        assert w._Wardriver__upload_session_to_wigle(prev) is False
        assert next(s for s in db.sessions() if s['id'] == prev)['wigle_uploaded'] is False

    @patch('wardriver.requests.post')
    def test_posts_to_wigle_api_url(self, mock_post, plugin):
        w, db, sid = plugin
        mock_post.return_value = _mock_ok_response()
        w._Wardriver__wigle_api_key = FAKE_KEY
        w._Wardriver__upload_session_to_wigle(sid)
        assert 'wigle.net' in mock_post.call_args[1]['url']


# ===========================================================================
# __upload_session_to_wdgwars
# ===========================================================================

class TestUploadToWdgwars:

    @patch('wardriver.requests.post')
    def test_success_marks_session_and_returns_true(self, mock_post, plugin_with_prev):
        w, db, sid, prev = plugin_with_prev
        mock_post.return_value = _mock_ok_response()

        assert w._Wardriver__upload_session_to_wdgwars(prev) is True
        s = next(x for x in db.sessions() if x['id'] == prev)
        assert s['wdgwars_uploaded']  is True
        assert s['soulcage_uploaded'] is False

    @patch('wardriver.requests.post')
    def test_failure_returns_false_and_leaves_flag_unset(self, mock_post, plugin_with_prev):
        w, db, sid, prev = plugin_with_prev
        mock_post.side_effect = Exception('connection refused')

        assert w._Wardriver__upload_session_to_wdgwars(prev) is False
        assert next(s for s in db.sessions() if s['id'] == prev)['wdgwars_uploaded'] is False

    @patch('wardriver.requests.post')
    def test_posts_to_wdgwars_url(self, mock_post, plugin):
        w, db, sid = plugin
        mock_post.return_value = _mock_ok_response()
        w._Wardriver__upload_session_to_wdgwars(sid)
        assert 'wdgwars.pl' in mock_post.call_args[1]['url']

    @patch('wardriver.requests.post')
    def test_request_carries_api_key_header(self, mock_post, plugin):
        w, db, sid = plugin
        mock_post.return_value = _mock_ok_response()
        w._Wardriver__upload_session_to_wdgwars(sid)
        assert mock_post.call_args[1]['headers']['X-API-Key'] == FAKE_KEY

    @patch('wardriver.requests.post')
    def test_body_is_signed_envelope(self, mock_post, plugin):
        w, db, sid = plugin
        mock_post.return_value = _mock_ok_response()
        w._Wardriver__upload_session_to_wdgwars(sid)
        envelope = json.loads(mock_post.call_args[1]['data'])
        assert {'data', 'nonce', 'sig'} == set(envelope.keys())

    @patch('wardriver.requests.post')
    def test_network_fields_have_correct_types(self, mock_post, plugin):
        w, db, sid = plugin
        mock_post.return_value = _mock_ok_response()
        w._Wardriver__upload_session_to_wdgwars(sid)
        envelope = json.loads(mock_post.call_args[1]['data'])
        net = json.loads(base64.b64decode(envelope['data']))['networks'][0]
        assert isinstance(net['lat'],     float)
        assert isinstance(net['lon'],     float)
        assert isinstance(net['channel'], int)
        assert isinstance(net['rssi'],    int)
        assert net['type'] == 'WIFI'

    @patch('wardriver.requests.post')
    def test_auth_mode_mapped_from_capabilities_string(self, mock_post, plugin):
        w, db, sid = plugin
        mock_post.return_value = _mock_ok_response()
        w._Wardriver__upload_session_to_wdgwars(sid)
        envelope = json.loads(mock_post.call_args[1]['data'])
        net = json.loads(base64.b64decode(envelope['data']))['networks'][0]
        # DB has '[WPA2][CCMP][PSK]' — must arrive as plain 'WPA2'
        assert net['auth'] == 'WPA2'


# ===========================================================================
# __upload_session_to_soulcage
# ===========================================================================

class TestUploadToSoulcage:

    @patch('wardriver.requests.post')
    def test_success_marks_session_and_returns_true(self, mock_post, plugin_with_prev):
        w, db, sid, prev = plugin_with_prev
        mock_post.return_value = _mock_ok_response()

        assert w._Wardriver__upload_session_to_soulcage(prev) is True
        s = next(x for x in db.sessions() if x['id'] == prev)
        assert s['soulcage_uploaded'] is True
        assert s['wdgwars_uploaded']  is False

    @patch('wardriver.requests.post')
    def test_failure_returns_false_and_leaves_flag_unset(self, mock_post, plugin_with_prev):
        w, db, sid, prev = plugin_with_prev
        mock_post.side_effect = Exception('timeout')

        assert w._Wardriver__upload_session_to_soulcage(prev) is False
        assert next(s for s in db.sessions() if s['id'] == prev)['soulcage_uploaded'] is False

    @patch('wardriver.requests.post')
    def test_posts_to_soulcage_url(self, mock_post, plugin):
        w, db, sid = plugin
        mock_post.return_value = _mock_ok_response()
        w._Wardriver__upload_session_to_soulcage(sid)
        assert 'soulcage.win' in mock_post.call_args[1]['url']

    @patch('wardriver.requests.post')
    def test_wdgwars_and_soulcage_hit_different_urls(self, mock_post, plugin):
        """The two methods are independent and must never share a base URL."""
        w, db, sid = plugin
        mock_post.return_value = _mock_ok_response()

        w._Wardriver__upload_session_to_wdgwars(sid)
        wdg_url = mock_post.call_args[1]['url']

        w._Wardriver__upload_session_to_soulcage(sid)
        sc_url = mock_post.call_args[1]['url']

        assert wdg_url != sc_url
        assert 'wdgwars.pl'   in wdg_url
        assert 'soulcage.win' in sc_url


# ===========================================================================
# on_internet_available — automatic upload integration
# ===========================================================================

class TestAutoUpload:

    @patch('wardriver.requests.post')
    def test_uploads_pending_wdgwars_sessions_on_internet(self, mock_post, tmp_path):
        w, db, current = _make_plugin(tmp_path, wdgwars_enabled=True,
                                       soulcage_enabled=False)
        prev = db.new_wardriving_session()
        _add_network(db, prev, mac='BB:BB:CC:DD:EE:FF')
        mock_post.return_value = _mock_ok_response()

        w.on_internet_available(MagicMock())

        assert next(s for s in db.sessions() if s['id'] == prev)['wdgwars_uploaded'] is True

    @patch('wardriver.requests.post')
    def test_uploads_pending_soulcage_sessions_on_internet(self, mock_post, tmp_path):
        w, db, current = _make_plugin(tmp_path, wdgwars_enabled=False,
                                       soulcage_enabled=True)
        prev = db.new_wardriving_session()
        _add_network(db, prev, mac='BB:BB:CC:DD:EE:FF')
        mock_post.return_value = _mock_ok_response()

        w.on_internet_available(MagicMock())

        assert next(s for s in db.sessions() if s['id'] == prev)['soulcage_uploaded'] is True

    @patch('wardriver.requests.post')
    def test_does_not_upload_current_session(self, mock_post, tmp_path):
        w, db, current = _make_plugin(tmp_path, wdgwars_enabled=True)
        mock_post.return_value = _mock_ok_response()

        w.on_internet_available(MagicMock())

        # current session must stay unmarked regardless
        s = next(x for x in db.sessions() if x['id'] == current)
        assert s['wdgwars_uploaded'] is False


# ===========================================================================
# on_webhook
# ===========================================================================

class TestWebhook:

    def test_root_path_renders_html_template(self, plugin):
        w, db, sid = plugin
        _flask_mod.render_template_string.reset_mock()
        w.on_webhook('/', _mock_get())
        _flask_mod.render_template_string.assert_called_once()

    def test_current_session_returns_minus_one_in_manu_mode(self, plugin):
        w, db, sid = plugin
        w._Wardriver__agent_mode = 'manual'
        data = json.loads(w.on_webhook('current-session', _mock_get()))
        assert data['id'] == -1

    def test_current_session_returns_session_id_in_auto_mode(self, plugin):
        w, db, sid = plugin
        data = json.loads(w.on_webhook('current-session', _mock_get()))
        assert data['id'] == sid

    def test_general_stats_contains_all_service_config_flags(self, plugin):
        w, db, sid = plugin
        cfg = json.loads(w.on_webhook('general-stats', _mock_get()))['config']
        assert 'wigle_enabled'    in cfg
        assert 'wdgwars_enabled'  in cfg
        assert 'soulcage_enabled' in cfg

    def test_general_stats_contains_upload_counts_for_all_services(self, plugin):
        w, db, sid = plugin
        data = json.loads(w.on_webhook('general-stats', _mock_get()))
        assert 'sessions_wdgwars_uploaded'  in data
        assert 'sessions_soulcage_uploaded' in data

    def test_sessions_path_returns_list_with_all_upload_flags(self, plugin):
        w, db, sid = plugin
        data = json.loads(w.on_webhook('sessions', _mock_get()))
        assert isinstance(data, list)
        s = next(x for x in data if x['id'] == sid)
        assert 'wigle_uploaded'    in s
        assert 'wdgwars_uploaded'  in s
        assert 'soulcage_uploaded' in s

    def test_csv_path_returns_csv_with_header(self, plugin):
        w, db, sid = plugin
        result = w.on_webhook(f'csv/{sid}', _mock_get())
        assert result.startswith('MAC,SSID')

    @patch('wardriver.requests.post')
    def test_upload_wdgwars_path_returns_success(self, mock_post, plugin):
        w, db, sid = plugin
        mock_post.return_value = _mock_ok_response()
        result = w.on_webhook(f'upload-wdgwars/{sid}', _mock_get())
        assert 'Success' in result

    @patch('wardriver.requests.post')
    def test_upload_soulcage_path_returns_success(self, mock_post, plugin):
        w, db, sid = plugin
        mock_post.return_value = _mock_ok_response()
        result = w.on_webhook(f'upload-soulcage/{sid}', _mock_get())
        assert 'Success' in result

    @patch('wardriver.requests.post')
    def test_upload_wigle_path_returns_error_on_failure(self, mock_post, plugin):
        w, db, sid = plugin
        mock_post.side_effect = Exception('network error')
        w._Wardriver__wigle_api_key = FAKE_KEY
        result = w.on_webhook(f'upload/{sid}', _mock_get())
        assert 'Error' in result

    def test_map_networks_path_returns_center_and_networks(self, plugin):
        w, db, sid = plugin
        data = json.loads(w.on_webhook('map-networks', _mock_get()))
        assert 'center'   in data
        assert 'networks' in data
        assert len(data['networks']) == 1
