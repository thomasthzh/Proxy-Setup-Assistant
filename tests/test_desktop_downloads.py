"""No live downloads; validate official provenance, limits and corruption handling."""
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch
import urllib.request

from vps_proxy_setup.desktop import downloads as dl


class Response(io.BytesIO):
    def __init__(self, payload, url=dl.API_URL):
        super().__init__(payload)
        self.url = url

    def geturl(self):
        return self.url


def installer(payload=b"verified installer"):
    return dl.ReleaseInstaller("v2.5.8", "x64", "Clash.Verge_2.5.8_x64-setup.exe",
                               "https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v2.5.8/Clash.Verge_2.5.8_x64-setup.exe",
                               hashlib.sha256(payload).hexdigest(), len(payload))


def metadata(arch="x64", version="v2.5.8", digest="sha256:" + "a" * 64):
    filename = f"Clash.Verge_{version[1:]}_{arch}-setup.exe"
    return {"tag_name": version, "assets": [{"name": filename, "size": 1234, "digest": digest,
        "browser_download_url": f"https://github.com/{dl.REPOSITORY}/releases/download/{version}/{filename}"}]}


class DownloadTests(unittest.TestCase):
    def test_pinned_fallback_uses_verified_official_assets_without_network(self):
        with patch.object(dl.urllib.request, "urlopen") as network:
            for architecture, size in (("x64", 60230483), ("arm64", 53952182)):
                selected = dl.get_pinned_installer(architecture)
                self.assertEqual(selected.version, "v2.5.8")
                self.assertEqual(selected.architecture, architecture)
                self.assertEqual(selected.size, size)
                self.assertEqual(selected.sha256, dl.PINNED_DIGESTS[(selected.version, selected.filename)])
                self.assertTrue(selected.url.startswith("https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v2.5.8/"))
                dl._validate_installer(selected)
            with self.assertRaises(dl.DownloadError):
                dl.get_pinned_installer("x86")
            network.assert_not_called()

    def test_pinned_fallback_still_requires_opt_in_for_third_party_probe(self):
        selected = dl.get_pinned_installer("x64")
        with patch.object(dl, "_open_asset", side_effect=lambda *args, **kwargs: Response(b"MZfixture")) as network:
            official, = dl.probe_candidates(selected)
            self.assertFalse(official.third_party)
            self.assertEqual(network.call_count, 1)
        with patch.object(dl, "_open_asset", side_effect=lambda *args, **kwargs: Response(b"MZfixture")):
            routes = dl.probe_candidates(selected, allow_sourceforge=True)
            self.assertEqual(len(routes), 2)
            self.assertTrue(any(route.third_party for route in routes))

    def test_select_official_architecture_and_digest(self):
        for arch in ("x64", "arm64"):
            with patch.object(dl.urllib.request, "urlopen", return_value=Response(json.dumps(metadata(arch)).encode())):
                selected = dl.get_latest_installer(arch)
                self.assertEqual(selected.architecture, arch)
                self.assertEqual(selected.sha256, "a" * 64)

    def test_unsupported_architecture_makes_no_network_request(self):
        with patch.object(dl.urllib.request, "urlopen") as network:
            with self.assertRaises(dl.DownloadError):
                dl.get_latest_installer("x86")
            network.assert_not_called()

    def test_future_release_without_digest_fails_closed(self):
        data = metadata(version="v9.0.0", digest=None)
        with patch.object(dl.urllib.request, "urlopen", return_value=Response(json.dumps(data).encode())):
            with self.assertRaisesRegex(dl.DownloadError, "SHA-256"):
                dl.get_latest_installer("x64")

    def test_verified_pinned_digest_fallback_is_version_specific(self):
        with patch.object(dl.urllib.request, "urlopen", return_value=Response(json.dumps(metadata(digest=None)).encode())):
            selected = dl.get_latest_installer("x64")
        self.assertEqual(selected.sha256, dl.PINNED_DIGESTS[(selected.version, selected.filename)])

    def test_unofficial_asset_url_is_rejected(self):
        data = metadata()
        data["assets"][0]["browser_download_url"] = "https://example.com/setup.exe"
        with patch.object(dl.urllib.request, "urlopen", return_value=Response(json.dumps(data).encode())):
            with self.assertRaises(dl.DownloadError):
                dl.get_latest_installer("x64")

    def test_tls_failure_does_not_trigger_insecure_retry(self):
        with patch.object(dl.urllib.request, "urlopen", side_effect=ssl.SSLError("failed")) as network:
            with self.assertRaises(dl.DownloadError):
                dl.get_latest_installer("x64")
            self.assertEqual(network.call_count, 1)

    def test_download_hash_verified_before_return(self):
        payload = b"verified installer"
        progress = []
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(dl, "_open_asset", return_value=Response(payload)):
                path = dl.download_installer(installer(), directory, progress=lambda done, total: progress.append((done, total)))
            self.assertEqual(path.read_bytes(), payload)
            self.assertEqual(progress[-1], (len(payload), len(payload)))
            self.assertEqual([file.name for file in Path(directory).iterdir()], [path.name])

    def test_hash_size_and_tls_failures_remove_partial_files(self):
        for payload, error in ((b"corrupt installer!", None), (b"too long" * 40, None), (None, ssl.SSLError("failure"))):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                kwargs = {"side_effect": error} if error else {"return_value": Response(payload)}
                with patch.object(dl, "_open_asset", **kwargs), self.assertRaises(dl.DownloadError):
                    dl.download_installer(installer(), directory)
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_arbitrary_mirror_and_path_traversal_rejected_before_network(self):
        with patch.object(dl, "_open_asset") as network, tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(dl.DownloadError):
                dl.download_installer(installer(), directory, dl.DownloadCandidate("https://proxy.example/download", "bad"))
            with self.assertRaises(dl.DownloadError):
                dl.download_installer(replace(installer(), filename="../setup.exe"), directory)
            network.assert_not_called()

    def test_redirect_requires_https_and_approved_host(self):
        handler = dl._SafeRedirect(True)
        request = urllib.request.Request(installer().url)
        for url in ("http://github.com/setup.exe", "https://evil.example/setup.exe", "https://github.com.evil.example/setup.exe"):
            with self.subTest(url=url), self.assertRaises(dl.DownloadError):
                handler.redirect_request(request, None, 302, "redirect", {}, url)
        self.assertTrue(dl._safe_origin("https://release-assets.githubusercontent.com/asset"))
        self.assertFalse(dl._safe_origin("https://downloads.sourceforge.net/file"))
        self.assertTrue(dl._safe_origin("https://downloads.sourceforge.net/file", True))

    def test_probes_read_bounded_bytes_and_mark_optional_mirror(self):
        responses = []
        class Track(Response):
            def read1(self, count=-1):
                result = super().read1(count)
                responses.append(len(result))
                return result
        with patch.object(dl, "_open_asset", side_effect=lambda *args, **kwargs: Track(b"MZ" + b"x" * 300000)) as network:
            results = dl.probe_candidates(installer(), allow_sourceforge=True, max_bytes=100)
        self.assertEqual(sum(responses), 200)
        self.assertEqual(network.call_count, 2)
        self.assertTrue(any(item.third_party and "third-party" in item.label for item in results))
        self.assertTrue(all(item.bytes_per_second > 0 for item in results))

    def test_unavailable_probes_are_not_reported_as_fast(self):
        with patch.object(dl, "_open_asset", side_effect=ssl.SSLError("failed")):
            result, = dl.probe_candidates(installer())
        self.assertIsNotNone(result.error)
        self.assertEqual(result.bytes_per_second, 0)

    def test_mirror_interstitial_is_not_a_viable_installer_route(self):
        with patch.object(dl, "_open_asset", return_value=Response(b"<!DOCTYPE html><title>Just a moment</title>")):
            result, = dl.probe_candidates(installer())
        self.assertIsNotNone(result.error)
        self.assertEqual(result.bytes_per_second, 0)

    def test_download_wall_clock_deadline_discards_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(dl, "_open_asset", return_value=Response(b"verified installer")), \
                 patch.object(dl.time, "monotonic", side_effect=[0, 0, 0, 121]), \
                 self.assertRaisesRegex(dl.DownloadError, "time limit"):
                dl.download_installer(installer(), directory, timeout=120)
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
