import copy
import unittest

from urlmap_merge import PREFIX, merge, remove_own

BASE = {
    "name": "ma-platform-lb",
    "fingerprint": "abc=",
    "defaultService": "https://www.googleapis.com/compute/v1/projects/sms-ma-platform/global/backendServices/map-bk-default-prod",
    "hostRules": [
        {"hosts": ["cb.mobile-americas.com"], "pathMatcher": "path-matcher-5"},
        {"hosts": ["c.play-on.vip"], "pathMatcher": "path-matcher-8"},
        {"hosts": ["portal.play-on.vip"], "pathMatcher": "ma-portal-web"},
    ],
    "pathMatchers": [
        {"name": "path-matcher-5", "defaultService": "bs-entry"},
        {"name": "path-matcher-8", "defaultService": "bs-default"},
        {"name": "ma-portal-web", "defaultService": "bb-portal"},
    ],
}

FRAGMENT = {
    "hostRules": [{"hosts": ["auth2.mobile-americas.com"], "pathMatcher": "ma-platform-auth"}],
    "pathMatchers": [{"name": "ma-platform-auth", "defaultService": "bb-web"}],
}


AUTH_HOY = {
    "name": "ma-platform-lb",
    "defaultService": "bs-default",
    "hostRules": [
        {"hosts": ["auth.mobile-americas.com"], "pathMatcher": "path-matcher-7"},
        {"hosts": ["cb.mobile-americas.com"], "pathMatcher": "path-matcher-5"},
        {"hosts": ["portal.play-on.vip"], "pathMatcher": "ma-portal-web"},
    ],
    "pathMatchers": [
        {"name": "path-matcher-7", "defaultService": "bs-default"},
        {"name": "path-matcher-5", "defaultService": "bs-entry"},
        {"name": "ma-portal-web", "defaultService": "bb-portal"},
    ],
}

AUTH_FRAGMENTO = {
    "hostRules": [{"hosts": ["auth.mobile-americas.com"], "pathMatcher": "ma-platform-auth"}],
    "pathMatchers": [{"name": "ma-platform-auth", "defaultService": "bs-default",
                      "routeRules": [{"priority": 10, "matchRules": [{"prefixMatch": "/authorization-api/"}],
                                      "service": "be-auth"}]}],
}


class ReclamarHostTest(unittest.TestCase):
    def test_sin_reclamar_un_host_ajeno_se_rechaza(self):
        with self.assertRaisesRegex(ValueError, "auth.mobile-americas.com"):
            merge(AUTH_HOY, AUTH_FRAGMENTO)

    def test_reclamar_mueve_el_host_y_borra_el_path_matcher_que_queda_sin_uso(self):
        out = merge(AUTH_HOY, AUTH_FRAGMENTO, reclaim={"auth.mobile-americas.com"})
        self.assertIn({"hosts": ["auth.mobile-americas.com"], "pathMatcher": "ma-platform-auth"}, out["hostRules"])
        self.assertNotIn("path-matcher-7", [p["name"] for p in out["pathMatchers"]])
        self.assertNotIn("path-matcher-7", [h["pathMatcher"] for h in out["hostRules"]])

    def test_reclamar_no_toca_ninguna_otra_regla(self):
        out = merge(AUTH_HOY, AUTH_FRAGMENTO, reclaim={"auth.mobile-americas.com"})
        for regla in AUTH_HOY["hostRules"][1:]:
            self.assertIn(regla, out["hostRules"])
        for pm in AUTH_HOY["pathMatchers"][1:]:
            self.assertIn(pm, out["pathMatchers"])
        self.assertEqual(out["defaultService"], AUTH_HOY["defaultService"])

    def test_un_path_matcher_ajeno_que_sigue_en_uso_no_se_borra(self):
        base = copy.deepcopy(AUTH_HOY)
        base["hostRules"][0]["hosts"].append("otro.mobile-americas.com")
        out = merge(base, AUTH_FRAGMENTO, reclaim={"auth.mobile-americas.com"})
        self.assertIn({"hosts": ["otro.mobile-americas.com"], "pathMatcher": "path-matcher-7"}, out["hostRules"])
        self.assertIn("path-matcher-7", [p["name"] for p in out["pathMatchers"]])

    def test_reclamar_un_host_que_no_esta_en_el_fragmento_se_rechaza(self):
        with self.assertRaisesRegex(ValueError, "no lo usa el fragmento"):
            merge(AUTH_HOY, AUTH_FRAGMENTO, reclaim={"cb.mobile-americas.com"})


class MergeTest(unittest.TestCase):
    def test_el_prefijo_propio_es_el_del_auth(self):
        self.assertEqual(PREFIX, "ma-platform-auth")

    def test_quitar_lo_propio_no_toca_las_reglas_de_ma_portal(self):
        out = remove_own(merge(BASE, FRAGMENT))
        self.assertIn({"hosts": ["portal.play-on.vip"], "pathMatcher": "ma-portal-web"}, out["hostRules"])
        self.assertIn({"name": "ma-portal-web", "defaultService": "bb-portal"}, out["pathMatchers"])
        self.assertNotIn("ma-platform-auth", [p["name"] for p in out["pathMatchers"]])

    def test_adds_own_rules_and_keeps_foreign_ones_identical(self):
        out = merge(BASE, FRAGMENT)
        self.assertEqual(out["hostRules"][:3], BASE["hostRules"])
        self.assertEqual(out["pathMatchers"][:3], BASE["pathMatchers"])
        self.assertIn({"hosts": ["auth2.mobile-americas.com"], "pathMatcher": "ma-platform-auth"}, out["hostRules"])
        self.assertEqual(out["fingerprint"], "abc=")
        self.assertEqual(out["defaultService"], BASE["defaultService"])

    def test_is_idempotent_and_replaces_only_own_rules(self):
        once = merge(BASE, FRAGMENT)
        changed = copy.deepcopy(FRAGMENT)
        changed["pathMatchers"][0]["defaultService"] = "bb-web-2"
        twice = merge(once, changed)
        self.assertEqual(len(twice["hostRules"]), len(BASE["hostRules"]) + 1)
        self.assertEqual([p["defaultService"] for p in twice["pathMatchers"] if p["name"] == "ma-platform-auth"], ["bb-web-2"])

    def test_rejects_a_host_already_used_by_a_foreign_rule(self):
        bad = {"hostRules": [{"hosts": ["c.play-on.vip"], "pathMatcher": "ma-platform-auth"}],
               "pathMatchers": [{"name": "ma-platform-auth", "defaultService": "bb-web"}]}
        with self.assertRaisesRegex(ValueError, "c.play-on.vip"):
            merge(BASE, bad)

    def test_rejects_matchers_without_the_prefix(self):
        bad = {"hostRules": [{"hosts": ["x.mobile-americas.com"], "pathMatcher": "otro"}],
               "pathMatchers": [{"name": "otro", "defaultService": "bb"}]}
        with self.assertRaisesRegex(ValueError, PREFIX):
            merge(BASE, bad)

    def test_rejects_host_rules_pointing_to_a_matcher_not_in_the_fragment(self):
        bad = {"hostRules": [{"hosts": ["x.mobile-americas.com"], "pathMatcher": "ma-platform-auth-nada"}], "pathMatchers": []}
        with self.assertRaisesRegex(ValueError, "ma-platform-auth-nada"):
            merge(BASE, bad)

    def test_remove_own_restores_the_original_rules(self):
        out = remove_own(merge(BASE, FRAGMENT))
        self.assertEqual(out["hostRules"], BASE["hostRules"])
        self.assertEqual(out["pathMatchers"], BASE["pathMatchers"])

    def test_tests_are_added_only_when_requested(self):
        out = merge(BASE, FRAGMENT, tests=[{"host": "auth2.mobile-americas.com", "path": "/", "service": "bb-web"}])
        self.assertEqual(out["tests"][-1]["host"], "auth2.mobile-americas.com")
        self.assertNotIn("tests", merge(BASE, FRAGMENT))


if __name__ == "__main__":
    unittest.main()
