"""Tests de la reconnaissance faciale (alternative au code TOTP) : mesures de pose, chiffrement, enregistrement, connexion,
captures refusées consultables par l'admin.

Les routes sont testées avec un moteur factice (les modèles ONNX ne sont embarqués que dans l'image) : la couleur de la
capture désigne la personne, une capture rouge échoue au défi de pose. Le décodage JPEG et le chiffrement sont réels.
"""

import base64
import time

import cv2
import jwt
import numpy as np
import pyotp
import pytest

from conftest import ADMIN_TOTP_SECRET, FACE_ENCRYPTION_KEY
from service_loader import load_service

face = load_service("auth-service", "face")
PASSWORD = "motdepasse-solide"
ALICE, BOB, SPOOF = (0, 40, 0), (0, 200, 0), (0, 0, 255)  # couleurs BGR des captures factices


def jpeg(color: tuple[int, int, int]) -> bytes:
    # Cette méthode permet de fabriquer une capture JPEG unie de la couleur donnée (la « personne » du moteur factice).
    image = np.full((120, 160, 3), color, dtype=np.uint8)
    return cv2.imencode(".jpg", image)[1].tobytes()


class FakeEngine:
    # Moteur factice : même interface que face.FaceEngine, sans modèle.

    def check_liveness(self, frames: list[bytes], poses: list[str]):
        # Cette méthode permet de simuler le défi de pose : la teinte verte de la première capture donne l'empreinte,
        # une capture rouge (photo présentée à la caméra) échoue au défi.
        if len(frames) != len(poses):
            raise face.FaceError("face_invalid_image", "captures attendues")
        image = face.decode_jpeg(frames[0])
        blue, green, red = (int(v) for v in image[0, 0])
        if red > 200:
            raise face.FaceError("face_liveness_failed", "Mouvement non reconnu.", frames[0])
        embedding = np.zeros(128, dtype=np.float32)
        embedding[green // 64] = 1.0
        faces = [face.Face(embedding=embedding, landmarks=np.zeros((5, 2), np.float32))] * len(frames)
        return faces, []


@pytest.fixture
def client(auth_client):
    # Cette méthode permet de démarrer l'auth-service avec le moteur facial factice à la place des modèles absents.
    assert auth_client.app.state.face is None  # sans modèles, le service démarre et les routes faciales répondent 503
    auth_client.app.state.face = FakeEngine()
    return auth_client


def totp_code(secret: str, offset_steps: int = 0) -> str:
    # Cette méthode permet de calculer le code TOTP qu'afficherait l'appli d'authentification.
    return pyotp.TOTP(secret).at(time.time() + 30 * offset_steps)


def bearer(token: str) -> dict:
    # Cette méthode permet de construire l'en-tête Authorization d'un jeton d'accès.
    return {"Authorization": f"Bearer {token}"}


def login(client, email: str = "visage@test.local", password: str = PASSWORD):
    # Cette méthode permet de tenter une connexion par mot de passe et de renvoyer la réponse brute.
    return client.post("/login", json={"email": email, "password": password})


def mfa_user(client, email: str = "visage@test.local") -> tuple[list[str], dict]:
    # Cette méthode permet de créer un client avec la double authentification active ; renvoie ses codes de secours
    # (utilisés pour confirmer l'enregistrement, sans gêner les codes TOTP) et l'en-tête de sa session.
    client.post("/register", json={"email": email, "full_name": "Visage Test", "password": PASSWORD})
    headers = bearer(login(client, email).json()["access_token"])
    setup = client.post("/mfa/setup", headers=headers).json()
    activated = client.post("/mfa/activate", headers=headers, json={"code": totp_code(setup["secret"], -1)})
    return activated.json()["recovery_codes"], headers


def frames(color, count: int = 3) -> list[tuple]:
    # Cette méthode permet de préparer les captures d'un défi (trois à l'enregistrement, deux à la connexion)
    # au format multipart attendu par l'API.
    return [("frames", (f"pose{i}.jpg", jpeg(color), "image/jpeg")) for i in range(count)]


def open_enrollment(client, headers: dict, code: str, consent: bool = True):
    # Cette méthode permet d'ouvrir un défi d'enregistrement avec le consentement et le code de confirmation.
    return client.post("/mfa/face/challenge", headers=headers, json={"code": code, "consent": consent})


def enroll(client, headers: dict, code: str, color=ALICE):
    # Cette méthode permet d'ouvrir un défi d'enregistrement puis d'envoyer les captures ; renvoie le premier refus.
    opened = open_enrollment(client, headers, code)
    if opened.status_code != 200:
        return opened
    data = {"challenge_id": opened.json()["challenge_id"]}
    return client.post("/mfa/face", headers=headers, data=data, files=frames(color))


def face_login(client, color, email: str = "visage@test.local"):
    # Cette méthode permet de se connecter par mot de passe puis de présenter un visage au second facteur.
    step = login(client, email).json()
    challenge = client.post("/login/mfa/face/challenge", json={"mfa_token": step["mfa_token"]}).json()
    data = {"mfa_token": step["mfa_token"], "challenge_id": challenge["challenge_id"]}
    return client.post("/login/mfa/face", data=data, files=frames(color, len(challenge["poses"]))), step, challenge


def admin_headers(client) -> dict:
    # Cette méthode permet d'ouvrir une session admin (mot de passe + TOTP imposé).
    step = login(client, "admin@resilience.local", "admin-password-test").json()
    done = client.post("/login/mfa", json={"mfa_token": step["mfa_token"], "code": totp_code(ADMIN_TOTP_SECRET)})
    return bearer(done.json()["access_token"])


def project(points: np.ndarray, yaw_deg: float, distance: float = 50, focal: float = 600) -> np.ndarray:
    # Cette méthode permet de photographier (projection perspective) des points 3D en cm tournés autour de l'axe vertical
    # du crâne (9 cm derrière les yeux), comme une tête qui tourne devant une webcam.
    t = np.radians(yaw_deg)
    rotation = np.array([[np.cos(t), 0, np.sin(t)], [0, 1, 0], [-np.sin(t), 0, np.cos(t)]])
    turned = (points - [0, 0, -9]) @ rotation.T + [0, 0, -9]
    depth = distance - turned[:, 2]
    return np.stack([focal * turned[:, 0] / depth + 320, focal * turned[:, 1] / depth + 240], 1).astype(np.float32)


# Repères d'un visage moyen (cm) : œil droit, œil gauche, nez (2,3 cm en avant), coins droit et gauche de la bouche.
HEAD = np.array([[-3.2, 0, 0], [3.2, 0, 0], [0, 3.5, 2.3], [-2.4, 6.5, -0.4], [2.4, 6.5, -0.4]])


def test_yaw_and_parallax_tell_a_turning_head_from_a_tilted_photo():
    front = project(HEAD, 0)
    left, right = project(HEAD, 25), project(HEAD, -25)
    assert abs(face.estimate_yaw(front)) < 0.01
    assert face.estimate_yaw(left) > face.YAW_TURN_MIN and face.estimate_yaw(right) < -face.YAW_TURN_MIN
    assert face.parallax(front, left) > face.PARALLAX_MIN and face.parallax(front, right) < -face.PARALLAX_MIN
    # Photo imprimée du visage de face (tous les repères dans un même plan), inclinée de 35° : le nez « tourne »
    # aussi, mais reste exactement où le prédit le plan yeux-bouche.
    photo = HEAD.copy()
    photo[:, 2] = 0
    tilted = project(photo, 35)
    assert abs(face.estimate_yaw(tilted) - face.estimate_yaw(project(photo, 0))) < 0.05
    assert abs(face.parallax(project(photo, 0), tilted)) < 0.01


def test_enrollment_poses_start_in_front_then_turn_both_ways():
    orders = {tuple(face.new_poses("enroll")) for _ in range(50)}
    assert orders == {("center", "left", "right"), ("center", "right", "left")}


def test_login_poses_start_in_front_then_turn_one_random_side():
    orders = {tuple(face.new_poses("login")) for _ in range(50)}
    assert orders == {("center", "left"), ("center", "right")}


def test_vault_binds_ciphertext_to_its_owner():
    vault = face.FaceVault(FACE_ENCRYPTION_KEY)
    sealed = vault.seal(b"empreinte", "user-1:face-reference:template")
    assert b"empreinte" not in sealed and vault.open(sealed, "user-1:face-reference:template") == b"empreinte"
    with pytest.raises(ValueError):
        vault.open(sealed, "user-2:face-reference:template")  # recopié sur un autre compte : indéchiffrable
    with pytest.raises(RuntimeError):
        face.FaceVault("dHJvcC1jb3VydGU=")


def test_face_routes_answer_503_without_models(auth_client):
    codes, headers = mfa_user(auth_client)
    res = open_enrollment(auth_client, headers, codes[0])
    assert res.status_code == 503 and res.json()["code"] == "face_unavailable"


def test_enrollment_needs_mfa_consent_and_a_code(client):
    client.post("/register", json={"email": "sans-mfa@test.local", "full_name": "Sans MFA", "password": PASSWORD})
    no_mfa = bearer(login(client, "sans-mfa@test.local").json()["access_token"])
    res = open_enrollment(client, no_mfa, "123456")
    assert res.status_code == 409 and res.json()["code"] == "mfa_not_enabled"

    codes, headers = mfa_user(client)
    assert client.get("/mfa/face", headers=headers).json() == {"enrolled": False, "enrolled_at": None,
                                                                "consented_at": None}
    refused = open_enrollment(client, headers, codes[0], consent=False)
    assert refused.status_code == 422 and refused.json()["code"] == "face_consent_required"
    wrong_code = open_enrollment(client, headers, "000000")
    assert wrong_code.status_code == 400 and wrong_code.json()["code"] == "mfa_invalid_code"
    spoofed = enroll(client, headers, codes[0], color=SPOOF)
    assert spoofed.status_code == 400 and spoofed.json()["code"] == "face_liveness_failed"

    done = enroll(client, headers, codes[1])
    assert done.status_code == 200, done.text
    assert done.json()["enrolled"] is True and done.json()["consented_at"] is not None
    assert set(done.json()) == {"enrolled", "enrolled_at", "consented_at"}  # aucune photo de référence rendue
    assert client.get("/mfa", headers=headers).json()["face_enrolled"] is True
    assert login(client).json()["methods"] == ["totp", "face"]


def test_enroll_challenge_allows_a_few_attempts_then_closes(client):
    codes, headers = mfa_user(client)
    challenge = open_enrollment(client, headers, codes[0]).json()
    assert challenge["poses"][0] == "center" and len(challenge["poses"]) == 3 and challenge["expires_in"] == 120
    data = {"challenge_id": challenge["challenge_id"]}
    failures = [client.post("/mfa/face", headers=headers, data=data, files=frames(SPOOF)).json()["code"]
                for _ in range(3)]
    assert failures == ["face_liveness_failed"] * 3  # FACE_ENROLL_ATTEMPTS
    spent = client.post("/mfa/face", headers=headers, data=data, files=frames(ALICE))
    assert spent.status_code == 409 and spent.json()["code"] == "face_challenge_expired"

    data = {"challenge_id": open_enrollment(client, headers, codes[1]).json()["challenge_id"]}
    assert client.post("/mfa/face", headers=headers, data=data, files=frames(ALICE)).status_code == 200
    replay = client.post("/mfa/face", headers=headers, data=data, files=frames(ALICE))
    assert replay.status_code == 409 and replay.json()["code"] == "face_challenge_expired"


def test_enroll_code_is_checked_before_the_capture_and_counted(client, caplog):
    codes, headers = mfa_user(client)
    res = open_enrollment(client, headers, "000000")
    assert res.status_code == 400 and res.json()["code"] == "mfa_invalid_code"
    assert any(r.message == "mfa_failed" and getattr(r, "step", None) == "face_enroll" for r in caplog.records)
    assert open_enrollment(client, headers, codes[0]).status_code == 200
    reused = open_enrollment(client, headers, codes[0])
    assert reused.status_code == 400 and reused.json()["code"] == "mfa_invalid_code"


def test_login_with_face_carries_the_face_amr(client, rsa_keys):
    codes, headers = mfa_user(client)
    assert login(client).json()["methods"] == ["totp"]
    no_face = client.post("/login/mfa/face/challenge", json={"mfa_token": login(client).json()["mfa_token"]})
    assert no_face.status_code == 409 and no_face.json()["code"] == "face_not_enrolled"
    enroll(client, headers, codes[0])

    res, step, challenge = face_login(client, ALICE)
    assert challenge["poses"][0] == "center" and len(challenge["poses"]) == 2  # de face puis un seul côté
    assert res.status_code == 200, res.text
    claims = jwt.decode(res.json()["access_token"], rsa_keys[1], algorithms=["RS256"], audience="payment-api")
    assert claims["amr"] == ["pwd", "face"]
    # Étape consommée : ni un nouveau défi ni un code ne rouvrent de session avec le même jeton.
    again = client.post("/login/mfa/face/challenge", json={"mfa_token": step["mfa_token"]})
    assert again.status_code == 401 and again.json()["code"] == "mfa_challenge_expired"


def test_rejected_face_is_archived_for_the_admin_only(client, caplog):
    codes, headers = mfa_user(client)
    enroll(client, headers, codes[0])

    res, _, _ = face_login(client, BOB)
    assert res.status_code == 401 and res.json()["code"] == "face_no_match"
    spoof, _, _ = face_login(client, SPOOF)
    assert spoof.status_code == 401 and spoof.json()["code"] == "face_liveness_failed"
    assert client.get("/admin/face-captures", headers=headers).status_code == 403  # un client n'y a pas accès

    admin = admin_headers(client)
    captures = client.get("/admin/face-captures", headers=admin).json()
    assert [(c["email"], c["reason"]) for c in captures] == [("visage@test.local", "face_liveness_failed"),
                                                             ("visage@test.local", "face_no_match")]
    assert captures[1]["score"] == 0.0 and captures[0]["score"] is None
    caplog.clear()
    detail = client.get(f"/admin/face-captures/{captures[1]['id']}", headers=admin).json()
    decoded = face.decode_jpeg(base64.b64decode(detail["image"].split(",", 1)[1]))
    assert np.allclose(decoded[0, 0], BOB, atol=8)  # la capture de Bob, réencodée
    assert any(r.message == "face_capture_viewed" for r in caplog.records)  # consultation tracée


def test_login_side_cannot_be_redrawn_without_an_attempt(client):
    codes, headers = mfa_user(client)
    enroll(client, headers, codes[0])
    token = login(client).json()["mfa_token"]
    drawn = [client.post("/login/mfa/face/challenge", json={"mfa_token": token}).json() for _ in range(8)]
    assert len({tuple(c["poses"]) for c in drawn}) == 1  # même côté tant que le défi n'est pas tenté
    assert len({c["challenge_id"] for c in drawn}) == 8


def test_face_failures_count_and_burn_the_mfa_step(client):
    codes, headers = mfa_user(client)
    enroll(client, headers, codes[0])
    step = login(client).json()
    answers = []
    for _ in range(5):
        challenge = client.post("/login/mfa/face/challenge", json={"mfa_token": step["mfa_token"]}).json()
        data = {"mfa_token": step["mfa_token"], "challenge_id": challenge["challenge_id"]}
        answers.append(client.post("/login/mfa/face", data=data, files=frames(BOB, 2)).json()["code"])
    assert answers == ["face_no_match"] * 4 + ["mfa_challenge_expired"]
    late = client.post("/login/mfa/face/challenge", json={"mfa_token": step["mfa_token"]})
    assert late.status_code == 401


def test_face_is_removed_on_request_and_with_mfa(client):
    codes, headers = mfa_user(client)
    enroll(client, headers, codes[0])
    assert client.delete("/mfa/face", headers=headers).status_code == 204
    assert client.get("/mfa", headers=headers).json()["face_enrolled"] is False
    again = client.delete("/mfa/face", headers=headers)
    assert again.status_code == 409 and again.json()["code"] == "face_not_enrolled"

    enroll(client, headers, codes[1])
    assert client.post("/mfa/disable", headers=headers, json={"password": PASSWORD, "code": codes[2]}).status_code == 204
    assert client.get("/mfa/face", headers=headers).json()["enrolled"] is False


def test_wrong_number_of_frames_is_refused(client):
    codes, headers = mfa_user(client)
    challenge = open_enrollment(client, headers, codes[0]).json()
    data = {"challenge_id": challenge["challenge_id"]}
    res = client.post("/mfa/face", headers=headers, data=data, files=frames(ALICE, 2))
    assert res.status_code == 422 and res.json()["code"] == "face_invalid_image"
    too_many = client.post("/mfa/face", headers=headers, data=data, files=frames(ALICE, 4))
    assert too_many.status_code == 422 and too_many.json()["code"] == "face_invalid_image"

    enroll(client, headers, codes[1])
    step = login(client).json()
    challenge = client.post("/login/mfa/face/challenge", json={"mfa_token": step["mfa_token"]}).json()
    data = {"mfa_token": step["mfa_token"], "challenge_id": challenge["challenge_id"]}
    res = client.post("/login/mfa/face", data=data, files=frames(ALICE, 3))  # trois captures pour un défi à deux poses
    assert res.status_code == 422 and res.json()["code"] == "face_invalid_image"
