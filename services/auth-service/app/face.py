"""Reconnaissance faciale, second facteur au choix du TOTP : détection (YuNet), empreinte (SFace), défi de pose
contre les photos, chiffrement des données biométriques (AES-256-GCM).

Modèles ONNX d'OpenCV Zoo, embarqués dans l'image (Dockerfile, empreintes SHA-256 vérifiées au build), exécutés sur CPU.
"""

import base64
import os
import secrets
import threading
from dataclasses import dataclass

# Plafond de pixels du décodeur, posé avant l'import : une image de 400 Ko peut annoncer 65535 × 65535 pixels
# (bombe de décompression). 4 Mpx couvrent largement les captures 640 × 480 du navigateur.
os.environ.setdefault("OPENCV_IO_MAX_IMAGE_PIXELS", str(4_000_000))

import cv2  # noqa: E402
import numpy as np  # noqa: E402
from cryptography.exceptions import InvalidTag  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

DETECTOR_MODEL = "face_detection_yunet_2023mar.onnx"
RECOGNIZER_MODEL = "face_recognition_sface_2021dec.onnx"

# Une capture par pose : de face d'abord (comparée à la référence), puis les profils tirés au hasard : les deux, dans un
# ordre aléatoire, à l'enregistrement ; un seul à la connexion (il suffit à la détection du vivant, voir check_liveness).
TURNS = ("left", "right")
MAX_POSES = 1 + len(TURNS)
MAX_FRAME_BYTES = 400_000
MIN_FACE_PX = 80
DETECTION_SCORE = 0.8
STORED_IMAGE_SIDE = 480

# Seuils réglables par variable d'environnement (journal face_liveness en DEBUG pour les calibrer) :
# - similarité cosinus SFace avec la référence : 0,363 est le seuil recommandé par OpenCV ;
# - entre la capture de face et les profils, plus bas (le visage tourné ressemble moins à lui-même de face) ;
# - lacet = décalage horizontal du nez par rapport au milieu des yeux, rapporté à l'écart des yeux : la capture de face
#   doit rester sous YAW_CENTER_MAX, chaque profil s'en écarter d'au moins YAW_TURN_MIN dans le sens demandé ;
# - parallaxe = écart du nez à la position que prédit le plan yeux-bouche (voir parallax), rapporté à l'écart des yeux.
MATCH_THRESHOLD = float(os.getenv("FACE_MATCH_THRESHOLD", "0.363"))
POSE_MATCH_THRESHOLD = float(os.getenv("FACE_POSE_MATCH_THRESHOLD", "0.30"))
YAW_CENTER_MAX = float(os.getenv("FACE_YAW_CENTER_MAX", "0.20"))
YAW_TURN_MIN = float(os.getenv("FACE_YAW_TURN_MIN", "0.15"))
PARALLAX_MIN = float(os.getenv("FACE_PARALLAX_MIN", "0.05"))

_VAULT_VERSION = b"\x01"


class FaceError(Exception):
    def __init__(self, code: str, detail: str, frame: bytes | None = None):
        # Cette méthode permet de porter un refus de la vérification faciale (code stable lu par le front),
        # avec la capture concernée lorsqu'elle a pu être décodée, pour l'archiver à l'usage du SOC.
        super().__init__(detail)
        self.code, self.detail, self.frame = code, detail, frame


@dataclass
class Face:
    embedding: np.ndarray
    landmarks: np.ndarray  # 5 × 2 : œil droit, œil gauche, nez, coin droit et coin gauche de la bouche (repères YuNet)

    @property
    def yaw(self) -> float:
        # Cette méthode permet d'exposer la rotation estimée de la tête sur cette capture.
        return estimate_yaw(self.landmarks)


def new_poses(purpose: str) -> list[str]:
    # Cette méthode permet de tirer la suite de poses du défi : de face, puis gauche et droite dans un ordre aléatoire
    # à l'enregistrement (« enroll »), ou un seul côté tiré au hasard à la connexion (« login »).
    turns = 1 if purpose == "login" else len(TURNS)
    return ["center", *secrets.SystemRandom().sample(TURNS, turns)]


def turn_sign(pose: str) -> int:
    # Cette méthode permet de donner le sens attendu du lacet pour une consigne : +1 tête à gauche, -1 à droite, 0 de face.
    return {"left": 1, "right": -1}.get(pose, 0)


def eye_gap(landmarks: np.ndarray) -> float:
    # Cette méthode permet de mesurer l'écart horizontal des yeux, unité commune des mesures de pose (indépendante du zoom).
    return max(abs(float(landmarks[1][0] - landmarks[0][0])), 1.0)


def estimate_yaw(landmarks: np.ndarray) -> float:
    # Cette méthode permet d'estimer la rotation de la tête à partir des repères YuNet (œil droit, œil gauche, nez) :
    # positif quand la personne tourne la tête vers sa gauche (vers la droite de l'image non inversée), ~0 de face.
    right_eye, left_eye, nose = landmarks[0], landmarks[1], landmarks[2]
    return float(nose[0] - (right_eye[0] + left_eye[0]) / 2) / eye_gap(landmarks)


def parallax(front: np.ndarray, turned: np.ndarray) -> float:
    # Cette méthode permet de distinguer une tête en relief d'une photo inclinée : les yeux et les coins de la bouche
    # (quasi plans) donnent l'homographie entre les deux captures, qui prédit exactement le nez d'une image plate ;
    # le nez d'une vraie tête, en avant de ce plan, s'en écarte dans le sens de la rotation (écart signé, en écarts d'yeux).
    plane = [0, 1, 3, 4]
    homography = cv2.getPerspectiveTransform(np.float32(front[plane]), np.float32(turned[plane]))
    predicted = cv2.perspectiveTransform(np.float32(front[2]).reshape(1, 1, 2), homography)[0][0]
    return float(turned[2][0] - predicted[0]) / eye_gap(turned)


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    # Cette méthode permet de mesurer la similarité de deux empreintes faciales (1 = identiques).
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-9))


def decode_jpeg(frame: bytes) -> np.ndarray | None:
    # Cette méthode permet de décoder une capture JPEG d'au plus 400 Ko ; renvoie None pour tout autre contenu.
    if len(frame) > MAX_FRAME_BYTES or not frame.startswith(b"\xff\xd8\xff"):
        return None
    return cv2.imdecode(np.frombuffer(frame, dtype=np.uint8), cv2.IMREAD_COLOR)


def encode_jpeg(image: np.ndarray) -> bytes:
    # Cette méthode permet de réencoder une capture en JPEG réduit (480 px au plus), sans les métadonnées d'origine (EXIF).
    height, width = image.shape[:2]
    scale = STORED_IMAGE_SIDE / max(height, width)
    if scale < 1:
        image = cv2.resize(image, (round(width * scale), round(height * scale)), interpolation=cv2.INTER_AREA)
    ok, buffer = cv2.imencode(".jpg", image, [cv2.IMWRITE_JPEG_QUALITY, 85])
    if not ok:
        raise FaceError("face_invalid_image", "Image illisible.")
    return buffer.tobytes()


def jpeg_data_uri(jpeg: bytes) -> str:
    # Cette méthode permet de rendre une image JPEG affichable par le front (data URI, autorisée par la CSP img-src).
    return "data:image/jpeg;base64," + base64.b64encode(jpeg).decode()


def embedding_bytes(embedding: np.ndarray) -> bytes:
    # Cette méthode permet de sérialiser une empreinte (128 flottants 32 bits, petit-boutiste) avant chiffrement.
    return np.asarray(embedding, dtype="<f4").tobytes()


def embedding_from_bytes(raw: bytes) -> np.ndarray:
    # Cette méthode permet de relire une empreinte sérialisée par embedding_bytes.
    return np.frombuffer(raw, dtype="<f4")


class FaceEngine:
    def __init__(self, models_dir: str):
        # Cette méthode permet de charger les deux modèles ONNX ; ils ne sont pas sûrs en accès concurrent,
        # d'où un verrou (≈ 30 ms par capture sur CPU, deux ou trois captures par vérification).
        cv2.setNumThreads(2)
        self._detector = cv2.FaceDetectorYN.create(os.path.join(models_dir, DETECTOR_MODEL), "", (320, 320),
                                                   DETECTION_SCORE, 0.3, 5000)
        self._recognizer = cv2.FaceRecognizerSF.create(os.path.join(models_dir, RECOGNIZER_MODEL), "")
        self._lock = threading.Lock()

    def analyze(self, frame: bytes) -> Face:
        # Cette méthode permet d'extraire d'une capture JPEG l'unique visage présent : empreinte et repères ;
        # refuse une image illisible, sans visage, avec plusieurs visages ou un visage trop petit (trop loin).
        image = decode_jpeg(frame)
        if image is None:
            raise FaceError("face_invalid_image", "Image refusée : JPEG de 400 Ko au plus attendu.")
        height, width = image.shape[:2]
        with self._lock:
            self._detector.setInputSize((width, height))
            _, detected = self._detector.detect(image)
            faces = [] if detected is None else [f for f in detected if f[2] >= MIN_FACE_PX and f[3] >= MIN_FACE_PX]
            if not faces:
                raise FaceError("face_not_detected", "Aucun visage détecté : rapprochez-vous et éclairez votre visage.", frame)
            if len(faces) > 1:
                raise FaceError("face_multiple", "Plusieurs visages détectés : une seule personne doit être face à la caméra.",
                                frame)
            aligned = self._recognizer.alignCrop(image, faces[0])
            embedding = self._recognizer.feature(aligned).flatten().astype(np.float32)
        landmarks = np.asarray(faces[0][4:14], dtype=np.float32).reshape(5, 2)
        return Face(embedding=embedding, landmarks=landmarks)

    def check_liveness(self, frames: list[bytes], poses: list[str]) -> tuple[list[Face], list[dict]]:
        # Cette méthode permet de vérifier le défi de pose (de face, puis les profils dans l'ordre tiré) : bonne orientation,
        # relief du visage (parallaxe du nez, qu'une photo inclinée ne produit pas) et même personne sur toutes les captures ;
        # renvoie aussi les mesures de chaque profil, journalisées pour calibrer les seuils.
        if len(frames) != len(poses) or poses[0] != "center":
            raise FaceError("face_invalid_image", f"{len(poses)} captures attendues.")
        faces = [self.analyze(frame) for frame in frames]
        front = faces[0]
        if abs(front.yaw) > YAW_CENTER_MAX:
            raise FaceError("face_liveness_failed", "Regardez droit vers la caméra pour la première capture.", frames[0])
        measures = []
        for face, pose, frame in zip(faces[1:], poses[1:], frames[1:]):
            sign = turn_sign(pose)
            measure = {"pose": pose, "turn": round(sign * (face.yaw - front.yaw), 3),
                       "parallax": round(sign * parallax(front.landmarks, face.landmarks), 3),
                       "similarity": round(cosine(face.embedding, front.embedding), 3)}
            measures.append(measure)
            if measure["turn"] < YAW_TURN_MIN:
                raise FaceError("face_liveness_failed", "Mouvement non reconnu : tournez franchement la tête comme indiqué.",
                                frame)
            if measure["parallax"] < PARALLAX_MIN:
                raise FaceError("face_liveness_failed", "Relief du visage non reconnu : présentez votre propre visage.", frame)
            if measure["similarity"] < POSE_MATCH_THRESHOLD:
                raise FaceError("face_liveness_failed", "Le visage a changé pendant la vérification.", frame)
        return faces, measures


class FaceVault:
    def __init__(self, key_b64: str):
        # Cette méthode permet de charger la clé AES-256 des données biométriques (secret face_encryption_key, base64).
        key = base64.b64decode(key_b64)
        if len(key) != 32:
            raise RuntimeError("FACE_ENCRYPTION_KEY doit faire 32 octets encodés en base64 (scripts/init_secrets.py)")
        self._aead = AESGCM(key)

    def seal(self, data: bytes, context: str) -> bytes:
        # Cette méthode permet de chiffrer une empreinte ou une capture ; le contexte (utilisateur, usage) est authentifié,
        # si bien qu'un chiffré recopié sur une autre ligne ou un autre compte devient indéchiffrable.
        nonce = os.urandom(12)
        return _VAULT_VERSION + nonce + self._aead.encrypt(nonce, data, context.encode())

    def open(self, blob: bytes, context: str) -> bytes:
        # Cette méthode permet de déchiffrer une donnée scellée par seal avec le même contexte.
        blob = bytes(blob)
        if not blob.startswith(_VAULT_VERSION):
            raise ValueError("format de chiffré inconnu")
        try:
            return self._aead.decrypt(blob[1:13], blob[13:], context.encode())
        except InvalidTag as exc:
            raise ValueError("chiffré altéré ou contexte différent") from exc
