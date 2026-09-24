import os
import base64
import json
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_SIZE = 32
NONCE_SIZE = 12


class LocalKeyManager:

    def __init__(self, key_directory):

        self.key_directory = key_directory

        os.makedirs(
            self.key_directory,
            exist_ok=True
        )

        # Directory for versioned Master KEKs
        self.master_key_directory = os.path.join(
            self.key_directory,
            "master_keys"
        )

        os.makedirs(
            self.master_key_directory,
            exist_ok=True
        )

        # File that stores the current KEK version
        self.current_version_file = os.path.join(
            self.key_directory,
            "current_version.txt"
        )

        self._initialize_master_key()

    # =========================================================
    # INITIALIZE MASTER KEK
    # =========================================================

    def _initialize_master_key(self):

        # If current version already exists,
        # verify that the corresponding KEK exists.

        if os.path.exists(
            self.current_version_file
        ):

            with open(
                self.current_version_file,
                "r",
                encoding="utf-8"
            ) as file:

                version = int(
                    file.read().strip()
                )

            key_path = self._get_master_key_path(
                version
            )

            if not os.path.exists(
                key_path
            ):

                raise FileNotFoundError(
                    f"Master KEK version {version} "
                    "not found."
                )

            return

        # -----------------------------------------------------
        # Create first KEK
        # -----------------------------------------------------

        version = 1

        master_key = AESGCM.generate_key(
            bit_length=256
        )

        key_path = self._get_master_key_path(
            version
        )

        with open(
            key_path,
            "wb"
        ) as file:

            file.write(
                master_key
            )

        self._write_current_version(
            version
        )

    # =========================================================
    # MASTER KEK PATH
    # =========================================================

    def _get_master_key_path(
        self,
        version
    ):

        return os.path.join(
            self.master_key_directory,
            f"master_v{version}.key"
        )

    # =========================================================
    # WRITE CURRENT VERSION
    # =========================================================

    def _write_current_version(
        self,
        version
    ):

        temp_fd, temp_path = tempfile.mkstemp(
            dir=self.key_directory,
            prefix="version_",
            text=True
        )

        try:

            with os.fdopen(
                temp_fd,
                "w",
                encoding="utf-8"
            ) as file:

                file.write(
                    str(version)
                )

                file.flush()

                os.fsync(
                    file.fileno()
                )

            os.replace(
                temp_path,
                self.current_version_file
            )

        finally:

            if os.path.exists(
                temp_path
            ):

                os.remove(
                    temp_path
                )

    # =========================================================
    # GET CURRENT KEK VERSION
    # =========================================================

    def get_current_version(self):

        with open(
            self.current_version_file,
            "r",
            encoding="utf-8"
        ) as file:

            return int(
                file.read().strip()
            )

    # =========================================================
    # LOAD MASTER KEK
    # =========================================================

    def _load_master_key(
        self,
        version
    ):

        key_path = self._get_master_key_path(
            version
        )

        if not os.path.exists(
            key_path
        ):

            raise FileNotFoundError(
                f"Master KEK version {version} "
                "not found."
            )

        with open(
            key_path,
            "rb"
        ) as file:

            master_key = file.read()

        if len(master_key) != KEY_SIZE:

            raise ValueError(
                "Master KEK must be 256 bits."
            )

        return master_key

    # =========================================================
    # WRAP FILE DEK
    # =========================================================

    def _wrap_key(
        self,
        file_key,
        master_key
    ):

        nonce = os.urandom(
            NONCE_SIZE
        )

        aesgcm = AESGCM(
            master_key
        )

        wrapped_key = aesgcm.encrypt(
            nonce,
            file_key,
            None
        )

        return nonce, wrapped_key

    # =========================================================
    # UNWRAP FILE DEK
    # =========================================================

    def _unwrap_key(
        self,
        nonce,
        wrapped_key,
        master_key
    ):

        aesgcm = AESGCM(
            master_key
        )

        file_key = aesgcm.decrypt(
            nonce,
            wrapped_key,
            None
        )

        return file_key

    # =========================================================
    # SAVE FILE DEK
    # =========================================================

    def save_key(
        self,
        file_id,
        key
    ):

        # File DEK must be 256 bits
        if len(key) != KEY_SIZE:

            raise ValueError(
                "File encryption key must be 256 bits."
            )

        # Get current KEK version
        kek_version = self.get_current_version()

        # Load current Master KEK
        master_key = self._load_master_key(
            kek_version
        )

        # Wrap the File DEK
        nonce, wrapped_key = self._wrap_key(
            key,
            master_key
        )

        # File containing wrapped DEK
        key_path = os.path.join(
            self.key_directory,
            f"{file_id}.key"
        )

        # Metadata describing the wrapped DEK
        key_data = {

            "version": 2,

            "algorithm": "AES-256-GCM",

            "key_type": "wrapped_DEK",

            "kek_version": kek_version,

            "nonce": base64.b64encode(
                nonce
            ).decode("utf-8"),

            "wrapped_key": base64.b64encode(
                wrapped_key
            ).decode("utf-8")
        }

        # -----------------------------------------------------
        # Atomic write
        # -----------------------------------------------------

        temp_fd, temp_path = tempfile.mkstemp(
            dir=self.key_directory,
            prefix=f"{file_id}_",
            text=True
        )

        try:

            with os.fdopen(
                temp_fd,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    key_data,
                    file,
                    indent=4
                )

                file.flush()

                os.fsync(
                    file.fileno()
                )

            os.replace(
                temp_path,
                key_path
            )

        finally:

            if os.path.exists(
                temp_path
            ):

                os.remove(
                    temp_path
                )

        return key_path

    # =========================================================
    # LOAD FILE DEK
    # =========================================================

    def load_key(
        self,
        file_id
    ):

        key_path = os.path.join(
            self.key_directory,
            f"{file_id}.key"
        )

        if not os.path.exists(
            key_path
        ):

            raise FileNotFoundError(
                "Encryption key not found."
            )

        with open(
            key_path,
            "r",
            encoding="utf-8"
        ) as file:

            key_data = json.load(
                file
            )

        if key_data.get("version") != 2:

            raise ValueError(
                "Unsupported key format."
            )

        if key_data.get("key_type") != "wrapped_DEK":

            raise ValueError(
                "Invalid key type."
            )

        kek_version = key_data.get(
            "kek_version"
        )

        if kek_version is None:

            raise ValueError(
                "KEK version is missing."
            )

        # Load the KEK version that originally
        # wrapped this DEK.
        master_key = self._load_master_key(
            kek_version
        )

        nonce = base64.b64decode(
            key_data["nonce"]
        )

        wrapped_key = base64.b64decode(
            key_data["wrapped_key"]
        )

        file_key = self._unwrap_key(
            nonce,
            wrapped_key,
            master_key
        )

        if len(file_key) != KEY_SIZE:

            raise ValueError(
                "Recovered DEK is invalid."
            )

        return file_key

    # =========================================================
    # DELETE FILE DEK
    # =========================================================

    def delete_key(
        self,
        file_id
    ):

        key_path = os.path.join(
            self.key_directory,
            f"{file_id}.key"
        )

        if os.path.exists(
            key_path
        ):

            os.remove(
                key_path
            )

    # =========================================================
    # ROTATE MASTER KEK
    # =========================================================

    def rotate_master_key(self):

        old_version = self.get_current_version()

        old_master_key = self._load_master_key(
            old_version
        )

        new_version = old_version + 1

        new_master_key = AESGCM.generate_key(
            bit_length=256
        )

        new_master_key_path = (
            self._get_master_key_path(
                new_version
            )
        )

        # -----------------------------------------------------
        # Save new KEK
        # -----------------------------------------------------

        with open(
            new_master_key_path,
            "wb"
        ) as file:

            file.write(
                new_master_key
            )

            file.flush()

            os.fsync(
                file.fileno()
            )

        processed = 0

        try:

            # -------------------------------------------------
            # Find all wrapped DEKs
            # -------------------------------------------------

            for filename in os.listdir(
                self.key_directory
            ):

                if not filename.endswith(
                    ".key"
                ):

                    continue

                # Ignore old legacy master.key
                if filename == "master.key":

                    continue

                key_path = os.path.join(
                    self.key_directory,
                    filename
                )

                # Read wrapped DEK metadata
                try:

                    with open(
                        key_path,
                        "r",
                        encoding="utf-8"
                    ) as file:

                        key_data = json.load(
                            file
                        )

                except (
                    json.JSONDecodeError,
                    UnicodeDecodeError
                ):

                    continue

                if key_data.get(
                    "key_type"
                ) != "wrapped_DEK":

                    continue

                current_kek_version = (
                    key_data.get(
                        "kek_version"
                    )
                )

                # Only rewrap DEKs using old KEK
                if current_kek_version != old_version:

                    continue

                nonce = base64.b64decode(
                    key_data["nonce"]
                )

                wrapped_key = base64.b64decode(
                    key_data["wrapped_key"]
                )

                # ---------------------------------------------
                # Recover DEK using old KEK
                # ---------------------------------------------

                file_key = self._unwrap_key(
                    nonce,
                    wrapped_key,
                    old_master_key
                )

                # ---------------------------------------------
                # Wrap DEK using new KEK
                # ---------------------------------------------

                new_nonce, new_wrapped_key = (
                    self._wrap_key(
                        file_key,
                        new_master_key
                    )
                )

                new_key_data = {

                    "version": 2,

                    "algorithm": "AES-256-GCM",

                    "key_type": "wrapped_DEK",

                    "kek_version": new_version,

                    "nonce": base64.b64encode(
                        new_nonce
                    ).decode("utf-8"),

                    "wrapped_key": base64.b64encode(
                        new_wrapped_key
                    ).decode("utf-8")
                }

                # ---------------------------------------------
                # Atomic replacement
                # ---------------------------------------------

                temp_fd, temp_path = tempfile.mkstemp(
                    dir=self.key_directory,
                    prefix=f"{filename}_rotation_",
                    text=True
                )

                try:

                    with os.fdopen(
                        temp_fd,
                        "w",
                        encoding="utf-8"
                    ) as file:

                        json.dump(
                            new_key_data,
                            file,
                            indent=4
                        )

                        file.flush()

                        os.fsync(
                            file.fileno()
                        )

                    os.replace(
                        temp_path,
                        key_path
                    )

                finally:

                    if os.path.exists(
                        temp_path
                    ):

                        os.remove(
                            temp_path
                        )

                processed += 1

            # -------------------------------------------------
            # Make new KEK current
            # -------------------------------------------------

            self._write_current_version(
                new_version
            )

        except Exception:

            # Rotation failed.
            # Keep old KEK available.

            if os.path.exists(
                new_master_key_path
            ):

                os.remove(
                    new_master_key_path
                )

            raise

        return {

            "old_version": old_version,

            "new_version": new_version,

            "keys_rewrapped": processed
        }