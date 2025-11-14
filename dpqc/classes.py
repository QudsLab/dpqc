import json
import ctypes
import platform
import hashlib
import urllib.request
from pathlib import Path


class InitializePQC:
    """Base class for PQC library initialization"""
    
    _instance = None
    _library = None
    _cache_dir = None
    
    def __new__(cls, bin_dir=None):
        """Singleton pattern to load library only once"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, bin_dir=None):
        """Initialize PQC library loader"""
        if self._library is not None:
            return  # Already initialized
        
        self.__source_url = "https://github.com/QudsLab/PQChub/raw/refs/heads/main/bins/binaries.json"
        
        # Determine cache directory
        if bin_dir:
            self._cache_dir = Path(bin_dir)
        elif self._cache_dir is None:
            self._cache_dir = self._get_cache_dir()
        
        # Detect platform and load metadata
        success, platform_key = self._detect_platform()
        if not success:
            raise RuntimeError(f"Unsupported platform: {platform.system()} {platform.machine()}")
        
        self.__platform = platform_key
        self._load_metadata()
        
        # Download and verify binary
        binary_path = self._ensure_binary()
        
        # Load the library (only once)
        self._library = ctypes.CDLL(str(binary_path))
    
    def _get_cache_dir(self):
        """Get cache directory, trying home first, then current dir"""
        try:
            home_cache = Path.home() / ".cache" / "pqc"
            home_cache.mkdir(parents=True, exist_ok=True)
            test_file = home_cache / ".test"
            test_file.touch()
            test_file.unlink()
            return home_cache
        except (OSError, PermissionError):
            return Path(__file__).parent / ".cache" / "pqc"
    
    def _detect_platform(self):
        """Detect current platform and return platform key"""
        system = platform.system().lower()
        machine = platform.machine().lower()

        arch_map = {
            "x86_64": "x86_64", "amd64": "x86_64",
            "x64": "x86_64", "i386": "x86", "i686": "x86",
            "x86": "x86", "aarch64": "aarch64", "arm64": "aarch64",
            "armv7l": "armeabi-v7a", "armv8l": "arm64-v8a",
        }
        arch = arch_map.get(machine, machine)

        maps = {
            "windows": {
                "x86_64": "windows-x64",
                "x86": "windows-x86"
            },
            "darwin": {
                "aarch64": "macos-arm64",
                "x86_64": "macos-x86_64"
            },
            "linux": {
                "aarch64": "linux-aarch64",
                "x86_64": "linux-x86_64"
            }
        }

        key = maps.get(system, {}).get(arch)
        return (True, key) if key else (False, None)
    
    def _load_metadata(self):
        """Load binary metadata from remote JSON"""
        try:
            with urllib.request.urlopen(self.__source_url) as response:
                metadata = json.loads(response.read().decode('utf-8'))
            
            if self.__platform not in metadata['binaries']:
                raise RuntimeError(f"No binary available for platform: {self.__platform}")
            
            binary_info = metadata['binaries'][self.__platform]
            self.__filename = binary_info['filename']
            self.__size = binary_info['size']
            self.__url = binary_info['url']
            self.__md5 = binary_info['checksums']['md5']
            self.__sha256 = binary_info['checksums']['sha256']
            self.__sha512 = binary_info['checksums']['sha512']
        except Exception as e:
            raise RuntimeError(f"Failed to load metadata: {e}")
    
    def _verify_checksum(self, file_path):
        """Verify file checksums"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            md5_hash = hashlib.md5(data).hexdigest()
            sha256_hash = hashlib.sha256(data).hexdigest()
            
            if md5_hash != self.__md5:
                return False, f"MD5 mismatch"
            
            if sha256_hash != self.__sha256:
                return False, f"SHA256 mismatch"
            
            return True, "Checksum verified"
        except Exception as e:
            return False, str(e)
    
    def _download_binary(self, dest_path):
        """Download binary file"""
        try:
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            urllib.request.urlretrieve(self.__url, dest_path)
            return True, "Download successful"
        except Exception as e:
            return False, f"Download failed: {e}"
    
    def _ensure_binary(self):
        """Ensure binary exists and is verified, download if needed"""
        binary_path = self._cache_dir / self.__platform / self.__filename
        
        if binary_path.exists():
            verified, msg = self._verify_checksum(binary_path)
            if verified:
                return binary_path
            else:
                binary_path.unlink()
        
        success, msg = self._download_binary(binary_path)
        if not success:
            raise RuntimeError(msg)
        
        verified, msg = self._verify_checksum(binary_path)
        if not verified:
            binary_path.unlink()
            raise RuntimeError(f"Downloaded binary verification failed: {msg}")
        
        return binary_path
    
    @property
    def lib(self):
        """Get the loaded ctypes library"""
        return self._library


class MLKEM512(InitializePQC):
    PUBLICKEY_BYTES = 800
    SECRETKEY_BYTES = 1632
    CIPHERTEXT_BYTES = 768
    SHAREDSECRET_BYTES = 32
    
    def __init__(self, bin_dir=None):
        super().__init__(bin_dir)
        self.lib.PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair.restype = ctypes.c_int
        self.lib.PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc.restype = ctypes.c_int
        self.lib.PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec.restype = ctypes.c_int
    
    def keypair(self):
        pk = ctypes.create_string_buffer(self.PUBLICKEY_BYTES)
        sk = ctypes.create_string_buffer(self.SECRETKEY_BYTES)
        if self.lib.PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(
                ctypes.cast(pk, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(sk, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Keypair failed")
        return bytes(pk), bytes(sk)
    
    def encapsulate(self, pk):
        ct = ctypes.create_string_buffer(self.CIPHERTEXT_BYTES)
        ss = ctypes.create_string_buffer(self.SHAREDSECRET_BYTES)
        pk_buf = ctypes.create_string_buffer(pk)
        if self.lib.PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(
                ctypes.cast(ct, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(ss, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(pk_buf, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Encapsulation failed")
        return bytes(ct), bytes(ss)
    
    def decapsulate(self, ct, sk):
        ss = ctypes.create_string_buffer(self.SHAREDSECRET_BYTES)
        ct_buf = ctypes.create_string_buffer(ct)
        sk_buf = ctypes.create_string_buffer(sk)
        if self.lib.PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(
                ctypes.cast(ss, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(ct_buf, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(sk_buf, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Decapsulation failed")
        return bytes(ss)


class MLKEM768(InitializePQC):
    PUBLICKEY_BYTES = 1184
    SECRETKEY_BYTES = 2400
    CIPHERTEXT_BYTES = 1088
    SHAREDSECRET_BYTES = 32
    
    def __init__(self, bin_dir=None):
        super().__init__(bin_dir)
        self.lib.PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair.restype = ctypes.c_int
        self.lib.PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc.restype = ctypes.c_int
        self.lib.PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec.restype = ctypes.c_int
    
    def keypair(self):
        pk = ctypes.create_string_buffer(self.PUBLICKEY_BYTES)
        sk = ctypes.create_string_buffer(self.SECRETKEY_BYTES)
        if self.lib.PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(
                ctypes.cast(pk, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(sk, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Keypair failed")
        return bytes(pk), bytes(sk)
    
    def encapsulate(self, pk):
        ct = ctypes.create_string_buffer(self.CIPHERTEXT_BYTES)
        ss = ctypes.create_string_buffer(self.SHAREDSECRET_BYTES)
        pk_buf = ctypes.create_string_buffer(pk)
        if self.lib.PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(
                ctypes.cast(ct, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(ss, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(pk_buf, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Encapsulation failed")
        return bytes(ct), bytes(ss)
    
    def decapsulate(self, ct, sk):
        ss = ctypes.create_string_buffer(self.SHAREDSECRET_BYTES)
        ct_buf = ctypes.create_string_buffer(ct)
        sk_buf = ctypes.create_string_buffer(sk)
        if self.lib.PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(
                ctypes.cast(ss, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(ct_buf, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(sk_buf, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Decapsulation failed")
        return bytes(ss)


class MLKEM1024(InitializePQC):
    PUBLICKEY_BYTES = 1568
    SECRETKEY_BYTES = 3168
    CIPHERTEXT_BYTES = 1568
    SHAREDSECRET_BYTES = 32
    
    def __init__(self, bin_dir=None):
        super().__init__(bin_dir)
        self.lib.PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair.restype = ctypes.c_int
        self.lib.PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc.restype = ctypes.c_int
        self.lib.PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec.restype = ctypes.c_int
    
    def keypair(self):
        pk = ctypes.create_string_buffer(self.PUBLICKEY_BYTES)
        sk = ctypes.create_string_buffer(self.SECRETKEY_BYTES)
        if self.lib.PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(
                ctypes.cast(pk, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(sk, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Keypair failed")
        return bytes(pk), bytes(sk)
    
    def encapsulate(self, pk):
        ct = ctypes.create_string_buffer(self.CIPHERTEXT_BYTES)
        ss = ctypes.create_string_buffer(self.SHAREDSECRET_BYTES)
        pk_buf = ctypes.create_string_buffer(pk)
        if self.lib.PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(
                ctypes.cast(ct, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(ss, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(pk_buf, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Encapsulation failed")
        return bytes(ct), bytes(ss)
    
    def decapsulate(self, ct, sk):
        ss = ctypes.create_string_buffer(self.SHAREDSECRET_BYTES)
        ct_buf = ctypes.create_string_buffer(ct)
        sk_buf = ctypes.create_string_buffer(sk)
        if self.lib.PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(
                ctypes.cast(ss, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(ct_buf, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(sk_buf, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Decapsulation failed")
        return bytes(ss)


class MLDSA44(InitializePQC):
    PUBLICKEY_BYTES = 1312
    SECRETKEY_BYTES = 2560
    SIGNATURE_BYTES = 2420
    
    def __init__(self, bin_dir=None):
        super().__init__(bin_dir)
        self.lib.PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair.restype = ctypes.c_int
        self.lib.PQCLEAN_MLDSA44_CLEAN_crypto_sign.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ulonglong), 
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong, ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_MLDSA44_CLEAN_crypto_sign.restype = ctypes.c_int
        self.lib.PQCLEAN_MLDSA44_CLEAN_crypto_sign_open.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ulonglong), 
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong, ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_MLDSA44_CLEAN_crypto_sign_open.restype = ctypes.c_int
    
    def keypair(self):
        pk = ctypes.create_string_buffer(self.PUBLICKEY_BYTES)
        sk = ctypes.create_string_buffer(self.SECRETKEY_BYTES)
        if self.lib.PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(
                ctypes.cast(pk, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(sk, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Keypair failed")
        return bytes(pk), bytes(sk)
    
    def sign(self, message, sk):
        sm = ctypes.create_string_buffer(len(message) + self.SIGNATURE_BYTES)
        smlen = ctypes.c_ulonglong()
        msg_buf = ctypes.create_string_buffer(message)
        sk_buf = ctypes.create_string_buffer(sk)
        if self.lib.PQCLEAN_MLDSA44_CLEAN_crypto_sign(
                ctypes.cast(sm, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.byref(smlen), 
                ctypes.cast(msg_buf, ctypes.POINTER(ctypes.c_ubyte)), 
                len(message), 
                ctypes.cast(sk_buf, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Signing failed")
        return bytes(sm[:smlen.value])
    
    def verify(self, signed_message, pk):
        m = ctypes.create_string_buffer(len(signed_message))
        mlen = ctypes.c_ulonglong()
        sm_buf = ctypes.create_string_buffer(signed_message)
        pk_buf = ctypes.create_string_buffer(pk)
        if self.lib.PQCLEAN_MLDSA44_CLEAN_crypto_sign_open(
                ctypes.cast(m, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.byref(mlen), 
                ctypes.cast(sm_buf, ctypes.POINTER(ctypes.c_ubyte)), 
                len(signed_message), 
                ctypes.cast(pk_buf, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Verification failed")
        return bytes(m[:mlen.value])


class MLDSA65(InitializePQC):
    PUBLICKEY_BYTES = 1952
    SECRETKEY_BYTES = 4032
    SIGNATURE_BYTES = 3309
    
    def __init__(self, bin_dir=None):
        super().__init__(bin_dir)
        self.lib.PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair.restype = ctypes.c_int
        self.lib.PQCLEAN_MLDSA65_CLEAN_crypto_sign.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ulonglong), 
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong, ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_MLDSA65_CLEAN_crypto_sign.restype = ctypes.c_int
        self.lib.PQCLEAN_MLDSA65_CLEAN_crypto_sign_open.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ulonglong), 
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong, ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_MLDSA65_CLEAN_crypto_sign_open.restype = ctypes.c_int
    
    def keypair(self):
        pk = ctypes.create_string_buffer(self.PUBLICKEY_BYTES)
        sk = ctypes.create_string_buffer(self.SECRETKEY_BYTES)
        if self.lib.PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(
                ctypes.cast(pk, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(sk, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Keypair failed")
        return bytes(pk), bytes(sk)
    
    def sign(self, message, sk):
        sm = ctypes.create_string_buffer(len(message) + self.SIGNATURE_BYTES)
        smlen = ctypes.c_ulonglong()
        msg_buf = ctypes.create_string_buffer(message)
        sk_buf = ctypes.create_string_buffer(sk)
        if self.lib.PQCLEAN_MLDSA65_CLEAN_crypto_sign(
                ctypes.cast(sm, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.byref(smlen), 
                ctypes.cast(msg_buf, ctypes.POINTER(ctypes.c_ubyte)), 
                len(message), 
                ctypes.cast(sk_buf, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Signing failed")
        return bytes(sm[:smlen.value])
    
    def verify(self, signed_message, pk):
        m = ctypes.create_string_buffer(len(signed_message))
        mlen = ctypes.c_ulonglong()
        sm_buf = ctypes.create_string_buffer(signed_message)
        pk_buf = ctypes.create_string_buffer(pk)
        if self.lib.PQCLEAN_MLDSA65_CLEAN_crypto_sign_open(
                ctypes.cast(m, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.byref(mlen), 
                ctypes.cast(sm_buf, ctypes.POINTER(ctypes.c_ubyte)), 
                len(signed_message), 
                ctypes.cast(pk_buf, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Verification failed")
        return bytes(m[:mlen.value])


class MLDSA87(InitializePQC):
    PUBLICKEY_BYTES = 2592
    SECRETKEY_BYTES = 4896
    SIGNATURE_BYTES = 4627
    
    def __init__(self, bin_dir=None):
        super().__init__(bin_dir)
        self.lib.PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair.restype = ctypes.c_int
        self.lib.PQCLEAN_MLDSA87_CLEAN_crypto_sign.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ulonglong), 
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong, ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_MLDSA87_CLEAN_crypto_sign.restype = ctypes.c_int
        self.lib.PQCLEAN_MLDSA87_CLEAN_crypto_sign_open.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ulonglong), 
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong, ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_MLDSA87_CLEAN_crypto_sign_open.restype = ctypes.c_int
    
    def keypair(self):
        pk = ctypes.create_string_buffer(self.PUBLICKEY_BYTES)
        sk = ctypes.create_string_buffer(self.SECRETKEY_BYTES)
        if self.lib.PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(
                ctypes.cast(pk, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(sk, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Keypair failed")
        return bytes(pk), bytes(sk)
    
    def sign(self, message, sk):
        sm = ctypes.create_string_buffer(len(message) + self.SIGNATURE_BYTES)
        smlen = ctypes.c_ulonglong()
        msg_buf = ctypes.create_string_buffer(message)
        sk_buf = ctypes.create_string_buffer(sk)
        if self.lib.PQCLEAN_MLDSA87_CLEAN_crypto_sign(
                ctypes.cast(sm, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.byref(smlen), 
                ctypes.cast(msg_buf, ctypes.POINTER(ctypes.c_ubyte)), 
                len(message), 
                ctypes.cast(sk_buf, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Signing failed")
        return bytes(sm[:smlen.value])
    
    def verify(self, signed_message, pk):
        m = ctypes.create_string_buffer(len(signed_message))
        mlen = ctypes.c_ulonglong()
        sm_buf = ctypes.create_string_buffer(signed_message)
        pk_buf = ctypes.create_string_buffer(pk)
        if self.lib.PQCLEAN_MLDSA87_CLEAN_crypto_sign_open(
                ctypes.cast(m, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.byref(mlen), 
                ctypes.cast(sm_buf, ctypes.POINTER(ctypes.c_ubyte)), 
                len(signed_message), 
                ctypes.cast(pk_buf, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Verification failed")
        return bytes(m[:mlen.value])


class Falcon512(InitializePQC):
    PUBLICKEY_BYTES = 897
    SECRETKEY_BYTES = 1281
    SIGNATURE_BYTES = 752
    
    def __init__(self, bin_dir=None):
        super().__init__(bin_dir)
        self.lib.PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair.restype = ctypes.c_int
        self.lib.PQCLEAN_FALCON512_CLEAN_crypto_sign.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ulonglong), 
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong, ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_FALCON512_CLEAN_crypto_sign.restype = ctypes.c_int
        self.lib.PQCLEAN_FALCON512_CLEAN_crypto_sign_open.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ulonglong), 
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong, ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_FALCON512_CLEAN_crypto_sign_open.restype = ctypes.c_int
    
    def keypair(self):
        pk = ctypes.create_string_buffer(self.PUBLICKEY_BYTES)
        sk = ctypes.create_string_buffer(self.SECRETKEY_BYTES)
        if self.lib.PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(
                ctypes.cast(pk, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(sk, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Keypair failed")
        return bytes(pk), bytes(sk)
    
    def sign(self, message, sk):
        sm = ctypes.create_string_buffer(len(message) + self.SIGNATURE_BYTES)
        smlen = ctypes.c_ulonglong()
        msg_buf = ctypes.create_string_buffer(message)
        sk_buf = ctypes.create_string_buffer(sk)
        if self.lib.PQCLEAN_FALCON512_CLEAN_crypto_sign(
                ctypes.cast(sm, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.byref(smlen), 
                ctypes.cast(msg_buf, ctypes.POINTER(ctypes.c_ubyte)), 
                len(message), 
                ctypes.cast(sk_buf, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Signing failed")
        return bytes(sm[:smlen.value])
    
    def verify(self, signed_message, pk):
        m = ctypes.create_string_buffer(len(signed_message))
        mlen = ctypes.c_ulonglong()
        sm_buf = ctypes.create_string_buffer(signed_message)
        pk_buf = ctypes.create_string_buffer(pk)
        if self.lib.PQCLEAN_FALCON512_CLEAN_crypto_sign_open(
                ctypes.cast(m, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.byref(mlen), 
                ctypes.cast(sm_buf, ctypes.POINTER(ctypes.c_ubyte)), 
                len(signed_message), 
                ctypes.cast(pk_buf, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Verification failed")
        return bytes(m[:mlen.value])


class Falcon1024(InitializePQC):
    PUBLICKEY_BYTES = 1793
    SECRETKEY_BYTES = 2305
    SIGNATURE_BYTES = 1462
    
    def __init__(self, bin_dir=None):
        super().__init__(bin_dir)
        self.lib.PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair.restype = ctypes.c_int
        self.lib.PQCLEAN_FALCON1024_CLEAN_crypto_sign.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ulonglong), 
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong, ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_FALCON1024_CLEAN_crypto_sign.restype = ctypes.c_int
        self.lib.PQCLEAN_FALCON1024_CLEAN_crypto_sign_open.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ulonglong), 
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong, ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.PQCLEAN_FALCON1024_CLEAN_crypto_sign_open.restype = ctypes.c_int
    
    def keypair(self):
        pk = ctypes.create_string_buffer(self.PUBLICKEY_BYTES)
        sk = ctypes.create_string_buffer(self.SECRETKEY_BYTES)
        if self.lib.PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(
                ctypes.cast(pk, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.cast(sk, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Keypair failed")
        return bytes(pk), bytes(sk)
    
    def sign(self, message, sk):
        sm = ctypes.create_string_buffer(len(message) + self.SIGNATURE_BYTES)
        smlen = ctypes.c_ulonglong()
        msg_buf = ctypes.create_string_buffer(message)
        sk_buf = ctypes.create_string_buffer(sk)
        if self.lib.PQCLEAN_FALCON1024_CLEAN_crypto_sign(
                ctypes.cast(sm, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.byref(smlen), 
                ctypes.cast(msg_buf, ctypes.POINTER(ctypes.c_ubyte)), 
                len(message), 
                ctypes.cast(sk_buf, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Signing failed")
        return bytes(sm[:smlen.value])
    
    def verify(self, signed_message, pk):
        m = ctypes.create_string_buffer(len(signed_message))
        mlen = ctypes.c_ulonglong()
        sm_buf = ctypes.create_string_buffer(signed_message)
        pk_buf = ctypes.create_string_buffer(pk)
        if self.lib.PQCLEAN_FALCON1024_CLEAN_crypto_sign_open(
                ctypes.cast(m, ctypes.POINTER(ctypes.c_ubyte)), 
                ctypes.byref(mlen), 
                ctypes.cast(sm_buf, ctypes.POINTER(ctypes.c_ubyte)), 
                len(signed_message), 
                ctypes.cast(pk_buf, ctypes.POINTER(ctypes.c_ubyte))) != 0:
            raise Exception("Verification failed")
        return bytes(m[:mlen.value])


# Example usage
if __name__ == "__main__":
    # Test ML-KEM (Key Encapsulation)
    print("=== ML-KEM 768 ===")
    kem = MLKEM768()
    pk, sk = kem.keypair()
    print(f"Public key: {len(pk)} bytes")
    print(f"Secret key: {len(sk)} bytes")
    
    ct, ss1 = kem.encapsulate(pk)
    print(f"Ciphertext: {len(ct)} bytes")
    print(f"Shared secret: {len(ss1)} bytes")
    
    ss2 = kem.decapsulate(ct, sk)
    print(f"Decapsulated shared secret matches: {ss1 == ss2}")
    
    # Test ML-DSA (Digital Signature)
    print("\n=== ML-DSA 65 ===")
    dsa = MLDSA65()
    pk, sk = dsa.keypair()
    print(f"Public key: {len(pk)} bytes")
    print(f"Secret key: {len(sk)} bytes")
    
    message = b"Hello, Post-Quantum World!"
    signed = dsa.sign(message, sk)
    print(f"Signed message: {len(signed)} bytes")
    
    verified = dsa.verify(signed, pk)
    print(f"Verification matches: {verified == message}")
    
    # Test Falcon
    print("\n=== Falcon 512 ===")
    falcon = Falcon512()
    pk, sk = falcon.keypair()
    print(f"Public key: {len(pk)} bytes")
    print(f"Secret key: {len(sk)} bytes")
    
    signed = falcon.sign(message, sk)
    print(f"Signed message: {len(signed)} bytes")
    
    verified = falcon.verify(signed, pk)
    print(f"Verification matches: {verified == message}")