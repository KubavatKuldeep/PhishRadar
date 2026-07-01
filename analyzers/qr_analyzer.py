"""
PhishRadar - Dynamic Matrix QR Processing Engine
"""
from PIL import Image
from pyzbar.pyzbar import decode

class QrAnalyzer:
    @staticmethod
    def decode_stream(image_stream) -> str:
        """
        Parses uploaded byte streams in-memory to decode payload pointers.
        Returns empty string if decoding fails.
        """
        try:
            with Image.open(image_stream) as img:
                decoded_objects = decode(img)
                if decoded_objects:
                    return decoded_objects[0].data.decode('utf-8').strip()
        except Exception:
            pass
        return ""