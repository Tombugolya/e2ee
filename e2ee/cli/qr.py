import base64
from io import BytesIO

from PIL import Image


def display_qr(base64_qr_code: str, user_id: str) -> None:
    """
    Display the QR code image using the default image viewer and save it to a file.
    """
    # Decode the base64 string to binary data
    img_data = base64.b64decode(base64_qr_code)

    # Create an image object using PIL
    img = Image.open(BytesIO(img_data))
    # Save the image to a file
    name = f"{user_id}_qr_code.png"
    img.save(name)
    # open above image in default image viewer
    img.show(name)
