import pyotp
import qrcode
import io
import base64

def generate_totp_secret():
    return pyotp.random_base32()

def get_totp_uri(username, secret, issuer="Verify_It"):
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)

def verify_totp(token, secret):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def generate_qr_code_base64(uri):
    qr = qrcode.QRCode(box_size=4, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_bytes = buffered.getvalue()
    return base64.b64encode(img_bytes).decode("utf-8")