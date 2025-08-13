import pyotp
import qrcode
import io
import base64

def generate_totp_secret():
    return pyotp.random_base32()

def get_totp_uri(username, secret, issuer_name="Verify_It"):
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer_name)

def generate_qr_code_base64(data):
    qr = qrcode.QRCode(box_size=4, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_b64 = base64.b64encode(buffered.getvalue()).decode()
    return f"data:image/png;base64,{img_b64}"

def verify_totp(token, secret):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)
