from fastapi import FastAPI, Request, UploadFile, Depends, File, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Annotated, List
from rembg import remove
from PIL import Image
import zipfile, rarfile, tempfile, shutil, os, uuid, io, time, filetype, base64, hmac, hashlib, json


OUTPUT_DIR = "outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)
ALLOWED_EXTENSIONS = {"jpeg", "jpg", "png", "webp"}

class CustomHTTPBearer(HTTPBearer):
    async def __call__(self, request: Request) -> HTTPAuthorizationCredentials:
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)
        token = credentials.credentials

        # Eğer Swagger'dan sadece token girilmişse Bearer olarak say
        if not credentials.scheme or credentials.scheme.lower() != "bearer":
            credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

        return credentials

app = FastAPI(
    title="Arka Plan Kaldırıcı API",
    description="Yüklenen görsellerin arka planını kaldırır",
    version="1.0.0",
    docs_url="/swagger",
    redoc_url=None
)

@app.get("/", include_in_schema=False)
async def redirect_to_docs():
    return RedirectResponse(url="/swagger")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "TritophiaStrongAndSecretKeyTritophiaStrongAndSecretKeyTritophiaStrongAndSecretKey"
ALGORITHM = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512"
security = CustomHTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials
    try:
        payload = verify_and_decode_jwt(token)
        user_id = payload.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")
        if not user_id:
            raise HTTPException(status_code=401, detail="Kullanıcı bulunamadı.")
        return user_id
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
        
def verify_and_decode_jwt(token: str) -> dict:
    try:
        # Token 3 parçaya ayrılmalı
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Token 3 parçalı değil")

        encoded_header, encoded_payload, encoded_signature = parts

        # Header & Payload decode
        header = json.loads(base64url_decode(encoded_header))
        payload = json.loads(base64url_decode(encoded_payload))
        signature = base64url_decode(encoded_signature)

        # Algoritmayı kontrol et
        alg = header.get("alg")
        # .NET-style URI gelirse onu da HS512 olarak kabul et
        if alg not in ("HS512", "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512"):
            raise ValueError(f"Desteklenmeyen algoritma: {alg}")


        # Signature'ı doğrula
        signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
        key_bytes = SECRET_KEY.encode("utf-8")
        expected_signature = hmac.new(key_bytes, signing_input, hashlib.sha512).digest()

        # Karşılaştır
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("İmza doğrulanamadı")

        # exp kontrolü
        if "exp" in payload:
            if time.time() > payload["exp"]:
                raise ValueError("Token süresi dolmuş")
        
        return payload

    except Exception as e:
        raise ValueError(f"JWT doğrulama başarısız: {str(e)}")


def base64url_decode(data):
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=')

def validate_file_type(content: bytes) -> str:
    kind = filetype.guess(content)
    if kind and kind.extension in ALLOWED_EXTENSIONS:
        return kind.extension
    raise HTTPException(status_code=400, detail="Geçersiz dosya türü: yalnızca jpg, png, jpeg, webp kabul edilir.")

def schedule_file_deletion(file_path: str, delay: int = 600):
    time.sleep(delay)
    if os.path.exists(file_path):
        os.remove(file_path)        

@app.post("/remove-background/", summary="Arka plan kaldır", description="Yüklenen görsellerin arka planını kaldırır.")
async def remove_background(
    background_tasks: BackgroundTasks,
    files: Annotated[List[UploadFile], 
    File(description="Birden fazla görsel yükleyin")],
    user_id: str = Depends(verify_token)
):
    user_output_dir = os.path.join("outputs", user_id)
    os.makedirs(user_output_dir, exist_ok=True)
    output_files = []

    for file in files:
        content = await file.read()

        try:
            validate_file_type(content)
        except HTTPException as e:
            raise HTTPException(status_code=400, detail=f"{file.filename} - {e.detail}")

        output_data = remove(content)
        output_image = Image.open(io.BytesIO(output_data)).convert("RGBA")

        filename = f"{uuid.uuid4().hex}.png"
        output_path = os.path.join(user_output_dir, filename)
        output_image.save(output_path)
        
        # 🔁 Arka planda silme işlemi 10 dakika sonra
        background_tasks.add_task(schedule_file_deletion, output_path, delay=600)

        output_files.append({"original": file.filename, "processed": filename})        
    
    return {
            "message": f"{len(output_files)} görsel işlendi ve 10 dakika sonra silinecek.",
            "results": output_files
        }
    
@app.post("/process-archive/")
async def process_archive(
    background_tasks: BackgroundTasks,
    archive: UploadFile = File(...),
    user_id: str = Depends(verify_token)
):
    filename = archive.filename.lower()
    if not (filename.endswith(".zip") or filename.endswith(".rar")):
        raise HTTPException(status_code=400, detail="Sadece .zip veya .rar dosyası yükleyin")

    # ⛺ Geçici çalışma dizini oluştur
    temp_dir = tempfile.mkdtemp()
    archive_path = os.path.join(temp_dir, archive.filename)

    # 📥 Arşiv dosyasını yaz
    with open(archive_path, "wb") as f:
        f.write(await archive.read())

    # 📦 Arşivi aç
    extracted_dir = os.path.join(temp_dir, "extracted")
    os.makedirs(extracted_dir, exist_ok=True)

    try:
        if filename.endswith(".zip"):
            with zipfile.ZipFile(archive_path, "r") as zip_ref:
                zip_ref.extractall(extracted_dir)
        elif filename.endswith(".rar"):
            with rarfile.RarFile(archive_path) as rar:
                rar.extractall(extracted_dir)
    except Exception as e:
        shutil.rmtree(temp_dir)
        raise HTTPException(status_code=500, detail=f"Arşiv açılamadı: {e}")

    # 🎯 Geçerli görselleri bul ve işle
    processed_dir = os.path.join(temp_dir, "processed")
    os.makedirs(processed_dir, exist_ok=True)
    processed_files: List[str] = []

    for root, _, files in os.walk(extracted_dir):
        for file_name in files:
            full_path = os.path.join(root, file_name)
            with open(full_path, "rb") as f:
                content = f.read()
                try:
                    validate_file_type(content)
                except:
                    continue  # Geçersiz uzantı atla

                output_data = remove(content)
                image = Image.open(io.BytesIO(output_data)).convert("RGBA")

                output_name = f"{uuid.uuid4().hex}.png"
                output_path = os.path.join(processed_dir, output_name)
                image.save(output_path)
                processed_files.append(output_path)

    # 📁 Kullanıcıya özel klasör oluştur
    user_output_dir = os.path.join(OUTPUT_DIR, user_id)
    os.makedirs(user_output_dir, exist_ok=True)
    
    # 📦 Zip oluştur
    result_zip_name = f"{uuid.uuid4().hex}.zip"
    result_zip_path = os.path.join(user_output_dir, result_zip_name)
    with zipfile.ZipFile(result_zip_path, "w") as zipf:
        for file_path in processed_files:
            arcname = os.path.basename(file_path)
            zipf.write(file_path, arcname=arcname)

    # 🧹 Arka planda zip'i silme görevi (10 dakika sonra)
    background_tasks.add_task(schedule_file_deletion, result_zip_path, delay=600)

    # ✔ Link döndür
    return {
        "message": "İşlem tamamlandı",
        "download_url": f"/download/{result_zip_name}",
        "expires_in_seconds": 60
    }

@app.get("/download/{filename}", response_class=FileResponse, summary="İşlenmiş görseli indir")
async def download_image(
    filename: str, 
    user_id: str = Depends(verify_token)
):
    path = os.path.join(OUTPUT_DIR, user_id, filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Dosya bulunamadı")
    return FileResponse(path, media_type="image/png", filename=filename)

if __name__ == "__main__":
    from dotenv import load_dotenv
    import uvicorn
    import os

    load_dotenv()
    
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="127.0.0.1", port=port)