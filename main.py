from fastapi import FastAPI, Request, UploadFile, Depends, File, HTTPException
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Annotated, List
from rembg import remove
from PIL import Image
import uuid
import os
import io
import filetype
import zipfile
import rarfile
import tempfile
import shutil

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
security = CustomHTTPBearer()

@app.get("/", include_in_schema=False)
async def redirect_to_docs():
    return RedirectResponse(url="/swagger")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    # token = credentials.credentials
    # if not token:
    #     raise HTTPException(status_code=401, detail="Token eksik")
    # return token
    return True

def validate_file_type(content: bytes) -> str:
    kind = filetype.guess(content)
    if kind and kind.extension in ALLOWED_EXTENSIONS:
        return kind.extension
    raise HTTPException(status_code=400, detail="Geçersiz dosya türü: yalnızca jpg, png, jpeg, webp kabul edilir.")

@app.post("/remove-background/", summary="Arka plan kaldır", description="Yüklenen görsellerin arka planını kaldırır.")
async def remove_background(files: Annotated[List[UploadFile], File(description="Birden fazla görsel yükleyin")]):
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
        output_path = os.path.join(OUTPUT_DIR, filename)
        output_image.save(output_path)

        output_files.append({"original": file.filename, "processed": filename})

    return {"message": "İşlem tamamlandı", "results": output_files}

@app.post("/process-archive/", summary="ZIP/RAR ile görsel yükle", description="ZIP veya RAR dosyasındaki görsellerin arka planını kaldırır ve işlenmiş görselleri .zip olarak döner.")
async def process_archive(
    archive: UploadFile = File(...)
):
    # 🔐 Uzantı kontrolü
    filename = archive.filename.lower()
    if not (filename.endswith(".zip") or filename.endswith(".rar")):
        raise HTTPException(status_code=400, detail="Sadece .zip veya .rar dosyası yükleyebilirsiniz.")

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
        raise HTTPException(status_code=500, detail=f"Arşiv açılırken hata oluştu: {e}")

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

    # 📦 Sonuçları ziple
    result_zip_path = os.path.join(temp_dir, "results.zip")
    with zipfile.ZipFile(result_zip_path, "w") as zipf:
        for file_path in processed_files:
            arcname = os.path.basename(file_path)
            zipf.write(file_path, arcname=arcname)

    # ⬇️ Kullanıcıya zip dosyasını indir
    response = FileResponse(
        path=result_zip_path,
        filename="processed_results.zip",
        media_type="application/zip"
    )

    # 🧹 Geçici klasör temizliği: response ile birlikte asenkron yapılabilir (geliştirilebilir)
    return response

@app.get("/download/{filename}", response_class=FileResponse, summary="İşlenmiş görseli indir")
async def download_image(filename: str, token: str = Depends(verify_token)):
    path = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Dosya bulunamadı")
    return FileResponse(path, media_type="image/png", filename=filename)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)