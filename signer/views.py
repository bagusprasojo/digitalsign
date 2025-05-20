from django.http import JsonResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.sign.signers import PdfSignatureMetadata
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
import tempfile, os
import threading
import json
from .models import ApiUser, PdfSignLog  
from .utils import hash_password, generate_self_signed_cert, verify_password
from django.conf import settings


@csrf_exempt
def sign_pdf_view_by_email(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST allowed'}, status=405)
    
    ip = request.META.get('REMOTE_ADDR')
    email = request.POST.get("email")
    password = request.POST.get("password")
    pdf_file = request.FILES.get("pdf")
    field_name = request.POST.get("field_name")
    
    if not email:
        msg = 'Missing email fields'
        PdfSignLog.objects.create(email=email or '', ip_address=ip, status='FAILED', message=msg)
        return JsonResponse({'error': 'Missing email'}, status=400)
    
    
    if not password:
        msg = 'Missing password fields'
        PdfSignLog.objects.create(email=email or '', ip_address=ip, status='FAILED', message=msg)
        return JsonResponse({'error': 'Missing password'}, status=400)   

    if not pdf_file:
        msg = 'Missing pdf fields'
        PdfSignLog.objects.create(email=email or '', ip_address=ip, status='FAILED', message=msg)
        return JsonResponse({'error': 'Missing PDF file'}, status=400)

    if not field_name:
        msg = 'Missing field_name  fields'
        PdfSignLog.objects.create(email=email or '', ip_address=ip, status='FAILED', message=msg)        
        return JsonResponse({'error': 'Missing field name'}, status=400)

    
    

    try:
        user = ApiUser.objects.get(email=email)
    except ApiUser.DoesNotExist:
        msg = 'User not found'
        PdfSignLog.objects.create(email=email, ip_address=ip, status='FAILED', message=msg)
        
        return JsonResponse({'error': 'User not found'}, status=404)

    if not verify_password(password, user.password_hash):
        msg = 'Invalid password'
        PdfSignLog.objects.create(email=email, ip_address=ip, status='FAILED', message=msg)
        
        return JsonResponse({'error': 'Invalid password'}, status=403)

    try:
        signer = signers.SimpleSigner.load_pkcs12(user.cert_file.path,passphrase=password.encode())
    except Exception as e:
        msg = f'Failed to load certificate: {str(e)}'
        PdfSignLog.objects.create(email=email, ip_address=ip, status='FAILED', message=msg)
        
        return JsonResponse({'error': f'Failed to load certificate: {str(e)}'}, status=500)

    # Simpan input PDF ke file sementara
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_input:
            for chunk in pdf_file.chunks():
                temp_input.write(chunk)

        # Tanda tangan PDF
        with open(temp_input.name, 'rb') as pdf:
            writer = IncrementalPdfFileWriter(pdf)
            meta = PdfSignatureMetadata(field_name=field_name)
            signed_pdf = signers.sign_pdf(
                writer, meta,
                signer=signer,
                existing_fields_only=False,
                new_field_spec=SigFieldSpec(sig_field_name=field_name)
            )

        # Simpan hasil ke file sementara untuk respons
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as output_file:
            output_file.write(signed_pdf.getbuffer())
            signed_path = output_file.name

        PdfSignLog.objects.create(email=email, ip_address=ip, status='SUCCESS', message='Signed PDF successfully')        
        return FileResponse(open(signed_path, 'rb'), as_attachment=True, filename='signed.pdf')
    except Exception as e:
        msg = f'Unexpected error: {str(e)}'
        PdfSignLog.objects.create(email=email, ip_address=ip, status='FAILED', message=msg)
        
        return JsonResponse({'error': str(e)}, status=500)  

@csrf_exempt
def register_api_user(request):
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data["email"]
        name = data["name"]
        password = data["password"]

        if ApiUser.objects.filter(email=email).exists():
            return JsonResponse({"error": "Email already registered"}, status=400)

        # Hash password
        hashed = hash_password(password)

        # Generate cert
        cert_bytes = generate_self_signed_cert(name, email, password)

        # Save to file
        filename = f"{email.replace('@', '_')}.p12"
        # filepath = os.path.join("media/certificates", filename)
        filepath = os.path.join(settings.MEDIA_ROOT, 'certificates', filename)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "wb") as f:
            f.write(cert_bytes)

        user = ApiUser.objects.create(
            email=email,
            name=name,
            password_hash=hashed,
            cert_file=f"certificates/{filename}"
        )

        return JsonResponse({"message": "Registered successfully", "email": user.email})

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


def delayed_delete(path):
    import time
    time.sleep(5)  # beri waktu 5 detik agar file tidak masih dibaca saat dihapus
    if os.path.exists(path):
        os.remove(path)

@csrf_exempt
def sign_pdf_view(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST allowed'}, status=405)

    pdf = request.FILES.get('pdf')
    cert = request.FILES.get('cert')
    password = request.POST.get('cert_pass')

    if not pdf :
        return JsonResponse({'error': 'Missing PDF file'}, status=400)
    if not cert:
        return JsonResponse({'error': 'Missing certificate file'}, status=400)
    if not password:
        return JsonResponse({'error': 'Missing file or password'}, status=400)

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as pdf_file, \
             tempfile.NamedTemporaryFile(delete=False, suffix=".p12") as cert_file:
            for chunk in pdf.chunks():
                pdf_file.write(chunk)
            for chunk in cert.chunks():
                cert_file.write(chunk)

        signer = signers.SimpleSigner.load_pkcs12(cert_file.name, passphrase=password.encode())

        with open(pdf_file.name, "rb") as doc:
            w = IncrementalPdfFileWriter(doc)
            meta = PdfSignatureMetadata(field_name="Sig1")
            out = signers.sign_pdf(
                w, meta, signer=signer,
                existing_fields_only=False,
                new_field_spec=SigFieldSpec(sig_field_name="Sig1")
            )

        signed_path = pdf_file.name.replace(".pdf", "_signed.pdf")
        with open(signed_path, "wb") as f_out:
            f_out.write(out.getbuffer())

        # Kirim file ke user
        response = FileResponse(open(signed_path, "rb"), content_type="application/pdf")
        response['Content-Disposition'] = 'attachment; filename="signed_output.pdf"'

        # Hapus file di background setelah delay
        threading.Thread(target=delayed_delete, args=(signed_path,)).start()
        return response

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

    finally:
        os.remove(pdf_file.name)
        os.remove(cert_file.name)
