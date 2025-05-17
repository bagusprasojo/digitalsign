from django.urls import path
from .views import sign_pdf_view, register_api_user, sign_pdf_view_by_email

urlpatterns = [
    path('sign-pdf/', sign_pdf_view, name='sign_pdf'),
    path('sign-pdf-by-email/', sign_pdf_view_by_email, name='sign_pdf_view_by_email'),
    path("register/", register_api_user, name="register"),
]
