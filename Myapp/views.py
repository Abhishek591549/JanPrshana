from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from django.core.mail import send_mail
from django.http import JsonResponse
import json
import random
from .models import User

@csrf_exempt
def register_user(request):
    if request.method == 'POST':
        data = json.loads(request.body)

        required_fields = [
            'full_name', 'gender', 'mobile_number', 'email',
            'home_number', 'ward_number', 'password', 'confirm_password'
        ]

        for field in required_fields:
            if not data.get(field):
                return JsonResponse({field: "This field is required."}, status=400)

        if data['password'] != data['confirm_password']:
            return JsonResponse({"error": "Passwords do not match."}, status=400)

        if User.objects.filter(email=data['email']).exists():
            return JsonResponse({"error": "Email already registered."}, status=400)

        # Generate OTP
        otp = str(random.randint(100000, 999999))

        # Store data temporarily in cache for 60 seconds
        cache.set(data['email'], {**data, 'otp': otp}, timeout=60)

        # Send email
        send_mail(
            subject='Your OTP Verification Code',
            message=f"Hello {data['full_name']}, your OTP is: {otp}",
            from_email='abhisheksavalgi601@gmail.com',  # your email
            recipient_list=[data['email']],
            fail_silently=False,
        )

        return JsonResponse({"message": "OTP sent to your email."}, status=200)
    else:
        return JsonResponse({"error": "Only POST method is allowed."}, status=405)



@csrf_exempt
def verify_otp(request):
    if request.method == 'POST':
        data = json.loads(request.body)

        email = data.get('email')
        otp_input = data.get('otp')

        if not email or not otp_input:
            return JsonResponse({"error": "Email and OTP are required."}, status=400)

        cached_data = cache.get(email)

        if not cached_data:
            return JsonResponse({"error": "OTP expired. Please register again."}, status=400)

        if cached_data['otp'] != otp_input:
            return JsonResponse({"error": "Invalid OTP."}, status=400)

        # Create the user
        user = User.objects.create_user(
            email=cached_data['email'],
            password=cached_data['password'],
            full_name=cached_data['full_name'],
            gender=cached_data['gender'],
            mobile_number=cached_data['mobile_number'],
            home_number=cached_data['home_number'],
            ward_number=cached_data['ward_number'],
            live_location=cached_data.get('live_location', ''),
            is_verified=True
        )

        cache.delete(email)

        return JsonResponse({"message": "User registered successfully!"}, status=201)
    else:
        return JsonResponse({"error": "Only POST method is allowed."}, status=405)
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()

@api_view(['POST'])
@permission_classes([AllowAny])
def custom_login_view(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({"error": "Email and password are required"}, status=400)

    user = authenticate(request, username=email, password=password)
    if not user:
        return Response({"error": "Invalid credentials"}, status=400)

    refresh = RefreshToken.for_user(user)

    response = Response({
        "message": "Login successful",
        "is_superuser": user.is_superuser,
        "is_staff": user.is_staff,
        "access_token": str(refresh.access_token),
        "refresh_token": str(refresh),
    })

    # set cookies
    response.set_cookie(
        key="access_token",
        value=str(refresh.access_token),
        httponly=True,
        secure=False,   # set True in production with HTTPS
        samesite="Lax",
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=str(refresh),
        httponly=True,
        secure=False,
        samesite="Lax",
        path="/",
    )

    # ✅ you MUST return this
    return response

def resend_otp(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')

        if not email:
            return JsonResponse({"error": "Email is required."}, status=400)

        cached_data = cache.get(email)

        if not cached_data:
            return JsonResponse({"error": "No registration data found. Please register again."}, status=400)

        # Generate new OTP
        otp = str(random.randint(100000, 999999))
        cached_data['otp'] = otp

        # Update cache with new OTP (valid for 60 sec again)
        cache.set(email, cached_data, timeout=60)

        # Send email again
        send_mail(
            subject="Your New OTP Verification Code",
            message=f"Hello {cached_data['full_name']}, your new OTP is: {otp}",
            from_email="abhisheksavalgi601@gmail.com",
            recipient_list=[email],
            fail_silently=False,
        )

        return JsonResponse({"message": "A new OTP has been sent to your email."}, status=200)

    else:
        return JsonResponse({"error": "Only POST method is allowed."}, status=405)


    return response
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .authentication import CookieJWTAuthentication  # ✅ custom cookie-based JWT auth

@api_view(["GET"])
@authentication_classes([CookieJWTAuthentication])  # ✅ read JWT from cookies
@permission_classes([IsAuthenticated])
def get_profile(request):
    """
    API to fetch logged-in user profile details
    """
    user = request.user
    data = {
        "id": user.id,
        "full_name": getattr(user, "full_name", ""),
        "email": user.email,
        "mobile_number": getattr(user, "mobile_number", ""),
        "gender": getattr(user, "gender", ""),
        "ward_number": getattr(user, "ward_number", ""),
        "home_number": getattr(user, "home_number", ""),
        "live_location": getattr(user, "live_location", ""),
    }
    return Response(data)




from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from django.utils import timezone
import random
from .authentication import CookieJWTAuthentication

@api_view(["PUT"])
@authentication_classes([CookieJWTAuthentication])  
@permission_classes([IsAuthenticated])  
def update_profile(request):
    """
    API to update logged-in user profile details
    """
    user = request.user
    data = request.data

    # Update normal fields
    user.full_name = data.get("full_name", user.full_name)
    user.mobile_number = data.get("mobile_number", user.mobile_number)
    user.gender = data.get("gender", user.gender)
    user.ward_number = data.get("ward_number", user.ward_number)
    user.home_number = data.get("home_number", user.home_number)
    user.live_location = data.get("live_location", user.live_location)

    # Handle email change
    new_email = data.get("email")
    if new_email and new_email != user.email:
        if user.pending_email and user.pending_email != new_email:
            return Response({"error": "You have already requested an email change. Please verify OTP first."}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=new_email).exists():
            return Response({"error": "This email is already in use"}, status=status.HTTP_400_BAD_REQUEST)

        # Generate OTP for email change
        otp = str(random.randint(100000, 999999))
        user.pending_email = new_email
        user.email_otp = otp
        user.email_otp_created_at = timezone.now()
        
        # Send OTP to new email
        send_mail(
            subject="Email Change OTP",
            message=f"Hello {user.full_name}, your OTP to change email is: {otp}",
            from_email="abhisheksavalgi601@gmail.com",
            recipient_list=[new_email],
            fail_silently=False,
        )

    user.save()

    response_data = {
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,  # current email, will change after OTP verification
        "mobile_number": user.mobile_number,
        "gender": user.gender,
        "ward_number": user.ward_number,
        "home_number": user.home_number,
        "live_location": user.live_location,
    }

    if new_email and new_email != user.email:
        response_data["message"] = "OTP sent to new email. Please verify to update email."

    return Response(response_data, status=status.HTTP_200_OK)


from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from django.utils import timezone
import random
from .authentication import CookieJWTAuthentication
from .models import User

@api_view(["POST"])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def request_email_change(request):
    """
    Request OTP for changing email
    """
    user = request.user
    new_email = request.data.get("email")

    if not new_email:
        return Response({"error": "New email is required"}, status=status.HTTP_400_BAD_REQUEST)

    if new_email == user.email:
        return Response({"error": "New email must be different from current email"}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=new_email).exists():
        return Response({"error": "This email is already in use"}, status=status.HTTP_400_BAD_REQUEST)

    # Generate OTP
    otp = str(random.randint(100000, 999999))
    user.pending_email = new_email
    user.email_otp = otp
    user.email_otp_created_at = timezone.now()
    user.save()

    # Send OTP to new email
    send_mail(
        subject="Email Change OTP",
        message=f"Hello {user.full_name}, your OTP to change email is: {otp}",
        from_email="abhisheksavalgi601@gmail.com",
        recipient_list=[new_email],
        fail_silently=False,
    )

    return Response({"message": "OTP sent to new email. Please verify to update email."}, status=status.HTTP_200_OK)
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from .authentication import CookieJWTAuthentication

@api_view(["POST"])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def verify_email_otp(request):
    """
    Verify OTP and update user email
    """
    user = request.user
    otp_input = request.data.get("otp")

    if not otp_input:
        return Response({"error": "OTP is required"}, status=status.HTTP_400_BAD_REQUEST)

    # Check if OTP exists and not expired (10 min validity)
    if not user.email_otp or not user.pending_email:
        return Response({"error": "No pending email change request"}, status=status.HTTP_400_BAD_REQUEST)

    time_diff = timezone.now() - user.email_otp_created_at
    if time_diff.total_seconds() > 600:  # 10 minutes
        user.pending_email = None
        user.email_otp = None
        user.email_otp_created_at = None
        user.save()
        return Response({"error": "OTP expired. Please request again"}, status=status.HTTP_400_BAD_REQUEST)

    if otp_input != user.email_otp:
        return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

    # Update email
    user.email = user.pending_email
    user.pending_email = None
    
    user.email_otp = None
    user.email_otp_created_at = None
    user.save()

    return Response({"message": "Email updated successfully"}, status=status.HTTP_200_OK)

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import Complaint
from .authentication import CookieJWTAuthentication

@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def submit_complaint(request):
    category = request.data.get('category')
    description = request.data.get('description')
    image = request.FILES.get('image')  # optional
    ward_number = request.data.get('ward_number')
    live_location = request.data.get('live_location')

    if not all([category, description, ward_number, live_location]):
        return Response({'error': 'Missing required fields'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        ward_number = int(ward_number)
    except:
        return Response({'error': 'Ward number must be integer'}, status=status.HTTP_400_BAD_REQUEST)

    complaint = Complaint.objects.create(
        user=request.user,
        category=category,
        description=description,
        image=image,
        ward_number=ward_number,
        live_location=live_location
    )

    return Response({'message': 'Complaint submitted successfully', 'complaint_id': complaint.id}, status=status.HTTP_201_CREATED)

from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import Complaint
from .authentication import CookieJWTAuthentication

@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def my_complaints(request):
    complaints = Complaint.objects.filter(user=request.user).order_by('-created_at')
    data = [
        {
            'id': c.id,
            'category': c.category,
            'description': c.description,
            'image': request.build_absolute_uri(c.image.url) if c.image else None,
            'ward_number': c.ward_number,
            'live_location': c.live_location,
            'status': c.status,
            'created_at': c.created_at.isoformat()
        }
        for c in complaints
    ]
    return Response(data)


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny  # allow even expired tokens
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

@api_view(['POST'])
@permission_classes([AllowAny])
def logout_view(request):
    refresh_token = request.COOKIES.get('refresh_token')
    if not refresh_token:
        return Response({"error": "No refresh token found."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        token = RefreshToken(refresh_token)
        token.blacklist()
    except TokenError:
        return Response({"error": "Invalid refresh token."}, status=status.HTTP_400_BAD_REQUEST)

    response = Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
    # Delete the auth cookies
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return response

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from .models import Complaint
from .authentication import CookieJWTAuthentication

# ✅ Admin: Get all complaints
@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated, IsAdminUser])
def get_all_complaints(request):
    complaints = Complaint.objects.all().order_by('-created_at')
    data = [
        {
            'id': comp.id,
            'user': getattr(comp.user, 'full_name', str(comp.user)),
            'category': comp.category,
            'description': comp.description,
            'image': request.build_absolute_uri(comp.image.url) if comp.image else None,
            'ward_number': comp.ward_number,
            'live_location': comp.live_location,
            'status': comp.status,
            'created_at': comp.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        for comp in complaints
    ]
    return Response(data, status=status.HTTP_200_OK)

# ✅ Admin: Update complaint status
@api_view(['PATCH'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated, IsAdminUser])
def update_complaint_status(request, complaint_id):
    try:
        complaint = Complaint.objects.get(id=complaint_id)
        new_status = request.data.get('status')
        if new_status not in ['pending', 'working', 'resolved', 'rejected']:
            return Response({'error': 'Invalid status.'}, status=status.HTTP_400_BAD_REQUEST)
        complaint.status = new_status
        complaint.save()
        return Response({'message': f'Status updated to {new_status}.'}, status=status.HTTP_200_OK)
    except Complaint.DoesNotExist:
        return Response({'error': 'Complaint not found.'}, status=status.HTTP_404_NOT_FOUND)


# myapp/views.py
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

User = get_user_model()

@api_view(['GET'])
@permission_classes([AllowAny])
def me_view(request):
    token = request.COOKIES.get('access_token')
    if not token:
        return Response({"detail": "Authentication credentials were not provided."}, status=401)

    try:
        access = AccessToken(token)
        user_id = access.get('user_id')
    except (TokenError, InvalidToken):
        return Response({"detail": "Invalid or expired token."}, status=401)

    user = User.objects.filter(id=user_id).first()
    if not user:
        return Response({"detail": "User not found."}, status=401)

    return Response({
        "email": getattr(user, 'email', ''),
        "full_name": getattr(user, 'full_name', getattr(user, 'email', '')),
        "is_superuser": getattr(user, 'is_superuser', False),
        "is_staff": getattr(user, 'is_staff', False),
    }, status=200)
# views.py
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.db.models import Count
from django.db.models.functions import ExtractMonth
from datetime import datetime
from .models import Complaint
from .authentication import CookieJWTAuthentication

@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def complaints_chart_data(request):
    year = datetime.now().year
    queryset = Complaint.objects.filter(created_at__year=year)

    # Group by month and status
    data = queryset.annotate(month=ExtractMonth('created_at')) \
                   .values('month', 'status') \
                   .annotate(count=Count('id')) \
                   .order_by('month')

    chart_data = {status: [0]*12 for status in ['pending', 'working', 'resolved', 'rejected']}
    for item in data:
        month_index = item['month'] - 1
        chart_data[item['status']][month_index] = item['count']

    return Response(chart_data)
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from Myapp.models import Document

def document_detail_api(request, id):  # <-- matches <int:id> in urls.py
    doc = get_object_or_404(Document, id=id)

    data = {
        "id": doc.id,
        "name": doc.name,
        "required_documents": doc.required_documents,
        "process": doc.process,
        "office_address": doc.office_address,
        "office_contact": doc.office_contact,
        "office_hours": doc.office_hours,
        "image": doc.image.url if doc.image else None
    }
    return JsonResponse(data)
# Myapp/views.py
from django.http import JsonResponse
from Myapp.models import Document

def documents_list_api(request):
    docs = Document.objects.all()
    data = [{"id": doc.id, "name": doc.name} for doc in docs]
    return JsonResponse(data, safe=False)
# Myapp/views.py
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from .models import Document
from .authentication import CookieJWTAuthentication

@csrf_exempt
@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAdminUser])
def add_document_api(request):
    """
    API to add a new Document (superuser only) without using serializer.
    """
    # Required fields
    name = request.data.get('name')
    required_documents = request.data.get('required_documents')
    process = request.data.get('process')
    office_address = request.data.get('office_address')
    office_contact = request.data.get('office_contact')
    office_hours = request.data.get('office_hours')
    image = request.FILES.get('image')  # optional

    # Validation
    missing_fields = []
    for field_name, value in [
        ('name', name),
        ('required_documents', required_documents),
        ('process', process),
        ('office_address', office_address),
        ('office_contact', office_contact),
        ('office_hours', office_hours),
    ]:
        if not value:
            missing_fields.append(field_name)

    if missing_fields:
        return Response(
            {"error": f"Missing required fields: {', '.join(missing_fields)}"},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Check if document with same name exists
    if Document.objects.filter(name=name).exists():
        return Response(
            {"error": "Document with this name already exists."},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Create and save document
    document = Document(
        name=name,
        required_documents=required_documents,
        process=process,
        office_address=office_address,
        office_contact=office_contact,
        office_hours=office_hours,
        image=image
    )
    document.save()

    return Response(
        {
            "message": "Document added successfully",
            "document": {
                "id": document.id,
                "name": document.name,
                "slug": document.slug,
                "required_documents": document.required_documents,
                "process": document.process,
                "office_address": document.office_address,
                "office_contact": document.office_contact,
                "office_hours": document.office_hours,
                "image": document.image.url if document.image else None
            }
        },
        status=status.HTTP_201_CREATED
    )
