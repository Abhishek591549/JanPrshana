from django.urls import path
from .views import register_user, verify_otp,custom_login_view,submit_complaint,my_complaints,update_complaint_status,logout_view,get_all_complaints,me_view,complaints_chart_data,  document_detail_api,documents_list_api,add_document_api,resend_otp
from .views import get_profile,update_profile,verify_email_otp,request_email_change



urlpatterns = [
            path('register/', register_user, name='register'),
            path('verify-otp/', verify_otp, name='verify-otp'),
            path('login/', custom_login_view, name='custom_login'),
            path('complaints/submit/', submit_complaint, name='submit_complaint'),
            path('mine/', my_complaints, name='my-complaints'),
            path('complaints/<int:complaint_id>/status/', update_complaint_status, name='update_complaint_status'),
            path('logout/', logout_view, name='logout'),
            path('complaints/', get_all_complaints, name='get_all_complaints'),
            path('me/', me_view,name='me_view'),
            path('complaints/chart/', complaints_chart_data, name='complaints-chart'),
            path('documents/<int:id>/', document_detail_api, name='document-detail'),
            path('documents/', documents_list_api, name='documents-list'),
            path('add-document/', add_document_api, name='add_document_api'),
            path('resend-otp/', resend_otp, name='resend_otp'),  # ✅ new endpoint
            path("profile/", get_profile, name="get_profile"),
            path("profile/update/", update_profile, name="update_profile"),
            path("profile/change-email/", request_email_change, name="request_email_change"),
            path("profile/verify-email-otp/", verify_email_otp, name="verify_email_otp"),
       
  
]




