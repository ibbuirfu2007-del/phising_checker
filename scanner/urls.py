
from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("history/", views.history, name="history"),
    path("register/", views.register_view, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("delete-scan/<int:scan_id>/", views.delete_scan, name="delete_scan"),
    path("export-history/", views.export_history, name="export_history"),
    path("scan-details/<int:scan_id>/", views.scan_details, name="scan_details"),
]
