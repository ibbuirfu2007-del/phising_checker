import csv
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .services import analyze_url
from .models import ScanHistory
from .forms import CustomUserCreationForm
from django.core.paginator import Paginator
from django.db.models import Count
from django.db.models.functions import TruncDate
def register_view(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)

        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect("home")
    else:
        form = UserCreationForm()

    return render(request, "scanner/register.html", {
        "form": form
    })


def login_view(request):
    if request.method == "POST":
        form = AuthenticationForm(
            request,
            data=request.POST
        )

        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect("home")
    else:
        form = AuthenticationForm()

    return render(request, "scanner/login.html", {
        "form": form
    })


def logout_view(request):
    if request.method == "POST":
        logout(request)

    return redirect("login")


@login_required(login_url="login")
def home(request):
    result = None
    error = None

    if request.method == "POST":
        url = request.POST.get("url", "").strip()

        try:
            result = analyze_url(url)

            ScanHistory.objects.create(
                user=request.user,
                url=result["url"],
                risk_score=result["risk_score"],
                risk_level=result["risk_level"],
                reasons=result["reasons"]
            )

        except ValueError as e:
            error = str(e)

    # Dashboard statistics
    scans = ScanHistory.objects.filter(user=request.user)

    total_scans = scans.count()
    low_count = scans.filter(risk_level="Low").count()
    medium_count = scans.filter(risk_level="Medium").count()
    high_count = scans.filter(risk_level="High").count()
    recent_scans = scans.order_by("-scanned_at")[:5]
    daily_scans = (
            scans.annotate(date=TruncDate("scanned_at"))
            .values("date")
            .annotate(total=Count("id"))
            .order_by("date")
        )

    chart_labels = [
            item["date"].strftime("%d-%m")
            for item in daily_scans
        ]

    chart_data = [
    item["total"]
    for item in daily_scans
]
    return render(request, "scanner/index.html", {
        "result": result,
        "error": error,
        "total_scans": total_scans,
        "low_count": low_count,
        "medium_count": medium_count,
        "high_count": high_count,
        "recent_scans": recent_scans,
        "chart_labels": chart_labels,
        "chart_data": chart_data
    })



@login_required(login_url="login")
def history(request):
    scans = ScanHistory.objects.filter(user=request.user)

    # Search
    search_query = request.GET.get("search", "").strip()

    if search_query:
        scans = scans.filter(url__icontains=search_query)

    # Risk filter
    risk_filter = request.GET.get("risk", "")

    if risk_filter in ["Low", "Medium", "High"]:
        scans = scans.filter(risk_level=risk_filter)

    # Sorting
    sort_order = request.GET.get("sort", "latest")

    if sort_order == "oldest":
        scans = scans.order_by("scanned_at", "id")
    else:
        sort_order = "latest"
        scans = scans.order_by("-scanned_at", "-id")

    # Pagination
    paginator = Paginator(scans, 10)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    return render(request, "scanner/history.html", {
        "scans": page_obj,
        "page_obj": page_obj,
        "search_query": search_query,
        "risk_filter": risk_filter,
        "sort_order": sort_order,
    })


@login_required(login_url="login")
def delete_scan(request, scan_id):
    if request.method == "POST":
        scan = ScanHistory.objects.filter(
            id=scan_id,
            user=request.user
        ).first()

        if scan:
            scan.delete()

    return redirect("history")
@login_required(login_url="login")
def export_history(request):
    scans = ScanHistory.objects.filter(
        user=request.user
    ).order_by("-scanned_at")

    response = HttpResponse(
        content_type="text/csv"
    )

    response["Content-Disposition"] = (
        'attachment; filename="phishing_scan_history.csv"'
    )

    writer = csv.writer(response)

    writer.writerow([
        "URL",
        "Risk Score",
        "Risk Level",
        "Reasons",
        "Scanned At"
    ])

    for scan in scans:
        writer.writerow([
            scan.url,
            scan.risk_score,
            scan.risk_level,
            ", ".join(scan.reasons),
            scan.scanned_at.strftime("%d-%m-%Y %I:%M %p")
        ])

    return response

@login_required(login_url="login")
def scan_details(request, scan_id):
    scan = ScanHistory.objects.filter(
        id=scan_id,
        user=request.user
    ).first()

    if not scan:
        return redirect("history")

    return render(request, "scanner/details.html", {
        "scan": scan
    })
