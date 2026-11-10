
from django.db import models
from django.conf import settings

class ScanHistory(models.Model):
    user = models.ForeignKey(
    settings.AUTH_USER_MODEL,
    on_delete=models.CASCADE,
    related_name="scans",
    null=True,
    blank=True
)

    RISK_CHOICES = [
        ("Low", "Low"),
        ("Medium", "Medium"),
        ("High", "High"),
    ]

    url = models.URLField(max_length=2048)

    risk_score = models.PositiveSmallIntegerField()

    risk_level = models.CharField(
        max_length=10,
        choices=RISK_CHOICES
    )

    reasons = models.JSONField(default=list)

    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.url} - {self.risk_level}"
