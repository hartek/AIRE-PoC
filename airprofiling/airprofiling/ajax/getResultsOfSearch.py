from airprofiling.panels.search import getHtmlOfTable
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse

@login_required
def view(request):
    html = getHtmlOfTable(request)
    data = {"status":"OK", "html":html}
    return JsonResponse(data)