from django.conf.urls import url, include
from rest_framework import routers
from rest_framework.authtoken import views as authviews
from django.contrib import admin
from django.views.generic.base import RedirectView

# Api Rest
from pcap_api import views as views_pcap_api
from airprofiling import views as views_airprofiling



router = routers.DefaultRouter()
router.register(r'pcap-api', views_pcap_api.PcapFileViewSet)

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^accounts/', include('django.contrib.auth.urls')),
]

urlpatterns_pcap = [
    url(r'^pcapfiles/pcap-api/update/(?P<request_type>(error|parsed|analyzed)+)/(?P<id>[0-9\.a-zA-Z\-\_]+)/?$', views_pcap_api.update_pcapfile, name='update_pcapfile'),
    url(r'^pcapfiles/pcap-api/uploads/(?P<file_name>[0-9\.a-zA-Z\-\_]+)/?$', views_pcap_api.pcapfile_details, name='download_file'),
    url(r'^pcapfiles/', include(router.urls), name='pcapfiles'),

    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    url(r'^api-token-auth/', authviews.obtain_auth_token),
]

favicon_view = RedirectView.as_view(url='/static/img/favicon.ico', permanent=True)

urlpatterns_airprofiling = [
    url(r'^favicon\.ico$', favicon_view),

    url(r'^airprofiling/?$', views_airprofiling.dashboard, name='index'),
    url(r'^airprofiling/dashboard?/?$', views_airprofiling.dashboard, name='dashboard'),
    url(r'^airprofiling/home?/?$', views_airprofiling.dashboard, name='home'),
    url(r'^airprofiling/data/(?P<idTarget>[0-9a-zA-Z\:]+)/?$', views_airprofiling.details, name='details'),
    url(r'^airprofiling/search/(?P<search_term>[\w]+)?/?$', views_airprofiling.search, name='search'),
    url(r'^airprofiling/list/?$', views_airprofiling.vw_list, name='vw_list'),

    #
    url(r'^airprofiling/ajax/getResultsOfSearch/?$', views_airprofiling.ajax_getResultsOfSearch, name='ajax_getResultsOfSearch'),
    url(r'^airprofiling/ajax/getTimelineFiltered/(?P<idTarget>[0-9a-zA-Z\:]+)$', views_airprofiling.ajax_getTimelineFiltered, name='ajax_getTimelineFiltered'),
]


urlpatterns += urlpatterns_pcap + urlpatterns_airprofiling