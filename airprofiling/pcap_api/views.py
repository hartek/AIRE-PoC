import datetime, os, json

from rest_framework import viewsets
from rest_framework.parsers import JSONParser, FormParser, MultiPartParser
from rest_framework.decorators import api_view,authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import TokenAuthentication, SessionAuthentication, BasicAuthentication

from django.http import StreamingHttpResponse, HttpResponse, JsonResponse
#from django.core.servers.basehttp import FileWrapper
from wsgiref.util import FileWrapper
import mimetypes


from .serializers import PcapFileSerializer
from .models import PcapFile


def download_file(file_path):
   filename = os.path.basename(file_path)
   chunk_size = 8192
   response = StreamingHttpResponse(FileWrapper(open(file_path, 'rb'), chunk_size),
                           content_type=mimetypes.guess_type(file_path)[0])
   response['Content-Length'] = os.path.getsize(file_path)
   response['Content-Disposition'] = "attachment; filename=%s" % filename
   return response



def pcapfile_details(request, file_name):
    try:
        file = PcapFile.objects.get(id=file_name)
    except (PcapFile.DoesNotExist, ValueError):
        # Comprueba si es por el nombre
        try:
            file = PcapFile.objects.get(name=file_name.split('.')[0])
        except PcapFile.DoesNotExist:
            return HttpResponse(status=404)

    if request.method == 'GET':
        serializer = PcapFileSerializer(file)
        # descargar sólo el archivo serializado
        return download_file(serializer.data.get('file'))

    elif request.method == 'PUT':
        data = JSONParser().parse(request)
        serializer = SnippetSerializer(snippet, data=data)
        if serializer.is_valid():
            serializer.save()
            return JsonResponse(serializer.data)
        return JsonResponse(serializer.errors, status=400)

    elif request.method == 'DELETE':
        snippet.delete()
        return HttpResponse(status=204)


@api_view(['POST', 'PUT'])
@authentication_classes((TokenAuthentication, SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated, ))
def update_pcapfile(request, request_type, id):

    # Según el tipo, actualiza lo que sea
    # hace save

    # Coge el objeto
    try:
        file = PcapFile.objects.get(id=id)
    except:
        return HttpResponse(status=404)
    
    request_data = JSONParser().parse(request)

    serializer = PcapFileSerializer(file)
    if request_type == "parsed":
        data = {
            'status': 1,
            'parsed_json': request_data['parsed_json']
        }
    elif request_type == "analyzed":
        data = {
            'status': 2,
            'analyzed_json': request_data['analyzed_json']
        }
    elif request_type == 'error':
        data = {
            'status': -1
        }
    else:
        return HttpResponse(status=405)
    file = serializer.update(file, data)
    return JsonResponse(serializer.data)



class PcapFileViewSet(viewsets.ModelViewSet): # pylint: disable=too-many-ancestors,missing-docstring
    """
    API Endpoint que permite ver los archivos
    """
    serializer_class = PcapFileSerializer

    queryset = PcapFile.objects.all().order_by('-created')
    parser_classes = (JSONParser, MultiPartParser, FormParser,)
    permission_classes = (IsAuthenticated,)
        

    def get_queryset(self):
        status = self.request.query_params.get('status', None)

        if status is not None:
            self.queryset = self.queryset.filter(status = status)

        return self.queryset

    def pre_save(self, obj):
        obj.samplesheet = self.request.FILES.get('file')


    def perform_create(self, serializer):
        serializer.save(owner=self.request.user,
                       file=self.request.data.get('file'))


    def perform_update(self, serializer):
        serializer.save(file=self.request.data.get('file'),
                        modifier=self.request.user,
                        status=self.request.data.get('status'),
                        updated=datetime.datetime.now(),
                        processed_date=self.getProcessedDate())


    def getProcessedDate(self):
        processed_date = None
        if self.request.data.get('status') == 1:
            processed_date = datetime.datetime.now()
        return processed_date
