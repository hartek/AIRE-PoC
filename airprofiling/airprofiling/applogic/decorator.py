from django.shortcuts import render_to_response as render
from django.template import RequestContext


def template(template):
    def wrapper(view):
        def call(request, *args, **kwargs):
            context = {}
            ret = view(request, context, *args, **kwargs)
            if ret: return(ret)
            return(render(template, RequestContext(request, context)))
        return call
    return wrapper
