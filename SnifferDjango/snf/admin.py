from django.contrib import admin
from .models import *
# Register your models here.


admin.site.register(SniffRun)
admin.site.register(Packet)
admin.site.register(Signature)
admin.site.register(NetworkInfo)
admin.site.register(AvgNetworkInfo)
admin.site.register(CheckedPackets)