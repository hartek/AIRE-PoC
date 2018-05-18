#! /usr/bin/env python3
# serializers.py

import os
from datetime import datetime
from rest_framework import serializers, status
from rest_framework.response import Response
import dpkt
from .models import PcapFile

class PcapFileSerializer(serializers.ModelSerializer):

    class Meta:
        model = PcapFile
        fields = ('id', 'file', 'name', 'description', 'created', 'updated', 'size', 'owner', 'status', 'parsed_json', 'analyzed_date', 'analyzed_json')
        read_only_fields = ('id', 'name', 'created', 'updated', 'size')


    def validate(self, validated_data):
        validated_data['owner'] = self.context['request'].user
        if 'file' in validated_data and validated_data['file']:
            validated_data['name'] = os.path.splitext(validated_data['file'].name)[0]
            validated_data['size'] = validated_data['file'].size
        return validated_data


    def create(self, validated_data):
        # If pcap is not valid, raise exception
        self.checkValidPcapFile(validated_data['file']);

        return PcapFile.objects.create(**validated_data)


    def update(self, instance, validated_data):
        #instance.modifier = self.context['request'].user
        instance.name = validated_data.get('name', instance.name)
        instance.description = validated_data.get('description', instance.file)
        file_aux = validated_data.get('file', instance.file)
        if file_aux and file_aux != '':
            instance.file = file_aux
            instance.size = instance.file.size

        old_status = instance.status
        instance.status = validated_data.get('status', instance.status)

        if old_status in [0,-1] and instance.status == 1:
            instance.parsed_date = datetime.now()
            instance.parsed_json = validated_data.get('parsed_json', instance.parsed_json)

        elif old_status == 1 and instance.status == 2:
            instance.analyzed_date = datetime.now()
            instance.analyzed_json = validated_data.get('analyzed_json', instance.analyzed_json)

        instance.save()
        return instance


    def checkValidPcapFile(self, file):

        try: 
            pkts = dpkt.pcap.Reader(file)
            return True
        except Exception as msg: 
            error = "Invalid PCAP file"
            raise serializers.ValidationError(error)
