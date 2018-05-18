#!/usr/bin/env python3
"""
Este script debe de:
    - Pedir los JSON que estén sin analizar al servicio REST del servidor
    - Debe de iterar por cada mac:
        + Comprobando si existe en la DB.
        + Si existe, actualizar con los nuevos datos. Si no, subir desde 0.
        + Para extraer los datos:
            1. Mira el dispositivo.
            2. Mira el los datos que puede obtener.
            3. Extrae la info del pcap de json.
            4. Lo carga.
"""

import shutil
import click
import os, sys, json
sys.path.append(os.path.abspath(os.path.dirname(__file__))+'/..')
import conf.ApiRestConfiguration as ApiRestConfiguration
from classes.restApiControler import RestApiControler
from classes.pcapParser import PcapParser as Parser

import logging
FORMAT = '%(asctime)s %(levelname)s %(message)s'
#logging.basicConfig(filename="parsing.log", format=FORMAT)
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('parsePcapService')
logger.setLevel(logging.INFO)

import timeit


FILE_NAME = '/tmp/pcapfile.pcap'

@click.command()
@click.option('--errors','-e', type=bool, default=True)
@click.option('--newdata','-n', type=bool, default=True)
def main(newdata, errors):
    logger.info("Iniciando el programa de parseo de pcaps. HOST-> {}:{}{}".format(ApiRestConfiguration.HOST, ApiRestConfiguration.PORT, ApiRestConfiguration.URI))

    controler = RestApiControler(ApiRestConfiguration)

    listOfData = []
    if newdata == True:
        listOfData = controler.getNotParsedData() # status = new
        logger.info("\t - Archivos pcap a parsear nuevos: {}".format(len(listOfData)))

    if errors == True:
        dataWithErrors = controler.getDataWithErrors() # status = with error
        logger.info("\t - Archivos pcap a parsear con error: {}".format(len(dataWithErrors)))
        listOfData += dataWithErrors

    if len(listOfData) == 0:
        logger.info("\t - No se han encontrado archivos pcap que parsear. Saliendo!")

    num_ok = 0
    error_data = []
    for data in listOfData:
        # 1. Cojo el archivo.
        id = data.get('id')
        logger.info("Parseando el archivo [#{}]: {}".format(id, data.get('file')))
        start_time = timeit.default_timer()
        try:
            data = controler.getPcapData(id)
            with open(FILE_NAME, 'wb') as file:
                shutil.copyfileobj(data, file)

                size = os.path.getsize(FILE_NAME)
                logger.info("\t - Tamaño del archivo: {}Mb".format(size/(1024*1024)))

                json_data = parsePcapFile(FILE_NAME)
                logger.info("\t - Archivo parseado correctamente en {}s".format(timeit.default_timer() - start_time))

                upload_time = timeit.default_timer()
                controler.uploadParsedJson(id, json_data)
                logger.info("\t - Archivo subido correctamente en {}s".format(timeit.default_timer() - upload_time))

                # Elimina el archivo residual
                file.close()
                os.remove(FILE_NAME)
                num_ok += 1
        except Exception as e:
            error = "Error al parsear el archivo de ID#{}: {}".format(id, str(e))
            error_data.append(error)
            logger.error("\t{}".format(error))
            controler.setFileAsError(id)

    logger.info("----")
    logger.info("Proceso finalizado con exito para {}/{} paquetes".format(num_ok, len(listOfData)))
    if len(error_data) > 0:
        logger.info("- Errores en el parseo:")
    for error in error_data:
        logger.info("\t {}".format(error))

def parsePcapFile(pcap_filename):
    parser = Parser(pcap_filename)

    json_data = parser.extract()
    logger.debug("\t - JSON_DATA:\t{}".format(json_data))

    return json.loads(json_data)


if __name__ == "__main__":
    main()
