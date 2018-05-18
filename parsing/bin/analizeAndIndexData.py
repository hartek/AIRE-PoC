
#!/usr/bin/env python3
"""
Este script debería de:
 - Pedir al JSOn los datos sin tratar
 - Parsear el pcap que devuelve con el parser
  Subirlo y modificar el estado
"""


import os
import sys
import timeit
import logging
#sys.path.append(os.path.abspath(os.path.dirname(__file__))+'/..')
sys.path.append(os.path.abspath(os.path.dirname(__file__))+'/..')

import conf.ApiRestConfiguration as ApiRestConfiguration
import conf.ElasticConfiguration as ElasticConfiguration
import conf.tokens as TOKENS
from classes.restApiControler import RestApiControler
from classes.elasticControler import AnalyzerElasticControler

FORMAT = '%(asctime)s %(levelname)s %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('analizePcapData')
logger.setLevel(logging.INFO)

def main():
    logger.info("Iniciando el programa de análisis e indexación de datos. HOST-> {}:{}{}. ELKSERVER -> {}:{}/{}".format(
        ApiRestConfiguration.HOST, ApiRestConfiguration.PORT, ApiRestConfiguration.URI,
        ElasticConfiguration.HOST, ElasticConfiguration.ELASTIC_PORT, ElasticConfiguration.INDEX))

    controler = RestApiControler(ApiRestConfiguration)
    elkHandler = AnalyzerElasticControler(ElasticConfiguration, TOKENS)

    listOfData = controler.getParsedData()
    logger.info("Cantidad de paquetes a analizar e indexar: {}".format(len(listOfData)))

    num_ok = 0
    init_time = timeit.default_timer()
    error_data = []
    for data in listOfData:
        id = data.get('id')
        logger.info("- Analizando paquete [#{}]".format(id))
        start_time = timeit.default_timer()
        parsed_json = data.get('parsed_json')

        try:
            # Analiza los datos
            elkHandler.analizeJson(parsed_json)
            logger.info("\t- [OK] Paquete analizado en {}s".format(timeit.default_timer() - start_time))
            start_index = timeit.default_timer()

        except Exception as e:
            raise
            logger.error("Error al analizar los datos: {}".format(str(e)))
            continue

        try:
            # Sube los datos a elasticsearch
            elkHandler.uploadData()
            logger.info("\t- [OK] Datos indexados correctamente en {}s".format(timeit.default_timer() - start_index))
            start_update = timeit.default_timer()

            # Guarda los datos en la rest-api
            json_data = elkHandler.getJsonToStore()
            controler.uploadAnalyzedJson(id, json_data)
            logger.info("\t- [OK] ApiRest actualizada correctamente en {}s".format(timeit.default_timer() - start_update))
            num_ok += 1

            logger.info("\t- Total: {}s".format(timeit.default_timer() - start_time))
        except Exception as e:
            error = "Error al indexar los datos: {}".format(str(e))
            error_data.append(error)
            logger.error("{}".format(error))
            continue

    logger.info('----')
    if len(listOfData):
        logger.info("Proceso finalizado con exito para {}/{} paquetes en {}s".format(num_ok, len(listOfData), timeit.default_timer() - init_time))
    if len(error_data) > 0:
        logger.info("Errores encontrados:")
        for error in error_data:
            logger.info("\t-{}".format(error))

def parsePcapFile(pcap_filename):
    parser = Parser(pcap_filename)

    json_data = parser.extract()
    return json_data


if __name__ == "__main__":
    main()
