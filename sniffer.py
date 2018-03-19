
#encoding: UTF-8
#enconding: ISO-8859-1

import pyshark 
import csv
from datetime import datetime
captura = pyshark.LiveCapture(interface="eno1", only_summaries=True)
captura.sniff(packet_count=20)
nome_arquivo = ("dados_sniffer_%s.csv" % (datetime.now()))
with open(nome_arquivo, 'w', newline='') as csvfile:
	fieldnames = ["numero","tempo","origem","destino","protocolo","tamanho","informacao"]
	writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
	writer.writeheader()
	for pkt in captura:
		writer.writerow({
			'numero': pkt.no,
			'tempo': pkt.time,
			'origem': pkt.source,
			'destino': pkt.destination,
			'protocolo': pkt.protocol,
			'tamanho': pkt.length,
			'informacao': pkt.info,
			})

captura.close()
