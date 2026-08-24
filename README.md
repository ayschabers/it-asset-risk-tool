Was es macht: 
 liest eine Liste von Systemen aus einer CSV-Datei ein (Software, Version, Kritikalität),
 fragt für jede Software live bekannte Sicherheitslücken über die NVD-API ab,
 wertet den CVSS-Score der gefundenen Lücken aus,
 berechnet daraus zusammen mit der Systemkritikalität einen Risiko-Score,
 exportiert alles sortiert als CSV-Report

 Verwendung: 
CSV-Datei unter data/assets.csv anlegen (Spalten: system_name, software, version, criticality), dann pip install requests.python main.py.
Ergebnis liegt danach in output/risk_report.csv.

Was ich dabei gelernt habe: Erster echter Kontakt mit einer API und mit CVSS-Bewertungen vor allem, wie man Daten aus mehreren möglichen Formaten (CVSS v2, v3.0, v3.1) sauber abfängt, ohne dass das Skript bei fehlenden Werten abstürzt.
