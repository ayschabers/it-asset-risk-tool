import csv  #werkzeug für tabellen und csv dateien
import requests #werkzeug für internet anfragen
import time  #steuerung zeit

eingabedatei = "data/assets.csv" #variable mit dateipfad

ergebnisse =  []

gewichtung =  { #wörterbuch
    "niedrig": 1,
    "mittel": 2,
    "hoch": 3,
    "kritisch": 4
}

with open(eingabedatei) as datei: #öffnet datei
    reader = csv.DictReader(datei) #verwanedlt datei in ein verständliches tabellenformat
    for zeile in reader:
        system_name = zeile["system_name"]
        criticality = zeile["criticality"]
        software = zeile["software"]
        version = zeile["version"]
        print("Prüfe " + software + " " + version + " auf " + system_name + " ...")


        url = "https://services.nvd.nist.gov/rest/json/cves/2.0" #US datenbank für sicherheitslücken
        parameter = {"keywordSearch": software + " " + version, "resultsPerPage": 10}#suche nach diesem keyword und gib mir max 10 ergebnisse
        antwort = requests.get(url, params=parameter) #suchanfrage live ans internet ud hängt die paramter dran 
        daten = antwort.json() #wandelt die daten in ein verständliches format um   
        gefundene_lücken = daten.get("vulnerabilities", []) #holt sich die sicherheitslücken aus den daten, "get(..) schaut in daten nach "vulnerabilities" und wenn es das nicht gibt, dann gibt es eine leere liste zurück

        höchster_score = 0
        schlimmste_lücke = None #platzhalter für ID der Lücke

        for eintrag in gefundene_lücken:#alle sicherheitslücken durchgehen
           cve = eintrag["cve"] #holt sich die cve id aus dem eintrag
           metriken = cve.get("metrics", {}) #holt sich die bewertungssysteme der Lücke
           score = None

           if "cvssMetricV31" in metriken:
               score = metriken["cvssMetricV31"][0]["cvssData"]["baseScore"]
           elif "cvssMetricV30" in metriken:
              score = metriken["cvssMetricV30"][0]["cvssData"]["baseScore"]
           elif "cvssMetricV2" in metriken:
              score = metriken["cvssMetricV2"][0]["cvssData"]["baseScore"]  #prüft welche bewertungsmethode vorhanden
      
           if score is not None and score > höchster_score:  #prüft ob score vorhanden ist und ob er höher ist als der bisher höchste score
             höchster_score = score
             schlimmste_lücke = cve["id"]  #holt sich die id der schlimmsten lücke

             risiko = höchster_score * gewichtung[criticality]  #berechnet das risiko aus score und kritikalität

             ergebnisse.append({
             "system_name": system_name,
             "software": software,
             "version": version,
             "criticality": criticality,
             "hoechster_cvss": höchster_score,
             "schlimmste_cve": schlimmste_lücke,
             "risiko_score": risiko
}) #speichert berechnete daten ab
             time.sleep(6) #wartet 6 sekunden um vor Ip Sperren zu schützen von NVD-Datenbank

#jetzt sortieren
def risiko_wert(eintrag):
    return eintrag["risiko_score"]  #gibt den risiko score zurück


ergebnisse.sort(key=risiko_wert, reverse=True)  #sortiert liste absteigend

with open("output/risk_report.csv","w", newline="") as ausgabedatei: #erstellt zieldatei und output/risk_report.csv ist das ziel, w steht für write und wenn datei schon existiert wird sie überschrieben
    spalten = ["system_name", "software", "version", "criticality", "hoechster_cvss", "schlimmste_cve", "risiko_score"]
    writer = csv.DictWriter(ausgabedatei, fieldnames=spalten) #erstellt ein writer objekt
    writer.writeheader() #schreibt die spaltenüberschriften in die datei
    writer.writerows(ergebnisse) #schreibt die ergebnisse in die datei  

print("Fertig! Ergebnisse stehen in output/risk_report.csv")
