from extractor import extract_text_from_pdf, extract_ttps, extract_malware
from visualiser import generate_ttp_heatmap, generate_malware_ttp_graph, generate_mitre_matrix_html

text = extract_text_from_pdf("API_REPORT/TA2541_Proofpoint US.pdf")
ttps = extract_ttps(text)
malware = extract_malware(text)

generate_ttp_heatmap([(t['id'], t['description']) for t in ttps])
generate_malware_ttp_graph(malware)
generate_mitre_matrix_html(ttps)
