from flask import Flask, render_template, request, jsonify, session
import os
import logging
from werkzeug.utils import secure_filename
import json
import extractor_llm
import visualiser

# --- Base directory setup ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Uploads directory setup
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

logging.basicConfig(level=logging.INFO)

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route("/ttps")
def ttps():
    results_path = os.path.join(BASE_DIR, "scripts", "analysis_results.json")
    try:
        with open(results_path, "r") as f:
            data = json.load(f)
            malware = data.get("malware", [])
            ttps = data.get("report_ttps", [])
    except FileNotFoundError:
        malware = []
        ttps = []
    return render_template("ttps.html", malware=malware, ttps=ttps)

@app.route('/visuals')
def visuals():
    return render_template('visuals.html')

@app.route("/feedback", methods=["POST"])
def feedback():
    data = request.get_json()
    q1 = data.get("q1")
    q2 = data.get("q2")
    q3 = data.get("q3")
    experience = data.get("experience")
    feedback_text = data.get("feedback", "").strip()
    if not all([q1, q2, q3, experience]):
        return jsonify({"message": "Please fill all fields."}), 400
    log_path = os.path.join(BASE_DIR, "scripts", "feedback_log.txt")
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"Usefulness: {q1} | Usability: {q2} | Visual Appeal: {q3} | Experience: {experience}\n")
        if feedback_text:
            f.write(f"User Comment: {feedback_text}\n")
        f.write("---\n")
    return jsonify({"message": "✅ Thanks for your feedback!"})

@app.route('/reports')
def reports():
    return render_template('reports.html')

@app.route('/results')
def results():
    return render_template('results.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected for uploading"}), 400
    if file and file.filename.endswith('.pdf'):
        try:
            analysis_data = extractor_llm.analyze_report_data(file)
            if analysis_data.get("error"):
                return jsonify({"error": analysis_data["error"]}), 500
            logging.info("📊 Generating visualizations...")
            visualiser.generate_timeline_viz(analysis_data['timeline_df'])
            visualiser.generate_heatmap_viz(analysis_data['report_ttps'])
            visualiser.generate_malware_ttp_graph_viz(analysis_data['malware'])
            visualiser.generate_mitre_matrix_viz(analysis_data['report_ttps'])
            logging.info("✅ All visualizations generated.")
            session['malware'] = analysis_data['malware']
            session['ttps'] = analysis_data['report_ttps']
            results_path = os.path.join(BASE_DIR, "scripts", "analysis_results.json")
            with open(results_path, "w") as f:
                json.dump({
                    "malware": analysis_data['malware'],
                    "report_ttps": analysis_data['report_ttps']
                }, f, indent=2)
            return jsonify({
                "malware": analysis_data['malware'],
                "report_ttps": analysis_data['report_ttps']
            })
        except Exception as e:
            logging.error(f"An error occurred during analysis: {e}", exc_info=True)
            return jsonify({"error": "An internal server error occurred."}), 500
    return jsonify({"error": "Invalid file type. Please upload a PDF."}), 400

# --- Run App ---
if __name__ == '__main__':
    app.run(debug=True, port=5001)