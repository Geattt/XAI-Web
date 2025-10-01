# XAI-Web
Our project, “XAI-Based Ransomware Detection: A New Breakthrough in Machine Learning,” addresses these challenges by integrating machine learning with explainable AI (XAI). The system not only improves detection accuracy but also explains the specific behaviors and characteristics that classify a file as ransomware, making the process more transparent and trustworthy. This combination empowers users to better understand, respond to, and prevent ransomware threats.

# 🚀 Demo Instructions

Follow the steps below to run and test the web application locally:

### 1️⃣ Install Dependencies

Make sure you have **Python 3.9+** installed. Then install the required packages:

```bash
pip install flask joblib numpy pandas scikit-learn==1.6.1 shap
```

### 2️⃣ Configure the Project Path

Open `server.py` and update the `BASE_PATH` variable to the absolute path where you placed this project folder.

For example:

```python
BASE_PATH = "C:/Users/YourName/Projects/Website"
```

### 3️⃣ Start the Server

Run the application with:

```bash
python server.py
```
<img width="935" height="30" alt="image" src="https://github.com/user-attachments/assets/4ce83d42-9d9c-4054-bc98-17ada130ee74" />

The web app will start, usually accessible by clicking the `index.html`.

### 4️⃣ Upload a File

* Navigate to the **Dashboard Tab**.
* Upload a `.exe` or `.dll` file that you want to analyze.

  <img width="2559" height="1195" alt="image" src="https://github.com/user-attachments/assets/97546113-8b1c-4330-9891-741a15a7b313" />


### 5️⃣ View Results

* Go to the **Result Tab**.
* You will see the following output:

📊 Analysis Results

**Malicious Probability** → likelihood the file is malicious

**Risk Score** → risk severity based on probability thresholds

**Prediction Confidence** → confidence level of the model

**Processing Time** → how long the analysis took

<img width="1971" height="792" alt="image" src="https://github.com/user-attachments/assets/d14ef25c-8969-439d-9534-dbafe107ff9f" />


🤖 Model Information

**The machine learning model used for prediction**

**XAI Explanation (SHAP)** → shows why the model flagged the file as malicious

<img width="1533" height="1060" alt="image" src="https://github.com/user-attachments/assets/b3d2925d-f888-49e7-a682-c0ed409bb6b2" />

🛠 Technical Details (example)

File Hash: 44e770de753f3ef0d96d0efef328710c1b674f976cffd9fd89148795a6cc50cf
File Size: 85.66 KB
Analysis Time: 10/1/2025, 10:36:24 AM
Features Analyzed: 55

<img width="1481" height="772" alt="image" src="https://github.com/user-attachments/assets/b0c6f04d-d3c0-4492-95b0-5c728f9c7dde" />


### 6️⃣ Check History

* Open the **History Tab** to review all previously uploaded files and their results.
<img width="715" height="545" alt="image" src="https://github.com/user-attachments/assets/6ab2f670-bd4e-4d12-8c7e-76689f46086a" />

---

👉 This setup allows you to quickly test the model’s detection capability, interpret predictions, and track past analyses.

---

