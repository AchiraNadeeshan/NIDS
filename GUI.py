import PySimpleGUI as sg
import joblib
import pandas as pd
from scapy.all import sniff, IP, TCP
from threading import Thread, Event
import queue
from sklearn.preprocessing import LabelEncoder
import warnings
from sklearn.exceptions import InconsistentVersionWarning

warnings.filterwarnings("ignore", category=InconsistentVersionWarning)


# Load the pre-trained model
loaded_model = joblib.load('random_forest_model.pkl')

# Initialize global variables
df_live_data = None

# Define the function to process packets and match with the required features
def process_packet(packet):
    feature_vector = {
        'duration': 0,
        'protocol_type': packet[IP].proto if IP in packet else 0,
        'flag': packet[IP].flags if IP in packet else 0,
        'src_bytes': len(packet[IP].payload) if IP in packet else 0,
        'dst_bytes': 0,
        'land': 1 if IP in packet and packet[IP].src == packet[IP].dst else 0,
        'wrong_fragment': packet[IP].frag if IP in packet else 0,
        'urgent': packet[TCP].urgptr if TCP in packet else 0,
        'hot': 0,
        'num_failed_logins': 0,
        'logged_in': 0,
        'num_compromised': 0,
        'root_shell': 0,
        'su_attempted': 0,
        'num_file_creations': 0,
        'num_shells': 0,
        'num_access_files': 0,
        'num_outbound_cmds': 0,
        'is_host_login': 0,
        'is_guest_login': 0,
        'count': 1,
        'srv_count': 1,
        'serror_rate': 0,
        'rerror_rate': 0,
        'same_srv_rate': 0,
        'diff_srv_rate': 0,
        'srv_diff_host_rate': 0,
        'dst_host_count': 0,
        'dst_host_srv_count': 0,
        'dst_host_diff_srv_rate': 0,
        'dst_host_same_src_port_rate': 0,
        'dst_host_srv_diff_host_rate': 0,
        'target': 0,
        'Attack Type': 'normal',
    }
    
    return feature_vector

# Function to capture packets and process them
def capture_live_traffic(packet_count=10, iface=None, output_queue=None):
    global df_live_data
    packets = sniff(count=packet_count, iface=iface)
    features = [process_packet(packet) for packet in packets]
    df_live_data = pd.DataFrame(features)
    
    # Manually define the expected feature names (replace with actual feature names)
    model_columns = ['duration', 'protocol_type', 'flag', 'src_bytes', 'dst_bytes', 'land',
                     'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
                     'num_compromised', 'root_shell', 'su_attempted', 'num_file_creations',
                     'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
                     'is_guest_login', 'count', 'srv_count', 'serror_rate', 'rerror_rate',
                     'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
                     'dst_host_count', 'dst_host_srv_count', 'dst_host_diff_srv_rate',
                     'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate']

    # Subset df_live_data to only include the expected features
    df_live_data = df_live_data[model_columns]

    # Apply label encoding to categorical features if necessary
    label_encoders = {}
    for column in df_live_data.columns:
        if df_live_data[column].dtype == 'object':
            le = LabelEncoder()
            df_live_data[column] = le.fit_transform(df_live_data[column].astype(str))
            label_encoders[column] = le  # Save encoder for potential inverse transformation

    # Ensure the DataFrame is fully numeric
    df_live_data = df_live_data.apply(pd.to_numeric)

    # Convert DataFrame to a CSV string with comma separation
    csv_data = df_live_data.to_csv(index=False, sep=',')

    # Convert DataFrame to numpy array
    X_live = df_live_data.values

    # Apply the model to the preprocessed live data
    predictions = loaded_model.predict(X_live)
    
    # Prepare the output
    output_queue.put(csv_data)
    output_queue.put("Predictions: " + ", ".join(map(str, predictions)))

# Define the UI layout
layout = [
    [sg.Text("Network Intrusion Detection System", font=("Helvetica", 16))],
    [sg.Button("Start Capturing", key="start_capture"), sg.Button("Stop Capturing", key="stop_capture"),
     sg.Button("Inject Malicious Data", key="inject_malicious")],
    [sg.Text("Scapy Captured Data", font=("Helvetica", 14))],
    [sg.Multiline(size=(80, 15), key="scapy_data", autoscroll=True, disabled=True)],
    [sg.Text("Predictions", font=("Helvetica", 14))],
    [sg.Multiline(size=(80, 5), key="predictions", autoscroll=True, disabled=True)],
    [sg.Text("", size=(80, 1), key="status")],
    [sg.Button("Reset", key="reset"), sg.Button("Exit")]
]

# Create the window
window = sg.Window("NIDS Interface", layout)

# Queue for communication between threads
output_queue = queue.Queue()
stop_event = Event()
capture_thread = None

# Function to handle the UI update
def update_ui():
    try:
        while True:
            output = output_queue.get_nowait()
            if "Predictions: " in output:
                window["predictions"].update(output + "\n", append=True)
            else:
                window["scapy_data"].update(output + "\n\n", append=True)
    except queue.Empty:
        pass

# Function to inject malicious data and get prediction
def inject_malicious_data(df_live_data):
    malicious_data = df_live_data.copy()
    
    # Attack 1
    malicious_data.iloc[1, malicious_data.columns.get_loc('duration')] = 0
    malicious_data.iloc[1, malicious_data.columns.get_loc('protocol_type')] = 1  # tcp
    malicious_data.iloc[1, malicious_data.columns.get_loc('flag')] = 0  # S0
    malicious_data.iloc[1, malicious_data.columns.get_loc('src_bytes')] = 0
    malicious_data.iloc[1, malicious_data.columns.get_loc('dst_bytes')] = 0
    
    # Convert DataFrame to numpy array
    X_malicious = malicious_data.values
    
    # Get predictions
    predictions = loaded_model.predict(X_malicious)
    
    return predictions

# Function to reset the UI and variables
def reset_all():
    global df_live_data
    df_live_data = None
    window["scapy_data"].update("")
    window["predictions"].update("")
    window["status"].update("")
    output_queue.queue.clear()  # Clear the output queue

while True:
    event, values = window.read(timeout=100)
    
    if event in (sg.WIN_CLOSED, "Exit"):
        stop_event.set()
        if capture_thread and capture_thread.is_alive():
            capture_thread.join()
        break
    
    if event == "start_capture":
        # Start capturing live traffic
        iface = 'Intel(R) Wi-Fi 6 AX201 160MHz'
        if not capture_thread or not capture_thread.is_alive():
            stop_event.clear()
            capture_thread = Thread(target=capture_live_traffic, args=(10, iface, output_queue), daemon=True)
            capture_thread.start()
            window["status"].update("Capturing traffic...")
    
    if event == "stop_capture":
        stop_event.set()
        if capture_thread and capture_thread.is_alive():
            capture_thread.join()
        window["status"].update("Stopped capturing traffic.")
    
    if event == "inject_malicious":
        # Inject malicious data and get prediction
        if df_live_data is not None:
            predictions = inject_malicious_data(df_live_data)
            window["status"].update("Injecting Malicious Data...")
            window["predictions"].update("Predictions: " + ", ".join(map(str, predictions)))
        else:
            sg.popup("Error", "No data available for injection.")
    
    if event == "reset":
        # Reset the UI and variables
        reset_all()

    # Update the UI with captured data and predictions
    update_ui()

window.close()
