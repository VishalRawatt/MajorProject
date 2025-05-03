import os
import datetime
import socket
import subprocess
import pyttsx3
import speech_recognition as sr
import webbrowser
from googlesearch import search
import wikipedia
import psutil

from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


private_key = x448.X448PrivateKey.generate()
peer_public_key = x448.X448PrivateKey.generate().public_key()

shared_key = private_key.exchange(peer_public_key)

derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'voice-assistant',
).derive(shared_key)

# AES-GCM encryption/decryption functions
def encrypt_message(message: str):
    nonce = os.urandom(12)
    aesgcm = AESGCM(derived_key)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
    return nonce, ciphertext

def decrypt_message(nonce, ciphertext):
    aesgcm = AESGCM(derived_key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

# Voice and speech setup
engine = pyttsx3.init()
engine.setProperty('rate', 150)
engine.setProperty('volume', 0.9)
recognizer = sr.Recognizer()
mic = sr.Microphone()

def speak_encrypted(text):
    nonce, encrypted = encrypt_message(text)
    decrypted = decrypt_message(nonce, encrypted)
    engine.say(decrypted)
    engine.runAndWait()
    print(f"[Encrypted]: {encrypted}")
    print(f"[Decrypted]: {decrypted}")

def check_wifi_connection():
    try:
        socket.create_connection(("8.8.8.8", 53))
        speak_encrypted("You are connected to the internet.")
    except OSError:
        speak_encrypted("You are not connected to the internet.")

def check_bluetooth_devices():
    try:
        devices = subprocess.check_output(
            'PowerShell "Get-PnpDevice -Class Bluetooth | Where-Object { $_.Status -eq \'OK\' }"',
            shell=True
        ).decode()
        if devices.strip():
            speak_encrypted("There are Bluetooth devices connected.")
        else:
            speak_encrypted("No Bluetooth devices are connected.")
    except Exception as e:
        speak_encrypted(f"Error while checking Bluetooth: {e}")

def get_battery_status():
    battery = psutil.sensors_battery()
    if battery is None:
        speak_encrypted("Battery information unavailable.")
        return
    percent = battery.percent
    plugged = battery.power_plugged
    status = f"Battery is at {percent}% and is {'charging' if plugged else 'not charging'}."
    speak_encrypted(status)

def perform_google_search(query):
    try:
        results = list(search(query, num_results=1))
        if results:
            top_result = results[0]
            if 'wikipedia' in top_result:
                try:
                    summary = wikipedia.summary(query, sentences=1)
                    speak_encrypted(f"According to Wikipedia: {summary}")
                except Exception as e:
                    speak_encrypted(f"Could not retrieve Wikipedia info: {e}")
            else:
                webbrowser.open(top_result)
                speak_encrypted(f"Opening result for {query}")
        else:
            speak_encrypted("No results found.")
    except Exception as e:
        speak_encrypted(f"Error during search: {e}")

def listen():
    with mic as source:
        recognizer.adjust_for_ambient_noise(source, duration=1)
        print("Listening...")
        audio = recognizer.listen(source)
    try:
        command = recognizer.recognize_google(audio)
        return command.lower()
    except:
        speak_encrypted("Sorry, I did not understand.")
        return ""

def handle_command(command):
    nonce, enc = encrypt_message(command)
    decrypted_command = decrypt_message(nonce, enc)

    print(f"User Command [Encrypted]: {enc}")
    print(f"User Command [Decrypted]: {decrypted_command}")

    if 'time' in decrypted_command:
        now = datetime.datetime.now().strftime('%I:%M %p')
        speak_encrypted(f"The time is {now}")
    elif 'battery' in decrypted_command:
        get_battery_status()
    elif 'open youtube' in decrypted_command:
        webbrowser.open("https://www.youtube.com")
        speak_encrypted("Opening YouTube")
    elif 'open google' in decrypted_command:
        webbrowser.open("https://www.google.com")
        speak_encrypted("Opening Google")
    elif 'wifi' in decrypted_command:
        check_wifi_connection()
    elif 'bluetooth' in decrypted_command:
        check_bluetooth_devices()
    elif 'exit' in decrypted_command or 'quit' in decrypted_command:
        speak_encrypted("Goodbye!")
        exit()
    else:
        speak_encrypted("Searching online...")
        perform_google_search(decrypted_command)

def main():
    speak_encrypted("Hello, how can I assist you?")
    while True:
        command = listen()
        if command:
            handle_command(command)

if __name__ == "__main__":
    main()
