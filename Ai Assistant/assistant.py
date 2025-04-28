import speech_recognition as sr
import pyttsx3
import datetime
import webbrowser
from googlesearch import search
import wikipedia
import psutil
import socket
import subprocess

engine = pyttsx3.init()
engine.setProperty('rate', 150) 
engine.setProperty('volume', 0.9) 
recognizer = sr.Recognizer()
mic = sr.Microphone()

def speak(text):
    engine.say(text) 
    engine.runAndWait() 
    print(f"Output (Text): {text}")

def check_wifi_connection():
    try:
        socket.create_connection(("8.8.8.8", 53))
        speak("You are connected to the internet.")
        print("WiFi Status (Text): Connected")
    except OSError:
        speak("You are not connected to the internet.")
        print("WiFi Status (Text): Not Connected")

def check_bluetooth_devices():
    try:
        devices = subprocess.check_output(
            'PowerShell "Get-PnpDevice -Class Bluetooth | Where-Object { $_.Status -eq \'OK\' }"',
            shell=True
        ).decode()

        if devices.strip():
            speak("There are Bluetooth devices connected.")
            print(f"Bluetooth Devices (Text):\n{devices}")
        else:
            speak("No Bluetooth devices are connected.")
            print("Bluetooth Devices (Text): None connected.")
    except Exception as e:
        speak(f"An error occurred while checking Bluetooth devices: {e}")
        print(f"Error (Text): {e}")

def listen():
    with mic as source:
        recognizer.adjust_for_ambient_noise(source, duration=1)
        print("Listening for a command...")
        audio = recognizer.listen(source)
    try:
        command = recognizer.recognize_google(audio)
        print(f"Recognized (Text): {command}")
        return command.lower()
    except sr.UnknownValueError:
        speak("Sorry, I did not understand that.")
        return ""
    except sr.RequestError as e:
        speak(f"Could not request results; {e}")
        return ""

def get_battery_status():
    battery = psutil.sensors_battery()
    if battery is None:
        speak("Sorry, I couldn't retrieve the battery information.")
        print("Battery Info (Text): None")
        return

    battery_percent = battery.percent
    battery_plugged = battery.power_plugged

    status = f"The battery is at {battery_percent} percent and is currently {'charging' if battery_plugged else 'not charging'}."
    speak(status)
    print(f"Battery Status (Text): {status}")

def perform_google_search(query):
    try:
        results = list(search(query, num_results=1))
        if results:
            top_result = results[0]

            if 'wikipedia' in top_result:
                try:
                    wiki_summary = wikipedia.summary(query, sentences=1)
                    speak(f"Here's the Wikipedia summary for {query}: {wiki_summary}")
                    print(f"Google Search Result (Text): {wiki_summary}")
                except wikipedia.exceptions.DisambiguationError as e:
                    speak("There were multiple Wikipedia pages, please specify more.")
                    print(f"Disambiguation Error (Text): {e}")
                except wikipedia.exceptions.HTTPTimeoutError:
                    speak("Sorry, I couldn't retrieve the Wikipedia page.")
                    print("Wikipedia HTTP Timeout Error (Text)")
                except wikipedia.exceptions.RequestError as e:
                    speak(f"An error occurred while fetching Wikipedia data: {e}")
                    print(f"Wikipedia Request Error (Text): {e}")
            else:
                webbrowser.open(top_result)
                speak(f"I found something for {query}, opening it now.")
                print(f"Google Search Result (Text): {top_result}")
        else:
            speak("Sorry, I couldn't find any results.")
            print("Google Search Result (Text): Sorry, I couldn't find any results.")
    except Exception as e:
        speak(f"An error occurred while performing the search: {e}")
        print(f"Error (Text): {e}")


def handle_command(command):
    if 'time' in command:
        current_time = datetime.datetime.now().strftime('%I:%M %p')
        speak(f"The current time is {current_time}")
        print(f"Current Time (Text): {current_time}")
    elif 'battery' in command:
        get_battery_status()
    elif 'open youtube' in command:
        webbrowser.open('https://www.youtube.com')
        speak("Opening YouTube")
        print("Opening YouTube (Text): https://www.youtube.com")
    elif 'open google' in command:
        webbrowser.open('https://www.google.com')
        speak("Opening Google")
        print("Opening Google (Text): https://www.google.com")
    elif 'exit' in command or 'quit' in command:
        speak("Goodbye!")
        print("Goodbye (Text): Exiting...")
        exit()
    elif 'wifi' in command:
        check_wifi_connection()
    elif 'bluetooth' in command:
        check_bluetooth_devices()
    else:
        speak("I can search that for you.")
        perform_google_search(command)
    

def main():
    speak("Hello, how can I assist you?")
    print("Assistant started...")
    while True:
        command = listen()
        if command:
            handle_command(command)

if __name__ == "__main__":
    main()