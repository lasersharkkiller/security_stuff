import subprocess
import time
import speech_recognition as sr
from googletrans import Translator
from pydub import AudioSegment

# Configuration
RTSP_URL = "rtsp://your_rtsp_stream_url"
OUTPUT_AUDIO_FILE = "output_audio.wav"
LOOP_INTERVAL = 1800  # 30 minutes in seconds

def extract_audio():
    """Extract one minute of audio from the RTSP stream and save as a WAV file."""
    command = [
        'ffmpeg', '-i', RTSP_URL, '-t', '60', '-vn', '-acodec', 'pcm_s16le', OUTPUT_AUDIO_FILE
    ]
    subprocess.run(command, check=True)

def transcribe_audio():
    """Transcribe the extracted audio using the SpeechRecognition library."""
    recognizer = sr.Recognizer()

    with sr.AudioFile(OUTPUT_AUDIO_FILE) as source:
        audio = recognizer.record(source)
    
    try:
        transcript = recognizer.recognize_google(audio)
        return transcript
    except sr.UnknownValueError:
        print("Google Speech Recognition could not understand audio")
        return ""
    except sr.RequestError as e:
        print(f"Could not request results from Google Speech Recognition service; {e}")
        return ""

def translate_text(text, target_language='es'):
    """Translate the transcribed text to the target language using googletrans."""
    translator = Translator()
    translation = translator.translate(text, dest=target_language)
    return translation.text

def main_loop():
    """Main loop that runs continuously."""
    while True:
        print("Extracting audio...")
        extract_audio()
        
        print("Transcribing audio...")
        transcript = transcribe_audio()
        print("Transcript:", transcript)
        
        if transcript:
            print("Translating transcript...")
            translated_text = translate_text(transcript)
            print("Translated Text:", translated_text)
        
        # Wait for the next loop cycle (30 minutes)
        time.sleep(LOOP_INTERVAL)

if __name__ == "__main__":
    main_loop()
