import subprocess
import speech_recognition as sr
from googletrans import Translator
from pydub import AudioSegment

# Configuration
INPUT_VIDEO_FILE = "your_video_file.mp4"  # Path to your MP4 file
OUTPUT_AUDIO_FILE = "output_audio.wav"
LOOP_INTERVAL = 1800  # 30 minutes in seconds (not used for a single file, but kept for consistency)

def extract_audio_from_video():
    """Extract the audio from the MP4 file and save it as a WAV file."""
    command = [
        'ffmpeg', '-i', INPUT_VIDEO_FILE, '-vn', '-acodec', 'pcm_s16le', OUTPUT_AUDIO_FILE
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
        print("Google Speech
