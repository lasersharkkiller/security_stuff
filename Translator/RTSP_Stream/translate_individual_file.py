import subprocess
import os
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
        # Specify 'zh-CN' for Mandarin Chinese transcription
        transcript = recognizer.recognize_google(audio, language="zh-CN")
        return transcript
    except sr.UnknownValueError:
        print("Google Speech Recognition could not understand audio")
        return ""
    except sr.RequestError as e:
        print(f"Could not request results from Google Speech Recognition service; {e}")
        return ""

def translate_text(text, target_language='en'):
    """Translate the transcribed text to the target language using googletrans."""
    translator = Translator()
    translation = translator.translate(text, dest=target_language)
    return translation.text

def process_video_file():
    """Process the MP4 file: extract audio, transcribe in Mandarin, translate to English, and delete the audio file."""
    print("Extracting audio from video...")
    extract_audio_from_video()
    
    print("Transcribing audio (Mandarin)...")
    transcript = transcribe_audio()
    print("Transcript (Mandarin):", transcript)
    
    if transcript:
        print("Translating transcript to English...")
        translated_text = translate_text(transcript)
        print("Translated Text (English):", translated_text)

    # Delete the audio file after processing
    if os.path.exists(OUTPUT_AUDIO_FILE):
        os.remove(OUTPUT_AUDIO_FILE)
        print(f"Deleted temporary audio file: {OUTPUT_AUDIO_FILE}")
    else:
        print(f"The file {OUTPUT_AUDIO_FILE} does not exist.")

if __name__ == "__main__":
    process_video_file()
