import os
import queue
import sounddevice as sd
import vosk
import json
from transformers import MarianMTModel, MarianTokenizer

# Path to your downloaded Mandarin Vosk model
MODEL_PATH = "path_to_your_mandarin_vosk_model"

# Initialize Vosk model
if not os.path.exists(MODEL_PATH):
    print(f"Please download the model from https://alphacephei.com/vosk/models and unpack as {MODEL_PATH}")
    exit(1)

model = vosk.Model(MODEL_PATH)
sample_rate = 16000

# Initialize MarianMT model and tokenizer
translation_model_name = "Helsinki-NLP/opus-mt-zh-en"
translation_tokenizer = MarianTokenizer.from_pretrained(translation_model_name)
translation_model = MarianMTModel.from_pretrained(translation_model_name)

# Define audio stream callback
q = queue.Queue()

def callback(indata, frames, time, status):
    if status:
        print(status, file=sys.stderr)
    q.put(bytes(indata))

# Function to translate text from Chinese to English
def translate_text(text):
    translated = translation_model.generate(**translation_tokenizer.prepare_seq2seq_batch([text], return_tensors="pt"))
    return translation_tokenizer.decode(translated[0], skip_special_tokens=True)

# Create an audio stream
def main():
    with sd.RawInputStream(samplerate=sample_rate, blocksize=8000, dtype='int16',
                           channels=1, callback=callback):
        print('#' * 80)
        print('Press Ctrl+C to stop the recording')
        print('#' * 80)

        rec = vosk.KaldiRecognizer(model, sample_rate)
        while True:
            data = q.get()
            if rec.AcceptWaveform(data):
                result = json.loads(rec.Result())
                mandarin_text = result.get("text", "")
                print("Transcript in Mandarin:", mandarin_text)
                if mandarin_text:
                    english_translation = translate_text(mandarin_text)
                    print("Translation in English:", english_translation)
            else:
                partial_result = json.loads(rec.PartialResult())
                print("Partial transcript:", partial_result.get("partial", ""))

if __name__ == "__main__":
    main()
