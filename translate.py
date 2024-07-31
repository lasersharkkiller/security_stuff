import os
import queue
import sounddevice as sd
import vosk
import json

# Path to your downloaded Mandarin model
MODEL_PATH = "path_to_your_mandarin_vosk_model"

# Initialize Vosk model
if not os.path.exists(MODEL_PATH):
    print(f"Please download the model from https://alphacephei.com/vosk/models and unpack as {MODEL_PATH}")
    exit(1)

model = vosk.Model(MODEL_PATH)
sample_rate = 16000

# Define audio stream callback
q = queue.Queue()

def callback(indata, frames, time, status):
    if status:
        print(status, file=sys.stderr)
    q.put(bytes(indata))

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
                print("Transcript:", result.get("text", ""))
            else:
                partial_result = json.loads(rec.PartialResult())
                print("Partial transcript:", partial_result.get("partial", ""))

if __name__ == "__main__":
    main()
