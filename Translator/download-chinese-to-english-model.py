from transformers import MarianMTModel, MarianTokenizer

# Model name for Chinese to English translation
model_name = "Helsinki-NLP/opus-mt-zh-en"

# Download and load the model and tokenizer
tokenizer = MarianTokenizer.from_pretrained(model_name)
model = MarianMTModel.from_pretrained(model_name)

print("Model and tokenizer downloaded successfully.")
