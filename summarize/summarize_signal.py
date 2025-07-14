import os
import sqlite3
import pandas as pd
from transformers import pipeline

# ======= CONFIG ========
CONTACT_FILTER = None # e.g., "Alice" or "Bob" or None for all
NUM_MESSAGES = 100 # Number of latest messages to summarize
DB_PATH = os.path.expanduser("~/.config/Signal/sql/db.sqlite")
# =======================

def extract_messages(db_path, contact=None, limit=100):
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Signal DB not found at {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    base_query = """
    SELECT messages.timestamp, messages.body, conversations.name
    FROM messages
    JOIN conversations ON messages.conversationId = conversations.id
    WHERE messages.body IS NOT NULL
    """

    params = []
    if contact:
        base_query += " AND conversations.name = ?"
        params.append(contact)
    
    base_query += " ORDER BY messages.timestamp DESC LIMIT ?"
    params.append(limit)

    df = pd.read_sql_query(base_query, conn, params=params)
    conn.close()
    return df

def summarize_text(text):
    summarizer = pipeline("summarization", model="facebook/bart-large-cnn")
    summary = summarizer(text, max_length=200, min_length=60, do_sample=False)
    return summary[0]['summary_text']

def main():
    print(f" Reading Signal database: {DB_PATH}")
    if CONTACT_FILTER:
        print(f" Filtering messages with: {CONTACT_FILTER}")
    
    df = extract_messages(DB_PATH, contact=CONTACT_FILTER, limit=NUM_MESSAGES)

    if df.empty:
        print(" No messages found for the given filter.")
        return

    combined_text = "\n".join(df['body'].dropna().tolist())
    print(f"\n Summarizing last {len(df)} messages...\n")
    summary = summarize_text(combined_text)

    print("Summary:\n")
    print(summary)

if __name__ == "__main__":
    main()
