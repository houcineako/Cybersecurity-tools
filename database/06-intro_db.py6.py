"""
Introduction à SQLite: crée une table, insère des données dans la table, puis récupère les données.
"""

# Import the SQLite3 module
import sqlite3

# Connect to SQLite database (or create if it doesn't exist)
conn = sqlite3.connect('demo_ciper.db')

# Create a cursor object to interact with the database
cursor = conn.cursor()

# Create a table if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS demo_ciper (
        id INTEGER PRIMARY KEY,
        name TEXT,
        age INTEGER
    )
''')

# Insert data into the table
data_to_insert = [
    ('Tim', 25),
    ('Charlie', 30),
    ('Alice', 22)
]

cursor.executemany('INSERT INTO demo_ciper (name, age) VALUES (?, ?)', data_to_insert)

# Commit the changes to the database
conn.commit()

# Select and display the data
cursor.execute('SELECT * FROM demo_ciper')
rows = cursor.fetchall()

# Display the header
print("ID | Name    | Age")
print("-" * 20)

# Display each row of data
for row in rows:
    print(f"{row[0]}  | {row[1]}  | {row[2]}")

# Close the database connection
conn.close()