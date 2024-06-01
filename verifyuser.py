import os
import psycopg2
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database connection parameters
DATABASE_URL = os.getenv('DATABASE_URL')

def verify_user(username):
    try:
        # Connect to the PostgreSQL database
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()

        # Update the user's is_verified status to true
        cur.execute("""
            UPDATE users
            SET is_verified = TRUE
            WHERE username = %s;
        """, (username,))

        # Commit the transaction
        conn.commit()

        # Close the cursor and connection
        cur.close()
        conn.close()

        print(f"User '{username}' has been verified.")

    except psycopg2.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Ask for the username in the terminal
    username_to_verify = input("Enter the username to verify: ")
    verify_user(username_to_verify)
