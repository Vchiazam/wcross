from dotenv import load_dotenv
import os
load_dotenv()
DB_NAME = os.environ.get("DB_NAME")
DB_USER_AND_PASSWORD=os.environ.get("DB_USER_AND_PASSWORD")
DB_HOST = os.environ.get("DB_HOST")
ADMIN_AUTH = os.environ.get("ADMIN_AUTH")
USER_AUTH = os.environ.get("USER_AUTH")
ADMIN_RESET_AUTH = os.environ.get("ADMIN_RESET_AUTH")
USER_RESET_AUTH = os.environ.get("USER_RESET_AUTH")