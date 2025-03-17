import os
from twilio.rest import Client
from dotenv import load_dotenv

# Cargar las variables de entorno
load_dotenv()

class WhatsAppService:
    def __init__(self):
        self.client = Client(os.getenv("TWILIO_ACCOUNT_SID"), os.getenv("TWILIO_AUTH_TOKEN"))
        self.from_number = os.getenv("TWILIO_WHATSAPP_NUMBER")

    def send_message(self, to_number, message):
        try:
            if not to_number.startswith("whatsapp:"):
                to_number = f"whatsapp:{to_number}"

            message = self.client.messages.create(
                from_=self.from_number,
                body=message,
                to=to_number
            )
            return {"status": "success", "message_sid": message.sid}
        except Exception as e:
            return {"status": "error", "error": str(e)}

if __name__ == "__main__":
    whatsapp = WhatsAppService()
    response = whatsapp.send_message(os.getenv("MY_PHONE_NUMBER"), "¡Hola! Este es un mensaje de prueba desde Flask.")
    print(response)
