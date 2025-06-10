import logging

class Logger:
    def __init__(self):
        logging.basicConfig(
            filename='robotic_arm.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger()

    def log(self, message, level="info"):
        getattr(self.logger, level.lower())(message)