import logging

logging.basicConfig(
    filename="firewall.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def info(msg):
    print(msg)
    logging.info(msg)

def alert(msg):
    print(msg)
    logging.warning(msg)
