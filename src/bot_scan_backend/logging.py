import logging

level = logging.INFO

logger = None


def get_logger():
    global logger
    if not logger:
        logger = logging.getLogger('clamav-scan')
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(level)
    return logger
