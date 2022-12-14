__version__ = '0.2.4'
__default_log_config__ = """
root:
    level: INFO
    handlers:
        - console
formatters:
    brief:
        format: "%(asctime)s %(levelname)s: %(message)s"
handlers:
    console:
        class: logging.StreamHandler
        stream: ext://sys.stdout
        formatter: brief
"""
__default_port__ = 8000
