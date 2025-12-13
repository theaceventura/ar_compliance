from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("o365_connector")
except PackageNotFoundError:
    __version__ = "0.1.0"
