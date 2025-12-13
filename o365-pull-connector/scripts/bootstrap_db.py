#!/usr/bin/env python
from o365_connector.app import create_app


def main():
    create_app()
    print("Database initialized")


if __name__ == "__main__":
    main()
