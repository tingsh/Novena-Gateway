"""
Novena Gateway — Entry Point

Usage:
    python -m novena_gateway.main [--config /path/to/config.json]
"""

import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import sys

from novena_gateway.gateway.novena_gateway import NovenaGateway
from novena_gateway.gateway.hardware_preflight import run_preflight


def setup_logging(level="INFO", log_config=None, enable_file=True):
    log_format = '%(asctime)s - |%(levelname)s| [%(name)s] - %(message)s'
    log_level = getattr(logging, level.upper(), logging.INFO)

    handlers = [logging.StreamHandler(sys.stdout)]

    # Add rotating file handler if configured
    if enable_file and log_config and log_config.get("file"):
        log_file = log_config["file"]
        max_bytes = log_config.get("max_bytes", 5 * 1024 * 1024)  # 5 MB default
        backup_count = log_config.get("backup_count", 5)

        # Ensure the log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir:
            try:
                os.makedirs(log_dir, exist_ok=True)
            except OSError as e:
                print(f"WARNING: File logging disabled for {log_file}: {e}")
                log_file = None

        if log_file:
            try:
                file_handler = RotatingFileHandler(
                    log_file, maxBytes=max_bytes, backupCount=backup_count
                )
                file_handler.setFormatter(logging.Formatter(log_format))
                handlers.append(file_handler)
            except OSError as e:
                print(f"WARNING: File logging disabled for {log_file}: {e}")

    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=handlers
    )


def main():
    parser = argparse.ArgumentParser(description="Novena Gateway IoT Gateway")
    parser.add_argument(
        "--config", "-c",
        default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json"),
        help="Path to config.json (default: ./config.json)"
    )
    parser.add_argument(
        "--log-level", "-l",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)"
    )
    parser.add_argument(
        "--validate-only", "-v",
        action="store_true",
        help="Validate the config file and exit"
    )
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Run read-only hardware preflight checks and exit"
    )
    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f"ERROR: Config file not found: {args.config}")
        sys.exit(1)

    # Load logging config from config.json (optional "logging" block)
    config = None
    log_config = None
    try:
        with open(args.config, 'r') as f:
            config = json.load(f)
            log_config = config.get("logging")
    except Exception as e:
        if args.validate_only:
            print(f"ERROR: Invalid JSON format: {e}")
            sys.exit(1)
        pass

    if args.validate_only:
        setup_logging("WARNING", log_config=log_config, enable_file=False)
        errors = NovenaGateway.validate_config(config)
        if errors:
            print(f"Configuration is INVALID. Found {len(errors)} error(s):")
            for err in errors:
                print(f"  x {err}")
            sys.exit(1)
        else:
            print("Configuration is VALID.")
            sys.exit(0)

    if args.preflight:
        setup_logging("WARNING", log_config=log_config, enable_file=False)
        print(json.dumps(run_preflight(config), indent=2))
        sys.exit(0)

    setup_logging(args.log_level, log_config=log_config)

    gateway = NovenaGateway(args.config)
    gateway.run()


if __name__ == "__main__":
    main()
