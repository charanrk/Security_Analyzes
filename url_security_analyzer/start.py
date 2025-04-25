import os
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Add the current directory to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

logger.info("Starting application...")
logger.info(f"Python path: {sys.path}")

try:
    # Import and run the application
    from app import create_app
    
    app = create_app()
    
    if __name__ == '__main__':
        logger.info("Running application on http://localhost:3002")
        app.run(host='0.0.0.0', port=3002, debug=True)
except Exception as e:
    logger.error(f"Error starting application: {e}", exc_info=True)
    sys.exit(1) 